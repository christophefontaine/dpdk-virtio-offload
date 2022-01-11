/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Red Hat
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <linux/netlink.h>
#include <linux/pkt_cls.h>
#include <libmnl/libmnl.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>
#include <rte_flow.h>

#include "testpmd.h"

#include "lib/vhost/rte_vhost.h"
#include "lib/vhost/vhost.h"
#include "lib/vhost/vhost_user.h"


struct per_port_burst {
	uint16_t count;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
};

/*
 * Forwarding of packets in I/O mode.
 * Forward packets "as-is".
 * This is the fastest possible forwarding operation, as it does not access
 * to packets data.
 */
static void
pkt_burst_flow_forward(struct fwd_stream *fs)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct per_port_burst tx_bursts[RTE_MAX_ETHPORTS];
	uint16_t nb_rx;
	uint16_t nb_tx;
	uint32_t retry;
	uint64_t start_tsc = 0;

	get_start_cycles(&start_tsc);
	memset(tx_bursts, 0, sizeof(tx_bursts));

	/*
	 * Receive a burst of packets and forward them.
	 */
	nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue,
			pkts_burst, nb_pkt_per_burst);
	inc_rx_burst_stats(fs, nb_rx);
	if (unlikely(nb_rx == 0))
		return;
	fs->rx_packets += nb_rx;

	/*********/
	/* Look for programmed flows, and modify packets accordingly
	 * fs->tx_port won't be relevant for the whole burst, so we may
	 * to group packets before calling rte_eth_tx_burst.
	 */
	tx_bursts[fs->tx_port].count = nb_rx;
	for (int i = 0; i < nb_rx; i++) {
		tx_bursts[fs->tx_port].pkts_burst[i] = pkts_burst[i];
	}
	/*********/

	for (int pid = 0; pid < RTE_MAX_ETHPORTS; pid++) {
		if(tx_bursts[pid].count == 0)
			continue;
		nb_tx = rte_eth_tx_burst(pid, fs->tx_queue,
				tx_bursts[pid].pkts_burst, tx_bursts[pid].count);
		fs->tx_packets += nb_tx;
		inc_tx_burst_stats(fs, nb_tx);
		if (unlikely(nb_tx < tx_bursts[pid].count)) {
			fs->fwd_dropped += (tx_bursts[pid].count - nb_tx);
			do {
				rte_pktmbuf_free(tx_bursts[pid].pkts_burst[nb_tx]);
			} while (++nb_tx < nb_rx);
		}
	}
	get_end_cycles(fs, start_tsc);
}

#define NLMSG_BUF 1024
struct nlmsg {
       struct nlmsghdr nh;
       char buf[NLMSG_BUF];
};

struct nl_pattern {
	char str[64];
	int (*display)(uint8_t *buf);
};

static int
print_eth(uint8_t *buf)
{
	char str[32] = "";
	rte_ether_format_addr(str, 32, (struct rte_ether_addr*)buf);
	printf("%s", str);
	return 0;
}

static int
print_ipv4(uint8_t *buf)
{
	printf("%d.%d.%d.^d", buf[0], buf[1], buf[2], buf[3]);
	return 0;
}

static int
print_ipv6(uint8_t *buf)
{
	printf("0x%08x", buf);
	return 0;
}

static int
print_port(uint8_t *buf)
{
	printf("%d", *(uint16_t*)buf);
	return 0;
}


static const struct nl_pattern nl_patterns[] = {
	[TCA_FLOWER_KEY_ETH_DST]	= { .str="TCA_FLOWER_KEY_ETH_DST"	, .display = print_eth, },
	[TCA_FLOWER_KEY_ETH_DST_MASK]	= { .str="TCA_FLOWER_KEY_ETH_DST_MASK"	, .display = print_eth, },
	[TCA_FLOWER_KEY_ETH_SRC]	= { .str="TCA_FLOWER_KEY_ETH_SRC"	, .display = print_eth, },
	[TCA_FLOWER_KEY_ETH_SRC_MASK]	= { .str="TCA_FLOWER_KEY_ETH_SRC_MASK"	, .display = print_eth, },
	[TCA_FLOWER_KEY_IPV4_SRC]	= { .str="TCA_FLOWER_KEY_IPV4_SRC"	, .display = print_ipv4, },
	[TCA_FLOWER_KEY_IPV4_SRC_MASK]	= { .str="TCA_FLOWER_KEY_IPV4_SRC_MASK"	, .display = print_ipv4, },
	[TCA_FLOWER_KEY_IPV4_DST]	= { .str="TCA_FLOWER_KEY_IPV4_DST"	, .display = print_ipv4, },
	[TCA_FLOWER_KEY_IPV4_DST_MASK]	= { .str="TCA_FLOWER_KEY_IPV4_DST_MASK"	, .display = print_ipv4, },
	[TCA_FLOWER_KEY_IPV6_SRC]	= { .str="TCA_FLOWER_KEY_IPV6_SRC"	, .display = print_ipv6, },
	[TCA_FLOWER_KEY_IPV6_SRC_MASK]	= { .str="TCA_FLOWER_KEY_IPV6_SRC_MASK"	, .display = print_ipv6, },
	[TCA_FLOWER_KEY_IPV6_DST]	= { .str="TCA_FLOWER_KEY_IPV6_DST"	, .display = print_ipv6, },
	[TCA_FLOWER_KEY_IPV6_DST_MASK]	= { .str="TCA_FLOWER_KEY_IPV6_DST_MASK"	, .display = print_ipv6, },
	[TCA_FLOWER_KEY_TCP_SRC]	= { .str="TCA_FLOWER_KEY_TCP_SRC"	, .display = print_port, },	
	[TCA_FLOWER_KEY_TCP_SRC_MASK]	= { .str="TCA_FLOWER_KEY_TCP_SRC_MASK"	, .display = print_port, },
	[TCA_FLOWER_KEY_TCP_DST]	= { .str="TCA_FLOWER_KEY_TCP_DST"	, .display = print_port, },	
	[TCA_FLOWER_KEY_TCP_DST_MASK]	= { .str="TCA_FLOWER_KEY_TCP_DST_MASK"	, .display = print_port, },
	[TCA_FLOWER_KEY_UDP_SRC]	= { .str="TCA_FLOWER_KEY_UDP_SRC"	, .display = print_port, },	
	[TCA_FLOWER_KEY_UDP_SRC_MASK]	= { .str="TCA_FLOWER_KEY_UDP_SRC_MASK"	, .display = print_port, },
	[TCA_FLOWER_KEY_UDP_DST]	= { .str="TCA_FLOWER_KEY_UDP_DST"	, .display = print_port, },
	[TCA_FLOWER_KEY_UDP_DST_MASK]	= { .str="TCA_FLOWER_KEY_UDP_DST_MASK"	, .display = print_port, },
	[TCA_FLOWER_KEY_SCTP_SRC]	= { .str="TCA_FLOWER_KEY_SCTP_SRC"	, .display = print_port, },
	[TCA_FLOWER_KEY_SCTP_SRC_MASK]	= { .str="TCA_FLOWER_KEY_SCTP_SRC_MASK"	, .display = print_port, },
	[TCA_FLOWER_KEY_SCTP_DST]	= { .str="TCA_FLOWER_KEY_SCTP_DST"	, .display = print_port, },
	[TCA_FLOWER_KEY_SCTP_DST_MASK]	= { .str="TCA_FLOWER_KEY_SCTP_DST_MASK"	, .display = print_port, },
};
static const char *nl_actions[] = {
};

static int dump_nl_flow(struct nlmsg *msg)
{
	return 0;
}

static int
flow_create(int port_id, uint8_t *rule, size_t len) {
	int err;

        struct nlmsghdr *msg = (struct nlmsghdr *)rule;
	struct nlattr *attr;
	int sz = mnl_attr_get_len(attr);
/*
	for()
	{
		if (mnl_attr_get_type(attr) == TCA_FLOW_KEYS) {
		}
	}
*/

//	for(; mnl_attr_ok(attr, sz); attr=mnl_attr_next(attr), sz=mnl_attr_get_len(attr))
	mnl_attr_for_each(attr, msg, 0)
	{
		uint16_t type = mnl_attr_get_type(attr);
		void *payload = mnl_attr_get_payload(attr);
		switch(type) {
			case TCA_FLOW_KEYS:
			{
				printf("Pattern:\n");
				struct nlattr * nestedattr;
				mnl_attr_for_each_nested(nestedattr, attr) {
				type = mnl_attr_get_type(nestedattr);
				uint16_t payload_len = mnl_attr_get_payload_len(nestedattr);
				uint8_t * payload = mnl_attr_get_payload(nestedattr);
				if (nl_patterns[type].str) {
					printf("%s ", nl_patterns[type].str);
					nl_patterns[type].display(payload);
					printf(" | ");
				} else {
					printf("type: %d len %d | ", type, payload_len);
				}
				}
			}
			break;
			case TCA_FLOW_ACT:
			{
				printf("\nActions:\n");
				struct nlattr * nestedattr;
				mnl_attr_for_each_nested(nestedattr, attr) {
				uint16_t payload_len = mnl_attr_get_payload_len(nestedattr);
				printf("type: %d len %d | ", type, payload_len);
				}
			}
			break;
			default:
				printf("Unknown upper type: %d | ", type);
				break;

		}
	}
	printf("\n");
	return 0;
}

static int
flow_destroy(int port_id, uint64_t flow_id) {
	printf("%s pid %d flow_id %lu\n", __func__, port_id, flow_id);
	fflush(stdout);
	return 0;
}

static int
flow_query(int port_id, uint64_t flow_id, uint64_t *pkt, uint64_t *bytes) {
	printf("%s pid %d flow_id %lu\n", __func__, port_id, flow_id);
	fflush(stdout);
	*pkt = 42;
	*bytes = 0xba0bab;
	return 0;
}

static int
flow_setup(portid_t pi)
{
	char path[256];
	int vid = rte_eth_vhost_get_vid_from_port_id(pi);
	
	if (vid >= 0) {
		rte_vhost_get_ifname(vid, path, 256);
		struct rte_vhost_device_ops * ops = vhost_driver_callback_get(path);
		ops->flow_create = flow_create;
		ops->flow_destroy = flow_destroy;
		ops->flow_query = flow_query;
	}
	return 0;
}

struct fwd_engine flow_fwd_engine = {
	.fwd_mode_name  = "flow",
	.port_fwd_begin = flow_setup,
	.port_fwd_end   = NULL,
	.packet_fwd     = pkt_burst_flow_forward,
};
