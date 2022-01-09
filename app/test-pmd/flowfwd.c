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

int
flow_create(int port_id, uint8_t *frule, size_t len) {
	int err;
	VirtioFlowSpec *rule = (VirtioFlowSpec *)frule;

	struct rte_flow_item *patterns = (struct rte_flow_item *)&rule->flow_spec[0];
	struct rte_flow_action *actions = (struct rte_flow_action *)&rule->flow_spec[rule->pattern_size];
	char *name = "";
	printf("pattern ");

	for(int i=0; patterns[i].type != RTE_FLOW_ITEM_TYPE_END; i++) {
		err = rte_flow_conv(RTE_FLOW_CONV_OP_ITEM_NAME_PTR,
	  	      &name, sizeof(char*),
		      (void*)(uintptr_t)patterns[i].type, NULL);
		if(err < 0) {
			printf("Unknown pattern type: %d", patterns[i].type);
			err = 0;
		} else {
			printf("%s", name);
		}
		printf(" ");
		switch(patterns[i].type) {
		case RTE_FLOW_ITEM_TYPE_ETH:
			{
			struct rte_flow_item_eth *fie = (struct rte_flow_item_eth *) patterns[i].spec;
			char buf[RTE_ETHER_ADDR_FMT_SIZE];
			rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, &fie->hdr.src_addr);
			printf("src %s ", buf);
			rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, &fie->hdr.dst_addr);
			printf("dst %s ", buf);
			}
			break;
		case RTE_FLOW_ITEM_TYPE_PORT_ID:
			printf("%d ", ((struct rte_flow_item_port_id*)patterns[i].spec)->id);
			break;
		default:
			printf(" UNKNOWN ");
		}
	}

	printf(" actions ");

	for (int i=0; actions[i].type != RTE_FLOW_ACTION_TYPE_END; i++) {
		err = rte_flow_conv(RTE_FLOW_CONV_OP_ACTION_NAME_PTR,
		  	      &name, sizeof(name),
			      (void*)(uintptr_t)(actions[i].type), NULL);
		if(err < 0) {
			printf("Unknown action type: %d", actions[i].type);
			err = 0;
		} else {
			printf("%s", name);
		}
		printf(" ");
		switch(actions[i].type) {
		case RTE_FLOW_ACTION_TYPE_PORT_ID:
			printf("%d ", ((struct rte_flow_action_port_id*)actions[i].conf)->id);
			break;
		case RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR:
		case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
			printf("%d ", ((struct rte_flow_action_ethdev*)actions[i].conf)->port_id);
			break;

		case RTE_FLOW_ACTION_TYPE_DROP:
			break;

		case RTE_FLOW_ACTION_TYPE_SET_MAC_SRC:
			{
			struct rte_flow_action_set_mac *mac =
				(struct rte_flow_action_set_mac *) actions[i].conf;
			char buf[RTE_ETHER_ADDR_FMT_SIZE];
			rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE,
					      (const struct rte_ether_addr *)&mac->mac_addr);
			printf("%s ", buf);
			}
			break;

		case RTE_FLOW_ACTION_TYPE_SET_MAC_DST:
			{
			struct rte_flow_action_set_mac *mac =
				(struct rte_flow_action_set_mac *) actions[i].conf;
			char buf[RTE_ETHER_ADDR_FMT_SIZE];
			rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE,
					      (const struct rte_ether_addr *)&mac->mac_addr);
			printf("%s ", buf);
			}
			break;

		case RTE_FLOW_ACTION_TYPE_COUNT:
			if (((struct rte_flow_query_count*)actions[i].conf)->hits_set)
			printf("hits %lu ", ((struct rte_flow_query_count*)actions[i].conf)->hits);
			if (((struct rte_flow_query_count*)actions[i].conf)->bytes_set)
			printf("bytes %lu", ((struct rte_flow_query_count*)actions[i].conf)->bytes);
			break;

		default:
			printf(" UNKNOWN ");
			break;
		}
	}

	printf("\n");
	return 0;
}

int
flow_destroy(int port_id, uint64_t flow_id) {
	printf("%s pid %d flow_id %lu", __func__, port_id, flow_id);
	return 0;
}

int
flow_query(int port_id, uint64_t flow_id, uint64_t *pkt, uint64_t *bytes) {
	printf("%s pid %d flow_id %lu", __func__, port_id, flow_id);
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
