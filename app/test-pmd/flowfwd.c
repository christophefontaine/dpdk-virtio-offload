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

#undef MAX_PKT_BURST
#include "lib/vhost/vhost.h"


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

void rule_offset_to_ptrs(struct rte_flow_conv_rule *rule);

static int
flow_create(int port_id __rte_unused, uint8_t *data, size_t len __rte_unused) {
	struct rte_flow_conv_rule *rule = (struct rte_flow_conv_rule *)data;
	rule_offset_to_ptrs(rule);
	rte_flow_describe(stdout, 
			rule->attr,
			rule->pattern,
			rule->actions);
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

int rte_eth_vhost_get_vid_from_port_id(portid_t pi);

static int
flow_setup(portid_t pi)
{
	char path[256];
	int vid = rte_eth_vhost_get_vid_from_port_id(pi);
	
	if (vid >= 0) {
		rte_vhost_get_ifname(vid, path, 256);
		/* A bit hacky */
#pragma GCC diagnostic push  // require GCC 4.6
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
		struct rte_vhost_device_ops * ops = vhost_driver_callback_get(path);
#pragma GCC diagnostic pop   // require GCC 4.6
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
