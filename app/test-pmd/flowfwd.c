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
#include <rte_member.h>

#include "testpmd.h"

#include "lib/vhost/rte_vhost.h"

#undef MAX_PKT_BURST
#include "lib/vhost/vhost.h"
#include "lib/vhost/vhost_user.h"

#define TCAM_SIZE 1024

struct per_port_burst {
	uint16_t count;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
};


struct ether_matcher {
};

struct flow_desc {
	LIST_ENTRY(flow_desc) next;
	uint64_t flow_id;
	uint64_t hits;
	uint64_t bytes;
	struct flow_matcher {
		struct rte_ether_addr dst_eth_addr;
	} matchers;
	struct flow_actions {
		struct rte_ether_addr dst_eth_addr;
		struct rte_ether_addr src_eth_addr;
		uint16_t port_id;
	} actions;
}__rte_aligned;
LIST_HEAD(flow_list, flow_desc) flow_list;



struct tcam_action_set {
	bool	in_use;
	uint16_t port_id;
};
struct tcam_action_set tcam_actions[TCAM_SIZE+1];

struct rte_member_setsum *tcam = NULL;

int rte_eth_vhost_get_vid_from_port_id(portid_t pi);
/*
 * Forwarding of packets according to the flow specs
 * basic flows will be inserted to ensure the traffic
 * going from 1 port to another
 */
static void
pkt_burst_flow_forward(struct fwd_stream *fs)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct per_port_burst tx_bursts[RTE_MAX_ETHPORTS+1];
	uint16_t nb_rx;
	uint16_t nb_tx;
	uint64_t start_tsc = 0;

	get_start_cycles(&start_tsc);

	/*
	 * Receive a burst of packets and forward them.
	 */
	nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue,
			pkts_burst, nb_pkt_per_burst);
	inc_rx_burst_stats(fs, nb_rx);
	rte_prefetch0(&tx_bursts[0]);
	if (unlikely(nb_rx == 0))
		return;
	for(int i=0; i < RTE_MAX_ETHPORTS; i++) {
		rte_prefetch0(&tx_bursts[i+1]);
		tx_bursts[i].count = 0;
	}

	rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[0], void *));
	fs->rx_packets += nb_rx;

	/*********/
	/* Look for programmed flows, and modify packets accordingly
	 * fs->tx_port won't be relevant for the whole burst, so we may
	 * to group packets before calling rte_eth_tx_burst.
	 */
//	rte_member_add(tcam, eth_hdr->src_addr, &action_id);


	for (int i = 0; i < nb_rx; i++) {
		if (likely(i < nb_rx-1)) {
			rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i+1], void *));
		}
		uint16_t action_id;
		struct rte_ether_hdr * eth_hdr = rte_pktmbuf_mtod(pkts_burst[i],
				struct rte_ether_hdr *);
		struct flow_desc *f;

		if (unlikely(rte_member_lookup(tcam, &eth_hdr->src_addr, &action_id) == 0 )) {
			for(int k = 1; k < TCAM_SIZE; k++) {
				if(tcam_actions[k].in_use == false) {
					tcam_actions[k].in_use = true;
					tcam_actions[k].port_id = fs->rx_port;
					rte_member_add(tcam, &eth_hdr->src_addr, k);
					break;
				}
			}
		} else if ( unlikely(tcam_actions[action_id].port_id != fs->rx_port) ) {
			tcam_actions[action_id].port_id = fs->rx_port;
		}


		uint16_t port_id = fs->tx_port;
		LIST_FOREACH(f, &flow_list, next) {
		if (rte_is_same_ether_addr(&eth_hdr->dst_addr,
					&f->matchers.dst_eth_addr)) {
			rte_ether_addr_copy(&f->actions.dst_eth_addr,
					&eth_hdr->dst_addr);
			rte_ether_addr_copy(&f->actions.src_eth_addr,
					&eth_hdr->src_addr);
			f->hits++;
			f->bytes += rte_pktmbuf_data_len(pkts_burst[i]);
			// port_id = f->actions.port_id;
			break;
			}
		}
		if (likely(rte_member_lookup(tcam, &eth_hdr->dst_addr, &action_id) == 1)) {
			port_id = tcam_actions[action_id].port_id;
		} else {
			port_id = fs->tx_port;
		}
		tx_bursts[port_id].pkts_burst[tx_bursts[port_id].count] = pkts_burst[i];
		tx_bursts[port_id].count++;
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


static int
flow_create(int port_id __rte_unused, uint8_t *data, size_t len __rte_unused) {
	struct virtio_net_flow_desc *flow_desc = (struct virtio_net_flow_desc *)data;
	struct rte_flow_conv_rule *rule = (struct rte_flow_conv_rule *)&flow_desc->hdr;
	rte_flow_describe(stdout, 
			rule->attr,
			rule->pattern,
			rule->actions);
	struct rte_flow_item * items = rule->pattern;
	struct rte_flow_action * actions = rule->actions;


	struct flow_desc *f = calloc(1, sizeof(struct flow_desc));
	f->flow_id = flow_desc->flow_id;

	for (; items->type != RTE_FLOW_ITEM_TYPE_END; ++items) {
	switch(items->type) {
	case RTE_FLOW_ITEM_TYPE_ETH:
	{
		const struct rte_flow_item_eth *fie =
			(const struct rte_flow_item_eth *) items->spec;
		rte_ether_addr_copy(&fie->hdr.dst_addr, &f->matchers.dst_eth_addr);
		break;
	}
	default:
		break;
	}
	}

	for (; actions->type != RTE_FLOW_ACTION_TYPE_END; actions++) {
	switch(actions->type) {
	case RTE_FLOW_ACTION_TYPE_SET_MAC_SRC:
		{
		const struct rte_flow_action_set_mac * m = actions->conf;
		rte_ether_addr_copy((struct rte_ether_addr*)&m->mac_addr, &f->actions.src_eth_addr);
		}
		break;
	case RTE_FLOW_ACTION_TYPE_SET_MAC_DST:
		{
		const struct rte_flow_action_set_mac * m = actions->conf;
		rte_ether_addr_copy((struct rte_ether_addr*)&m->mac_addr, &f->actions.dst_eth_addr);
		}
		break;
	case RTE_FLOW_ACTION_TYPE_PORT_ID:
		{
		const struct rte_flow_action_port_id *port = actions->conf;
		f->actions.port_id = port->id;
		}
		break;
	default:
		break;
	}
	}

	LIST_INSERT_HEAD(&flow_list, f, next);
	return 0;

fail:
	free(f);
	return -1;
}

static int
flow_destroy(int port_id, uint64_t flow_id) {
	printf("%s pid %d flow_id %lu\n", __func__, port_id, flow_id);
	fflush(stdout);
	struct flow_desc *f;
	LIST_FOREACH(f, &flow_list, next) {
		if (f->flow_id == flow_id) {
			LIST_REMOVE(f, next);
			free(f);
			return 0;
		}
	}
	return 0;
}

static int
flow_query(int port_id, uint64_t flow_id, uint64_t *pkts, uint64_t *bytes) {
	// int vid = rte_eth_vhost_get_vid_from_port_id(port_id);
	*pkts = 0;
	*bytes = 0;
	// if (vid >= 0) {
		printf("%s pid %d flow_id %lu\n", __func__, port_id, flow_id);
		struct flow_desc *f;
		LIST_FOREACH(f, &flow_list, next) {
			if (f->flow_id == flow_id) {
				*pkts = f->hits;
				*bytes = f->bytes;
				return 0;
			}
		}
	//}
	return -1;
}


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
	if(!tcam)
	{
		LIST_INIT(&flow_list);
		struct rte_member_parameters params = {
			.name = "content_access_memory",
			.type = RTE_MEMBER_TYPE_HT,
			.is_cache = 1,
			.num_keys = TCAM_SIZE,
			.key_len = 6, /* mac address */
			.prim_hash_seed = 0xcafebabe,
			.sec_hash_seed = 0xdeadbeef,
			.socket_id = 0,
		};
		tcam = rte_member_create(&params);
	}

	return 0;
}

static void
flow_end(portid_t pi __rte_unused)
{
	for(int i=0 ; i < TCAM_SIZE+1 ; i++) {
		tcam_actions[i].in_use = false;
	}
	rte_member_reset(tcam);
}

struct fwd_engine flow_fwd_engine = {
	.fwd_mode_name  = "flow",
	.port_fwd_begin = flow_setup,
	.port_fwd_end   = flow_end,
	.packet_fwd     = pkt_burst_flow_forward,
};
