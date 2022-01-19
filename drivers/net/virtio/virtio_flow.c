/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Red Hat, Inc.
 */


#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

/* used to serialize rte_flow to a netlink msg */
#include <linux/netlink.h>
#include <linux/pkt_cls.h>
#include <libmnl/libmnl.h>

#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_flow_driver.h>
#include <rte_tailq.h>

#include "virtio.h"
#include "virtio_logs.h"
#include "virtio_user/virtio_user_dev.h"
#include "virtio_user/vhost.h"

#define NLMSG_BUF 1024
struct vhost_flow_msg  {
	struct nlmsghdr nh;
	char buf[NLMSG_BUF];
} __rte_packed;

struct rte_flow {
	LIST_ENTRY(rte_flow) next; /* Pointer to the next rte_flow structure */
	struct rte_flow_conv_rule rule;
};


#define virtio_user_get_dev(hwp) container_of(hwp, struct virtio_user_dev, hw)
struct virtio_flow_items {
	const void *mask;
	const unsigned int mask_sz;
	const void *default_mask;
	int (*serialize)(const struct rte_flow_item *item, struct nlmsghdr *hdr);
	const enum rte_flow_item_type *const items;
};

struct virtio_flow_actions {
	const void *mask;
	const unsigned int mask_sz;
	const void *default_mask;
	int (*serialize)(const struct rte_flow_action *item, struct nlmsghdr *hdr);
};


static int
virtio_flow_dev_dump(struct rte_eth_dev *dev,
		struct rte_flow *flow,
		FILE *file,
		struct rte_flow_error *error);

static int virtio_flow_create_eth(const struct rte_flow_item *item, struct nlmsghdr *msg);
static int virtio_flow_create_vlan(const struct rte_flow_item *item, struct nlmsghdr *msg);
static int virtio_flow_create_ipv4(const struct rte_flow_item *item, struct nlmsghdr *msg);
static int virtio_flow_create_ipv6(const struct rte_flow_item *item, struct nlmsghdr *msg);
static int virtio_flow_create_udp(const struct rte_flow_item *item, struct nlmsghdr *msg);
static int virtio_flow_create_tcp(const struct rte_flow_item *item, struct nlmsghdr *msg);
static int virtio_flow_create_sctp(const struct rte_flow_item *item, struct nlmsghdr *msg);



/* Static initializer for items. */
#define ITEMS(...) \
	(const enum rte_flow_item_type []){ \
		__VA_ARGS__, RTE_FLOW_ITEM_TYPE_END, \
	}

static const struct virtio_flow_items virtio_flow_items[] = {
	[RTE_FLOW_ITEM_TYPE_END] = {
		.items = ITEMS(RTE_FLOW_ITEM_TYPE_ETH),
	},
	[RTE_FLOW_ITEM_TYPE_ETH] = {
		.items = ITEMS(
			RTE_FLOW_ITEM_TYPE_VLAN,
			RTE_FLOW_ITEM_TYPE_IPV4,
			RTE_FLOW_ITEM_TYPE_IPV6),
		.mask = &(const struct rte_flow_item_eth){
			.dst.addr_bytes = "\xff\xff\xff\xff\xff\xff",
			.src.addr_bytes = "\xff\xff\xff\xff\xff\xff",
			.type = -1,
		},
		.mask_sz = sizeof(struct rte_flow_item_eth),
		.default_mask = &rte_flow_item_eth_mask,
		.serialize = virtio_flow_create_eth,
	},
	[RTE_FLOW_ITEM_TYPE_VLAN] = {
		.items = ITEMS(RTE_FLOW_ITEM_TYPE_IPV4,
			       RTE_FLOW_ITEM_TYPE_IPV6),
		.mask = &(const struct rte_flow_item_vlan){
			/* DEI matching is not supported */
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
			.tci = 0xffef,
#else
			.tci = 0xefff,
#endif
			.inner_type = -1,
		},
		.mask_sz = sizeof(struct rte_flow_item_vlan),
		.default_mask = &rte_flow_item_vlan_mask,
		.serialize = virtio_flow_create_vlan,
	},
	[RTE_FLOW_ITEM_TYPE_IPV4] = {
		.items = ITEMS(RTE_FLOW_ITEM_TYPE_UDP,
			       RTE_FLOW_ITEM_TYPE_TCP),
		.mask = &(const struct rte_flow_item_ipv4){
			.hdr = {
				.src_addr = -1,
				.dst_addr = -1,
				.next_proto_id = -1,
			},
		},
		.mask_sz = sizeof(struct rte_flow_item_ipv4),
		.default_mask = &rte_flow_item_ipv4_mask,
		.serialize = virtio_flow_create_ipv4,
	},
	[RTE_FLOW_ITEM_TYPE_IPV6] = {
		.items = ITEMS(RTE_FLOW_ITEM_TYPE_UDP,
			       RTE_FLOW_ITEM_TYPE_TCP),
		.mask = &(const struct rte_flow_item_ipv6){
			.hdr = {
				.src_addr = {
					"\xff\xff\xff\xff\xff\xff\xff\xff"
					"\xff\xff\xff\xff\xff\xff\xff\xff",
				},
				.dst_addr = {
					"\xff\xff\xff\xff\xff\xff\xff\xff"
					"\xff\xff\xff\xff\xff\xff\xff\xff",
				},
				.proto = -1,
			},
		},
		.mask_sz = sizeof(struct rte_flow_item_ipv6),
		.default_mask = &rte_flow_item_ipv6_mask,
		.serialize = virtio_flow_create_ipv6,
	},
	[RTE_FLOW_ITEM_TYPE_UDP] = {
		.mask = &(const struct rte_flow_item_udp){
			.hdr = {
				.src_port = -1,
				.dst_port = -1,
			},
		},
		.mask_sz = sizeof(struct rte_flow_item_udp),
		.default_mask = &rte_flow_item_udp_mask,
		.serialize = virtio_flow_create_udp,
	},
	[RTE_FLOW_ITEM_TYPE_TCP] = {
		.mask = &(const struct rte_flow_item_tcp){
			.hdr = {
				.src_port = -1,
				.dst_port = -1,
			},
		},
		.mask_sz = sizeof(struct rte_flow_item_tcp),
		.default_mask = &rte_flow_item_tcp_mask,
		.serialize = virtio_flow_create_tcp,
	},
	[RTE_FLOW_ITEM_TYPE_SCTP] = {
		.mask = &(const struct rte_flow_item_sctp){
			.hdr = {
				.src_port = -1,
				.dst_port = -1,
			},
		},
		.mask_sz = sizeof(struct rte_flow_item_sctp),
		.default_mask = &rte_flow_item_sctp_mask,
		.serialize = virtio_flow_create_sctp,
	},

};

static int
virtio_flow_create_eth(const struct rte_flow_item *item, struct nlmsghdr *msg)
{
	const struct rte_flow_item_eth *spec = item->spec;
	const struct rte_flow_item_eth *mask = item->mask;

	/* use default mask if none provided */
	if (!mask)
		mask = virtio_flow_items[RTE_FLOW_ITEM_TYPE_ETH].default_mask;
	if (!spec)
		return 0;

	if (!rte_is_zero_ether_addr(&mask->dst)) {
		mnl_attr_put(msg, TCA_FLOWER_KEY_ETH_DST,
			  RTE_ETHER_ADDR_LEN,
			  &spec->dst.addr_bytes);
		mnl_attr_put(msg,
			  TCA_FLOWER_KEY_ETH_DST_MASK, RTE_ETHER_ADDR_LEN,
			  &mask->dst.addr_bytes);
	}
	if (!rte_is_zero_ether_addr(&mask->src)) {
		mnl_attr_put(msg, TCA_FLOWER_KEY_ETH_SRC,
			  RTE_ETHER_ADDR_LEN,
			  &spec->src.addr_bytes);
		mnl_attr_put(msg,
			  TCA_FLOWER_KEY_ETH_SRC_MASK, RTE_ETHER_ADDR_LEN,
			  &mask->src.addr_bytes);
	}
	return 0;
}

static int
virtio_flow_create_vlan(const struct rte_flow_item *item, struct nlmsghdr *msg)
{
	const struct rte_flow_item_vlan *spec = item->spec;
	if (!spec)
		return 0;
	mnl_attr_put_u16(msg, TCA_FLOWER_KEY_VLAN_ID, spec->hdr.vlan_tci);
	return 0;
}

static int
virtio_flow_create_ipv4(const struct rte_flow_item *item, struct nlmsghdr *msg)
{
	const struct rte_flow_item_ipv4 *spec = item->spec;
	const struct rte_flow_item_ipv4 *mask = item->mask;

	if (!mask)
		mask = virtio_flow_items[RTE_FLOW_ITEM_TYPE_IPV4].default_mask;

	if (!spec)
		return 0;

	if (mask->hdr.src_addr != 0) {
		mnl_attr_put_u32(msg, TCA_FLOWER_KEY_IPV4_SRC, spec->hdr.src_addr);
		mnl_attr_put_u32(msg, TCA_FLOWER_KEY_IPV4_SRC_MASK, mask->hdr.src_addr);
	}
	if (mask->hdr.dst_addr != 0) {
		mnl_attr_put_u32(msg, TCA_FLOWER_KEY_IPV4_DST, spec->hdr.dst_addr);
		mnl_attr_put_u32(msg, TCA_FLOWER_KEY_IPV4_DST_MASK, mask->hdr.dst_addr);
	}
	return 0;
}

static int
virtio_flow_create_ipv6(const struct rte_flow_item *item, struct nlmsghdr *msg)
{
	mnl_attr_put(msg, TCA_FLOWER_KEY_IPV6_SRC, 16, item->spec);
	return -ENOTSUP;
}

static int
virtio_flow_create_udp(const struct rte_flow_item *item, struct nlmsghdr *msg)
{
	const struct rte_flow_item_udp *spec = item->spec;
	const struct rte_flow_item_udp *mask = item->mask;
	if (!mask)
		mask = virtio_flow_items[RTE_FLOW_ITEM_TYPE_UDP].default_mask;
	if (!spec)
		return 0;

	if (mask->hdr.src_port != 0) {
		mnl_attr_put_u16(msg, TCA_FLOWER_KEY_UDP_SRC, spec->hdr.src_port);
		mnl_attr_put_u16(msg, TCA_FLOWER_KEY_UDP_SRC_MASK, mask->hdr.src_port);
	}
	if (mask->hdr.dst_port != 0) {
		mnl_attr_put_u16(msg, TCA_FLOWER_KEY_UDP_DST, spec->hdr.dst_port);
		mnl_attr_put_u16(msg, TCA_FLOWER_KEY_UDP_DST_MASK, mask->hdr.dst_port);
	}
	return 0;
}


static int
virtio_flow_create_tcp(const struct rte_flow_item *item, struct nlmsghdr *msg)
{
	const struct rte_flow_item_tcp *spec = item->spec;
	const struct rte_flow_item_tcp *mask = item->mask;
	if (!mask)
		mask = virtio_flow_items[RTE_FLOW_ITEM_TYPE_TCP].default_mask;
	if (!spec)
		return 0;

	if (mask->hdr.src_port != 0) {
		mnl_attr_put_u16(msg, TCA_FLOWER_KEY_TCP_SRC, spec->hdr.src_port);
		mnl_attr_put_u16(msg, TCA_FLOWER_KEY_TCP_SRC_MASK, mask->hdr.src_port);
	}
	if (mask->hdr.dst_port != 0) {
		mnl_attr_put_u16(msg, TCA_FLOWER_KEY_TCP_DST, spec->hdr.dst_port);
		mnl_attr_put_u16(msg, TCA_FLOWER_KEY_TCP_DST_MASK, mask->hdr.dst_port);
	}
	return 0;
}
static int
virtio_flow_create_sctp(const struct rte_flow_item *item, struct nlmsghdr *msg)
{
	const struct rte_flow_item_sctp *spec = item->spec;
	const struct rte_flow_item_sctp *mask = item->mask;
	if (!mask)
		mask = virtio_flow_items[RTE_FLOW_ITEM_TYPE_SCTP].default_mask;
	if (!spec)
		return 0;

	if (mask->hdr.src_port != 0) {
		mnl_attr_put_u16(msg, TCA_FLOWER_KEY_SCTP_SRC, spec->hdr.src_port);
		mnl_attr_put_u16(msg, TCA_FLOWER_KEY_SCTP_SRC_MASK, mask->hdr.src_port);
	}
	if (mask->hdr.dst_port != 0) {
		mnl_attr_put_u16(msg, TCA_FLOWER_KEY_SCTP_DST, spec->hdr.dst_port);
		mnl_attr_put_u16(msg, TCA_FLOWER_KEY_SCTP_DST_MASK, mask->hdr.dst_port);
	}
	return 0;
}

static int
virtio_flow_actions_noop(const struct rte_flow_action *action __rte_unused,
			 struct nlmsghdr *msg __rte_unused)
{
	return 0;
}

static int
virtio_flow_actions_drop(const struct rte_flow_action *action __rte_unused,
			 struct nlmsghdr *msg)
{
	uint8_t ;
	mnl_attr_put(msg,
		  TCA_FLOWER_ACT, RTE_ETHER_ADDR_LEN,
		  &conf->id);
	return 0;
}


static int
virtio_flow_actions_set_port_id(const struct rte_flow_action *action __rte_unused,
				struct nlmsghdr *msg)
{
	const struct rte_flow_action_port_id * conf = action->conf;
	mnl_attr_put(msg,
		  TCA_FLOWER_ACT, RTE_ETHER_ADDR_LEN,
		  &conf->id);
	return 0;
}

static int
virtio_flow_actions_set_mac_src(const struct rte_flow_action *action, struct nlmsghdr *msg)
{	
	const struct rte_flow_action_set_mac *conf = action->conf;
	if (!conf)
		return 0;
	mnl_attr_put(msg,
		  TCA_FLOWER_KEY_ETH_SRC, RTE_ETHER_ADDR_LEN,
		  conf->mac_addr);
	return 0;
}

static int
virtio_flow_actions_set_mac_dst(const struct rte_flow_action *action, struct nlmsghdr *msg)
{
	const struct rte_flow_action_set_mac *conf = action->conf;
	if (!action)
		return 0;
	mnl_attr_put(msg,
		  TCA_FLOWER_KEY_ETH_DST, RTE_ETHER_ADDR_LEN,
		  conf->mac_addr);
	return 0;
}

static const struct virtio_flow_actions virtio_flow_actions[] = {
	[RTE_FLOW_ACTION_TYPE_END] = {
		.serialize = virtio_flow_actions_noop,
	},
	[RTE_FLOW_ACTION_TYPE_VOID] = {
		.serialize = virtio_flow_actions_noop,
	},
	[RTE_FLOW_ACTION_TYPE_DROP] = {
		.serialize = virtio_flow_actions_drop,
	},
	[RTE_FLOW_ACTION_TYPE_COUNT] = {
		.serialize = virtio_flow_actions_noop,
	},
	[RTE_FLOW_ACTION_TYPE_PORT_ID] = {
		.serialize = virtio_flow_actions_set_port_id,
	},
	[RTE_FLOW_ACTION_TYPE_SET_MAC_SRC] = {
		.serialize = virtio_flow_actions_set_mac_src,
	},
	[RTE_FLOW_ACTION_TYPE_SET_MAC_DST] = {
		.serialize = virtio_flow_actions_set_mac_dst,
	},
	[RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC] = {
		.serialize = virtio_flow_actions_noop,
	},
	[RTE_FLOW_ACTION_TYPE_SET_IPV4_DST] = {
		.serialize = virtio_flow_actions_noop,
	},
	[RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC] = {
		.serialize = virtio_flow_actions_noop,
	},
	[RTE_FLOW_ACTION_TYPE_SET_IPV6_DST] = {
		.serialize = virtio_flow_actions_noop,
	},
	[RTE_FLOW_ACTION_TYPE_SET_TP_SRC] = {
		.serialize = virtio_flow_actions_noop,
	},
	[RTE_FLOW_ACTION_TYPE_SET_TP_DST] = {
		.serialize = virtio_flow_actions_noop,
	},
	[RTE_FLOW_ACTION_TYPE_DEC_TTL] = {
		.serialize = virtio_flow_actions_noop,
	},
	[RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR] = {
		.serialize = virtio_flow_actions_noop,
	},
	[RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT] = {
		.serialize = virtio_flow_actions_noop,
	},
	[RTE_FLOW_ACTION_TYPE_SAMPLE] = {
		.serialize = virtio_flow_actions_noop,
	},
	[RTE_FLOW_ACTION_TYPE_SECURITY] = {
		.serialize = virtio_flow_actions_set_port_id,
	},
	[RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID] = {
		.serialize = virtio_flow_actions_set_port_id,
	},
};


/**
 * Validate flow rule.
 *
 * @see rte_flow_validate()
 * @see rte_flow_ops
 */
static int
virtio_flow_validate(struct rte_eth_dev *dev __rte_unused,
			const struct rte_flow_attr *flow_attr,
			const struct rte_flow_item pattern[] __rte_unused,
			const struct rte_flow_action actions[] __rte_unused,
			struct rte_flow_error *error)
{
	rte_flow_error_set(error, EINVAL,
			   RTE_FLOW_ERROR_TYPE_ATTR,
			   flow_attr, "invalid");
	return -1;
}

/*
 * serialize rte_flow_conv_rule to a linear buffer
 * based on netlink format
 * return length of data
 */
static int
serialize_rte_flow(uint16_t pid __rte_unused,
		  const struct rte_flow_attr *attr __rte_unused,
		  const struct rte_flow_item items[],
		  const struct rte_flow_action actions[],
		  struct rte_flow_error *error,
		  struct nlmsghdr *n)
{
	/* Init netlink header
	 * msg_type and flags are not yet used, but this may be useful
	 * when we switch to a unique flow_crud API in netops ?
	 */
	n->nlmsg_len = sizeof(struct nlmsghdr);
	n->nlmsg_type = 0; /* RTM_NEWTFILTER  */
        n->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
	
	struct nlattr *start_pattern = mnl_attr_nest_start(n, TCA_FLOW_KEYS);
	for (; items->type != RTE_FLOW_ITEM_TYPE_END; ++items) {
		if (items->type == RTE_FLOW_ITEM_TYPE_VOID)
			continue;
		if (!virtio_flow_items[items->type].serialize) {
			rte_flow_error_set(
				error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ITEM,
				items, "Item not supported");
			goto fail;
		}
		virtio_flow_items[items->type].serialize(items, n);
	}
	mnl_attr_nest_end(n, start_pattern);

	struct nlattr *start_actions = mnl_attr_nest_start(n, TCA_FLOW_ACT);
	for (; actions->type != RTE_FLOW_ACTION_TYPE_END; ++actions) {
		if (actions->type == RTE_FLOW_ACTION_TYPE_VOID) {
			continue;
		}
		if (!virtio_flow_actions[actions->type].serialize) {
			rte_flow_error_set(
				error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ACTION,
				actions, "Item not supported");
			goto fail;
		}
		virtio_flow_actions[actions->type].serialize(actions, n);
	}
	mnl_attr_nest_end(n, start_actions);
	return n->nlmsg_len;
fail:
	return -1;
}

static struct rte_flow *
virtio_flow_create(struct rte_eth_dev *dev,
		   const struct rte_flow_attr *attr,
		   const struct rte_flow_item pattern[],
		   const struct rte_flow_action actions[],
		   struct rte_flow_error *error)
{
	struct virtio_hw *hw = dev->data->dev_private;
 	struct virtio_user_dev *vudev = virtio_user_get_dev(hw);
	struct rte_flow *flow = NULL;
	int ret, len;
	if (attr->egress) {
		rte_flow_error_set(error, EINVAL,
			   RTE_FLOW_ERROR_TYPE_ATTR,
			   attr, "can apply action on egress");
		return NULL;
	}

	const struct rte_flow_conv_rule rule = {
		.attr_ro = attr,
		.pattern_ro = pattern,
		.actions_ro = actions,
	};

	len = rte_flow_conv(RTE_FLOW_CONV_OP_RULE, NULL, 0, &rule, error);
	if (len < 0)
		return NULL;

	flow = rte_zmalloc(__func__, offsetof(struct rte_flow, rule) + len, 0);
	if (!flow) {
		rte_flow_error_set(error, ENOMEM, RTE_FLOW_ERROR_TYPE_HANDLE,
				   NULL, "cannot allocate memory for rte_flow");
	}

	ret = rte_flow_conv(RTE_FLOW_CONV_OP_RULE,
		&flow->rule, len,
		&rule, error);
	if (ret < 0) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL, "cannot copy flow rule");
		goto fail;
	}

	struct vhost_flow_msg nl_rule;
	len = serialize_rte_flow(hw->port_id, attr, pattern, actions, error, &nl_rule.nh);
	if(len <=0 || len > 1024)
		goto fail;
	ret = vudev->ops->flow_create(vudev, (uint8_t*)&nl_rule.nh, len);

	if (ret > 0) {
		LIST_INSERT_HEAD(&hw->flows, flow, next);
		virtio_flow_dev_dump(dev, flow, stdout, NULL);
		return flow;
	} else {
		rte_flow_error_set(error, ret, RTE_FLOW_ERROR_TYPE_HANDLE,
			   NULL, "flow_create error");
	}
	
fail:
	rte_free(flow);
	return NULL;
}

/**
 * Destroy user-configured flow rule.
 *
 * @see rte_flow_destroy()
 * @see rte_flow_ops
 */
static int
virtio_flow_destroy(struct rte_eth_dev *dev,
		       struct rte_flow *flow,
		       struct rte_flow_error *error __rte_unused)
{	
	struct virtio_hw *hw = dev->data->dev_private;
 	struct virtio_user_dev *vudev = virtio_user_get_dev(hw);
        vudev->ops->flow_destroy(vudev, (uintptr_t)flow);
	LIST_REMOVE(flow, next);
	rte_free(flow);
	return 0;
}

/**
 * Destroy user-configured flow rules.
 *
 * @see rte_flow_flush()
 * @see rte_flow_ops
 */
static int
virtio_flow_flush(struct rte_eth_dev *dev,
		struct rte_flow_error *error)
{
	struct virtio_hw *hw = dev->data->dev_private;
	while( !LIST_EMPTY(&hw->flows) ) {
		struct rte_flow *flow = LIST_FIRST(&hw->flows);
		virtio_flow_destroy(dev, flow, error);
	}
	return 0;
}


/**
 * Query user flow rule.
 *
 * @see rte_flow_query()
 * @see rte_flow_ops
 */
static int
virtio_flow_query(struct rte_eth_dev *dev,
		struct rte_flow *flow,
		const struct rte_flow_action *actions __rte_unused, /* COUNT OR AGE */
		void *data,
		struct rte_flow_error *error)
{
	struct virtio_hw *hw = dev->data->dev_private;
 	struct virtio_user_dev *vudev = virtio_user_get_dev(hw);
	uint64_t packets=0, bytes=0;
	struct rte_flow_query_count *count = (struct rte_flow_query_count *)data;
	int ret = vudev->ops->flow_query(vudev, (uintptr_t)flow, &packets, &bytes);
	if (ret<0) {
		rte_flow_error_set(error, ENOTSUP, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				NULL, "Vhost Flow Query failed");
		return ret;
	} else {
		count->hits = packets;
		count->bytes = bytes;
	        return 0;
	}
}

static int
virtio_flow_dev_dump(struct rte_eth_dev *dev,
		struct rte_flow *flow,
		FILE *file,
		struct rte_flow_error *error)
{
	int err = 0;
	struct virtio_hw *hw = dev->data->dev_private;
	if (flow) {
//		const struct rte_flow_attr *attr = &flow->rule.attr;
		const struct rte_flow_item *patterns = flow->rule.pattern_ro;
		const struct rte_flow_action *actions = flow->rule.actions_ro;

		char *name = NULL;
		fprintf(file, "pattern ");

		for(int i=0; patterns[i].type != RTE_FLOW_ITEM_TYPE_END; i++) {
			err = rte_flow_conv(RTE_FLOW_CONV_OP_ITEM_NAME_PTR,
		  	      &name, sizeof(char*),
			      (void*)(uintptr_t)patterns[i].type, error);
			if(err < 0) {
				fprintf(file, "Unknown pattern type: %d", patterns[i].type);
				err = 0;
			} else {
				fprintf(file, "%s", name);
			}

			fprintf(file, " ");
			switch(patterns[i].type) {

			case RTE_FLOW_ITEM_TYPE_ETH:
				if (patterns[i].spec)
				{
				const struct rte_flow_item_eth *fie =
					(const struct rte_flow_item_eth *) patterns[i].spec;
				char buf[RTE_ETHER_ADDR_FMT_SIZE];
				rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE,
						&fie->hdr.src_addr);
				fprintf(file, "src %s ", buf);
				rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE,
						&fie->hdr.dst_addr);
				fprintf(file, "dst %s ", buf);
				break;
				}
				// fall through
			case RTE_FLOW_ITEM_TYPE_PORT_ID:
				if (patterns[i].spec) {
					fprintf(file, "%d ", ((const struct rte_flow_item_port_id*)patterns[i].spec)->id);
					break;
				}
				// fall through
			default:
				fprintf(file, "Type %d ", patterns[i].type);
				break;
			}
		}

		fprintf(file, " actions ");

		for (int i=0; actions[i].type != RTE_FLOW_ACTION_TYPE_END; i++) {
			err = rte_flow_conv(RTE_FLOW_CONV_OP_ACTION_NAME_PTR,
			  	      &name, sizeof(name),
				      (void*)(uintptr_t)(actions[i].type), error);
			if(err < 0) {
				fprintf(file, "Unknown action type: %d", actions[i].type);
				err = 0;
			} else {
				fprintf(file, "%s", name);
			}
			fprintf(file, " ");
			switch(actions[i].type) {
			case RTE_FLOW_ACTION_TYPE_PORT_ID:
				fprintf(file, "%d ",
					((const struct rte_flow_action_port_id*)actions[i].conf)->id);
				break;
			case RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR:
			case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
				fprintf(file, "%d ",
					((const struct rte_flow_action_ethdev*)actions[i].conf)->port_id);
				break;

			case RTE_FLOW_ACTION_TYPE_DROP:
				break;

			case RTE_FLOW_ACTION_TYPE_SET_MAC_SRC:
				{
				const struct rte_flow_action_set_mac *mac =
					(const struct rte_flow_action_set_mac *) actions[i].conf;
				char buf[RTE_ETHER_ADDR_FMT_SIZE];
				rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE,
						      (const struct rte_ether_addr *)&mac->mac_addr);
				fprintf(file, "%s ", buf);
				}
				break;

			case RTE_FLOW_ACTION_TYPE_SET_MAC_DST:
				{
				const struct rte_flow_action_set_mac *mac =
					(const struct rte_flow_action_set_mac *) actions[i].conf;
				char buf[RTE_ETHER_ADDR_FMT_SIZE];
				rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE,
					(const struct rte_ether_addr *)&mac->mac_addr);
				fprintf(file, "%s ", buf);
				}
				break;

			case RTE_FLOW_ACTION_TYPE_COUNT:
				if (((const struct rte_flow_query_count*)actions[i].conf)->hits_set)
				fprintf(file, "hits %lu ", 
					((const struct rte_flow_query_count*)actions[i].conf)->hits);
				if (((const struct rte_flow_query_count*)actions[i].conf)->bytes_set)
				fprintf(file, "bytes %lu",
					((const struct rte_flow_query_count*)actions[i].conf)->bytes);
				break;

			default:
				fprintf(file, " UNKNOWN ");
				break;
			}
		}

		fprintf(file, "\n");

	} else {
		struct rte_flow *flow;
		for (flow = LIST_FIRST(&hw->flows);
		     flow;
		     flow = LIST_NEXT(flow, next)){
			err = virtio_flow_dev_dump(dev, flow, file, error);
			if (err)
				goto fail;
		}
	}
fail:
	return err<0 ? err: 0;
}

const struct rte_flow_ops virtio_flow_ops = {
	.create	= virtio_flow_create,
	.validate = virtio_flow_validate,
	.destroy = virtio_flow_destroy,
	.flush	= virtio_flow_flush,
	.query	= virtio_flow_query,
	.dev_dump = virtio_flow_dev_dump,
};
