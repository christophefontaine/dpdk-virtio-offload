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

#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_flow_driver.h>
#include <rte_tailq.h>

#include "virtio.h"
#include "virtio_logs.h"
#include "virtio_flow.h"
#include "virtio_user/virtio_user_dev.h"
#include "virtio_user/vhost.h"


struct rte_flow {
	LIST_ENTRY(rte_flow) next; /* Pointer to the next rte_flow structure */
	struct VirtioFlowSpec rule;
};

#define virtio_user_get_dev(hwp) container_of(hwp, struct virtio_user_dev, hw)


static
struct rte_flow *virtio_flow_create(struct rte_eth_dev *dev,
				   const struct rte_flow_attr *attr,
				   const struct rte_flow_item pattern[],
				   const struct rte_flow_action actions[],
				   struct rte_flow_error *error)
{
	struct virtio_hw *hw = dev->data->dev_private;
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

	flow->rule.flow_id = (uint64_t) flow;
	flow->rule.pattern_size = rte_flow_conv(RTE_FLOW_CONV_OP_PATTERN, NULL, 0, pattern, error);
	flow->rule.action_size = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS, NULL, 0, actions, error);

	ret = rte_flow_conv(RTE_FLOW_CONV_OP_PATTERN, 
		&flow->rule.flow_spec[0],
		flow->rule.pattern_size,
		pattern, error);

	ret = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS,
		&flow->rule.flow_spec[flow->rule.pattern_size],
		flow->rule.action_size,
		actions, error);

	if (ret >= 0) {
	 	struct virtio_user_dev *vudev = virtio_user_get_dev(hw);
	        ret = vudev->ops->flow_create(vudev, &flow->rule, len);
		if (ret > 0) {
			LIST_INSERT_HEAD(&hw->flows, flow, next);
			return flow;
		} else {
			rte_flow_error_set(error, ret, RTE_FLOW_ERROR_TYPE_HANDLE,
				   NULL, "flow_create error");
		}
	}

fail:
	rte_free(flow);
	return NULL;
}


/**
 * Validate flow rule.
 *
 * @see rte_flow_validate()
 * @see rte_flow_ops
 */
static int
virtio_flow_validate(struct rte_eth_dev *dev,
			const struct rte_flow_attr *flow_attr,
			const struct rte_flow_item pattern[],
			const struct rte_flow_action actions[],
			struct rte_flow_error *error)
{
	rte_flow_error_set(error, EINVAL,
			   RTE_FLOW_ERROR_TYPE_ATTR,
			   flow_attr, "invalid");
	return -1;
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
		       struct rte_flow_error *error)
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
virtio_flow_dev_dump(struct rte_eth_dev *dev __rte_unused,
		struct rte_flow *flow,
		FILE *file,
		struct rte_flow_error *error)
{
	int err = 0;
	struct virtio_hw *hw = dev->data->dev_private;
	if (flow) {
//		const struct rte_flow_attr *attr = &flow->rule.attr;
		const struct rte_flow_item *patterns = (struct rte_flow_item *) &flow->rule.flow_spec[0];
		const struct rte_flow_action *actions = (struct rte_flow_action *) &flow->rule.flow_spec[flow->rule.pattern_size];

		char *name = "";
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
				{
				struct rte_flow_item_eth *fie = (struct rte_flow_item_eth *) patterns[i].spec;
				char buf[RTE_ETHER_ADDR_FMT_SIZE];
				rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, &fie->hdr.src_addr);
				fprintf(file, "src %s ", buf);
				rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, &fie->hdr.dst_addr);
				fprintf(file, "dst %s ", buf);
				}
				break;
			case RTE_FLOW_ITEM_TYPE_PORT_ID:
				fprintf(file, "%d ", ((struct rte_flow_item_port_id*)patterns[i].spec)->id);
				break;
			default:
				fprintf(file, " UNKNOWN ");
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
				fprintf(file, "%d ", ((struct rte_flow_action_port_id*)actions[i].conf)->id);
				break;
			case RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR:
			case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
				fprintf(file, "%d ", ((struct rte_flow_action_ethdev*)actions[i].conf)->port_id);
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
				fprintf(file, "%s ", buf);
				}
				break;

			case RTE_FLOW_ACTION_TYPE_SET_MAC_DST:
				{
				struct rte_flow_action_set_mac *mac =
					(struct rte_flow_action_set_mac *) actions[i].conf;
				char buf[RTE_ETHER_ADDR_FMT_SIZE];
				rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE,
						      (const struct rte_ether_addr *)&mac->mac_addr);
				fprintf(file, "%s ", buf);
				}
				break;

			case RTE_FLOW_ACTION_TYPE_COUNT:
				if (((struct rte_flow_query_count*)actions[i].conf)->hits_set)
				fprintf(file, "hits %lu ", ((struct rte_flow_query_count*)actions[i].conf)->hits);
				if (((struct rte_flow_query_count*)actions[i].conf)->bytes_set)
				fprintf(file, "bytes %lu", ((struct rte_flow_query_count*)actions[i].conf)->bytes);
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
