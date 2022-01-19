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
#include "virtio_user/virtio_user_dev.h"
#include "virtio_user/vhost.h"

struct rte_flow {
	LIST_ENTRY(rte_flow) next; /* Pointer to the next rte_flow structure */
	struct rte_flow_conv_rule rule;
};

#define virtio_user_get_dev(hwp) container_of(hwp, struct virtio_user_dev, hw)
void rule_ptrs_to_offset(struct rte_flow_conv_rule *rule);
void rule_offset_to_ptrs(struct rte_flow_conv_rule *rule);

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

void rule_ptrs_to_offset(struct rte_flow_conv_rule *rule)
{
	uintptr_t base = (uintptr_t) rule;
	struct rte_flow_item *items = rule->pattern; 
	struct rte_flow_action *actions = rule->actions;

	for (; items->type != RTE_FLOW_ITEM_TYPE_END; ++items) {
		if (items->spec)
			items->spec = (void*)((uintptr_t)items->spec - base);
		if (items->last)
			items->last = (void*)((uintptr_t)items->last - base);
		if (items->mask)
			items->mask = (void*)((uintptr_t)items->mask - base);
	}
	for (; actions->type != RTE_FLOW_ACTION_TYPE_END; ++actions) {
		if (actions->conf)
			actions->conf = (void*)((uintptr_t)actions->conf - base);
	}

	/* Provide an offset to the beginning of the header */
	rule->attr = (struct rte_flow_attr *) ((uintptr_t)rule->attr - base);
	rule->pattern = (struct rte_flow_item *) ((uintptr_t)rule->pattern - base);
	rule->actions = (struct rte_flow_action *) ((uintptr_t)rule->actions - base);
}

void rule_offset_to_ptrs(struct rte_flow_conv_rule *rule)
{
	uintptr_t base = (uintptr_t) rule;
	rule->attr = (struct rte_flow_attr *) (base + (uintptr_t)rule->attr);
	rule->pattern = (struct rte_flow_item *) (base + (uintptr_t)rule->pattern);
	rule->actions = (struct rte_flow_action *) (base + (uintptr_t)rule->actions);

	struct rte_flow_item *items = rule->pattern; 
	struct rte_flow_action *actions = rule->actions;

	for (; items->type != RTE_FLOW_ITEM_TYPE_END; ++items) {
		if (items->spec)
			items->spec = (void*)((uintptr_t)items->spec + base);
		if (items->last)
			items->last = (void*)((uintptr_t)items->last + base);
		if (items->mask)
			items->mask = (void*)((uintptr_t)items->mask + base);
	}
	for (; actions->type != RTE_FLOW_ACTION_TYPE_END; ++actions) {
		if (actions->conf)
			actions->conf = (void*)((uintptr_t)actions->conf + base);
	}
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
	int ret, flow_len;
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

	flow_len = rte_flow_conv(RTE_FLOW_CONV_OP_RULE, NULL, 0, &rule, error);
	if (flow_len < 0)
		return NULL;

	flow = rte_zmalloc(__func__, offsetof(struct rte_flow, rule) + flow_len, 0);
	if (!flow) {
		rte_flow_error_set(error, ENOMEM, RTE_FLOW_ERROR_TYPE_HANDLE,
				   NULL, "cannot allocate memory for rte_flow");
	}

	ret = rte_flow_conv(RTE_FLOW_CONV_OP_RULE,
		&flow->rule, flow_len,
		&rule, error);
	if (ret < 0) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL, "cannot copy flow rule");
		goto fail;
	}

	rule_ptrs_to_offset(&flow->rule);
	ret = vudev->ops->flow_create(vudev, (uint8_t*)&flow->rule, flow_len);
	rule_offset_to_ptrs(&flow->rule);

	if (ret > 0) {
		LIST_INSERT_HEAD(&hw->flows, flow, next);
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
		rte_flow_describe(file, flow->rule.attr,
				flow->rule.pattern,
				flow->rule.actions);
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
