/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Red Hat, Inc.
 */

#ifndef _VIRTIO_FLOW_H_
#define _VIRTIO_FLOW_H_

#include <rte_ether.h>


typedef struct VirtioFlowSpec {
        uint64_t flow_id;
        uint16_t pattern_size; /* offset to actions */
        uint16_t action_size;
        uint8_t flow_spec[];
} VirtioFlowSpec;

typedef struct VirtioFlowStats {
        uint64_t flow_id;
        uint64_t packets;
        uint64_t bytes;
} VirtioFlowStats;

#endif /* _VIRTIO_FLOW_H_ */
