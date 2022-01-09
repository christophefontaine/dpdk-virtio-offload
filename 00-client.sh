#!/bin/bash
rm -f /tmp/testpmd-net1
rm -f /tmp/testpmd-net2
gdb --args ./build/app/dpdk-testpmd -m 1024 -l 1,3 \
	--file-prefix=testpmd_client_ \
	--vdev=net_virtio_user0,path=/tmp/testpmd-net1,server=1,queues=1,packed_vq=1 \
	--vdev=net_virtio_user1,path=/tmp/testpmd-net2,server=1,queues=1,packed_vq=1 \
	--no-pci --proc-type=auto -- --no-lsc-interrupt -i
reset
