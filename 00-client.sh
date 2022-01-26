#!/bin/bash
rm -f /tmp/testpmd-net1
rm -f /tmp/testpmd-net2
gdb --args ./build/app/dpdk-testpmd -m 1024 -l 2,7,8 \
	--file-prefix=testpmd_client_ \
	--vdev=net_virtio_user0,path=/tmp/testpmd-net1,server=1,queues=2 \
	--vdev=net_virtio_user1,path=/tmp/testpmd-net2,server=1,queues=2 \
	--no-pci --proc-type=auto \
	--log-level='pmd.net.virtio.*',8 \
	-- --no-lsc-interrupt -i --rxq=2 --txq=2 --nb-cores=2
reset
# --rxq=2 --txq=2
