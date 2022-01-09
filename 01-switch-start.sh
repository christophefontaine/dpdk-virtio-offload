#!/bin/bash

cat >script <<EOF
port attach 0000:05:00.0
port attach net_vhost0,iface=/tmp/testpmd-net1,client=1,queues=1
port attach 0000:05:00.1
port attach net_vhost1,iface=/tmp/testpmd-net2,client=1,queues=1
port start all
set nbcore 1
set nbport 4
show port summary all
show config fwd
start
EOF

gdb --args ./build/app/dpdk-testpmd -m 1024 -l 1,2 -a 0000:00:00.0 --file-prefix=testpmd_vswitch_ \
	-- --no-lsc-interrupt --forward-mode=flow -i  --cmdline-file=script
reset
