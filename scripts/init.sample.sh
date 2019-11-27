#/bin/bash
echo 8192 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 8192 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
modprobe uio
cd ${path-of-dpdk}
insmod build/kmod/igb_uio.ko
insmod build/kmod/rte_kni.ko
ifconfig eth0 down
ifconfig eth1 down
${path-of-dpdk}/usertools/dpdk-devbind.py -b igb_uio 0000:84:00.0 
${path-of-dpdk}/usertools/dpdk-devbind.py -b igb_uio 0000:84:00.1
