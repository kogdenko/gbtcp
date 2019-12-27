#!/bin/sh
# test directory must contains kernel modules: netmap.ko, netmap_veth.ko veth.ko

BASEDIR=$(dirname "$0")
BENCH=0

while getopts "hbx" o; do
	case "${o}" in
	h)
		echo "mk_testbed.sh [-hbx]"
		exit 0
		;;
	b)
		BENCH=1
		;;
	x)
		set -x
		;;
	*)
		;;
	esac
done
ip netns d t
rmmod veth
rmmod netmap
insmod $BASEDIR/netmap-`uname -r`.ko
if [ $BENCH = 1 ]
then
	insmod $BASEDIR/netmap-veth-`uname -r`.ko
else
	ip netns a t
fi
ip l a dev veth_g type veth peer name veth_t
ethtool -K veth_g rx off tx off
ethtool -K veth_t rx off tx off
ip l s dev veth_g address 72:9c:29:36:5e:01
ip l s dev veth_t address 72:9c:29:36:5e:02
ip l s dev veth_g up
ip a a dev veth_g 172.16.7.1/32
ip r a dev veth_g 72.16.7.1/24 initcwnd 1
if [ $BENCH = 1 ]
then
	ifconfig veth_t up
else
	ip l s dev veth_t netns t
	ip netns exec t ifconfig veth_t 172.16.7.2/24 up
fi
chmod a+rw /dev/netmap
