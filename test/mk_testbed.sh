#!/bin/sh

BASEDIR=$(dirname "$0")

usage()
{
	echo "$0 [-hbx]"
}

insert_module()
{
	insmod $BASEDIR/$1-`uname -r`.ko
}

while getopts "hbx" o; do
	case "${o}" in
	h)
		usage
		exit 0
		;;
	x)
		set -x
		;;
	*)
		;;
	esac
done

rmmod veth
rmmod ixgbe
rmmod netmap

insert_module netmap
insert_module veth
insert_module ixgbe

chmod a+rw /dev/netmap

ip l a dev veth_g type veth peer name veth_t
ethtool -K veth_g rx off tx off
ethtool -K veth_t rx off tx off
ip l s dev veth_g address 72:9c:29:36:5e:01
ip l s dev veth_t address 72:9c:29:36:5e:02
ip l s dev veth_g up
ip a a dev veth_g 172.16.7.1/32
ip r a dev veth_g 172.16.7.0/24 initcwnd 1
ifconfig veth_t up
for x in /sys/devices/system/cpu/cpu* ; do
	scaling_governor=$x/cpufreq/scaling_governor
	if [ -f $scaling_governor ]; then
		echo performance > $scaling_governor
	fi
done
