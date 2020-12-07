#!/bin/sh

BASEDIR=$(dirname "$0")
NETMAP_PATH=

usage()
{
	echo "Usage: $0 {netmap-path}"
}

copy_module()
{
	SRC=`find $NETMAP_PATH -name $1.ko | head -n1`
	if [ -f "$SRC" ]; then
		cp $SRC $BASEDIR/$1-`uname -r`.ko
	else
		echo "Module '$1.ko' not found in netmap directory"
	fi
}

if [ $# -lt 1 ]; then 
	usage
	exit 1
fi
NETMAP_PATH=$1

copy_module "netmap"
copy_module "veth"
copy_module "ixgbe"
