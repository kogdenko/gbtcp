#!/bin/sh
V=`uname -r`
PR="copy_modules.sh"

usage()
{
	echo "Usage: $PR {netmap-path} {dst-path}"
}
if [ $# -lt 2 ]; then 
	usage
	exit 1
fi 
cp `find $1 -name netmap.ko` $2/netmap-`uname -r`.ko
cp `find $1 -name veth.ko` $2/netmap-veth-`uname -r`.ko
