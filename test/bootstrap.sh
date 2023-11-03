#!/bin/bash

WORKDIR="/tmp/gbtcp_bootstrap/"
NETNS="gbtcp_s"
VETHC="gbtcp_c_veth"
VETHS="gbtcp_s_veth"
ARCHIVE=""
CHECKOUT=""

usage()                    
{                    
	echo "Usage: bootstrap.sh [-hx] [-w workdir] {-a archive }"
}   

while getopts "hxw:a:" opt; do
	case $opt in                                                                       
	h)
		usage
		;;
	x)
		set -x
		;;
	w)
		WORKDIR=$OPTARG
		;;
	a)
		ARCHIVE=$OPTARG
		;;
        esac
done

rm -rf $WORKDIR
mkdir -p $WORKDIR

GBTCP_PATH=$WORKDIR"gbtcp/"
SERVER_LOG="${WORKDIR}server.log"
BOOTSTRAP_LOG="${WORKDIR}bootstrap.log"

exec > >(tee -ia $BOOTSTRAP_LOG) 2>&1

ip netns del $NETNS
ip netns del $VETHC

if [ -z "$ARCHIVE" ]
then
	usage
	exit 1
fi

mkdir -p $GBTCP_PATH
tar -xvf $ARCHIVE -C $GBTCP_PATH

cd $GBTCP_PATH
RC=$?
if [ $RC -ne 0 ];
then
	echo "FAILED (extract)"
	exit $RC
fi

scons
RC=$?
if [ $RC -ne 0 ];
then
	echo "FAILED (build)"
	exit $RC
fi

ip netns add $NETNS
ip l a dev $VETHC type veth peer $VETHS
ip l s dev $VETHS netns $NETNS

ip netns exec $NETNS ./test/server.py -i $VETHS --cpu 0 --stdout 6 > $SERVER_LOG 2>&1 &
SERVER_PID=$!

./test/client.py -i $VETHC --cpu 1  --alive --stdout 6

RC=$?
if [ $RC -ne 0 ];
then
	echo "FAILED (test)"
else
	echo "SUCCESS"
fi

kill -9 $SERVER_PID

exit $RC
