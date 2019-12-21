#!/bin/sh

ROOT_PATH=`pwd`
TEST_DIR="test"
TEST_PATH=
BIN_DIR="bin"
BIN_PATH=
NETSTAT=
SYSCTL_CONF=
LIBGBTCP=
TCPKT=

set -x

die()
{
	echo $1
	exit 1
}

ckf()
{
	t=
	if [ ! -$2 $1 ]; then
		case $2 in
		f)
			t="a regular file"
			;;
		d)
			t="a directory"
			;;
		x)
			t="an executabe"
			;;
		esac
		die "$1 is not $t"
	fi
}

scan()
{	
	for x in `find $BIN_PATH -name test_*`; do
		if [ -x $x ]; then
			echo `basename $x`
		fi
	done
}

exect_pkt()
{
	echo "1"
}

exect()
{
	if [ $2 -eq 0 ]; then
		e=""
	else
		e="GBTCP_SYSCTL=$SYSCTL_CONF LD_PRELOAD=$LIBGBTCP "
	fi	
	e+="$BIN_PATH/$1 > $LOG_PATH/$1.log 2>&1 &"
	eval $e
	pid0="$!"
	if [ ! -f $TEST_PATH/$1.pkt ]; then
		wait $pid0
		return $?
	fi
	rc=`(tail -f $LOG_PATH/$1.log 2>/dev/null &) | grep -m 1 '^Ready\|^Failed'`
	if [[ "$rc" == Failed* ]]; then
		wait $pid0
		return 10
	fi
	$TCPKT $TEST_PATH/$1.pkt #> $LOG_PATH/$1.pkt.log 2>&1
	rc0="$?"
	wait $pid0
	rc1="$?"
	if [ ! $rc0 -eq 0 ]; then
		return $rc0
	elif [ ! $rc1 -eq 0 ]; then
		return $rc1
	else
		return 0
	fi
}

exect_wrap()
{
	echo -n "$1"
	for i in 0 1; do
		exect $1 $i
		rc="$?"
		if [ $rc -eq 0 ]; then
			echo -n " [Ok]"
		else
			echo -n " [Failed $rc]"
		fi
	done
	echo
}

usage()
{
	echo "Usage: unittest.sh [-hl] [-r path] [-m mode]"
}

lflag=0
tflag=
while getopts "hr:lm:t:" opt; do
	case $opt in
	h)
		usage
		;;
	r)
		ROOT_PATH=$OPTARG
		;;
	l)
		lflag=1
		;;
	m)
		;;
	t)
		tflag=$OPTARG
		;;
	esac
done
ckf "$ROOT_PATH" "d"
TEST_PATH="$ROOT_PATH/$TEST_DIR"
ckf $TEST_PATH "d"
BIN_PATH="$ROOT_PATH/$BIN_DIR"
ckf $BIN_PATH "d"
NETSTAT="$ROOT_PATH/$BIN_DIR/netstat"
ckf $NETSTAT "x"
SYSCTL_CONF="$TEST_PATH/sysctl.conf"
ckf $SYSCTL_CONF "f"
LIBGBTCP="$ROOT_PATH/$BIN_DIR/libgbtcp.so"
ckf $LIBGBTCP "x"
TCPKT="$TEST_PATH/tcpkt.sh"
ckf $TCPKT "x"
LOG_PATH=$TEST_PATH/"unittest.log/"
mkdir -p $LOG_PATH
TESTS=`scan`
if [ $lflag -eq 1 ]; then
	for x in $TESTS; do 
		if [ -r "$TEST_PATH/$x.pkt" ]; then
			echo "$x.pkt"
		else
			echo "$x"
		fi
	done
fi
if [ -n "$tflag" ]; then
	for x in $TESTS; do
		if [ $x = $tflag ]; then
			exect_wrap $x
			exit 0
		fi
	done
	echo "test $tflag not found"
fi
