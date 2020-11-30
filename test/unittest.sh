#!/bin/sh

ROOT_PATH=`pwd`
TEST_DIR="test"
TEST_PATH=
BIN_DIR="bin"
BIN_PATH=
NETSTAT=
TEST_CONF=
LIBGBTCP=
TCPKT=
MODE_NATIVE="native"
MODE_GBTCP="gbtcp"
mflag=""

die()
{
	echo $1
	exit 1
}

check_file()
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

scan_tests()
{	
	for x in `find $BIN_PATH -name gbtcp_test_*`; do
		if [ -x $x ]; then
			echo `basename $x`
		fi
	done
}

exec_test()
{
	e=""
	if [ $2 = $MODE_GBTCP ]; then
		e+="GBTCP_CTL=$TEST_CONF LD_PRELOAD=$LIBGBTCP "
	fi	
	e+="$BIN_PATH/$1 > $LOG_PATH/$2/$1.log 2>&1 &"
	eval $e
	pid0="$!"
	if [ ! -f $TEST_PATH/$1.pkt ]; then
		wait $pid0
		return $?
	fi
	rc=`(tail -f $LOG_PATH/$2/$1.log 2>/dev/null &) | grep -m 1 '^Ready\|^Failed'`
	if [[ "$rc" == Failed* ]]; then
		wait $pid0
		return 10
	fi
	$TCPKT $TEST_PATH/$1.pkt > $LOG_PATH/$2/$1.pkt.log 2>&1
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

exec_test_wrap()
{
	echo -n "$1 "
	for i in $MODE_NATIVE $MODE_GBTCP; do
		if [ "$mflag" = "" ] || [ "$mflag" = "$i" ]; then
			exec_test $1 $i
			rc="$?"
			if [ $rc -eq 0 ]; then
				echo -n " [Ok]"
			else
				echo -n "[Failed $rc]"
			fi
		fi
	done
	echo # line feed
}

usage()
{
	echo "Usage: unittest.sh [-hvxl] [-r path] [-m mode] [-t test]"
}

lflag=0
tflag=
while getopts "hvxr:lm:t:" opt; do
	case $opt in
	h)
		usage
		;;
	x)
		set -x
		;;
	r)
		ROOT_PATH=$OPTARG
		;;
	l)
		lflag=1
		;;
	m)
		if [ "$OPTARG" = "$MODE_NATIVE" ] ||
		   [ "$OPTARG" == "$MODE_GBTCP" ]; then
			mflag=$OPTARG
		else
			die "Invalid mode: $OPTARG"
		fi
		;;
	t)
		tflag=$OPTARG
		;;
	esac
done

check_file "$ROOT_PATH" "d"
TEST_PATH="$ROOT_PATH/$TEST_DIR"
check_file $TEST_PATH "d"
BIN_PATH="$ROOT_PATH/$BIN_DIR"
check_file $BIN_PATH "d"
NETSTAT="$ROOT_PATH/$BIN_DIR/netstat"
check_file $NETSTAT "x"
TEST_CONF="$TEST_PATH/test.conf"
check_file $TEST_CONF "f"
LIBGBTCP="$ROOT_PATH/$BIN_DIR/libgbtcp.so"
check_file $LIBGBTCP "x"
TCPKT="$TEST_PATH/tcpkt.sh"
check_file $TCPKT "x"
LOG_PATH=$TEST_PATH/"unit_test_logs"
mkdir -p "$LOG_PATH/$MODE_NATIVE"
mkdir -p "$LOG_PATH/$MODE_GBTCP"

TESTS=`scan_tests`
if [ $lflag -eq 1 ]; then
	for x in $TESTS; do 
		if [ -r "$TEST_PATH/$x.pkt" ]; then
			echo "$x (pkt)"
		else
			echo "$x"
		fi
	done
	exit 0
fi

ps aux | grep '[g]btcp_test' | awk '{print $2}' | xargs -r kill -9
for x in $TESTS; do
	if [ "$tflag" = "" ] || [ "$tflag" = "$x" ]; then
		exec_test_wrap $x
	fi
done
