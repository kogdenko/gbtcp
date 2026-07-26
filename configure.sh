#!/bin/sh

SCRIPT=$(basename $0)

usage()
{
	echo "-h|--help                Print this message"
	echo "--without-netmap         Do not use of netmap"
	echo "--without-netmap-vale    Do not use of netmap vale switch"
	echo "--without-xdp            Do not use of XDP"
	echo "--without-bsd44          Do not use of 4.4BSD tcp/ip stack"
}

ARGS=""

while [ $# -ge 1 ]; do
	case "$1" in
	-h|--help)
		usage
		shift
		exit 0
		;;
	--without-netmap)
		ARGS="$ARGS -Dwithout-netmap=true"
		shift
		;;
	--without-netmap-vale)
		ARGS="$ARGS -Dwithout-netmap-vale=true"
		shift
		;;
	--without-xdp)
		ARGS="$ARGS -Dwithout-xdp=true"
		shift
		;;
	--without-bsd44)
		ARGS="$ARGS -Dwithout-bsd44=true"
		shift
		;;
	* )
		echo "$SCRIPT: unrecognized option '$1'"
		exit 1
	esac
done

for buildtype in debug release debugoptimized; do
	builddir=build-$buildtype
	rm -rf $builddir
	meson setup $builddir --buildtype=$buildtype $ARGS
	if [ $? -ne 0 ]; then
		echo "$SCRIPT: meson failed"
		exit 1
	fi
done

meson configure build-debug -Ddebug=true -Doptimization=0
