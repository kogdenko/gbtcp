#!/bin/sh

C=0
INTERFACE=""

usage() 
{
	echo "set_irq_affinity.sh { -i INTERFACE } [-h]"
}

while getopts ":hi:" opt; do
	case $opt in
	h)
		usage
		exit 0
		;;
	i)
		INTERFACE=$OPTARG
		;;
	esac
done

if [ -z "$INTERFACE" ]
then
	usage
	exit 1
fi

for I in $(grep $INTERFACE-TxRx /proc/interrupts | cut -f 1 -d ':'); do
	Md=`echo 2^$C | bc`
	Mx=`printf "%x" $Md`
	echo "int $I -> core $C (0x$Mx)"
	echo $Mx > /proc/irq/$I/smp_affinity
	C=$((C+1))
done
