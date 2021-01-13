#!/bin/sh

GNUPLOT_IN=
INPUT="input.txt"
OUTPUT="output.png"
XLABEL="Number of CPUs"
YLABEL="Throughput (Mpps)"
DEBUG=0
PROG=$(basename "$0")

usage()
{
	echo "Usage: $PROG [-hd] [-i input] [-o output]"
	echo "       {column,title,color[ column,title,color ...]}"
}

gp_in()
{
	GNUPLOT_IN+="$1"$'\n'
}

while getopts hdL:x:y:i:o: opt
do
	case "$opt" in
	h)
		usage
		exit 0
		;;
	d)
		DEBUG=1
		;;
	L)
		LABEL=$OPTARG
		;;
	x)
		XLABEL=$OPTARG
		;;
	y)
		YLABEL=$OPTARG
		;;
	i)
		INPUT=$OPTARG
		;;
	o)
		OUTPUT="$OPTARG"
		;;		
	esac
done

shift $((OPTIND - 1))

if [ "$#" -eq 0 ]; then	
	usage
	exit 1
fi

gp_in "set term png"
gp_in "set title '$LABEL'"
gp_in "set xlabel '$XLABEL'"
gp_in "set ylabel '$YLABEL'"
gp_in "set key outside"
gp_in "set key left bottom horizontal Left maxcols 1"
gp_in "set grid xtics"
gp_in "set grid ytics"
gp_in "set output '$OUTPUT'"
gp_in "plot \\"

for A in "$@"
do
	IFS=',' read -r -a C <<< "$A"
	gp_in "'$INPUT' using 1:${C[0]} pt 5 lt rgb '${C[2]}' title '${C[1]}' with linesp, \\"
done

if [ "$DEBUG" -eq 1 ]; then
	echo "$GNUPLOT_IN"
fi

gnuplot <<- EOF
$GNUPLOT_IN
EOF
