#!/bin/sh

GNUPLOT_IN=
INPUT="input.txt"
OUTPUT="output.png"
YLABEL="mpps"
DEBUG=0
PROG=$(basename "$0")

usage()
{
	echo "Usage: $PROG [-hd] [-i input] [-o output]"
	echo "       {column,title,color[ column,title,color ...]}"
}

gnuplot_in()
{
	GNUPLOT_IN+="$1"$'\n'
}

gnuplot_in "set key autotitle columnhead"
gnuplot_in "set term png"
gnuplot_in "set xlabel 'Number of CPUs'"
gnuplot_in "set key left bottom horizontal Left"
gnuplot_in "set grid xtics"
gnuplot_in "set grid ytics"
gnuplot_in "set key outside"

while getopts hdy:i:o: opt
do
	case "$opt" in
	h)
		usage
		exit 0
		;;
	d)
		DEBUG=1
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

gnuplot_in "set ylabel '$YLABEL'"
gnuplot_in "set output '$OUTPUT'"

shift $((OPTIND - 1))

if [ "$#" -eq 0 ]; then	
	usage
	exit 1
fi

gnuplot_in "plot \\"

for A in "$@"
do
	IFS=',' read -r -a C <<< "$A"
	gnuplot_in "'$INPUT' using 1:${C[0]} lt rgb '${C[2]}' title '${C[1]}' with linesp, \\"
done

if [ "$DEBUG" -eq 1 ]; then
	echo "$GNUPLOT_IN"
fi

gnuplot <<- EOF
$GNUPLOT_IN
EOF
