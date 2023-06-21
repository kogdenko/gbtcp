TEST=""

#TRANSPORT="xdp"
#TRANSPORT="native"
TRANSPORT="netmap"

./test/client.py -i ix3a --cpu 2 --transport $TRANSPORT --sample 5 --duration 10 --concurrency 1000 --cooling 10 $@
