TEST=""
#TEST="$TEST nginx"
TEST="$TEST gbtcp-epoll-helloworld"
#TEST="$TEST gbtcp-aio-helloworld"

TRANSPORT="netmap"

./test/runner.py -i eth2 --cpu 2 3 4 --transport $TRANSPORT --sample 5 --duration 20 --concurrency 10000 --cooling 10  --test $TEST $@
