TEST=""
#APP="nginx"
APP="gbtcp-epoll-helloworld"
#APP="gbtcp-aio-helloworld"

TRANSPORT="netmap"

./test/runner.py -i eth2 --cpu 2 --transport $TRANSPORT --sample 5 --duration 10 --concurrency 10000 --cooling 10  --application $APP $@
