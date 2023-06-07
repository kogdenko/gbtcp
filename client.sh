TEST=""
#APP="nginx"
APP="gbtcp-epoll-helloworld"
#APP="gbtcp-aio-helloworld"

#TRANSPORT="xdp"
#TRANSPORT="native"
TRANSPORT="netmap"

./test/client.py -i ix3a --cpu 2 --transport $TRANSPORT --sample 5 --duration 20 --concurrency 1000 --cooling 10  --application $APP $@
