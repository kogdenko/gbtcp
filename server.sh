RELOAD_NETMAP=
RELOAD_NETMAP='--reload-netmap /home/k.kogdenko/Projects/open_source/netmap-5.15.26'


./test/tester.py -i eth3 --cpu 10 11 12 $RELOAD_NETMAP
