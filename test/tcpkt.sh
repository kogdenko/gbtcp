#!/bin/sh
ip netns exec t tcpkt -S 72:9c:29:36:5e:02 -D 72:9c:29:36:5e:01 -L -l 172.16.7.2 -f 172.16.7.1 -i 'netmap:veth_t' $@
