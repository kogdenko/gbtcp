#!/bin/sh
PREFIX="/usr/local/gbtcp"

killall -9 gbtcpd > /dev/null 2>&1
ps aux | grep '[f]irefox' | grep -v 'gbtcp-firefox' | awk '{print $2}' | xargs -r kill -9
$PREFIX/bin/gbtcpd -c $PREFIX/ctl/gbtcpd-firefox.conf &
LD_PRELOAD=$PREFIX/bin/libgbtcp.so /lib64/firefox/firefox-bin
