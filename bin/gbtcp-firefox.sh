#!/bin/sh
PREFIX="/usr/local/gbtcp"

ps aux | grep '[f]irefox' | awk '{print $2}' | xargs -r kill -9
LD_PRELOAD=$PREFIX/bin/libgbtcp.so /lib64/firefox/firefox-bin
