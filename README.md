# gbtcp -- Gagabit TCP 

## Introdution
User space TCP/IP stack (concept) based on netmap

## Build
- Build and install netmap

- Build and install gbtcp
```bash
./configure
# or
# ./configure -d # With debugging
make
```
## Configure
### Linux

Create direcory tree and add user to gbtcp group
```bash

adduser --system --no-create-home --user-group -s /sbin/nologin gbtcp

usermod -a -G gbtcp your_user # Optionaly

mkdir /usr/local/gbtcp
chmod 775 /usr/local/gbtcp

mkdir /usr/local/gbtcp/ctl
chmod 775 /usr/local/gbtcp/ctl

mkdir /usr/local/gbtcp/pid
chmod 775 /usr/local/gbtcp/pid

mkdir /usr/local/gbtcp/pid
chmod 775 /usr/local/gbtcp/pid

```

Disable all passible offloadings:
ethtool -K eth2 rx off tx off
ethtool -K eth2 gso off


## Configure RSS
ethtool -L eth2 combined 2
// Use ports in UDP hash
ethtool -N eth3 rx-flow-hash udp4 sdfn

Enable rss:
ethtool -K eth2 ntuple on

Watch what fields used in RSS hash function calculation:
```bash
ethtool --show-ntuple eth2 rx-flow-hash tcp4

TCP over IPV4 flows use these fields for computing Hash flow key:
IP SA
IP DA
L4 bytes 0 & 1 [TCP/UDP src port]
L4 bytes 2 & 3 [TCP/UDP dst port]
```
ethtool -N eth2 rx-flow-hash tcp4 sdfn

### FreeBSD
hw.ix.num_queues=1 # /boot/loader.conf
ifconfig re0 -rxcsum -txcsum

## Run
- Run gbtcpd
```bash
./gbtcpd
```

- Run service (for example - firefox)
```bash
LD_PRELOAD=./bin/libgbtcp.so /usr/lib64/firefox/firefox-bin
```

## Notes
- LD_PRELOAD cannot be used with setuid

- Run tcpdump. tcpdump must be started after netmpa application
```bash
LD_PRELOAD=libpcap.so.1.6.0-PRE-GIT tcpdump -Snni 'netmap:eth2^/rt'
```

- For maximal performance set scaling_governor
```bash
echo performance > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
```

