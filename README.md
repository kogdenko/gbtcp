# gbtcp -- Gigabit TCP 

## Introdution
User space TCP/IP stack based on netmap.

## Build
- Build and install netmap

- Build and install gbtcp
```bash
./configure
# or
# ./configure -d # With debugging
make
make install
```

## Configure environment

Modify (if necessary) configuraion files for processes which would be runed.
All configuration files stored at /usr/local/gbtcp/ctl
At least route.if.add must be set at /usr/local/gbtcp/ctl/gbtcpd.conf

### Linux

Disable all possible offloadings:
```bash
ethtool -K eth2 rx off tx off
ethtool -K eth2 gso off
```
Set number RSS queues (for example - 2)
```bash
ethtool -L eth2 combined 2
```
Enable rss:
```bash
ethtool -K eth2 ntuple on
```
Watch what fields used in RSS hash function calculation:
```bash
ethtool --show-ntuple eth2 rx-flow-hash tcp4

TCP over IPV4 flows use these fields for computing Hash flow key:
IP SA
IP DA
L4 bytes 0 & 1 [TCP/UDP src port]
L4 bytes 2 & 3 [TCP/UDP dst port]
```
Set hash function that gbtcp support:
```bash
ethtool -N eth2 rx-flow-hash tcp4 sdfn
ethtool -N eth2 rx-flow-hash udp4 sdfn
```

### FreeBSD
hw.ix.num_queues=1 # /boot/loader.conf
ifconfig re0 -rxcsum -txcsum

## Run
At first run gbtcpd:
```bash
./gbtcpd
```
After that process must be runed (for example - nginx)
```bash
LD_PRELOAD=./bin/libgbtcp.so nginx -c /etc/nginx.conf
```

## Notes
* LD_PRELOAD cannot be used with setuid

* Run tcpdump. tcpdump must be started after netmap application
```bash
LD_PRELOAD=libpcap.so.1.6.0-PRE-GIT tcpdump -Snni 'netmap:eth2^/rt'
```

* For maximal performance set scaling_governor
```bash
echo performance > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
...
echo performance > /sys/devices/system/cpu/cpuX/cpufreq/scaling_governor

```

## Benchmarks

Benchmarks done on AMD fx-8350

so_echo (ixgbe):

|CPUs|kcps |kpps |
| -: | --: | --: |
| 1  |  320| 2500|
| 2  |  490| 3920|
| 3  |  730| 5740|
| 4  |  920| 7100|
| 5  | 1100| 8270|
| 6  | 1240| 9760|

so_echo (veth):

|CPUs|kcps |kpps |
| -: | --: | --: |
| 1  |  330| 2620|

nginx (ixgbe):

|CPUs|kcps|kpps|
| -: | -: | -: |
| 1  | 140| 860|
| 2  | 210|1330|
| 3  | 300|1940|
| 4  | 380|2460|
| 5  | 480|3040|
| 6  | 540|3340|
| 7  | 630|4060|
| 8  | 700|4390|

---
echo 0 > /proc/sys/kernel/randomize_va_space
BUG: 
nginx
while true; do kill -HUP `cat /var/run/nginx.pid `; done
timeouts occured (after a while worker process become fully unresponsive)
