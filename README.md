# gbtcp -- Gigabit TCP 

## Build
- Build and install netmap. See https://github.com/luigirizzo/netmap

- Build and install gbtcp
```bash
./configure
# or
# ./configure -d # With debugging
make
make install
```

## Configure environment

### Linux

```bash
ethtool -K eth2 rx off tx off
ethtool -K eth2 gso off
ethtool -L eth2 combined 1
ethtool -K eth2 ntuple on
ethtool --show-ntuple eth2 rx-flow-hash tcp4
ethtool -N eth2 rx-flow-hash tcp4 sdfn
ethtool -N eth2 rx-flow-hash udp4 sdfn
```

### FreeBSD
hw.ix.num_queues=1 # /boot/loader.conf
ifconfig re0 -rxcsum -txcsum

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
BUG: 
nginx
while true; do kill -HUP `cat /var/run/nginx.pid `; done
timeouts occured (after a while worker process become fully unresponsive)
