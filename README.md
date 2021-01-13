# gbtcp -- Gigabit TCP 

## Status
Proof of Concept

## What is gbtcp?


## Build
### Build and install netmap
See https://github.com/luigirizzo/netmap
Especially LINUX/README.md how to build external drivers (--no-ext-drivers)

### Build and install gbtcp
```bash
./configure # -d for debug
make
make install
```

## Configure environment
First off all we must be sure that netmap worked well in out environent.



Create configuration file and put it in /usr/local/gbtcp/sysctl/. See example.conf

Each application use it's own configur file.
For example nginx - /usr/local/gbtcp/sysctl/nginx.conf

Minimal configur file:
```bash
route.if.add=eth
```
Where eth is name of ethernet adapter

### Linux

```bash
ethtool -K eth2 rx off tx off
ethtool -K eth2 gso off
ethtool -L eth2 combined 8
ethtool -K eth2 ntuple on
ethtool --show-ntuple eth2 rx-flow-hash tcp4
ethtool -N eth2 rx-flow-hash tcp4 sdfn
ethtool -N eth2 rx-flow-hash udp4 sdfn
```

### FreeBSD
```bash
hw.ix.num_queues=8 # /boot/loader.conf
ifconfig re0 -rxcsum -txcsum
```

## Run

```bash
LD_PRELOAD=./bin/libgbtcp.so nginx -c /etc/nginx.conf
```

## Notes
* LD_PRELOAD cannot be used with setuid

* To dump traffic we must use  https://github.com/luigirizzo/netmap-libpcap library
tcpdump must be started after netmap application
```bash
LD_PRELOAD=libpcap.so.1.6.0-PRE-GIT tcpdump -Snni 'netmap:eth2^/rt'
```

* For maximal performance set scaling_governor
```bash
echo performance > /sys/devices/system/cpu/cpuX/cpufreq/scaling_governor
```

* There make_plot.sh script for creating plots
```bash
./scripts/make_plot.sh -i ./benchmarks/gbtcp-20200713 -L epoll 5,gbtcp,green 7,linux,red 9,f-stack,blue
```

## Benchmarks

DUT:

    Ethernet controller: Intel Corporation 82599ES 10-Gigabit SFI/SFP+
    CPU: AMD FX(tm)-8350 Eight-Core Processor
    OS: CentOS Linux release 7.6.1810
    Kernel: 4.19.69

Traffic Generator:

```bash
./con-gen -S 00:1b:21:95:69:64 -D 00:1B:21:A6:E5:3C -s 1.1.2.10 -d 1.1.2.1  -a 0 -p 80 -c 1000 -i 'eth2-0' --toy -- -s 1.1.2.11  -i 'eth2-1' -a 1 -- -s 1.1.2.12 -i 'eth2-2' -a 2 -- -s 1.1.2.13 -i 'eth2-3' -a 3
```

![](nginx_pps.png)

![](epoll_pps.png)

![](apps_pps.png)

