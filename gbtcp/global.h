// gpl2
#ifndef GBTCP_GLOBAL_H
#define GBTCP_GLOBAL_H

#ifdef __linux__
#define _GNU_SOURCE
#endif // __linux__
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <limits.h>
#include <ctype.h>
#include <assert.h>
#include <getopt.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <strings.h>
#include <inttypes.h>
#include <errno.h>
#include <ifaddrs.h>
#include <poll.h>
#include <dlfcn.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <emmintrin.h>
#include <ucontext.h>
#include <dirent.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <syslog.h>
#include <pthread.h>
#include <net/if.h>

#ifdef __linux__
#include <sched.h>
#include <syscall.h>
#include <execinfo.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#else // __linux__
#include <libgen.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <execinfo.h>
#include <sys/thr.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/sysctl.h>
#include <sys/socketvar.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <libutil.h>
#include <pthread_np.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>
#endif // __linux__

#include "gbtcp.h"

struct strbuf;
struct arp_hdr;
struct service;
struct dev;
struct dev_pkt;
struct timer;
struct route_entry;
struct route_if;
struct route_entry_long;
struct shm_hdr;
struct mbuf;
struct mbuf_pool;

#define MOD_FOREACH(x) \
	x(sysctl) \
	x(log) \
	x(sys) \
	x(shm) \
	x(subr) \
	x(pid) \
	x(poll) \
	x(epoll) \
	x(mbuf) \
	x(htable) \
	x(timer) \
	x(fd_event) \
	x(signal) \
	x(dev) \
	x(api) \
	x(lptree) \
	x(route) \
	x(arp) \
	x(file) \
	x(inet) \
	x(sockbuf) \
	x(tcp) \
	x(service) \
	x(controller) \
	x(app)

#define MOD_ENUM(name) MOD_##name,

enum {
	MOD_ZERO,
	MOD_FOREACH(MOD_ENUM)
	MODS_MAX
};

#define MOD_FIRST 1

extern struct service *current;
extern struct shm_hdr *shared;
extern sigset_t current_sigprocmask;
extern int current_sigprocmask_set;
extern uint64_t nanoseconds;

#endif // GBTCP_GLOBAL_H
