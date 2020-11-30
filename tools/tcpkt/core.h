#ifndef TCPKT_CORE_H
#define TCPKT_CORE_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <unistd.h>
#include <inttypes.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <dlfcn.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#ifdef __linux__
#include <asm/types.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#else
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <sys/sysctl.h>
#endif

#define ETH_ADDR_LEN 6
#define ETH_ADDRSTRLEN 18

typedef uint16_t be16_t;
typedef uint32_t be32_t;

struct eth_addr {
	uint8_t bytes[ETH_ADDR_LEN];
} __attribute__((packed));

typedef union ipaddr {
	be32_t  ipv4;
	uint8_t ipv6[16];
	uint8_t data[16];
	be32_t  data_32[4];
	be32_t  ipv6_32[4];
} ipaddr_t;

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MIN3
#define MIN3(a, b, c) (MIN(MIN(a, b), c))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef container_of
#define field_off(type, field) ((intptr_t)&((type *)0)->field)
#define container_of(ptr, type, field) \
	(type *)((intptr_t)(ptr) - field_off(type, field))
#endif /* container_of */

#define CPU_TO_BE16(x) htons(x)
#define CPU_TO_BE32(x) htonl(x)
#define BE16_TO_CPU(x) ntohs(x)
#define BE32_TO_CPU(x) ntohl(x)

#define INET_NTOP(af, src) \
	inet_ntop(af, src, alloca(INET6_ADDRSTRLEN), INET6_ADDRSTRLEN)

extern ipaddr_t ipaddr_zero;
extern struct eth_addr eth_bcast;
extern struct eth_addr eth_zero;
extern int debuging;

void die(int err_num, const char *format, ...)
	__attribute__((format(printf, 2, 3)));

void dbg4(const char *file, int line, const char *func, const char *format, ...)
	__attribute__((format(printf, 4, 5)));

#define dbg(format, ...) \
	dbg4(__FILE__, __LINE__, __func__, format, ##__VA_ARGS__)

void *xmalloc(size_t size);
void *xmalloc_zero(size_t size);
void *xrealloc(void *ptr, size_t size);

char *strzcpy(char *dst, const char *src, size_t len);
char *trim(char *string, const char *what);

int set_bit(long *l, size_t i);
int unset_bit(long *l, size_t i);
int test_bit(long l, size_t i);

int eth_aton(struct eth_addr *a, const char *cp);
char *eth_ntoa(const struct eth_addr *src, char *dst);
int eth_is_bcast(struct eth_addr *a);

ipaddr_t *ipaddr_cpy(int af, ipaddr_t *dst, const ipaddr_t *src);
int ipaddr_cmp(int af, const ipaddr_t *l, const ipaddr_t *r);
int ipaddr_prefix(int af, const ipaddr_t *addr);
int ipaddr_is_zero(int af, const ipaddr_t *addr);

int ipport_pton(int af, const char *str, void *addr, be16_t *port);

#endif /* TCPKT_CORE_H */
