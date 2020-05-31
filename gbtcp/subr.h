// GPL2 license
#ifndef GBTCP_SUBR_H
#define GBTCP_SUBR_H

#ifdef __linux__
#define _GNU_SOURCE
#endif /* __linux__ */
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
#include <ifaddrs.h>
#include <poll.h>
#include <dlfcn.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
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
#else /* __linux__ */
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
#endif /* __linux__ */

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include "gbtcp.h"

#ifdef __linux__
#define GT_POLLRDHUP POLLRDHUP
#define GT_TCP_CORK TCP_CORK
#else /* __linux__ */
#define GT_POLLRDHUP 0
#define GT_TCP_CORK TCP_NOPUSH
#endif /* __linux__ */

#define CACHE_LINE_SIZE 64
#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)

#define ETHADDR_STRLEN 18
#define ETHADDR_LEN 6

#define IP6ADDR_LEN 16

#define RSS_KEY_SIZE 40

#define NETMAP_PFX "netmap:"
#define NETMAP_PFX_LEN (sizeof(NETMAP_PFX) - 1)
#define NM_IFNAMSIZ (IFNAMSIZ + NETMAP_PFX_LEN)
#define GT_PREFIX "/usr/local/gbtcp"

#define NANOSECONDS_SECOND 1000000000ull
#define NANOSECONDS_MILLISECOND 1000000ull
#define NANOSECONDS_MICROSECOND 1000ull
#define NANOSECONDS_MINUTE (60 * NANOSECONDS_SECOND)
#define NANOSECONDS_HOUR (60 * NANOSECONDS_MINUTE)
#define NANOSECONDS_INFINITY ((uint64_t)(-1))

typedef uint16_t be16_t;
typedef uint32_t be32_t;
typedef uint64_t be64_t;

struct strbuf;
struct arp_hdr;
struct service;
struct dev;
struct route_if;
struct route_entry_long;
struct init_hdr;

typedef int (*malloc_f)(void **, size_t);
typedef void (*free_f)(void *);

struct eth_addr {
	u_char ea_bytes[ETHADDR_LEN];
} __attribute__((packed));

struct spinlock {
	volatile int spinlock_locked;
};

typedef struct counter64 {
	uint64_t cnt64[GT_SERVICES_MAX];
} counter64_t;

struct profiler {
	const char *prf_name;
	uint64_t prf_hits;
	uint64_t prf_tsc;
	uint64_t prf_last_print_tsc;
	uint64_t prf_spended;
};


#ifndef field_off
#define field_off(type, field) ((intptr_t)&((type *)0)->field)
#endif /* field_off */

#ifndef container_of
#define container_of(ptr, type, field) \
	((type *)((intptr_t)(ptr) - field_off(type, field)))
#endif /* container_of */

#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif /* UNUSED */

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif /* MIN */

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif /* MAX */

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif /* ARRAY_SIZE */

#define STRSZ(s) (s), (sizeof(s) - 1)

#define ALIGNMENT sizeof(unsigned long)
#define ALIGN(x, a) (((x) + (a - 1)) & ~(a - 1))
#define ALIGN_PTR(x) ALIGN(x, ALIGNMENT)

#define ROUND_UP(x, y) ((((x) - 1) | (((__typeof__(x))(y)) - 1)) + 1)
#define ROUND_DOWN(x, y) ((x) & (~((y) - 1 )))

#define BSWAP16(x) \
	(((((uint16_t)(x)) & ((uint16_t)0x00FF)) << 8) | \
	 ((((uint16_t)(x)) & ((uint16_t)0xFF00)) >> 8))

#define BSWAP32(x) \
	(((((uint32_t)(x)) & ((uint32_t)0x000000FF)) << 24) | \
	 ((((uint32_t)(x)) & ((uint32_t)0x0000FF00)) <<  8) | \
	 ((((uint32_t)(x)) & ((uint32_t)0x00FF0000)) >>  8) | \
	 ((((uint32_t)(x)) & ((uint32_t)0xFF000000)) >> 24))

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define hton16(x) ((uint16_t)(x))
#define hton32(x) ((uint32_t)(x))
#define ntoh16(x) ((uint16_t)(x))
#define ntoh32(x) ((uint32_t)(x))
#else  // __BIG_ENDIAN
#define hton16(x) ((uint16_t)BSWAP16(x))
#define hton32(x) ((uint32_t)BSWAP32(x))
#define ntoh16(x) ((uint16_t)BSWAP16(x))
#define ntoh32(x) ((uint32_t)BSWAP32(x))
#endif // __BIG_ENDIAN


#define UNIQV_CAT3(x, res) res
#define UNIQV_CAT2(x, y, z) UNIQV_CAT3(~, x##y##z)
#define UNIQV_CAT(x, y, z) UNIQV_CAT2(x, y, z)
#define UNIQV(n) UNIQV_CAT(n, uniqv_, __LINE__)

#define MEM_PREFETCH(ptr) \
	__builtin_prefetch(ptr)


#define printf_rl(period, fmt, ...) \
do { \
	static uint64_t UNIQV(last); \
	static uint64_t UNIQV(now); \
	static int UNIQV(cnt); \
 \
	UNIQV(now) = nanoseconds; \
	if (UNIQV(now) - UNIQV(last) >= period) { \
		UNIQV(last) = UNIQV(now); \
		if (UNIQV(cnt)) { \
			printf("suppresed %d; ", UNIQV(cnt)); \
		} \
		printf(fmt, ##__VA_ARGS__); \
	} else { \
		UNIQV(cnt)++; \
	} \
} while (0)

#if 0
#define GT_PRF_INIT(x) 
#define GT_PRF_ENTER(x)
#define GT_PRF_LEAVE(x)
#else
#define GT_PRF_INIT(x) \
	static struct profiler prf_##x = { .prf_name = #x };
#define GT_PRF_ENTER(x) profiler_enter(&prf_##x)
#define GT_PRF_LEAVE(x) profiler_leave(&prf_##x)
#endif

#define dbg gt_dbg
#define dbg0 dbg("D")

#define barrier() __asm__ __volatile__("": : :"memory")
#define mb _mm_mfence
#define rmb _mm_sfence
#define wmb _mm_lfence
#define cpu_pause _mm_pause

#define READ_ONCE(x) \
({ \
	union { \
		typeof(x) val; \
		u_char data[1]; \
	} u; \
	read_once(&(x), u.data, sizeof(x)); \
	u.val; \
})

#define WRITE_ONCE(x, v) \
({ \
	union { \
		typeof(x) val; \
		u_char data[1]; \
	} u = { \
		.val = (typeof(x))(v) \
	}; \
	write_once(&(x), u.data, sizeof(x)); \
	u.val; \
})

#define rcu_assign_pointer(p, v) \
({ \
	barrier(); \
	WRITE_ONCE(p, v); \
})

extern uint64_t nanoseconds;
extern uint64_t HZ;
extern uint64_t mHZ;
extern __thread int api_locked;

int subr_mod_init(void **);
int subr_mod_attach(void *);
void subr_mod_deinit(void *);
void subr_mod_detach();

int eth_addr_aton(struct eth_addr *, const char *);
int eth_addr_is_mcast(const u_char *);
int eth_addr_is_ucast(const u_char *);
void eth_addr_make_ip6_mcast(struct eth_addr *, const u_char *);

void spinlock_init(struct spinlock *);
void spinlock_lock(struct spinlock *);
int spinlock_trylock(struct spinlock *);
void spinlock_unlock(struct spinlock *);

#define counter64_add(c, v) ((c)->cnt64[current->p_id] += (v))
#define counter64_inc(c) counter64_add(c, 1)
uint64_t counter64_get(struct counter64 *);

void profiler_enter(struct profiler *);
void profiler_leave(struct profiler *);

size_t strzlen(const char *);
char *strltrim(const char *);
char *strtrim(char *);
int strtrimcpy(char *, const char *, int);
int strsplit(const char *, const char *, struct iovec *, int);
char *strzcpy(char *, const char *, size_t);


uint32_t custom_hash32(uint32_t data, uint32_t initval);
uint32_t custom_hash(const void *data, size_t cnt, uint32_t val);

uint32_t toeplitz_hash(const u_char *, int, const u_char *);
uint32_t rss_hash4(be32_t, be32_t, be16_t, be16_t, u_char *);

int proc_get_comm(char *, int);

uint32_t upper_pow2_32(uint32_t x);
uint64_t upper_pow2_64(uint64_t x);
uint32_t lower_pow2_32(uint32_t x);
uint64_t lower_pow2_64(uint64_t x);

int fcntl_setfl_nonblock(int, int *);
#define fcntl_setfl_nonblock2(fd) \
	fcntl_setfl_nonblock(fd, NULL)

int connect_timed(int, const struct sockaddr *, socklen_t, uint64_t *);
ssize_t read_timed(int, void *, size_t, uint64_t *);
ssize_t write_full_buf(int, const void *, size_t);
ssize_t send_full_buf(int, const void *, size_t, int);

int read_rss_key(const char *, u_char *);

long gettid();

uint64_t rdtsc();

uint64_t sleep_compute_hz();

uint64_t rand64();
uint32_t rand32();

// to string
const char *tcp_state_str(int tcp_state);
const char *socket_domain_str(int domain);
const char *socket_type_str(int type);
const char *sockopt_level_str(int level);
const char *sockopt_optname_str(int level, int optname);
const char *fcntl_cmd_str(int cmd);
const char *ioctl_req_str(unsigned long req);
const char *shutdown_how_str(int how);
const char *sighandler_str(void *fn);
const char *sigprocmask_how_str(int how);

#ifdef __linux__
const char *epoll_op_str(int op);
#else /* __linux__ */
#endif /* __linux__ */

int iovec_len(const struct iovec *, int);
void print_backtrace(int);

void set_hz(uint64_t);
void rd_nanoseconds();

static inline void
read_once(const volatile void *p, void *data, int size)
{
	switch (size) {
	case 1: *(uint8_t *)data = *(volatile uint8_t *)p; break;
	case 2: *(uint16_t *)data = *(volatile uint16_t *)p; break;
	case 4: *(uint32_t *)data = *(volatile uint32_t *)p; break;
	case 8: *(uint64_t *)data = *(volatile uint64_t *)p; break;
	}
}

static inline void
write_once(volatile void *p, void *data, int size)
{
	switch (size) {
	case 1: *(volatile uint8_t *)p = *(uint8_t *)data; break;
	case 2: *(volatile uint16_t *)p = *(uint16_t *)data; break;
	case 4: *(volatile uint32_t *)p = *(uint32_t *)data; break;
	case 8: *(volatile uint64_t *)p = *(uint64_t *)data; break;
	}
}

#endif // GBTCP_SUBR_H
