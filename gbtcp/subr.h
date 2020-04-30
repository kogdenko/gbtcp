/* GPL2 license */
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

#define RSSKEYSIZ 40

#define NETMAP_PFX "netmap:"
#define NETMAP_PFX_LEN (sizeof(NETMAP_PFX) - 1)
#define NM_IFNAMSIZ (IFNAMSIZ + NETMAP_PFX_LEN)
#define GT_PREFIX "/usr/local/gbtcp"

#define GT_SEC 1000000000ull
#define GT_MSEC 1000000ull
#define GT_NSEC_MAX ((unsigned long long)(-1))

typedef uint16_t be16_t;
typedef uint32_t be32_t;
typedef uint64_t be64_t;

struct log;
struct gt_strbuf;

struct ethaddr {
	uint8_t etha_bytes[ETHADDR_LEN];
} __attribute__((packed));

struct gt_sock_tuple {
	be32_t sot_laddr;
	be32_t sot_faddr;
	be16_t sot_lport;
	be16_t sot_fport;
};

struct spinlock {
	volatile int spinlock_locked;
};

struct gt_profiler {
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

#define ARRAY_REMOVE(a, i, n) ((a)[i] = (a)[--(n)])

#define STRSZ(s) (s), (sizeof(s) - 1)

#define ALIGNMENT sizeof(unsigned long)
#define ALIGN(x, a) (((x) + (a - 1)) & ~(a - 1))
#define ALIGN_PTR(x) ALIGN(x, ALIGNMENT)

#define ROUND_UP(x, y) ((((x) - 1) | (((__typeof__(x))(y)) - 1)) + 1)
#define ROUND_DOWN(x, y) ((x) & (~((y) - 1 )))

#define GT_BSWAP16(x) \
	(((((uint16_t)(x)) & ((uint16_t)0x00FF)) << 8) | \
	 ((((uint16_t)(x)) & ((uint16_t)0xFF00)) >> 8))

#define GT_BSWAP32(x) \
	(((((uint32_t)(x)) & ((uint32_t)0x000000FF)) << 24) | \
	 ((((uint32_t)(x)) & ((uint32_t)0x0000FF00)) <<  8) | \
	 ((((uint32_t)(x)) & ((uint32_t)0x00FF0000)) >>  8) | \
	 ((((uint32_t)(x)) & ((uint32_t)0xFF000000)) >> 24))

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define GT_HTON16(x) ((uint16_t)(x))
#define GT_HTON32(x) ((uint32_t)(x))
#define GT_NTOH16(x) ((uint16_t)(x))
#define GT_NTOH32(x) ((uint32_t)(x))
#else  // __BIG_ENDIAN
#define GT_HTON16(x) ((uint16_t)GT_BSWAP16(x))
#define GT_HTON32(x) ((uint32_t)GT_BSWAP32(x))
#define GT_NTOH16(x) ((uint16_t)GT_BSWAP16(x))
#define GT_NTOH32(x) ((uint32_t)GT_BSWAP32(x))
#endif // __BIG_ENDIAN

#define mb _mm_mfence
#define rmb _mm_sfence
#define wmb _mm_lfence

#if 1
#define GT_PKT_COPY(d, s, len) nm_pkt_copy(s, d, len)
#else
#define GT_PKT_COPY(d, s, len) memcpy(d, s, len)
#endif

#define GT_UNIQV_CAT3(x, res) res
#define GT_UNIQV_CAT2(x, y, z) GT_UNIQV_CAT3(~, x##y##z)
#define GT_UNIQV_CAT(x, y, z) GT_UNIQV_CAT2(x, y, z)
#define GT_UNIQV(n) GT_UNIQV_CAT(n, gt_uniqv_, __LINE__)

#define GT_MEM_PREFETCH(ptr) \
	__builtin_prefetch(ptr)


#define gt_printf_rl(period, fmt, ...) \
do { \
	static uint64_t GT_UNIQV(last); \
	static uint64_t GT_UNIQV(now); \
	static int GT_UNIQV(cnt); \
	GT_UNIQV(now) = gt_rdtsc(); \
	if (GT_UNIQV(now) - GT_UNIQV(last) >= period) { \
		GT_UNIQV(last) = GT_UNIQV(now); \
		if (GT_UNIQV(cnt)) { \
			printf("suppresed %d; ", GT_UNIQV(cnt)); \
		} \
		printf(fmt, ##__VA_ARGS__); \
	} else { \
		GT_UNIQV(cnt)++; \
	} \
} while (0)

#if 0
#define GT_PRF_INIT(x) 
#define GT_PRF_ENTER(x)
#define GT_PRF_LEAVE(x)
#else
#define GT_PRF_INIT(x) \
	static struct gt_profiler prf_##x = { .prf_name = #x };
#define GT_PRF_ENTER(x) profiler_enter(&prf_##x)
#define GT_PRF_LEAVE(x) profiler_leave(&prf_##x)
#endif

extern uint64_t nanoseconds;
extern uint64_t gt_mHZ;
extern int gt_application_pid;
extern const char *gt_application_name;

int subr_mod_init(struct log *, void **);
int subr_mod_attach(struct log *, void *);
void subr_mod_deinit(struct log *, void *);
void subr_mod_detach(struct log *);

int ethaddr_aton(struct ethaddr *, const char *);

int ethaddr_is_mcast(const uint8_t *);

int ethaddr_is_ucast(const uint8_t *);

void ethaddr_make_ip6_mcast(struct ethaddr *, const uint8_t *);

void spinlock_init(struct spinlock *);
void spinlock_lock(struct spinlock *);
int spinlock_trylock(struct spinlock *);
void spinlock_unlock(struct spinlock *);

void gt_profiler_enter(struct gt_profiler *);

void gt_profiler_leave(struct gt_profiler *);

// string
char *gt_ltrim(const char *s);

char *gt_trim(const char *s);

int gt_strsplit(const char *str, const char *delim,
	struct iovec *iovec, int iovcnt);

char *strzcpy(char *dest, const char *src, size_t n);

// hash
uint32_t gt_custom_hash32(uint32_t data, uint32_t initval);

uint32_t gt_custom_hash(const void *data, size_t cnt, uint32_t val);

uint32_t toeplitz_hash(const uint8_t *data, int cnt, const uint8_t *key);

// byte
uint32_t gt_upper_pow_of_2_32(uint32_t x);

uint64_t gt_upper_pow_of_2_64(uint64_t x);

uint32_t gt_lower_pow_of_2_32(uint32_t x);

uint64_t gt_lower_pow_of_2_64(uint64_t x);



int gt_set_nonblock(struct log *, int fd);

int connect_timed(struct log *, int fd, const struct sockaddr *addr,
	socklen_t addrlen, uint64_t to);

int write_all(struct log *log, int fd, const void *buf, size_t count);

int read_rsskey(struct log *, const char *, u_char *);

long gt_gettid();

//rand
uint64_t gt_rdtsc();

uint64_t gt_rand64();

uint32_t gt_rand32();

// to string
const char *gt_tcp_state_str(int tcp_state);
const char *gt_socket_domain_str(int domain);
const char *gt_socket_type_str(int type);
const char *gt_sockopt_level_str(int level);
const char *gt_sockopt_optname_str(int level, int optname);
const char *gt_fcntl_cmd_str(int cmd);
const char *gt_ioctl_req_str(unsigned long req);
const char *gt_shutdown_how_str(int how);
const char *gt_sighandler_str(void *fn);
const char *gt_sigprocmask_how_str(int how);

#ifdef __linux__
const char *gt_epoll_op_str(int op);
#else /* __linux__ */
#endif /* __linux__ */

int iovec_len(const struct iovec *, int);
void print_backtrace(int);

#endif /* GBTCP_SUBR_H */
