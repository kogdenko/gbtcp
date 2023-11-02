// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_SUBR_H
#define GBTCP_SUBR_H

#include "sys.h"
#include "gbtcp.h"

#ifdef __linux__
#define GT_POLLRDHUP POLLRDHUP
#define GT_TCP_CORK TCP_CORK
#define gt_qsort_r qsort_r
#else // __linux__
#define GT_POLLRDHUP 0
#define GT_TCP_CORK TCP_NOPUSH
typedef cpuset_t cpu_set_t;
void gt_qsort_r(void *, size_t, size_t, int (*compar)(const void *, const void *, void *), void *);
#endif // __linux__

#ifndef CACHE_LINE_SIZE
#define CACHE_LINE_SIZE 64
#endif // CACHE_LINE_SIZE

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif // PAGE_SHIFT

#ifndef PAGE_SIZE
#define PAGE_SIZE (1 << PAGE_SHIFT)
#endif // PAGE_SIZE

#ifndef PAGE_MASK
#define PAGE_MASK (PAGE_SIZE - 1)
#endif // PAGE_MASK

#define ETHADDR_STRLEN 18
#define ETHADDR_LEN 6

#define IP6ADDR_LEN 16

#define RSS_KEY_SIZE 40

#ifdef __32BIT__
#define GT_PTR_STRLEN 10
#else
#define GT_PTR_STRLEN 18
#endif

#define GT_PREFIX "/usr/local/gbtcp"

#define NSEC_SEC 1000000000ull
#define NSEC_MSEC 1000000ull
#define NSEC_USEC 1000ull
#define NSEC_MINUTE (60 * NSEC_SEC)
#define NSEC_HOUR (60 * NSEC_MINUTE)
#define NSEC_INFINITY ((uint64_t)(-1))

typedef uint16_t be16_t;
typedef uint32_t be32_t;
typedef uint64_t be64_t;

typedef uint32_t bitset_word_t;

typedef void *(*malloc_f)(size_t);
typedef void (*free_f)(void *);

struct eth_addr {
	u_char ea_bytes[ETHADDR_LEN];
} __attribute__((packed));

struct spinlock {
	volatile int spinlock_locked;
};

struct counter64_per_service {
	uint64_t cntps_value;
	u_char cntps_pad[CACHE_LINE_SIZE - sizeof(uint64_t)];
};

typedef struct counter64 {
	struct counter64_per_service cnt_per_service[GT_SERVICES_MAX];
} counter64_t;

struct profiler {
	const char *prf_name;
	int prf_hits;
	uint64_t prf_tsc;
	uint64_t prf_last_print_tsc;
	uint64_t prf_spended;
};

#ifndef field_off
#define field_off(type, field) ((intptr_t)&((type *)0)->field)
#endif // field_off

#ifndef container_of
#define container_of(ptr, type, field) \
	((type *)((intptr_t)(ptr) - field_off(type, field)))
#endif // container_of

#define GT_UNUSED(x) (void)(x)

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif // MIN

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif // MAX

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif // ARRAY_SIZE

#ifndef BUG
#define BUG(msg) assert(!msg)
#endif

#define STRSZ(s) (s), (sizeof(s) - 1)

#define ALIGNMENT sizeof(void *)
#define U_ALIGN(x, a) (((x) + (a - 1)) & ~(a - 1))
#define ALIGN_PTR(x) U_ALIGN(x, ALIGNMENT)

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

#define GT_CAT2_RES(_, res) res
#define GT_CAT2_MED(x, y) GT_CAT2_RES(~, x##y)
#define GT_CAT2(x, y) GT_CAT2_MED(x, y)

#define GT_CAT3_RES(_, res) res
#define GT_CAT3_MED(x, y, z) GT_CAT3_RES(~, x##y##z)
#define GT_CAT3(x, y, z) GT_CAT3_MED(x, y, z)

#define GT_UNIQ_VAR(name) GT_CAT3(name, uniq_var_, __LINE__)

#define MEM_PREFETCH(ptr) \
	__builtin_prefetch(ptr)

#define SOCK_TYPE_FLAGS(type) ((type) & (SOCK_NONBLOCK|SOCK_CLOEXEC))
#define SOCK_TYPE_NOFLAGS(type) ((type) & (~(SOCK_NONBLOCK|SOCK_CLOEXEC)))

#define printf_rl(period, fmt, ...) \
do { \
	static uint64_t GT_UNIQV(last); \
	static uint64_t GT_UNIQV(now); \
	static int GT_UNIQV(cnt); \
 \
	GT_UNIQV(now) = nanoseconds; \
	if (GT_UNIQV(now) - GT_UNIQV(last) >= period) { \
		GT_UNIQV(last) = GT_UNIQV(now); \
		if (GT_UNIQV(cnt)) { \
			printf("suppresed %d; ", GT_UNIQV(cnt)); \
		} \
		printf(fmt, ##__VA_ARGS__); \
		GT_UNIQV(cnt) = 0; \
	} else { \
		GT_UNIQV(cnt)++; \
	} \
} while (0)

#define dbg_rl(period, fmt, ...) \
do { \
	static uint64_t GT_UNIQV(last); \
	static uint64_t GT_UNIQV(now); \
	static int GT_UNIQV(cnt); \
 \
	GT_UNIQV(now) = nanoseconds; \
	if (GT_UNIQV(now) - GT_UNIQV(last) >= (period) * NSEC_SEC) { \
		GT_UNIQV(last) = GT_UNIQV(now); \
		gt_dbg5(__FILE__, __LINE__, __func__, GT_UNIQV(cnt), fmt, ##__VA_ARGS__); \
		GT_UNIQV(cnt) = 0; \
	} else { \
		GT_UNIQV(cnt)++; \
	} \
} while (0)


#define BITSET_WORD_SIZE 32
#define BITSET_WORD_MASK (BITSET_WORD_SIZE - 1)
#define BITSET_WORD_SHIFT 5
#define BITSET_WORD_ARRAY_SIZE(n) \
	(ROUND_UP(n, BITSET_WORD_SIZE) >> BITSET_WORD_SHIFT)
#define BITSET_MASK(i) ((bitset_word_t)1 << (i & BITSET_WORD_MASK))
#define BITSET_WORD(i) (i >> BITSET_WORD_SHIFT)

#define PRF_INIT(x) \
	static struct profiler prf_##x = { .prf_name = #x };
#define PRF_ENTER(x) profiler_enter(&prf_##x)
#define PRF_LEAVE(x) profiler_leave(&prf_##x)

#define D_TRUE 1
#define D_FALSE 0

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

int eth_addr_aton(struct eth_addr *, const char *);
int eth_addr_is_mcast(const u_char *);
int eth_addr_is_ucast(const u_char *);
int eth_addr_is_bcast(const u_char *);

void eth_addr_make_ip6_mcast(struct eth_addr *, const u_char *);

void bitset_set(bitset_word_t *, int);
void bitset_clr(bitset_word_t *, int);
int bitset_get(const bitset_word_t *, int);

void spinlock_init(struct spinlock *);
void spinlock_lock(struct spinlock *);
int spinlock_trylock(struct spinlock *);
void spinlock_unlock(struct spinlock *);

// TODO:
#if 0
#define counter64_add(c, v)
#else // 1
#define counter64_add(c, v) \
	((c)->cnt_per_service[current->p_sid].cntps_value += (v))
#endif //1

#define counter64_inc(c) counter64_add(c, 1)
uint64_t counter64_get(struct counter64 *);

void profiler_enter(struct profiler *);
void profiler_leave(struct profiler *);

size_t strzlen(const char *);
char *strltrim(const char *);
char *strtrim(char *);
int strtrimcpy(char *, const char *, int);
int strsplit(const char *, const char *, struct iovec *, int);
char *gt_strzcpy(char *, const char *, size_t) GT_EXPORT;

uint32_t toeplitz_hash(const u_char *, int, const u_char *);
uint32_t rss_hash4(be32_t, be32_t, be16_t, be16_t, u_char *);

uint32_t upper_pow2_32(uint32_t x);
uint64_t upper_pow2_64(uint64_t x);
uint32_t lower_pow2_32(uint32_t x);
uint64_t lower_pow2_64(uint64_t x);

int fchgrp(int, struct stat *, const char *);
int fcntl_setfl_nonblock(int, int *);
#define fcntl_setfl_nonblock2(fd) \
	fcntl_setfl_nonblock(fd, NULL)

int connect_timed(int, const struct sockaddr *, socklen_t, uint64_t *);
ssize_t read_timed(int, void *, size_t, uint64_t *);
ssize_t write_record(int, const void *, size_t);
ssize_t send_record(int, const void *, size_t, int);

int read_rss_key(const char *, u_char *);
int read_rss_queue_num(const char *);

pid_t gt_gettid(void);
int read_proc_comm(char *, int);

uint64_t rdtsc(void);

uint64_t sleep_compute_hz(void);

int gt_set_affinity(int) GT_EXPORT;

uint64_t rand64(void);
uint32_t rand32(void);

// to string
const char *tcp_state_str(int tcp_state);
const char *socket_domain_str(int domain);
const char *socket_type_str(int type);
const char *sockopt_level_str(int level);
const char *sockopt_optname_str(int level, int optname);
const char *fcntl_cmd_str(int cmd);
const char *shutdown_how_str(int how);
const char *sighandler_str(void *fn);
const char *sigprocmask_how_str(int how);

#ifdef __linux__
const char *epoll_op_str(int op);
#else // __linux__
#endif // __linux__

int iovec_accum_len(const struct iovec *, int);
void print_backtrace(int);

void set_hz(uint64_t);
void rd_nanoseconds(void);

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
