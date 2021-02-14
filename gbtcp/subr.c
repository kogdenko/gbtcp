// gpl2
#include "internals.h"

#define CURMOD subr

union tsc {
	uint64_t tsc_64;
	struct {
		uint32_t lo_32;
		uint32_t hi_32;
	};
};


int
eth_addr_aton(struct eth_addr *a, const char *s)
{
	int rc;
	struct eth_addr x;

	rc = sscanf(s, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		x.ea_bytes + 0, x.ea_bytes + 1, x.ea_bytes + 2,
		x.ea_bytes + 3, x.ea_bytes + 4, x.ea_bytes + 5);
	if (rc == 6) {
		*a = x;
		return 0;
	} else {
		return -EINVAL;
	}
}

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
int
eth_addr_is_mcast(const u_char *addr)
{
	return 0x01 & (addr >> ((sizeof(addr) * 8) - 8));
}
#else // __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
int
eth_addr_is_mcast(const u_char *addr)
{
	return 0x01 & addr[0];
}
#endif // __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

int
eth_addr_is_ucast(const u_char *addr)
{
	return !eth_addr_is_mcast(addr);
}

void
eth_addr_make_ip6_mcast(struct eth_addr *addr, const u_char *ia6) 
{   
	addr->ea_bytes[0] = 0x33;
	addr->ea_bytes[1] = 0x33;
	addr->ea_bytes[2] = ia6[12];
	addr->ea_bytes[3] = ia6[13];
	addr->ea_bytes[4] = ia6[14];
	addr->ea_bytes[5] = ia6[15];
}

void
bitset_set(bitset_word_t *bitset_words, int i)
{
	bitset_words[BITSET_WORD(i)] |= BITSET_MASK(i);
}

void
bitset_clr(bitset_word_t *bitset_words, int i)
{
	bitset_words[BITSET_WORD(i)] &= ~BITSET_MASK(i);
}

int
bitset_get(const bitset_word_t *bitset_words, int i)
{
	return (bitset_words[BITSET_WORD(i)] & BITSET_MASK(i)) != 0;
}

void
spinlock_init(struct spinlock *sl)
{
	sl->spinlock_locked = 0;
}

#if 1
void
spinlock_lock(struct spinlock *sl)
{
	while (__sync_lock_test_and_set(&sl->spinlock_locked, 1)) {
		while (sl->spinlock_locked) {
			_mm_pause();
		}
	}
}

int
spinlock_trylock(struct spinlock *sl)
{
	return __sync_lock_test_and_set(&sl->spinlock_locked, 1) == 0;
}

void
spinlock_unlock(struct spinlock *sl)
{
	__sync_lock_release(&sl->spinlock_locked);
}

void rwlock_init(struct rwlock *rwl)
{
	rwl->rwl_cnt = 0;
}

void
rwlock_read_lock(struct rwlock *rwl)
{
	int rc, x;

	rc = 0;
	while (!rc) {
		x = rwl->rwl_cnt;
		if (x < 0) {
			_mm_pause();
			continue;
		}
		rc = __sync_bool_compare_and_swap(&rwl->rwl_cnt, x, x + 1);
	}
}

void
rwlock_read_unlock(struct rwlock *rwl)
{
	 __sync_fetch_and_sub(&rwl->rwl_cnt, 1);
}

//void rwlock_write_lock(struct rwlock *);
//void rwlock_write_unlock(struct rwlock *);

#else
void
spinlock_lock(struct spinlock *sl)
{
}

// return 1 if locked
int
spinlock_trylock(struct spinlock *sl)
{
	return 1;
}

void
spinlock_unlock(struct spinlock *sl)
{
}
#endif // debug

void
profiler_enter(struct profiler *p)
{
	assert(p->prf_tsc == 0);
	p->prf_tsc = rdtsc();
}

void
profiler_leave(struct profiler *p)
{
	u64 t, dt, elapsed;
	double avg;

	assert(p->prf_tsc != 0);
	t = rdtsc();
	dt = t - p->prf_tsc;
	p->prf_spended += dt;
	p->prf_hits++;
	elapsed = t - p->prf_last_print_tsc;
	if (elapsed > 3000000000ull) {
		p->prf_last_print_tsc = t;
		avg = (double)p->prf_spended / p->prf_hits;
		printf("profile <%-10s>: %llu tsc (%.3f%%) (%zu hits)\n",
			p->prf_name,
			(unsigned long long)(avg),
			100 * ((double)p->prf_spended) / elapsed,
			p->prf_hits);
		p->prf_spended = 0;
		p->prf_hits = 0;
	}
	p->prf_tsc = 0;
}

size_t
strzlen(const char *s)
{
	if (s == NULL) {
		return 0;
	} else {
		return strlen(s);
	}
}

char *
strltrim(const char *s)
{
	char *p;

	for (p = (char *)s; *p != '\0'; ++p) {
		if (!isspace(*p)) {
			break;
		}
	}
	return p;
}

char *
strrtrim(char *s)
{
	int i, len;

	len = strlen(s);
	for (i = len - 1; i >= 0; --i) {
		if (!isspace(s[i])) {
			break;
		}
	}
	s[i + 1] = '\0';
	return s;

}

char *
strtrim(char *s)
{
	char *trimmed;

	trimmed = strltrim(s);
	trimmed = strrtrim(trimmed);
	return trimmed;
}

int
strtrimcpy(char *dst, const char *src, int count)
{
	int i, len;
	const char *x;

	x = strltrim(src);
	len = 0;
	for (i = 0; x[i] != '\0'; ++i) {
		if (i < count) {
			dst[i] = x[i];
		}
		if (!isspace(x[i])) {
			len = i + 1;
		}
	}
	if (len < count) {
		dst[len] = '\0';
	}
	return len;
}

int
strsplit(const char *str, const char *delim, struct iovec *iovec, int iovcnt)
{
	int n, len;
	const char *p, *x;

	n = 0;
	p = str;
	while (1) {
		for (x = p; *x != '\0'; ++x) {
			if (strchr(delim, *x) != NULL) {
				break;
			}
		}
		len = x - p;
		if (len) {
			if (n < iovcnt) {
				iovec[n].iov_base = (void *)p;
		 		iovec[n].iov_len = len;
			}
			n++;
		}
		if (*x == '\0') {
			return n;
		}
		p = x + 1;
	}
}

char *
strzcpy(char *dest, const char *src, size_t n)
{
	size_t i;

	for (i = 0; i < n - 1; ++i) {
		if (src[i] == '\0') {
			break;
		}
		dest[i] = src[i];
	}
	dest[i] = '\0';
	return dest;
}

uint32_t
toeplitz_hash(const u_char *data, int cnt, const u_char *key)
{   
	uint32_t h, v;
	int i, b;

	h = 0; 
	v = (key[0] << 24) + (key[1] << 16) + (key[2] << 8) + key[3];
	for (i = 0; i < cnt; i++) {
		for (b = 0; b < 8; ++b) {
			if (data[i] & (1 << (7 - b))) {
				h ^= v;
			}
			v <<= 1;
			if ((i + 4) < RSS_KEY_SIZE &&
			    (key[i + 4] & (1 << (7 - b)))) {
				v |= 1;
			}
		}
	}
	return h;
}

uint32_t
rss_hash4(be32_t laddr, be32_t faddr, be16_t lport, be16_t fport, u_char *key)
{
	int off;
	uint32_t h;
	u_char data[12];

	off = 0;
	*(be32_t *)(data + off) = faddr;
	off += 4;
	*(be32_t *)(data + off) = laddr;
	off += 4;
	*(be16_t *)(data + off) = fport;
	off += 2;
	*(be16_t *)(data + off) = lport;
	off += 2;
	h = toeplitz_hash(data, off, key);
	h &= 0x0000007F;
	return h;
}

uint32_t
upper_pow2_32(uint32_t x)
{
	x--;
	x |= x >>  1lu;
	x |= x >>  2lu;
	x |= x >>  4lu;
	x |= x >>  8lu;
	x |= x >> 16lu;
	x++;
	return x;
}

uint64_t
upper_pow2_64(uint64_t x)
{
	x--;
	x |= x >>  1llu;
	x |= x >>  2llu;
	x |= x >>  4llu;
	x |= x >>  8llu;
	x |= x >> 16llu;
	x |= x >> 32llu;
	x++;
	return x;
}

uint32_t
lower_pow2_32(uint32_t x)
{
	x = x | (x >> 1lu);
	x = x | (x >> 2lu);
	x = x | (x >> 4lu);
	x = x | (x >> 8lu);
	x = x | (x >> 16lu);
	return x - (x >> 1lu);
}

uint64_t
lower_pow2_64(uint64_t x)
{
	x = x | (x >>  1llu);
	x = x | (x >>  2llu);
	x = x | (x >>  4llu);
	x = x | (x >>  8llu);
	x = x | (x >> 16llu);
	x = x | (x >> 32llu);
	return x - (x >> 1);
}

static void
set_normalized_timespec(struct timespec *ts, s64 sec, s64 nsec)
{
	while (nsec >= NSEC_PER_SEC) {
		nsec -= NSEC_PER_SEC;
		sec++;
	}
	while (nsec < 0) {
		nsec += NSEC_PER_SEC;
		sec--;
	}
	ts->tv_sec = sec;
	ts->tv_nsec = nsec;
}

struct timespec
timespec_sub(struct timespec *lhs, struct timespec *rhs)
{
	struct timespec res;

	set_normalized_timespec(&res, lhs->tv_sec - rhs->tv_sec,
		lhs->tv_nsec - rhs->tv_nsec);
	return res;
}

int
fchgrp(int fd, struct stat *buf, const char *group_name)
{
	int rc;
	struct group *group;

	rc = sys_getgrnam(group_name, &group);
	if (rc == 0) {
		rc = sys_fstat(fd, buf);
		if (rc == 0 && buf->st_gid != group->gr_gid)  {
			rc = sys_fchown(fd, -1, group->gr_gid);
		}
	}
	return rc;
}

int
fcntl_setfl_nonblock(int fd, int *old_flags)
{
	int rc, flags;

	rc = sys_fcntl(fd, F_GETFL, 0);
	if (rc < 0) {
		return rc;
	}
	flags = rc;
	if (old_flags != NULL) {
		*old_flags = flags;
	}
	if (flags & O_NONBLOCK) {
		return 0;
	}
	flags |= O_NONBLOCK;
	rc = sys_fcntl(fd, F_SETFL, flags);
	return rc;
}

static int
fcntl_setfl_nonblock_rollback(int fd, int old_flags)
{
	int rc;

	rc = 0;
	if (!(old_flags & O_NONBLOCK)) {
		rc = sys_fcntl(fd, F_SETFL, old_flags & ~O_NONBLOCK);
	}
	return rc;
}

int
connect_timed(int fd, const struct sockaddr *addr,
		socklen_t addrlen, struct timespec *to)
{
	int rc, errnum, flags;
	socklen_t opt_len;
	struct timespec ts, ts2, elapsed;
	struct pollfd pfd;

	if (to == NULL) {
		rc = sys_connect(fd, addr, addrlen);
		return rc;
	}
	rc = fcntl_setfl_nonblock(fd, &flags);
	if (rc) {
		return rc;
	}
	do {
		rc = sys_connect(fd, addr, addrlen);
		errnum = -rc;
	} while (addr->sa_family == AF_UNIX && errnum == EAGAIN);
	fcntl_setfl_nonblock_rollback(fd, flags);
	if (errnum == 0) {
		return 0;
	} else if (errnum != EINPROGRESS) {
		return -errnum;
	} else if (to->tv_sec == 0 && to->tv_nsec == 0) {
		errnum = ETIMEDOUT;
		goto out;
	}
	pfd.events = POLLOUT;
	pfd.fd = fd;
	clock_gettime(CLOCK_MONOTONIC, &ts);
restart:
	rc = sys_ppoll(&pfd, 1, to, NULL);
	clock_gettime(CLOCK_MONOTONIC, &ts2);
	elapsed = timespec_sub(&ts2, &ts);
	*to = timespec_sub(to, &elapsed);
	if (to->tv_sec < 0) {
		to->tv_sec = to->tv_nsec = 0;
	}
	ts = ts2;
	switch (rc) {
	case 0:
		errnum = ETIMEDOUT;
		break;
	case 1:
		opt_len = sizeof(errnum);
		rc = sys_getsockopt(fd, SOL_SOCKET, SO_ERROR,
			&errnum, &opt_len);
		if (rc) {
			return rc;
		}
		break;
	case -EINTR:
		if (to->tv_sec || to->tv_nsec) {
			goto restart;
		} else {
			errnum = ETIMEDOUT;
			break;
		}
	default:
		errnum = -rc;
		break;
	}
out:
	if (errnum) {
		if (errnum == ETIMEDOUT) {
			to->tv_sec = to->tv_nsec = 0;
			sys_shutdown(fd, SHUT_RDWR);
		}
		ERR(errnum, "connect_timed() failed; fd=%d, addr=%s",
			fd, log_add_sockaddr(addr, addrlen));
	}
	return -errnum;
}

ssize_t
read_timed(int fd, void *buf, size_t count, struct timespec *to)
{
	int flags;
	ssize_t rc;
	struct timespec ts, ts2, elapsed;
	struct pollfd pfd;

	if (to == NULL) {
		rc = sys_read(fd, buf, count);
		return rc;
	}
	rc = fcntl_setfl_nonblock(fd, &flags);
	if (rc) {
		return rc;
	}
	pfd.events = POLLIN;
	pfd.fd = fd;
	clock_gettime(CLOCK_MONOTONIC, &ts);
restart:
	rc = sys_ppoll(&pfd, 1, to, NULL);
	clock_gettime(CLOCK_MONOTONIC, &ts2);
	elapsed = timespec_sub(&ts2, &ts);
	*to = timespec_sub(to, &elapsed);
	if (to->tv_sec < 0) {
		to->tv_sec = to->tv_nsec = 0;
	}
	ts = ts2;
	switch (rc) {
	case 0:
		rc = -ETIMEDOUT;
		break;
	case 1:
		rc = sys_read(fd, buf, count);
		if (rc == -EAGAIN) {
			if (to->tv_sec || to->tv_nsec) {
				goto restart;
			} else {
				rc = -ETIMEDOUT;
				break;
			}
		}
		break;
	case -EINTR:
		goto restart;
	default:
		break;
	}
	fcntl_setfl_nonblock_rollback(fd, flags);
	if (rc < 0) {
		if (rc == -ETIMEDOUT) {
			to->tv_sec = to->tv_nsec = 0;
		}
		ERR(-rc, "read_timed() failed; fd=%d", fd);
	}
	return rc;
}

#define SYS_CALL_RECORD(name, fd, buf, cnt, ...) ({ \
	ssize_t rc, ret, off; \
 \
	ret = 0; \
	for (off = 0; off < cnt; off += rc) { \
		rc = sys_##name(fd, (const u_char *)buf + off, \
		                cnt - off, ##__VA_ARGS__); \
		if (rc < 0) { \
			ret = rc; \
			break; \
		} \
	} \
	ret; \
})

ssize_t
write_record(int fd, const void *buf, size_t cnt)
{
	int rc;

	rc = SYS_CALL_RECORD(write, fd, buf, cnt);
	return rc;
}

ssize_t
send_record(int fd, const void *buf, size_t cnt, int flags)
{
	int rc;

	rc = SYS_CALL_RECORD(send, fd, buf, cnt, flags);
	return rc;
}

#ifdef __linux__
int
read_rss_key(const char *ifname, u_char *rss_key)
{
	int fd, rc, size, off;
	struct ifreq ifr;
	struct ethtool_rxfh rss, *rss2;

	rss2 = NULL;
	rc = sys_socket(AF_INET, SOCK_DGRAM, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	memset(&ifr, 0, sizeof(ifr));
	memset(&rss, 0, sizeof(rss));
	strzcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	rss.cmd = ETHTOOL_GRSSH;
	ifr.ifr_data = (void *)&rss;
	rc = sys_ioctl(fd, SIOCETHTOOL, (uintptr_t)&ifr);
	if (rc < 0) {
		goto out;
	}
	if (rss.key_size != RSS_KEY_SIZE) {
		ERR(0, "%s: Bad RSS key size %d vs %d",
			ifname, rss.key_size, RSS_KEY_SIZE);
		goto out;
	}
	size = (sizeof(rss) + rss.key_size +
		rss.indir_size * sizeof(rss.rss_config[0]));
	rss2 = sys_malloc(size);
	if (rss2 == NULL) {
		goto out;
	}
	memset(rss2, 0, size);
	rss2->cmd = ETHTOOL_GRSSH;
	rss2->indir_size = rss.indir_size;
	rss2->key_size = rss.key_size;
	ifr.ifr_data = (void *)rss2;
	rc = sys_ioctl(fd, SIOCETHTOOL, (uintptr_t)&ifr);
	if (rc) {
		goto out;
	}
	off = rss2->indir_size * sizeof(rss2->rss_config[0]);
	memcpy(rss_key, (u_char *)rss2->rss_config + off, RSS_KEY_SIZE);
out:
	sys_free(rss2);
	sys_close(&fd);
	return rc;
}

int
read_irq_table(const char *ifname, u_char *q2cpu)
{
	int rc, irq, cpu_id, n_queues, queue_id, queue_id_max;
	unsigned long long cpu_mask;
	char *s, buf[256], pattern[IFNAMSIZ + 16], path[PATH_MAX];
	struct iovec f[12];
	FILE *file_interrupts, *file_irq;

	n_queues = 0;
	queue_id_max = -1;
	snprintf(pattern, sizeof(pattern), "%s-TxRx-%%d", ifname);
	rc = sys_fopen(&file_interrupts, "/proc/interrupts", "r");
	if (rc) {
		return rc;
	}
	while ((s = fgets(buf, sizeof(buf), file_interrupts)) != NULL) {
		rc = strsplit(s, "\r\n\t ", f, ARRAY_SIZE(f));
		if (rc < 12) {
			continue;
		}
		((char *)f[11].iov_base)[f[11].iov_len] = '\0';
		rc = sscanf(f[11].iov_base, pattern, &queue_id);
		if (rc != 1) {
			continue;
		}
		if (queue_id >= WORKER_CPU_NUM) {
			ERR(0, "%s: Too many RSS queues (>%d)",
				ifname, WORKER_CPU_NUM);
			rc = -EINVAL;
			goto err;
		}
		n_queues++;
		queue_id_max = MAX(queue_id_max, queue_id);
		irq = strtoul(f[0].iov_base, NULL, 10);
		snprintf(path, sizeof(path), "/proc/irq/%d/smp_affinity", irq);
		rc = sys_fopen(&file_irq, path, "r");
		if (rc < 0) {
			goto err;
		}
		s = sys_fgets(path, buf, sizeof(buf), file_irq);
		fclose(file_irq);
		if (s == NULL) {
			goto err;
		}
		cpu_mask = strtoull(buf, NULL, 16);
		if (cpu_mask == 0) {
			ERR(0, "%s: Unexpected cpu mask (0)", path);
			goto err_bad_format;
		}
		cpu_id = ffsl(cpu_mask) - 1;
		if (cpu_id >= CPU_NUM) {
			ERR(0, "%s: cpu %d exceeds maximum support size %d",
				path, cpu_id, CPU_NUM);
			goto err_bad_format;
		}
		if (cpu_mask != (1llu << cpu_id)) {
			ERR(0, "%s: cpu mask (0x%llx) must be power of 2",
				path, cpu_mask);
			goto err_bad_format;
		}
		q2cpu[queue_id] = cpu_id;
			
	}
	if (!n_queues) {
		ERR(0, "Cannot find RSS queues: grep %s-TxRx /proc/interrupts",
			ifname);
		goto err_bad_format;
	}
	if (n_queues != queue_id_max + 1) {
		ERR(0, "RSS queue is missing: grep %s-TxRx /proc/interrupts",
			ifname);
		goto err_bad_format;
	}
	fclose(file_interrupts);
	return n_queues;
err_bad_format:
	rc = -EINVAL;
err:
	fclose(file_interrupts);
	return rc;
}

long
gettid()
{
	long tid;

	tid = syscall(SYS_gettid);
	return tid;
}

int
read_proc_name(char *name, int pid)
{
	int rc, len;
	FILE *file;
	char *s;
	char buf[PROC_NAME_MAX + 32];

	snprintf(buf, sizeof(buf), "/proc/%d/status", pid);
	rc = sys_fopen(&file, buf, "r");
	if (rc) {
		return rc;
	}
	s = fgets(buf, sizeof(buf), file);
	fclose(file);
	if (s == NULL) {
		goto err;
	}
	len = strlen(s);
	if (len < 5 || memcmp(s, STRSZ("Name:"))) {
		goto err;
	}
	len = strtrimcpy(name, s + 6, PROC_NAME_MAX);
	if (len > 0 && len < PROC_NAME_MAX) {
		return 0;
	}
err:
	ERR(0, "/proc/%d/status: unexpected format", pid);
	return -EPROTO;
}
#else // __linux__
int
read_rss_key(const char *ifname, u_char *rss_key)
{
	static uint8_t freebsd_rss_key[RSS_KEY_SIZE] = {
		0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
		0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
		0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
		0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
		0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
	};
	memcpy(rss_key, freebsd_rss_key, RSS_KEY_SIZE);
	return 0;
}

long
gettid()
{
	long tid;

	thr_self(&tid);
	return tid;
}

int
read_proc_comm(char *name, int pid)
{
	int rc;
	struct kinfo_proc *info;

	info = kinfo_getproc(pid);
	if (info == NULL) {
		rc = -errno;
		assert(rc);
		return rc;
	}
	strzcpy(name, info->ki_comm, GT_COMMLEN);
	free(info);
	return 0;
}

struct qsort_data {
	int (*compar)(const void *, const void *, void *);
	void *arg;
};

static int
qsort_compar(void *udata, const void *a1, const void *a2)
{
	struct qsort_data *data;

	data = udata;
	return (*data->compar)(a1, a2, data->arg);
}

void
gt_qsort_r(void *base, size_t nmemb, size_t size,
	int (*compar)(const void *, const void *, void *), void *arg)
{
	struct qsort_data data;

	data.compar = compar;
	data.arg = arg;
	qsort_r(base, nmemb, size, &data, qsort_compar);
}
#endif // __linux__

uint64_t
rdtsc()
{
	union tsc tsc;

	asm volatile("rdtsc" :
		"=a" (tsc.lo_32),
		"=d" (tsc.hi_32));
	return tsc.tsc_64;;
}

int
set_affinity(int cpu_id)
{
	int rc;
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET(cpu_id, &mask);
	rc = pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask);
	if (rc != 0) {
		ERR(rc, "pthread_setaffinity_np() failed; cpu_id=%d", cpu_id);
	}
	return -rc;
}

uint64_t
rand64()
{
	uint64_t x, y;

	x = lrand48();
	x <<= 32;
	y = lrand48();
	return x | y;
}

uint32_t
rand32()
{
	return lrand48();
}

const char *
tcp_state_str(int tcp_state)
{
	switch (tcp_state) {
	case GT_TCPS_CLOSED: return "CLOSED";
	case GT_TCPS_LISTEN: return "LISTEN";
	case GT_TCPS_SYN_SENT: return "SYN_SENT";
	case GT_TCPS_SYN_RCVD: return "SYN_RCVD";
	case GT_TCPS_ESTABLISHED: return "ESTABLISHED";
	case GT_TCPS_CLOSE_WAIT: return "CLOSE_WAIT";
	case GT_TCPS_LAST_ACK: return "LAST_ACK";
	case GT_TCPS_FIN_WAIT_1: return "FIN_WAIT_1";
	case GT_TCPS_FIN_WAIT_2: return "FIN_WAIT_2";
	case GT_TCPS_CLOSING: return "CLOSING";
	case GT_TCPS_TIME_WAIT: return "TIME_WAIT";
	default: return NULL;
	}
}

const char *
socket_domain_str(int domain)
{
	switch (domain) {
	case AF_LOCAL: return "AF_LOCAL";
	case AF_INET: return "AF_INET";
	case AF_INET6: return "AF_INET6";
	default: return NULL;
	}
}

#ifdef __linux__
static const char *
socket_type_str_os(int type)
{
	switch (type) {
	case SOCK_PACKET: return "SOCK_PACKET";
	default: return NULL;
	}
}
#else /* __linux__ */
static const char *
socket_type_str_os(int type)
{
	return NULL;
}
#endif /* __linux__ */

const char *
socket_type_str(int type)
{
	const char *s;

	switch (type) {
	case SOCK_STREAM: return "SOCK_STREAM";
	case SOCK_DGRAM: return "SOCK_DGRAM";
	case SOCK_SEQPACKET: return "SOCK_SEQPACKET";
	case SOCK_RAW: return "SOCK_RAW";
	case SOCK_RDM: return "SOCK_DRM";
	default:
		s = socket_type_str_os(type);
		return s;
	}
}

const char *
sockopt_level_str(int level)
{
	switch (level) {
	case IPPROTO_TCP: return "IPPROTO_TCP";
	case SOL_SOCKET: return "SOL_SOCKET";
	default: return NULL;
	}
}

const char *
sockopt_optname_str(int level, int optname)
{
	switch (level) {
	case IPPROTO_TCP:
		switch (optname) {
		case TCP_MAXSEG: return "TCP_MAXSEG";
		case TCP_NODELAY: return "TCP_NODELAY";
		case TCP_KEEPIDLE: return "TCP_KEEPIDLE";
		case TCP_KEEPINTVL: return "TCP_KEEPINTVL";
		case TCP_KEEPCNT: return "TCP_KEEPCNT";
		case GT_TCP_CORK: return "TCP_CORK";
		}
		break;
	case SOL_SOCKET:
		switch (optname) {
		case SO_ERROR: return "SO_ERROR";
		case SO_RCVBUF: return "SO_RCVBUF";
		case SO_SNDBUF: return "SO_SNDBUF";
		case SO_REUSEADDR: return "SO_REUSEADDR";
		case SO_REUSEPORT: return "SO_REUSEPORT";
		case SO_KEEPALIVE: return "SO_KEEPALIVE";
		case SO_LINGER: return "SO_LINGER";
		}
		break;
	}
	return NULL;
}

const char *
fcntl_cmd_str(int cmd)
{
	switch (cmd) {
	case F_GETFD: return "F_GETFD";
	case F_SETFD: return "F_SETFD";
	case F_GETFL: return "F_GETFL";
	case F_SETFL: return "F_SETFL";
	default: return NULL;
	}
}

const char *
shutdown_how_str(int how)
{
	switch (how) {
	case SHUT_RD: return "SHUT_RD";
	case SHUT_WR: return "SHUT_WR";
	case SHUT_RDWR: return "SHUT_RDWR";
	default: return NULL;
	}
}

const char *
sighandler_str(void *fn)
{
	if (fn == SIG_ERR) {
		return "SIG_ERR";
	} else if (fn == SIG_IGN) {
		return "SIG_IGN";
	} else if (fn == SIG_DFL) {
		return "SIG_DFL";
	} else {
		return NULL;
	}
}

const char *
sigprocmask_how_str(int how)
{
	switch (how) {
	case SIG_BLOCK: return "SIG_BLOCK";
	case SIG_UNBLOCK: return "SIG_UNBLOCK";
	case SIG_SETMASK: return "SIG_SETMASK";
	default: return NULL;
	}
}

#ifdef __linux__
const char *
epoll_op_str(int op)
{
	switch (op) {
	case EPOLL_CTL_ADD: return "EPOLL_CTL_ADD";
	case EPOLL_CTL_MOD: return "EPOLL_CTL_MOD";
	case EPOLL_CTL_DEL: return "EPOLL_CTL_DEL";
	default: return NULL;
	}
}
#endif /* __linux__ */

int
iovec_accum_len(const struct iovec *iov, int iovcnt)
{
	int i, accum_len;

	accum_len = 0;
	for (i = 0; i < iovcnt; ++i) {
		accum_len += iov[i].iov_len;
	}
	return accum_len;
}

void
print_backtrace(int depth_off)
{
	char buf[4096];
	char *s;
	struct strbuf sb;

	strbuf_init(&sb, buf, sizeof(buf));
	strbuf_add_backtrace(&sb, depth_off);
	s = strbuf_cstr(&sb);
	printf("%s", s);
}


