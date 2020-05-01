#include "internals.h"

#define SUBR_LOG_MSG_FOREACH(x) \
	x(rsskey) \
	x(connect)
	

struct subr_mod {
	struct log_scope log_scope;
	SUBR_LOG_MSG_FOREACH(LOG_MSG_DECLARE);
};

union gt_tsc {
	uint64_t tsc_64;
	struct {
		uint32_t lo_32;
		uint32_t hi_32;
	};
};

uint64_t nanoseconds;
uint64_t HZ = 3000000000;
uint64_t mHZ = 3000000;
__thread int gbtcp_errno;


static struct subr_mod *current_mod;

#define MURMUR_MMIX(h,k) \
do { \
	k *= m; \
	k ^= k >> r; \
	k *= m; \
	h *= m; \
	h ^= k; \
} while (0)

static uint32_t
gt_murmur(const void * key, unsigned int len, uint32_t init_val)
{
	int r;
	unsigned int k, l, m, h, t;
	uint8_t *data;

	r = 24;
	m = 0x5bd1e995;
	l = len;
	h = init_val;
	t = 0;
	data = (uint8_t *)key;
	while (len >= 4) {
		k = *(u_int *)data;
		MURMUR_MMIX(h, k);
		data += 4;
		len -= 4;
	}
	switch(len) {
	case 3:
		t ^= data[2] << 16;
	case 2:
		t ^= data[1] << 8;
	case 1:
		t ^= data[0];
	}
	MURMUR_MMIX(h, t);
	MURMUR_MMIX(h, l);
	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;
	return h;
}


#ifdef __linux__
int
proc_get_name(struct log *log, char *name, int pid)
{
	int rc;
	FILE *file;
	char *s;
	char fmt[32];
	char path[32];
	char buf[256];

	LOG_TRACE(log);
	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	rc = sys_fopen(log, &file, path, "r");
	if (rc) {
		return rc;
	}
	s = fgets(buf, sizeof(buf), file);
	fclose(file);
	if (s == NULL) {
		goto err;
	}
	snprintf(fmt, sizeof(fmt), "Name: %%%dc", PROC_NAME_SIZE_MAX - 1);
	rc = sscanf(buf, fmt, name);
	if (rc == 1) {
		strtrim2(name, name);
		return 0;
	}
err:
	LOGF(log, 7, LOG_ERR, 0, "inavlid format; path=%s", path);
	return -EPROTO;
}
#else /* __linux__ */
static int
proc_get_name()
{
	int rc;
	struct kinfo_proc *info;

	info = kinfo_getproc(gt_application_pid);
	if (info == NULL) {
		rc = -errno;
		GT_ASSERT(rc);
		return rc;
	}
	strzcpy(gt_application_name_buf, info->ki_comm,
	        sizeof(gt_application_name_buf));
	free(info);
	gt_application_name = gt_application_name_buf;
	return 0;
}
#endif /* __linux__ */

//service {
//	svc_app_name
//};

int
subr_mod_init(struct log *log, void **pp)
{
	int rc;
	struct subr_mod *mod;
	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (!rc) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "subr");
	}
	return rc;
}

int
subr_mod_attach(struct log *log, void *raw_mod)
{
	current_mod = raw_mod;
	return 0;
}

void
subr_mod_deinit(struct log *log, void *raw_mod)
{
	struct subr_mod *mod;
	LOG_TRACE(log);
	mod = raw_mod;
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}

void
subr_mod_detach(struct log *log)
{
	current_mod = NULL;
}

int
ethaddr_aton(struct ethaddr *a, const char *s)
{
	int rc;
	struct ethaddr x;

	rc = sscanf(s, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
	            x.etha_bytes + 0, x.etha_bytes + 1, x.etha_bytes + 2,
	            x.etha_bytes + 3, x.etha_bytes + 4, x.etha_bytes + 5);
	if (rc == 6) {
		*a = x;
		return 0;
	} else {
		return -EINVAL;
	}
}

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
int
ethaddr_is_mcast(const uint8_t *addr)
{
	return 0x01 & (addr >> ((sizeof(addr) * 8) - 8));
}
#else /* __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ */
int
ethaddr_is_mcast(const uint8_t *addr)
{
	return 0x01 & addr[0];
}
#endif /* __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ */

int
ethaddr_is_ucast(const uint8_t *addr)
{
	return !ethaddr_is_mcast(addr);
}

void
ethaddr_make_ip6_mcast(struct ethaddr *addr, const uint8_t *ip6) 
{   
	addr->etha_bytes[0] = 0x33;
	addr->etha_bytes[1] = 0x33;
	addr->etha_bytes[2] = ip6[12];
	addr->etha_bytes[3] = ip6[13];
	addr->etha_bytes[4] = ip6[14];
	addr->etha_bytes[5] = ip6[15];
}

void
spinlock_init(struct spinlock *sl)
{
	sl->spinlock_locked = 0;
}

void
spinlock_lock(struct spinlock *sl)
{
	while (__sync_lock_test_and_set(&sl->spinlock_locked, 1)) {
		while (sl->spinlock_locked) {
			_mm_pause();
		}
	}
}

// Return 1 if locked
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

void
gt_profiler_enter(struct gt_profiler *p)
{
	assert(p->prf_tsc == 0);
	p->prf_tsc = rdtsc();
}

void
gt_profiler_leave(struct gt_profiler *p)
{
	uint64_t t, dt, elapsed;
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

char *
strtrim2(char *dst, const char *src)
{
	int i, len;
	const char *x;

	x = strltrim(src);
	len = 0;
	for (i = 0; x[i] != '\0'; ++i) {
		dst[i] = x[i];
		if (!isspace(x[i])) {
			len = i + 1;
		}
	}
	dst[len] = '\0';
	return dst;
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
gt_custom_hash32(uint32_t data, uint32_t initval)
{
	return gt_murmur(&data, sizeof(data), initval);
}

uint32_t
gt_custom_hash(const void *data, size_t cnt, uint32_t initval)
{
	return gt_murmur(data, cnt, initval);
}

uint32_t
toeplitz_hash(const uint8_t *data, int cnt, const uint8_t *key)
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
			if ((i + 4) < RSSKEYSIZ &&
			    (key[i + 4] & (1 << (7 - b)))) {
				v |= 1;
			}
		}
	}
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

int
fcntl_setfl_nonblock(struct log *log, int fd, int *old_flags)
{
	int rc, flags;

	rc = sys_fcntl(log, fd, F_GETFL, 0);
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
	rc = sys_fcntl(log, fd, F_SETFL, flags);
	return rc;
}

static int
fcntl_setfl_nonblock_rollback(struct log *log, int fd, int old_flags)
{
	int rc;

	rc = 0;
	if (!(old_flags & O_NONBLOCK)) {
		rc = sys_fcntl(log, fd, F_SETFL, old_flags & ~O_NONBLOCK);
	}
	return rc;
}

static struct timespec *
nanoseconds_to_timespec(struct timespec *ts, uint64_t t)
{
	if (t < NANOSECONDS_SECOND) {
		ts->tv_sec = 0;
		ts->tv_nsec = t;
	} else {
		ts->tv_sec = t / NANOSECONDS_SECOND;
		ts->tv_nsec = t % NANOSECONDS_SECOND;
	}
	return ts;
}

int
connect_timed(struct log *log, int fd, const struct sockaddr *addr,
	socklen_t addrlen, uint64_t *to)
{
	int rc, errnum, flags;
	uint64_t t, elapsed;
	socklen_t opt_len;
	struct timespec ts;
	struct pollfd pfd;

	if (to == NULL) {
		rc = sys_connect(log, fd, addr, addrlen);
		return rc;
	}
	LOG_TRACE(log);
	rc = fcntl_setfl_nonblock(log, fd, &flags);
	if (rc) {
		return rc;
	}
	do {
		rc = sys_connect(NULL, fd, addr, addrlen);
		errnum = -rc;
	} while (addr->sa_family == AF_UNIX && errnum == EAGAIN);
	fcntl_setfl_nonblock_rollback(log, fd, flags);
	if (errnum == 0) {
		return 0;
	} else if (errnum != EINPROGRESS) {
		goto out;
	} else if (*to == 0) {
		errnum = ETIMEDOUT;
		goto out;
	}
	pfd.events = POLLOUT;
	pfd.fd = fd;
restart:
	t = nanoseconds;
	nanoseconds_to_timespec(&ts, *to);
	rc = sys_ppoll(log, &pfd, 1, &ts, NULL);
	rdtsc_update_time();
	elapsed = MIN(*to, nanoseconds - t);
	*to -= elapsed;
	switch (rc) {
	case 0:
		*to = 0;
		errnum = ETIMEDOUT;
		break;
	case 1:
		opt_len = sizeof(errnum);
		rc = sys_getsockopt(log, fd, SOL_SOCKET, SO_ERROR,
		                    &errnum, &opt_len);
		if (rc) {
			return rc;
		}
		break;
	case -EINTR:
		if (*to) {
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
		LOGF(log, LOG_MSG(connect), LOG_ERR, errnum,
		     "failed; fd=%d, addr=%s",
		     fd, log_add_sockaddr(addr, addrlen));
	}
	return -errnum;
}

ssize_t
read_timed(struct log *log, int fd, void *buf, size_t count, uint64_t *to)
{
	int flags;
	ssize_t rc;
	uint64_t t, elapsed;
	struct timespec ts;
	struct pollfd pfd;

	if (to == NULL) {
		rc = sys_read(log, fd, buf, count);
		return rc;
	}
	LOG_TRACE(log);
	rc = fcntl_setfl_nonblock(log, fd, &flags);
	if (rc) {
		return rc;
	}
	pfd.events = POLLIN;
	pfd.fd = fd;
restart:
	t = nanoseconds;
	nanoseconds_to_timespec(&ts, *to);
	rc = sys_ppoll(log, &pfd, 1, &ts, NULL);
	rdtsc_update_time();
	elapsed = MIN(*to, t - nanoseconds);
	*to -= elapsed;
	switch (rc) {
	case 0:
		*to = 0;
		rc = -ETIMEDOUT;
		break;
	case 1:
		rc = sys_read(log, fd, buf, count);
		if (rc == -EAGAIN) {
			goto restart;
		}
		break;
	case -EINTR:
		goto restart;
	default:
		break;
	}
	fcntl_setfl_nonblock_rollback(log, fd, flags);
	return rc;
}

ssize_t
write_all(struct log *log, int fd, const void *buf, size_t cnt)
{
	ssize_t rc, off;

	for (off = 0; off < cnt; off += rc) {
		rc = sys_write(log, fd,
		               (const uint8_t *)buf + off,
		               cnt - off);
		if (rc < 0) {
			return rc;
		}
	}
	return 0;
}

#ifdef __linux__
int
read_rsskey(struct log *log, const char *ifname, uint8_t *rsskey)
{
	int fd, rc, size, off;
	struct ifreq ifr;
	struct ethtool_rxfh rss, *rss2;

	LOG_TRACE(log);
	rc = sys_socket(log, AF_INET, SOCK_DGRAM, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	strzcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	rss.cmd = ETHTOOL_GRSSH;
	ifr.ifr_data = (void *)&rss;
	rc = sys_ioctl(log, fd, SIOCETHTOOL, (uintptr_t)&ifr);
	if (rc < 0) {
		goto out;
	}
	if (rss.key_size != RSSKEYSIZ) {
		LOGF(log, LOG_MSG(rsskey), LOG_ERR, 0,
		     "invalid rss key_size; key_size=%d", rss.key_size);
		goto out;
	}
	size = (sizeof(rss) + rss.key_size +
	       rss.indir_size * sizeof(rss.rss_config[0]));
	rc = sys_malloc(log, (void **)&rss2, size);
	if (rc) {
		goto out;
	}
	memset(rss2, 0, size);
	rss2->cmd = ETHTOOL_GRSSH;
	rss2->indir_size = rss.indir_size;
	rss2->key_size = rss.key_size;
	ifr.ifr_data = (void *)rss2;
	rc = sys_ioctl(log, fd, SIOCETHTOOL, (uintptr_t)&ifr);
	if (rc) {
		goto out2;
	}
	off = rss2->indir_size * sizeof(rss2->rss_config[0]);
	memcpy(rsskey, (uint8_t *)rss2->rss_config + off, RSSKEYSIZ);
out2:
	free(rss2);
out:
	sys_close(log, fd);
	return rc;
}
#else /* __linux__ */
int
read_rsskey(struct log *log, const char *ifname, u_char *rsskey)
{
	return 0;
}
#endif /* __linux__ */

#ifdef __linux__
long
gettid()
{
	long tid;

	tid = syscall(SYS_gettid);
	return tid;
}
#else /* __linux__ */
long
gettid()
{
	long tid;

	thr_self(&tid);
	return tid;
}
#endif /* __linux__ */

uint64_t
rdtsc()
{
	union gt_tsc tsc;

	asm volatile("rdtsc" :
		"=a" (tsc.lo_32),
		"=d" (tsc.hi_32));
	return tsc.tsc_64;;
}

uint64_t
gt_rand64()
{
	uint64_t x, y;

	x = lrand48();
	x <<= 32;
	y = lrand48();
	return x | y;
}

uint32_t
gt_rand32()
{
	return lrand48();
}

const char *
gt_tcp_state_str(int tcp_state)
{
	switch (tcp_state) {
	case GT_TCP_S_CLOSED: return "CLOSED";
	case GT_TCP_S_LISTEN: return "LISTEN";
	case GT_TCP_S_SYN_SENT: return "SYN_SENT";
	case GT_TCP_S_SYN_RCVD: return "SYN_RCVD";
	case GT_TCP_S_ESTABLISHED: return "ESTABLISHED";
	case GT_TCP_S_CLOSE_WAIT: return "CLOSE_WAIT";
	case GT_TCP_S_LAST_ACK: return "LAST_ACK";
	case GT_TCP_S_FIN_WAIT_1: return "FIN_WAIT_1";
	case GT_TCP_S_FIN_WAIT_2: return "FIN_WAIT_2";
	case GT_TCP_S_CLOSING: return "CLOSING";
	case GT_TCP_S_TIME_WAIT: return "TIME_WAIT";
	default: return NULL;
	}
}

const char *
gt_socket_domain_str(int domain)
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
gt_socket_type_str_os(int type)
{
	switch (type) {
	case SOCK_PACKET: return "SOCK_PACKET";
	default: return NULL;
	}
}
#else /* __linux__ */
static const char *
gt_socket_type_str_os(int type)
{
	return NULL;
}
#endif /* __linux__ */

const char *
gt_socket_type_str(int type)
{
	const char *s;

	switch (type) {
	case SOCK_STREAM: return "SOCK_STREAM";
	case SOCK_DGRAM: return "SOCK_DGRAM";
	case SOCK_SEQPACKET: return "SOCK_SEQPACKET";
	case SOCK_RAW: return "SOCK_RAW";
	case SOCK_RDM: return "SOCK_DRM";
	default:
		s = gt_socket_type_str_os(type);
		return s;
	}
}

const char *
gt_sockopt_level_str(int level)
{
	switch (level) {
	case IPPROTO_TCP: return "IPPROTO_TCP";
	case SOL_SOCKET: return "SOL_SOCKET";
	default: return NULL;
	}
}

const char *
gt_sockopt_optname_str(int level, int optname)
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
gt_fcntl_cmd_str(int cmd)
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
gt_ioctl_req_str(unsigned long req)
{
	switch (req) {
	case FIONBIO: return "FIONBIO";
	default: return NULL;
	}
}

const char *
gt_shutdown_how_str(int how)
{
	switch (how) {
	case SHUT_RD: return "SHUT_RD";
	case SHUT_WR: return "SHUT_WR";
	case SHUT_RDWR: return "SHUT_RDWR";
	default: return NULL;
	}
}

const char *
gt_sighandler_str(void *fn)
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
gt_sigprocmask_how_str(int how)
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
gt_epoll_op_str(int op)
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
iovec_len(const struct iovec *iov, int iovcnt)
{
	int i, len;

	len = 0;
	for (i = 0; i < iovcnt; ++i) {
		len += iov[i].iov_len;
	}
	return len;
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



