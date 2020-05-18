// GPL2 license
#include "internals.h"

struct log_mod {
	int log_stdout;
	int log_level;
	char log_pattern[PATH_MAX];
};

static char log_buf[LOG_BUFSIZ];
static int log_tid;
static int log_pidtid_width;
static struct strbuf log_sb;
static int log_early_stdout = 1;
static int log_early_level_changed;
static int log_early_level = LOG_ERR;
static int log_fd = -1;
static int log_stdout_fd = -1;
static struct log_mod *curmod;

static int
log_is_stdout(int force_stdout, int debug)
{
	if (log_stdout_fd < 0) {
		return 0;
	} else if (force_stdout) {
		return 1;
	} else if (curmod != NULL) {
		return curmod->log_stdout;
	} else {
		return log_early_stdout;
	}
}

static void
log_fclose(struct log *log)
{
	if (log_fd != -1) {
		sys_close(log, log_fd);
		log_fd = -1;
	}
}

// Log filename pattern:
// %p - pid
// %e - process name
static int
log_expand_pattern(struct strbuf *path, const char *pattern)
{
	int fmt;
	const char *ptr;

	ptr = pattern;
	while (*ptr != '\0') {
		if (*ptr == '%') {
			fmt = *(ptr + 1);
			switch (fmt) {
			case 'p':
				strbuf_addf(path, "%d", current->p_pid);
				break;
			case 'e':
				strbuf_add_str(path, current->p_comm);
				break;
			case '%':
				strbuf_add_ch(path, '%');
				break;
			default:
				return -EINVAL;
			}
			ptr += 2;
		} else {
			strbuf_add_ch(path, *ptr);
			ptr += 1;
		}
	}
	return 0;
}

static int
log_fopen(struct log *log, const char *pattern, int add_flags)
{
	int rc;
	char path_buf[PATH_MAX];
	struct strbuf path;

	LOG_TRACE(log);
	if (!strcmp(pattern, "/dev/null")) {
		return 0;
	}
	strbuf_init(&path, path_buf, sizeof(path_buf));
	rc = log_expand_pattern(&path, pattern);
	if (rc) {
		return rc;
	}
	if (path.sb_buf[0] != '/') {
		// relative path
		strbuf_insert(&path, 0, STRSZ(GT_PREFIX"/log/"));
	}
	if (strbuf_space(&path) == 0) {
		return -ENAMETOOLONG;
	}
	rc = sys_open(log, strbuf_cstr(&path),
	              O_RDWR|O_CLOEXEC|O_CREAT|add_flags,
	              S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH);
	if (rc < 0) {
		return rc;
	}
	log_fclose(log);
	log_fd = rc;
	return 0;
}

static int
log_sysctl_out(struct log *log, struct sysctl_conn *cp,
	void *udata, const char *new, struct strbuf *out)
{
	struct log_mod *mod;

	mod = udata;
	strbuf_add(out, STRSZ("/dev/null"));
	if (new != NULL) {
		strzcpy(mod->log_pattern, new, sizeof(mod->log_pattern));
	}
	return 0;
}

void
log_init_early()
{
	if (log_stdout_fd < 0) {
		log_stdout_fd = sys_open(NULL, "/dev/stdout", O_WRONLY, 0);
	}
}

int
log_mod_init(struct log *log, void **pp)
{
	int rc;
	struct log_mod *mod;

	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (rc) {
		return rc;
	}
	mod = *pp;
	mod->log_level = LOG_ERR;
	if (log_early_level_changed) {
		mod->log_level = log_early_level;
	}
	strzcpy(mod->log_pattern, "/dev/null", sizeof(mod->log_pattern));
	sysctl_add_int(log, "log.stdout", SYSCTL_WR,
	               &mod->log_stdout, 0, 1);
	sysctl_add_int(log, "log.level", SYSCTL_WR,
	               &mod->log_level, LOG_EMERG, LOG_DEBUG);
	sysctl_add(log, "log.out", SYSCTL_LD, mod, NULL, log_sysctl_out);
	return 0;
}

int
log_mod_attach(struct log *log, void *raw_mod)
{
	struct log_mod *mod;

	LOG_TRACE(log);
	mod = raw_mod;
	log_fd = -1;
	log_fopen(log, mod->log_pattern, O_TRUNC);
	curmod = mod;
	return 0;
}

void
log_mod_deinit(struct log *log, void *raw_mod)
{
	struct log_mod *mod;

	LOG_TRACE(log);
	mod = raw_mod;
	sysctl_del(log, "log.out");
	sysctl_del(log, "log.level");
	sysctl_del(log, "log.stdout");
	shm_free(mod);
}

void
log_mod_detach(struct log *log)
{
	LOG_TRACE(log);
	if (log_stdout_fd >= 0) {
		sys_close(log, log_stdout_fd);
		log_stdout_fd = -1;
	}
	log_fclose(log);
	curmod = NULL;
}
void
log_scope_init_early(struct log_scope *scope, const char *name)
{
	memset(scope, 0, sizeof(*scope));
	scope->lgs_level = LOG_ERR;
	strzcpy(scope->lgs_name, name, sizeof(scope->lgs_name));
	scope->lgs_name_len = strlen(scope->lgs_name);
	ASSERT(scope->lgs_name_len);
}
void
log_scope_init(struct log_scope *scope, const char *name)
{
	char path[PATH_MAX];
	struct log *log;

	log_scope_init_early(scope, name);
	log = log_trace0();
	snprintf(path, sizeof(path), "log.scope.%s.level", name);
	sysctl_add_int(log, path, SYSCTL_WR,
	               &scope->lgs_level, LOG_EMERG, LOG_DEBUG);
}
void
log_scope_deinit(struct log *log, struct log_scope *scope)
{
	char path[PATH_MAX];
	LOG_TRACE(log);
	snprintf(path, sizeof(path), "log.scope.%s", scope->lgs_name);
	sysctl_del(log, path);
}

void
log_set_level(int level)
{
	if (curmod == NULL) {
		log_early_level = level;
		log_early_level_changed = 1;
	} else {
		curmod->log_level = level;
	}
}

int
log_is_enabled(struct log_scope *scope, int level, int debug)
{
	int thresh, is_stdout;

	is_stdout = log_is_stdout(0, debug);
	if (log_fd == -1 && is_stdout == 0) {
		// Nowhere to write logs
		return 0;
	}
	if (curmod == NULL) {
		// Early stage
		thresh = log_early_level;
	} else {
		thresh = curmod->log_level;
		if (scope != NULL && thresh < scope->lgs_level) {
			thresh = scope->lgs_level;
		}
	}
	return level <= thresh;
}

static void
log_fill_hdr(struct strbuf *sb)
{
	int pid, tid, len, width;
	time_t t;
	struct timeval tv;
	struct tm tm;

	gettimeofday(&tv, NULL);
	t = tv.tv_sec;
	localtime_r(&t, &tm);
	pid = getpid();
	len = sb->sb_len;
	strbuf_addf(sb, "%d", pid);
	if (log_tid) {
		tid = gettid();
		strbuf_addf(sb, ":%d", tid);
	}
	width = sb->sb_len - len;
	if (log_pidtid_width <= width) {
		log_pidtid_width = width;
	} else {
		strbuf_add_ch3(sb, ' ', log_pidtid_width - width);
	}
	strbuf_addf(sb, " %02d/%02d/%04d %02d:%02d:%02d.%06ld ",
	            tm.tm_mday, tm.tm_mon, tm.tm_year + 1900,
	            tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec);
}

static void
log_fill_pfx(struct log *bottom, u_int level, struct strbuf *sb)
{
	struct log *cur, *top;
	static const char *L = "EACEWNID";

	assert(level < 8);
	strbuf_addf(sb, "[%c] [", L[level]);
	if (1) {
		strbuf_add_str(sb, bottom->lg_func);
	} else {
		bottom->lg_lower = NULL;
		for (top = bottom; top->lg_upper != NULL; top = top->lg_upper) {
			top->lg_upper->lg_lower = top;
		}
		for (cur = top; cur != NULL; cur = cur->lg_lower) {
			if (cur != top) {
				strbuf_add(sb, STRSZ("->"));
			}
			strbuf_add_str(sb, cur->lg_func);
		}
	}
	strbuf_add(sb, STRSZ("] "));
}

static void
log_fill_sfx(struct strbuf *sb, int errnum)
{
	if (errnum) {
		strbuf_addf(sb, " (%d:%s)", errnum, strerror(errnum));
	}
	strbuf_add_ch(sb, '\n');
}

static void
log_write(struct strbuf *sb, int force_stdout)
{
	int len;

	len = MIN(sb->sb_len, sb->sb_cap);
	if (log_fd != -1) {
		write_full_buf(NULL, log_fd, sb->sb_buf, len);
	}
	if (log_is_stdout(force_stdout, 0)) {
		write_full_buf(NULL, log_stdout_fd, sb->sb_buf, len);
	}
}

void
log_vprintf(struct log *log, int level, int err, const char *fmt, va_list ap)
{
	char buf[LOG_BUFSIZ];
	struct strbuf sb;

	strbuf_init(&sb, buf, sizeof(buf));
	log_fill_hdr(&sb);
	log_fill_pfx(log, level, &sb);
	strbuf_vaddf(&sb, fmt, ap);
	log_fill_sfx(&sb, err);
	log_write(&sb, 0);
}

void
log_printf(struct log *log, int level, int err, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	log_vprintf(log, level, err, fmt, ap);
	va_end(ap);
}
void
log_backtrace(int depth_off)
{
	char buf[LOG_BUFSIZ];
	struct strbuf sb;
	strbuf_init(&sb, buf, sizeof(buf));
	strbuf_add_backtrace(&sb, depth_off);
	log_write(&sb, 0);
}
void
log_hexdump_ascii(uint8_t *data, int count)
{
	int i, j, k, x, ch;
	char buf[LOG_BUFSIZ];
	struct strbuf sb;
	strbuf_init(&sb, buf, sizeof(buf));
	for (i = 0; i < count;) {
		x = i;
		for (j = 0; j < 8; ++j) {
			for (k = 0; k < 2; ++k) {
				if (i < count) {
					strbuf_addf(&sb, "%02hhx", data[i]);
					i++;
				} else {
					strbuf_add(&sb, STRSZ("  "));
				}
			}
			strbuf_add(&sb, STRSZ(" "));
		}
		strbuf_add(&sb, STRSZ(" "));
		for (j = x; j < i; ++j) {
			ch = data[j];
			strbuf_add_ch(&sb, isprint(ch) ? ch : '.');
		}
		strbuf_add(&sb, STRSZ("\n"));
	}
}

void
log_abort(struct log *log, const char *filename, int line, int errnum,
	const char *expr, const char *fmt, ...)
{
	char buf[LOG_BUFSIZ];
	va_list ap;
	struct strbuf sb;

	log_buf_init();
	strbuf_init(&sb, buf, sizeof(buf));
	log_fill_hdr(&sb);
	if (expr != NULL) {
		strbuf_addf(&sb, "assertion '%s' failed ", expr);
	} else {
		strbuf_add(&sb, STRSZ("bug "));
	}
	strbuf_addf(&sb, "at %s:%u", filename, line);
	if (fmt != NULL && fmt[0] != '\0') {
		strbuf_add(&sb, STRSZ(": "));
		va_start(ap, fmt);
		strbuf_vaddf(&sb, fmt, ap);
		va_end(ap);
	}
	log_fill_sfx(&sb, errnum);
	log_write(&sb, 1);
	abort();
}

void
log_buf_init()
{
	strbuf_init(&log_sb, log_buf, sizeof(log_buf));
}
struct strbuf *
log_buf_alloc_space()
{
	int len, cap;
	len = log_sb.sb_len;
	cap = log_sb.sb_cap;
	log_sb.sb_buf = log_sb.sb_buf + len + 1;
	log_sb.sb_len = 0;
	cap = cap - (len + 1);
	if (cap > 0) {
		log_sb.sb_cap = cap;
	} else {
		log_sb.sb_cap = 0;
	}
	return &log_sb;
}
const char *
log_add_ipaddr(int af, const void *ip)
{
	const char *ret;
	struct strbuf *sb; 
	sb = log_buf_alloc_space();
	strbuf_add_ipaddr(sb, af, ip);
	ret = strbuf_cstr(sb);
	return ret;
}

const char *
log_add_sockaddr_in(const struct sockaddr_in *a)
{
	const char *ret;
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_ipaddr(sb, AF_INET, &a->sin_addr.s_addr);
	strbuf_addf(sb, ":%hu", ntoh16(a->sin_port));
	ret = strbuf_cstr(sb);
	return ret;
}

const char *
log_add_sockaddr_un(const struct sockaddr_un *a, int sa_len)
{
	const char *ret;
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	if (sa_len > sizeof(sa_family_t)) {
		strbuf_add(sb, a->sun_path, sa_len - sizeof(sa_family_t));
	}
	ret = strbuf_cstr(sb);
	return ret;
}

const char *
log_add_sockaddr(const struct sockaddr *a, int sa_len)
{
	const char *ret;
	struct strbuf *sb;

	switch (a->sa_family) {
	case AF_INET:
		if (sa_len < sizeof(struct sockaddr_in)) {
			break;
		}
		ret = log_add_sockaddr_in((const struct sockaddr_in *)a);
		return ret;
	case AF_UNIX:
		ret = log_add_sockaddr_un((const struct sockaddr_un *)a, sa_len);
		return ret;
	default:
		break;
	}
	sb = log_buf_alloc_space();
	strbuf_addf(sb, "(sa_family=%d, sa_len=%d)", a->sa_family, sa_len);
	ret = strbuf_cstr(sb);
	return ret;
}

const char *
log_add_socket_domain(int domain)
{
	const char *ret;
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_socket_domain(sb, domain);
	ret = strbuf_cstr(sb);
	return ret;
}

const char *
log_add_socket_type(int type)
{
	const char *ret;
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_socket_type(sb, type);
	ret = strbuf_cstr(sb);
	return ret;
}

const char *
log_add_socket_flags(int flags)
{
	const char *ret;
	struct strbuf *sb;
	sb = log_buf_alloc_space();
	strbuf_add_socket_flags(sb, flags);
	ret = strbuf_cstr(sb);
	return ret;
}
const char *
log_add_shutdown_how(int how)
{
	const char *ret;
	struct strbuf *sb;
	sb = log_buf_alloc_space();
	strbuf_add_shutdown_how(sb, how);
	ret = strbuf_cstr(sb);
	return ret;
}
const char *
log_add_fcntl_cmd(int cmd)
{
	const char *ret;
	struct strbuf *sb;
	sb = log_buf_alloc_space();
	strbuf_add_fcntl_cmd(sb, cmd);
	ret = strbuf_cstr(sb);
	return ret;
}
const char *
log_add_ioctl_req(unsigned long req)
{
	const char *ret;
	struct strbuf *sb;
	sb = log_buf_alloc_space();
	strbuf_add_ioctl_req(sb, req);
	ret = strbuf_cstr(sb);
	return ret;
}
const char *
log_add_sockopt_level(int level)
{
	const char *ret;
	struct strbuf *sb;
	sb = log_buf_alloc_space();
	strbuf_add_sockopt_level(sb, level);
	ret = strbuf_cstr(sb);
	return ret;
}
const char *
log_add_sockopt_optname(int level, int optname)
{
	const char *ret;
	struct strbuf *sb;
	sb = log_buf_alloc_space();
	strbuf_add_sockopt_optname(sb, level, optname);
	ret = strbuf_cstr(sb);
	return ret;
}
const char *
log_add_poll_events(short events)
{
	const char *ret;
	struct strbuf *sb;
	sb = log_buf_alloc_space();
	strbuf_add_poll_events(sb, events);
	ret = strbuf_cstr(sb);
	return ret;
}
const char *
log_add_pollfds_events(struct pollfd *pfds, int npfds)
{
	const char *ret;
	struct strbuf *sb;
	sb = log_buf_alloc_space();
	strbuf_add_pollfds_events(sb, pfds, npfds);
	ret = strbuf_cstr(sb);
	return ret;
}
const char *
log_add_pollfds_revents(struct pollfd *pfds, int npfds)
{
	const char *ret;
	struct strbuf *sb;
	sb = log_buf_alloc_space();
	strbuf_add_pollfds_revents(sb, pfds, npfds);
	ret = strbuf_cstr(sb);
	return ret;
}
const char *
log_add_sighandler(void *handler)
{
	const char *ret;
	struct strbuf *sb;
	sb = log_buf_alloc_space();
	strbuf_add_sighandler(sb, handler);
	ret = strbuf_cstr(sb);
	return ret;
}
const char *
log_add_sigprocmask_how(int how)
{
	const char *ret;
	struct strbuf *sb;
	sb = log_buf_alloc_space();
	strbuf_add_sigprocmask_how(sb, how);
	ret = strbuf_cstr(sb);
	return ret;
}
#ifdef __linux__
const char *
log_add_clone_flags(int flags)
{
	const char *ret;
	struct strbuf *sb;
	sb = log_buf_alloc_space();
	strbuf_add_clone_flags(sb, flags);
	ret = strbuf_cstr(sb);
	return ret;
}
const char *
log_add_epoll_op(int op)
{
	const char *ret;
	struct strbuf *sb;
	sb = log_buf_alloc_space();
	strbuf_add_epoll_op(sb, op);
	ret = strbuf_cstr(sb);
	return ret;
}
const char *
log_add_epoll_event_events(short events)
{
	const char *ret;
	struct strbuf *sb;
	sb = log_buf_alloc_space();
	strbuf_add_epoll_event_events(sb, events);
	ret = strbuf_cstr(sb);
	return ret;
}
#endif /* __linux__ */
