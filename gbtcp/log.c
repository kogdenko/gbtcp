/* GPL2 license */
#include "log.h"
#include "sys.h"
#include "ctl.h"
#include "strbuf.h"

int log_stdout;
int log_debug;

static char log_buf[LOG_BUFSIZ];
static char log_pattern[PATH_MAX];
static int log_tid;
static int log_pid_tid_width;
static int log_level;
static int log_fd = -1;
static int log_stdout_fd = -1;
static struct gt_strbuf log_sb;

#define ldbg(...) \
	if (log_debug) { \
		dbg(__VA_ARGS__); \
	}

static void
log_fclose(struct gt_log *log)
{
	if (log_fd != -1) {
		gt_sys_close(log, log_fd);
		log_fd = -1;
	}
}

/*
 * Log filename pattern:
 * %p - application pid
 * %e - application process name
 */
static int
log_expand_pattern(struct gt_strbuf *path, const char *pattern)
{
	int fmt;
	const char *ptr;

	ptr = pattern;
	while (*ptr != '\0') {
		if (*ptr == '%') {
			fmt = *(ptr + 1);
			switch (fmt) {
			case 'p':
				gt_strbuf_addf(path, "%d", gt_application_pid);
				break;
			case 'e':
				gt_strbuf_add_str(path, gt_application_name);
				break;
			case '%':
				gt_strbuf_add_ch(path, '%');
				break;
			default:
				return -EINVAL;
			}
			ptr += 2;
		} else {
			gt_strbuf_add_ch(path, *ptr);
			ptr += 1;
		}
	}
	return 0;
}

static int
log_fopen(struct gt_log *log, const char *pattern, int add_flags)
{
	int rc;
	char path_buf[PATH_MAX];
	struct gt_strbuf path;

	LOG_TRACE(log);
	gt_strbuf_init(&path, path_buf, sizeof(path_buf));
	rc = log_expand_pattern(&path, pattern);
	if (rc) {
		return rc;
	}
	if (path.sb_buf[0] != '/') {
		// relative path
		gt_strbuf_insert(&path, 0, GT_STRSZ(GT_PREFIX"/log/"));
	}
	if (gt_strbuf_space(&path) == 0) {
		return -ENAMETOOLONG;
	}
	rc = gt_sys_open(log, gt_strbuf_cstr(&path),
	                 O_RDWR|O_CLOEXEC|O_CREAT|add_flags,
	                 S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH);
	if (rc < 0) {
		return rc;
	}
	log_fclose(log);
	gt_strzcpy(log_pattern, pattern, sizeof(log_pattern));
	log_fd = rc;
	return 0;
}

static int
log_sysctl_out(struct gt_log *log, void *udata, const char *new,
	struct gt_strbuf *out)
{
	int rc;

	if (log_fd == -1) {
		gt_strbuf_add(out, GT_STRSZ("/dev/null"));
	} else {
		gt_strbuf_add_str(out, log_pattern);
	}
	if (new == NULL) {
		return 0;
	}
	if (!strcmp(new, "/dev/null")) {
		log_fclose(log);
		return 0;
	}
	rc = log_fopen(log, new, O_TRUNC);
	return rc;
}

int
gt_log_mod_init()
{
	int rc;
	struct gt_log *log;

	rc = gt_sys_dup(NULL, STDOUT_FILENO);
	if (rc < 0) {
		log_stdout_fd = -1;
	} else {
		log_stdout_fd = rc;
	}
	log_level = LOG_ERR;
	log_fd = -1;
	log = log_trace0();
	gt_ctl_add_int(log, "log.stdout", GT_CTL_WR,
	               &log_stdout, 0, 1);
	gt_ctl_add_int(log, "log.level", GT_CTL_WR,
	               &log_level, LOG_EMERG, LOG_DEBUG);
	gt_ctl_add(log, "log.out", GT_CTL_WR, NULL, NULL, log_sysctl_out);
	return 0;
}

void
gt_log_mod_deinit(struct gt_log *log)
{
	LOG_TRACE(log);
	gt_ctl_del(log, "log.out");
	gt_ctl_del(log, "log.level");
	gt_ctl_del(log, "log.stdout");
	if (log_stdout_fd != -1) {
		gt_sys_close(log, log_stdout_fd);
		log_stdout_fd = -1;
	}
	if (log_fd != -1) {
		gt_sys_close(log, log_fd);
		log_fd = -1;
	}
}

void
log_scope_init_early(struct log_scope *scope, const char *name)
{
	memset(scope, 0, sizeof(*scope));
	scope->lgs_name = name;
	scope->lgs_namelen = strlen(name);
	ASSERT(scope->lgs_namelen);
}

void
log_scope_init(struct log_scope *scope, const char *name)
{
	char path[PATH_MAX];
	struct gt_log *log;

	log_scope_init_early(scope, name);
	log = log_trace0();
	snprintf(path, sizeof(path), "log.scope.%s.level", name);
	gt_ctl_add_int(log, path, GT_CTL_WR,
	               &scope->lgs_level, LOG_EMERG, LOG_DEBUG);
}

void
log_scope_deinit(struct gt_log *log, struct log_scope *scope)
{
	char path[PATH_MAX];

	LOG_TRACE(log);
	snprintf(path, sizeof(path), "log.scope.%s", scope->lgs_name);
	gt_ctl_del(log, path);
}

struct gt_log *
log_copy(struct gt_log *dst, int cnt, struct gt_log *src)
{
	int i, depth;
	struct gt_log *cur;

	ASSERT(cnt > 0);
	depth = 0;
	for (cur = src; cur != NULL; cur = cur->lg_upper) {
		dst[depth].lg_func = cur->lg_func;
		depth++;
		if (depth == cnt) {
			break;
		}
	}
	if (depth == 0) {
		return NULL;
	}
	for (i = 0; i < depth - 1; ++i) {
		dst[i].lg_upper = dst + i + 1;
	}
	dst[depth - 1].lg_upper = NULL;
	return dst;
}

int
log_is_enabled(struct log_scope *scope, int msg_level, int level)
{
	int thresh;

	if (log_fd == -1 && log_stdout == 0) {
		/* Nowhere to write logs */
		return 0;
	}
	if (msg_level) {
		thresh = msg_level;
	} else if (scope->lgs_level) {
		thresh = scope->lgs_level;
	} else {
		thresh = log_level;
	}
	return level <= thresh;
}

static void
log_fill_hdr(struct gt_strbuf *sb)
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
	gt_strbuf_addf(sb, "%d", pid);
	if (log_tid) {
		tid = gt_gettid();
		gt_strbuf_addf(sb, ":%d", tid);
	}
	width = sb->sb_len - len;
	if (log_pid_tid_width <= width) {
		log_pid_tid_width = width;
	} else {
		gt_strbuf_add_ch3(sb, ' ', log_pid_tid_width - width);
	}
	gt_strbuf_addf(sb, " %02d/%02d/%04d %02d:%02d:%02d.%06ld ",
	               tm.tm_mday,
	               tm.tm_mon,
	               tm.tm_year + 1900,
	               tm.tm_hour,
	               tm.tm_min,
	               tm.tm_sec,
	               tv.tv_usec);
}

static void
log_fill_pfx(struct gt_log *bottom, int level, struct gt_strbuf *sb)
{
	char x;
	struct gt_log *cur, *top;

	switch (level) {
	case LOG_ERR:
		x = 'E';
		break;
	case LOG_INFO:
		x = 'I';
		break;
	case LOG_DEBUG:
		x = 'D';
		break;
	default:
		x = '?';
		break;
	}
	gt_strbuf_addf(sb, "[%c] ", x);
	bottom->lg_lower = NULL;
	for (top = bottom; top->lg_upper != NULL; top = top->lg_upper) {
		top->lg_upper->lg_lower = top;
	}
	gt_strbuf_add_ch(sb, '[');
	for (cur = top; cur != NULL; cur = cur->lg_lower) {
		gt_strbuf_add_str(sb, cur->lg_func);
		gt_strbuf_add(sb, GT_STRSZ("."));
	}
	gt_strbuf_add(sb, GT_STRSZ("] "));
}

static void
log_fill_sfx(struct gt_strbuf *sb, int eno)
{
	if (eno) {
		gt_strbuf_addf(sb, " (%d:%s)", eno, strerror(eno));
	}
	gt_strbuf_add_ch(sb, '\n');
}

static void
log_write(struct gt_strbuf *sb, int force)
{
	int len;

	len = MIN(sb->sb_len, sb->sb_cap);
	if (log_fd != -1) {
		gt_write_all(NULL, log_fd, sb->sb_buf, len);
	}
	if ((log_stdout || force) && log_stdout_fd != -1) {
		gt_write_all(NULL, log_stdout_fd, sb->sb_buf, len);
	}
}

void
log_vprintf(struct gt_log *log, int level, int err,
	const char *fmt, va_list ap)
{
	char buf[LOG_BUFSIZ];
	struct gt_strbuf sb;

	gt_strbuf_init(&sb, buf, sizeof(buf));
	log_fill_hdr(&sb);
	log_fill_pfx(log, level, &sb);
	gt_strbuf_vaddf(&sb, fmt, ap);
	log_fill_sfx(&sb, err);
	log_write(&sb, 0);
}

void
log_printf(struct gt_log *log, int level, int err, const char *fmt, ...)
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
	struct gt_strbuf sb;

	gt_strbuf_init(&sb, buf, sizeof(buf));
	gt_strbuf_add_backtrace(&sb, depth_off);
	log_write(&sb, 0);
}

void
log_hexdump_ascii(uint8_t *data, int count)
{
	int i, j, k, x, ch;
	char buf[LOG_BUFSIZ];
	struct gt_strbuf sb;

	gt_strbuf_init(&sb, buf, sizeof(buf));
	for (i = 0; i < count;) {
		x = i;
		for (j = 0; j < 8; ++j) {
			for (k = 0; k < 2; ++k) {
				if (i < count) {
					gt_strbuf_addf(&sb, "%02hhx", data[i]);
					i++;
				} else {
					gt_strbuf_add(&sb, GT_STRSZ("  "));
				}
			}
			gt_strbuf_add(&sb, GT_STRSZ(" "));
		}
		gt_strbuf_add(&sb, GT_STRSZ(" "));
		for (j = x; j < i; ++j) {
			ch = data[j];
			gt_strbuf_add_ch(&sb, isprint(ch) ? ch : '.');
		}
		gt_strbuf_add(&sb, GT_STRSZ("\n"));
	}
}

#ifndef NDEBUG
void
log_abort(const char *filename, int line, int eno, const char *expr,
	const char *fmt, ...)
{
	char buf[LOG_BUFSIZ];
	va_list ap;
	struct gt_strbuf sb;

	log_buf_init();
	gt_strbuf_init(&sb, buf, sizeof(buf));
	log_fill_hdr(&sb);
	if (expr != NULL) {
		gt_strbuf_addf(&sb, "assertion '%s' failed ", expr);
	} else {
		gt_strbuf_add(&sb, GT_STRSZ("bug "));
	}
	gt_strbuf_addf(&sb, "at %s:%u", filename, line);
	if (fmt != NULL && fmt[0] != '\0') {
		gt_strbuf_add(&sb, GT_STRSZ(": "));
		va_start(ap, fmt);
		gt_strbuf_vaddf(&sb, fmt, ap);
		va_end(ap);
	}
	log_fill_sfx(&sb, eno);
	log_write(&sb, 1);
	log_backtrace(1);
	abort();
}
#endif /* NDEBUG */

void
log_buf_init()
{
	gt_strbuf_init(&log_sb, log_buf, sizeof(log_buf));
}

struct gt_strbuf *
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
	struct gt_strbuf *sb; 

	sb = log_buf_alloc_space();
	gt_strbuf_add_ip_addr(sb, af, ip);
	ret = gt_strbuf_cstr(sb);
	return ret;
}

const char *
log_add_sockaddr_in(const struct sockaddr_in *a)
{
	const char *ret;
	struct gt_strbuf *sb;

	sb = log_buf_alloc_space();
	gt_strbuf_add_ip_addr(sb, AF_INET, &a->sin_addr.s_addr);
	gt_strbuf_addf(sb, ":%hu", GT_NTOH16(a->sin_port));
	ret = gt_strbuf_cstr(sb);
	return ret;
}

const char *
log_add_socket_domain(int domain)
{
	const char *ret;
	struct gt_strbuf *sb;

	sb = log_buf_alloc_space();
	gt_strbuf_add_socket_domain(sb, domain);
	ret = gt_strbuf_cstr(sb);
	return ret;
}

const char *
log_add_socket_type(int type)
{
	const char *ret;
	struct gt_strbuf *sb;

	sb = log_buf_alloc_space();
	gt_strbuf_add_socket_type(sb, type);
	ret = gt_strbuf_cstr(sb);
	return ret;
}

const char *
log_add_socket_flags(int flags)
{
	const char *ret;
	struct gt_strbuf *sb;

	sb = log_buf_alloc_space();
	gt_strbuf_add_socket_flags(sb, flags);
	ret = gt_strbuf_cstr(sb);
	return ret;
}

const char *
log_add_shutdown_how(int how)
{
	const char *ret;
	struct gt_strbuf *sb;

	sb = log_buf_alloc_space();
	gt_strbuf_add_shutdown_how(sb, how);
	ret = gt_strbuf_cstr(sb);
	return ret;
}

const char *
log_add_fcntl_cmd(int cmd)
{
	const char *ret;
	struct gt_strbuf *sb;

	sb = log_buf_alloc_space();
	gt_strbuf_add_fcntl_cmd(sb, cmd);
	ret = gt_strbuf_cstr(sb);
	return ret;
}

const char *
log_add_ioctl_req(unsigned long req)
{
	const char *ret;
	struct gt_strbuf *sb;

	sb = log_buf_alloc_space();
	gt_strbuf_add_ioctl_req(sb, req);
	ret = gt_strbuf_cstr(sb);
	return ret;
}

const char *
log_add_sockopt_level(int level)
{
	const char *ret;
	struct gt_strbuf *sb;

	sb = log_buf_alloc_space();
	gt_strbuf_add_sockopt_level(sb, level);
	ret = gt_strbuf_cstr(sb);
	return ret;
}

const char *
log_add_sockopt_optname(int level, int optname)
{
	const char *ret;
	struct gt_strbuf *sb;

	sb = log_buf_alloc_space();
	gt_strbuf_add_sockopt_optname(sb, level, optname);
	ret = gt_strbuf_cstr(sb);
	return ret;
}

const char *
log_add_poll_events(short events)
{
	const char *ret;
	struct gt_strbuf *sb;

	sb = log_buf_alloc_space();
	gt_strbuf_add_poll_events(sb, events);
	ret = gt_strbuf_cstr(sb);
	return ret;
}

const char *
log_add_pollfds_events(struct pollfd *pfds, int npfds)
{
	const char *ret;
	struct gt_strbuf *sb;

	sb = log_buf_alloc_space();
	gt_strbuf_add_pollfds_events(sb, pfds, npfds);
	ret = gt_strbuf_cstr(sb);
	return ret;
}

const char *
log_add_pollfds_revents(struct pollfd *pfds, int npfds)
{
	const char *ret;
	struct gt_strbuf *sb;

	sb = log_buf_alloc_space();
	gt_strbuf_add_pollfds_revents(sb, pfds, npfds);
	ret = gt_strbuf_cstr(sb);
	return ret;
}

const char *
log_add_sighandler(void *handler)
{
	const char *ret;
	struct gt_strbuf *sb;

	sb = log_buf_alloc_space();
	gt_strbuf_add_sighandler(sb, handler);
	ret = gt_strbuf_cstr(sb);
	return ret;
}

const char *
log_add_sigprocmask_how(int how)
{
	const char *ret;
	struct gt_strbuf *sb;

	sb = log_buf_alloc_space();
	gt_strbuf_add_sigprocmask_how(sb, how);
	ret = gt_strbuf_cstr(sb);
	return ret;
}

#ifdef __linux__
const char *
log_add_clone_flags(int flags)
{
	const char *ret;
	struct gt_strbuf *sb;

	sb = log_buf_alloc_space();
	gt_strbuf_add_clone_flags(sb, flags);
	ret = gt_strbuf_cstr(sb);
	return ret;
}

const char *
log_add_epoll_op(int op)
{
	const char *ret;
	struct gt_strbuf *sb;

	sb = log_buf_alloc_space();
	gt_strbuf_add_epoll_op(sb, op);
	ret = gt_strbuf_cstr(sb);
	return ret;
}

const char *
log_add_epoll_event_events(short events)
{
	const char *ret;
	struct gt_strbuf *sb;

	sb = log_buf_alloc_space();
	gt_strbuf_add_epoll_event_events(sb, events);
	ret = gt_strbuf_cstr(sb);
	return ret;
}
#endif /* __linux__ */
