// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/kernel/log.h>
#include <gbtcp/kernel/mod.h>
#include <gbtcp/kernel/shm.h>

#define LOG_LEVEL_DEFAULT LOG_NOTICE

static char log_buf[LOG_BUFSIZ];
static struct strbuf log_sb;
static int log_early_level = LOG_LEVEL_DEFAULT;

struct gt_main *gt_main;

void
log_init_early(void)
{
	openlog(NULL, LOG_PID, LOG_DAEMON);
}

void
log_scope_init(struct log_scope *scope, const char *name)
{
	char path[PATH_MAX];

	memset(scope, 0, sizeof(*scope));
	scope->lgs_level = LOG_NOTICE;
	gt_strzcpy(scope->lgs_name, name, sizeof(scope->lgs_name));
	scope->lgs_name_len = strlen(scope->lgs_name);
	assert(scope->lgs_name_len);
	snprintf(path, sizeof(path), "log.scope.%s.level", name);
}

void
log_scope_deinit(struct log_scope *scope)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "log.scope.%s", scope->lgs_name);
}

int
log_get_level(void)
{
	return log_early_level;
}

void
log_set_level(int level)
{
	if (gt_main == NULL) {
		log_early_level = level;
	} else {
		gt_main->log_level = level;
	}
}

int
log_is_enabled(struct log_scope *scope, int level, int debug)
{
	int thresh;

	// FIXME: segfault
	return 0;
	if (gt_main == NULL) {
		thresh = log_early_level;
	} else {
		thresh = gt_main->log_level;
		if (scope != NULL && thresh < scope->lgs_level) {
			thresh = scope->lgs_level;
		}
	}
	return level <= thresh;
}

static void
log_fill_errnum(struct strbuf *sb, int errnum)
{
	if (errnum) {
		strbuf_addf(sb, " (%d:%s)", errnum, strerror(errnum));
	}
}

void
log_vprintf(int level, const char *func, int errnum, const char *fmt,
	    va_list ap)
{
	char buf[LOG_BUFSIZ];
	struct strbuf sb;

	strbuf_init(&sb, buf, sizeof(buf));
	if (0) {
		strbuf_addf(&sb, "%s: ", func);
	}
	strbuf_vaddf(&sb, fmt, ap);
	if (errnum) {
		log_fill_errnum(&sb, errnum);
	}
	syslog(level, "%s", strbuf_cstr(&sb));
}

void
log_printf(int level, const char *func, int err, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_vprintf(level, func, err, fmt, ap);
	va_end(ap);
}

void
log_buf_init(void)
{
	strbuf_init(&log_sb, log_buf, sizeof(log_buf));
}

struct strbuf *
log_buf_alloc_space(void)
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
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_ipaddr(sb, af, ip);
	return strbuf_cstr(sb);
}

const char *
log_add_sockaddr_in(const struct sockaddr_in *a)
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_ipaddr(sb, AF_INET, &a->sin_addr.s_addr);
	strbuf_addf(sb, ":%hu", ntoh16(a->sin_port));
	return strbuf_cstr(sb);
}

const char *
log_add_sockaddr_un(const struct sockaddr_un *a, int sa_len)
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	if (sa_len > sizeof(sa_family_t)) {
		strbuf_add(sb, a->sun_path, sa_len - sizeof(sa_family_t));
	}
	return strbuf_cstr(sb);
}

const char *
log_add_sockaddr(const struct sockaddr *a, int sa_len)
{
	struct strbuf *sb;
	const struct sockaddr_un *a_un;
	const struct sockaddr_in *a_in;

	switch (a->sa_family) {
	case AF_INET:
		if (sa_len < sizeof(struct sockaddr_in)) {
			break;
		}
		a_in = (const struct sockaddr_in *)a;
		return log_add_sockaddr_in(a_in);
	case AF_UNIX:
		a_un = (const struct sockaddr_un *)a;
		return log_add_sockaddr_un(a_un, sa_len);
	default:
		break;
	}
	sb = log_buf_alloc_space();
	strbuf_addf(sb, "(sa_family=%d, sa_len=%d)", a->sa_family, sa_len);
	return strbuf_cstr(sb);
}

const char *
log_add_socket_domain(int domain)
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_socket_domain(sb, domain);
	return strbuf_cstr(sb);
}

const char *
log_add_socket_type(int type)
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_socket_type(sb, type);
	return strbuf_cstr(sb);
}

const char *
log_add_socket_flags(int flags)
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_socket_flags(sb, flags);
	return strbuf_cstr(sb);
}

const char *
log_add_shutdown_how(int how)
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_shutdown_how(sb, how);
	return strbuf_cstr(sb);
}

const char *
log_add_fcntl_cmd(int cmd)
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_fcntl_cmd(sb, cmd);
	return strbuf_cstr(sb);
}

const char *
log_add_ioctl_req(u_long req, uintptr_t arg)
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_ioctl_req(sb, req, arg);
	return strbuf_cstr(sb);
}

const char *
log_add_sockopt_level(int level)
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_sockopt_level(sb, level);
	return strbuf_cstr(sb);
}

const char *
log_add_sockopt_optname(int level, int optname)
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_sockopt_optname(sb, level, optname);
	return strbuf_cstr(sb);
}

const char *
log_add_ppoll_timeout(const struct timespec *timeout)
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	if (timeout == NULL) {
		strbuf_add_str(sb, "inf");
	} else {
		strbuf_addf(sb, "sec=%ld, nsec=%ld", timeout->tv_sec,
			    timeout->tv_nsec);
	}
	return strbuf_cstr(sb);
}

const char *
log_add_poll_events(short events)
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_poll_events(sb, events);
	return strbuf_cstr(sb);
}

const char *
log_add_pollfds_events(struct pollfd *pfds, int npfds)
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_pollfds_events(sb, pfds, npfds);
	return strbuf_cstr(sb);
}

const char *
log_add_pollfds_revents(struct pollfd *pfds, int npfds)
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_pollfds_revents(sb, pfds, npfds);
	return strbuf_cstr(sb);
}

const char *
log_add_sighandler(void *handler)
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_sighandler(sb, handler);
	return strbuf_cstr(sb);
}

const char *
log_add_sigprocmask_how(int how)
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_sigprocmask_how(sb, how);
	return strbuf_cstr(sb);
}

#ifdef __linux__
const char *
log_add_clone_flags(int flags)
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_clone_flags(sb, flags);
	return strbuf_cstr(sb);
}

const char *
log_add_epoll_op(int op)
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_epoll_op(sb, op);
	return strbuf_cstr(sb);
}

const char *
log_add_epoll_event_events(short events)
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_epoll_event_events(sb, events);
	return strbuf_cstr(sb);
}
#endif /* __linux__ */
