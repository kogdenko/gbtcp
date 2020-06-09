// gpl2 license
#include "internals.h"

#ifdef NDEBUG
#define LOG_LEVEL_DEFAULT LOG_NOTICE
#else // NDEBUG
#define LOG_LEVEL_DEFAULT LOG_DEBUG
#endif // NDEBUG

#define CURMOD log

struct log_mod {
	struct log_scope log_scope;
	int log_level;
};

static char log_buf[LOG_BUFSIZ];
static struct strbuf log_sb;
static int log_early_level_set;
static int log_early_level = LOG_LEVEL_DEFAULT;
static char ident_buf[SERVICE_COMM_MAX + 7];
static const char *ident;

void
log_init_early(const char *comm, u_int log_level)
{
	if (comm == NULL) {
		ident = NULL;
	} else {
		snprintf(ident_buf, sizeof(ident_buf), "gbtcp: %s", comm);
		ident = ident_buf;
	}
	assert(log_level < LOG_DEBUG);
	if (log_level) {
		log_set_level(log_level);
	}
	openlog(ident, LOG_PID, LOG_DAEMON);
}

static const char *
log_level_str(int level)
{
	switch (level) {
	case LOG_EMERG: return "EMERG";
	case LOG_ALERT: return "ALERT";
	case LOG_CRIT: return "CRIT";
	case LOG_ERR: return "ERR";
	case LOG_WARNING: return "WARNING";
	case LOG_NOTICE: return "NOTICE";
	case LOG_INFO: return "INFO";
	case LOG_DEBUG: return "DEBUG";
	default: return NULL;
	}
}

static int
sysctl_log_level(struct sysctl_conn *cp, void *udata,
	const char *new, struct strbuf *out)
{
	u_long level;
	char *endptr;
	const char *s;

	s = log_level_str(curmod->log_level);
	if (s == NULL) {
		strbuf_addf(out, "%d", curmod->log_level);
	} else {
		strbuf_add_str(out, s);
	}
	if (new == NULL) {
		return 0;
	}
	level = strtoul(new, &endptr, 10);
	if (*endptr == '\0') {
		if (level > LOG_DEBUG) {
			return -EINVAL;
		}
	} else if (!strcasecmp(new, "EMERG")) {
		level = LOG_EMERG;
	} else if (!strcasecmp(new, "ALERT")) {
		level = LOG_ALERT;
	} else if (!strcasecmp(new, "CRIT")) {
		level = LOG_CRIT;
	} else if (!strcasecmp(new, "ERR")) {
		level = LOG_ERR;
	} else if (!strcasecmp(new, "WARNING")) {
		level = LOG_WARNING;
	} else if (!strcasecmp(new, "NOTICE")) {
		level = LOG_NOTICE;
	} else if (!strcasecmp(new, "INFO")) {
		level = LOG_INFO;
	} else if (!strcasecmp(new, "DEBUG")) {
		level = LOG_DEBUG;
	} else {
		return -EINVAL;
	}
	curmod->log_level = level;
	return 0;
}

int
log_mod_init(void **pp)
{
	int rc;

	rc = curmod_init();
	if (rc) {
		return rc;
	}
	if (log_early_level_set) {
		curmod->log_level = log_early_level;
	} else {
		curmod->log_level = LOG_NOTICE;
	}
	sysctl_add("log.level", SYSCTL_WR, NULL, NULL, sysctl_log_level); 
	return 0;
}

void
log_mod_deinit()
{
	sysctl_del("log");
	curmod_deinit();
}

void
log_scope_init(struct log_scope *scope, const char *name)
{
	char path[PATH_MAX];

	memset(scope, 0, sizeof(*scope));
	scope->lgs_level = LOG_NOTICE;
	strzcpy(scope->lgs_name, name, sizeof(scope->lgs_name));
	scope->lgs_name_len = strlen(scope->lgs_name);
	assert(scope->lgs_name_len);
	snprintf(path, sizeof(path), "log.scope.%s.level", name);
	sysctl_add_int(path, SYSCTL_WR, &scope->lgs_level,
	               LOG_EMERG, LOG_DEBUG);
}

void
log_scope_deinit(struct log_scope *scope)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "log.scope.%s", scope->lgs_name);
	sysctl_del(path);
}

void
log_set_level(int level)
{
	if (mod_get(MOD_log) == NULL) {
		log_early_level = level;
		log_early_level_set = 1;
	} else {
		curmod->log_level = level;
	}
}

int
log_is_enabled(int mod_id, int level, int debug)
{
	int thresh;
	struct log_scope *scope;

	if (mod_get(MOD_log) == NULL) {
		thresh = log_early_level;
	} else {
		thresh = curmod->log_level;
		scope = mod_get(mod_id);
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
log_vprintf(int level, const char *func, int errnum,
	const char *fmt, va_list ap)
{
	char buf[LOG_BUFSIZ];
	struct strbuf sb;

	strbuf_init(&sb, buf, sizeof(buf));
	strbuf_addf(&sb, "%s: ", func);
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
log_add_ioctl_req(u_long req, uintptr_t arg)
{
	const char *ret;
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_ioctl_req(sb, req, arg);
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
