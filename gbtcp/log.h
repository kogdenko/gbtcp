/* GPL2 license */
#ifndef GBTCP_LOG_H
#define GBTCP_LOG_H

#include "subr.h"
#include "strbuf.h"

#define LOG_STACKSIZ 16
#define LOG_BUFSIZ 16384

struct gt_log_scope {
	const char *lgs_name;
	int lgs_namelen;
	int lgs_level;
};

struct gt_log_node {
	struct gt_log_scope *lgn_scope;
	const char *lgn_name;
	int lgn_namelen;
	int lgn_level;
};

struct gt_log {
	struct gt_log_node *lg_node;
	struct gt_log *lg_upper;
	struct gt_log *lg_lower;
};

#define GT_LOG_NODE(func) (&log_node__##func)

#define GT_LOG_NODE_STATIC(func) \
	static struct gt_log_node log_node__##func;

//#define GT_LOG_FINDOUT_UNUSED
//#define LOG_DISABLED

#ifdef GT_LOG_FINDOUT_GT_UNUSED
#define GT_LOG_NODE_INIT(func)
#else /* GT_LOG_FINDOUT_UNUSED */
#define GT_LOG_NODE_INIT(func) \
	gt_log_node_init(&log_node__##func, &this_log, #func);
#endif /* GT_LOG_FINDOUT_UNUSED */

#ifdef LOG_DISABLED
#define GT_LOG_TRACE(upper, func)
#define GT_LOGF(bottom, level, err, fmt, ...) \
	do { \
		UNUSED(bottom); \
		UNUSED(err); \
	} while (0)
#else /* LOG_DISABLED */

#define GT_LOG_TRACE(upper, func) \
({ \
	struct gt_log *GT_UNIQV(trace); \
	GT_UNIQV(trace) = alloca(sizeof(struct gt_log)); \
	GT_UNIQV(trace)->lg_node = &log_node__##func; \
	GT_UNIQV(trace)->lg_upper = upper; \
	GT_UNIQV(trace); \
})

#define GT_LOGF(bottom, level, err, fmt, ...) \
do { \
	if (log_isenabled(bottom, level)) { \
		log_bufinit(); \
		gt_log_printf(bottom, level, err, fmt, ##__VA_ARGS__); \
	} \
} while (0)
#endif /* LOG_DISABLED */

#define GT_LOG_TRACE1(func) GT_LOG_TRACE(NULL, func)

#ifdef NDEBUG
#define GT_DBG(...)
#define GT_ASSERT3(err, expr, fmt, ...) \
	do { \
	} while (0)
#define GT_BUG2(err, fmt, ...) \
	do { \
	} while (0)
#else /*NDEBUG */
#define GT_DBG(func, err, ...) \
	GT_LOGF(GT_LOG_TRACE1(func), LOG_DEBUG, err, __VA_ARGS__)
#define GT_ASSERT3(err, expr, fmt, ...) \
	((expr) ? \
	(void)(0) : \
	gt_log_abort(__FILE__, __LINE__, err, #expr, fmt, ##__VA_ARGS__))
#define GT_BUG2(err, fmt, ...) \
	gt_log_abort(__FILE__, __LINE__, err, NULL, fmt, ##__VA_ARGS__)
#endif /* NDEBUG */

#define GT_ASSERT2(err, expr) GT_ASSERT3(err, expr, NULL)
#define GT_ASSERT(expr) GT_ASSERT2(0, expr)

#define GT_BUG1(fmt, ...) GT_BUG2(0, fmt, ##__VA_ARGS__)
#define GT_BUG GT_BUG1(NULL)

int gt_log_mod_init();

void gt_log_mod_deinit(struct gt_log *log);

void gt_log_scope_init_early(struct gt_log_scope *scope, const char *name);

void gt_log_scope_init(struct gt_log_scope *scope, const char *name);

void gt_log_scope_deinit(struct gt_log *log, struct gt_log_scope *scope);

void gt_log_node_init(struct gt_log_node *node, struct gt_log_scope *scope,
	const char *func);

struct gt_log *gt_log_copy(struct gt_log *dst, int cnt, struct gt_log *bottom);

int log_isenabled(struct gt_log *bottom, int level);

void gt_log_vprintf(struct gt_log *bottom, int err, int level,
	const char *fmt, va_list ap);

void gt_log_printf(struct gt_log *bottom, int level, int err,
	const char *fmt, ...)
	__attribute__((format(printf, 4, 5)));

void log_backtrace(int depth_off);

void gt_log_hexdump_ascii(uint8_t *data, int cnt);

void gt_log_abort(const char *file, int line, int error, const char *expr,
	const char *fmt, ...)
	__attribute__((format(printf, 5, 6)));

void log_bufinit();

struct gt_strbuf *gt_log_buf_alloc_space();

const char *gt_log_add_ip_addr(int af, const void *ip);

const char *gt_log_add_sockaddr_in(const struct sockaddr_in *a);

const char *gt_log_add_socket_domain(int domain);

const char *gt_log_add_socket_type(int type);

const char *gt_log_add_socket_flags(int flags);

const char *gt_log_add_shutdown_how(int how);

const char *gt_log_add_fcntl_cmd(int cmd);

const char *gt_log_add_ioctl_req(unsigned long req);

const char *gt_log_add_sockopt_level(int level);

const char *gt_log_add_sockopt_optname(int level, int optname);

const char *gt_log_add_poll_events(short events);

const char *gt_log_add_pollfds_events(struct pollfd *pfds, int npfds);

const char *gt_log_add_pollfds_revents(struct pollfd *pfds, int npfds);

const char *gt_log_add_sighandler(void *handler);

const char *gt_log_add_sigprocmask_how(int how);

#ifdef __linux__
const char *gt_log_add_clone_flags(int flags);

const char *gt_log_add_epoll_op(int op);

const char *gt_log_add_epoll_event_events(short events);
#else /* __linux__ */
#endif /* __linux__ */

#endif /* GBTCP_LOG_H */
