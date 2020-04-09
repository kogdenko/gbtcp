/* GPL2 license */
#ifndef GBTCP_LOG_H
#define GBTCP_LOG_H

#include "subr.h"
#include "strbuf.h"

#define LOG_STACKSIZ 16
#define LOG_BUFSIZ 16384

struct log_scope {
	const char *lgs_name;
	int lgs_namelen;
	int lgs_level;
};

struct gt_log {
	const char *lg_func;
	struct gt_log *lg_upper;
	struct gt_log *lg_lower;
};

#define LOG_MSG_DECLARE(name) int log_level_##name;
#define LOG_MSG(name) ((this_mod)->log_level_##name)

#define LOG_DISABLED

#ifdef LOG_DISABLED
#define log_trace(upper) \
({ \
	struct gt_log *GT_UNIQV(log); \
	GT_UNIQV(log) = alloca(sizeof(struct gt_log)); \
	UNUSED(upper); \
	GT_UNIQV(log); \
})

#define LOG_TRACE UNUSED
#define LOGF(log, name, level, err, fmt, ...) \
	do { \
		UNUSED(log); \
		UNUSED(err); \
	} while (0)
#else /* LOG_DISABLED */

#define log_trace(upper) \
({ \
	struct gt_log *GT_UNIQV(log); \
	GT_UNIQV(log) = alloca(sizeof(struct gt_log)); \
	GT_UNIQV(log)->lg_func = __func__; \
	GT_UNIQV(log)->lg_upper = upper; \
	GT_UNIQV(log); \
})

#define LOG_TRACE(log) (log) = log_trace(log)

#define LOGF(log, name, level, err, fmt, ...) \
do { \
	if (log_is_enabled(&this_mod->log_scope, \
	                    this_mod->log_level_##name, level)) { \
		log_buf_init(); \
		log_printf(log, level, err, fmt, ##__VA_ARGS__); \
	} \
} while (0)
#endif /* LOG_DISABLED */

#define log_trace0() log_trace(NULL)

#ifdef NDEBUG
#define DBG(...)
#define ASSERT3(err, expr, fmt, ...) \
	do { \
	} while (0)
#define BUG2(err, fmt, ...) \
	do { \
	} while (0)
#else /*NDEBUG */
#define DBG(trace, name, err, ...) \
	LOGF(trace, name , LOG_DEBUG, err, __VA_ARGS__)
#define ASSERT3(err, expr, fmt, ...) \
	((expr) ? \
	(void)(0) : \
	log_abort(__FILE__, __LINE__, err, #expr, fmt, ##__VA_ARGS__))
#define BUG2(err, fmt, ...) \
	log_abort(__FILE__, __LINE__, err, NULL, fmt, ##__VA_ARGS__)
#endif /* NDEBUG */

#define ASSERT2(err, expr) ASSERT3(err, expr, NULL)
#define ASSERT(expr) ASSERT2(0, expr)

#define BUG1(fmt, ...) BUG2(0, fmt, ##__VA_ARGS__)
#define BUG BUG1(NULL)

int gt_log_mod_init();

void gt_log_mod_deinit(struct gt_log *log);

void log_scope_init_early(struct log_scope *, const char *);

void log_scope_init(struct log_scope *, const char *);

void log_scope_deinit(struct gt_log *, struct log_scope *);

struct gt_log *log_copy(struct gt_log *, int, struct gt_log *);

int log_is_enabled(struct log_scope *, int, int);

void log_vprintf(struct gt_log *, int, int, const char *, va_list);

void log_printf(struct gt_log *, int, int, const char *, ...)
	__attribute__((format(printf, 4, 5)));

void log_backtrace(int depth_off);

void log_hexdump_ascii(uint8_t *data, int cnt);

void log_abort(const char *, int, int, const char *, const char *, ...)
	__attribute__((format(printf, 5, 6)));

void log_buf_init();

struct gt_strbuf *log_buf_alloc_space();

const char *log_add_ipaddr(int, const void *);

const char *log_add_sockaddr_in(const struct sockaddr_in *);

const char *log_add_socket_domain(int);

const char *log_add_socket_type(int);

const char *log_add_socket_flags(int);

const char *log_add_shutdown_how(int);

const char *log_add_fcntl_cmd(int);

const char *log_add_ioctl_req(unsigned long);

const char *log_add_sockopt_level(int);

const char *log_add_sockopt_optname(int, int);

const char *log_add_poll_events(short);

const char *log_add_pollfds_events(struct pollfd *, int);

const char *log_add_pollfds_revents(struct pollfd *, int);

const char *log_add_sighandler(void *);

const char *log_add_sigprocmask_how(int);

#ifdef __linux__
const char *log_add_clone_flags(int);

const char *log_add_epoll_op(int);

const char *log_add_epoll_event_events(short);
#else /* __linux__ */
#endif /* __linux__ */

#endif /* GBTCP_LOG_H */
