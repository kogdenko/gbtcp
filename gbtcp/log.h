// gpl2 license
#ifndef GBTCP_LOG_H
#define GBTCP_LOG_H

#include "subr.h"
#include "strbuf.h"

#define LOG_BUFSIZ 1024

struct log_scope {
	char lgs_name[16];
	int lgs_name_len;
	int lgs_level;
};

#ifdef LOG_DISABLED
#define LOGF(level, errnum, fmt, ...) \
	do { \
		UNUSED(errnum); \
	} while (0)
#else // LOG_DISABLED
#define LOGF(level, errnum, fmt, ...) \
do { \
	if (log_is_enabled(CAT2(MOD_, CURMOD), level, 0)) { \
		log_buf_init(); \
		log_printf(level, __func__, errnum, fmt, ##__VA_ARGS__); \
	} \
} while (0)
#endif // LOG_DISABLED

#define log_trace0() log_trace(NULL)

#ifdef NDEBUG
#define DBG(err, ...)
#define INFO(...)
#else /*NDEBUG */
#define DBG(err, ...) LOGF(LOG_DEBUG, err, __VA_ARGS__)
#define INFO(err, ...) LOGF(LOG_INFO, err, __VA_ARGS__)
#endif /* NDEBUG */

#define die(errnum, fmt, ...) \
do { \
	LOGF(LOG_CRIT, errnum, fmt, ##__VA_ARGS__); \
	abort(); \
} while (0)

#define NOTICE(err, ...) LOGF(LOG_NOTICE, err, __VA_ARGS__)
#define WARN(err, ...) LOGF(LOG_WARNING, err, __VA_ARGS__)
#define ERR(err, ...) LOGF(LOG_ERR, err, __VA_ARGS__)

void log_init_early(const char *, u_int);

int log_mod_init(void **);

void log_scope_init(struct log_scope *, const char *);
void log_scope_deinit(struct log_scope *);

void log_set_level(int);

int log_is_enabled(int, int, int);

void log_vprintf(int, const char *, int, const char *, va_list);
void log_printf(int, const char *, int, const char *, ...)
	__attribute__((format(printf, 4, 5)));

void log_hexdump_ascii(uint8_t *data, int cnt);

void log_buf_init();
struct strbuf *log_buf_alloc_space();

const char *log_add_ipaddr(int, const void *);
const char *log_add_sockaddr_in(const struct sockaddr_in *);
const char *log_add_sockaddr_un(const struct sockaddr_un *, int);
const char *log_add_sockaddr(const struct sockaddr *, int);
const char *log_add_socket_domain(int);
const char *log_add_socket_type(int);
const char *log_add_socket_flags(int);
const char *log_add_shutdown_how(int);
const char *log_add_fcntl_cmd(int);
const char *log_add_ioctl_req(u_long, uintptr_t);
const char *log_add_sockopt_level(int);
const char *log_add_sockopt_optname(int, int);
const char *log_add_ppoll_timeout(const struct timespec *);
const char *log_add_poll_events(short);
const char *log_add_pollfds_events(struct pollfd *, int);
const char *log_add_pollfds_revents(struct pollfd *, int);
const char *log_add_sighandler(void *);
const char *log_add_sigprocmask_how(int);

#ifdef __linux__
const char *log_add_clone_flags(int);
const char *log_add_epoll_op(int);
const char *log_add_epoll_event_events(short);
#else // __linux__
#endif // __linux__

#endif // GBTCP_LOG_H
