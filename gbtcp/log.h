// GPL v2
#ifndef GBTCP_LOG_H
#define GBTCP_LOG_H

#include "subr.h"
#include "strbuf.h"

#ifndef LOG_LEVEL
#error "LOG_LEVEL not defined"
#endif

#define LOG_BUFSZ 1024

struct log_scope {
	char lgs_name[16];
	int lgs_name_len;
	int lgs_level;
};

#define LOGF(level, errnum, fmt, ...) \
do { \
	log_buf_init(); \
	log_printf(level, errnum, fmt, ##__VA_ARGS__); \
} while (0)

#if LOG_LEVEL >= LOG_DEBUG
#define DBG(err, ...) LOGF(LOG_DEBUG, err, __VA_ARGS__)
#else
#define DBG(err, ...)
#endif

#if LOG_LEVEL >= LOG_INFO
#define INFO(err, ...) LOGF(LOG_INFO, err, __VA_ARGS__)
#else
#define INFO(err, ...)
#endif

#define NOTICE(err, ...) LOGF(LOG_NOTICE, err, __VA_ARGS__)
#define WARN(err, ...) LOGF(LOG_WARNING, err, __VA_ARGS__)
#define ERR(err, ...) LOGF(LOG_ERR, err, __VA_ARGS__)

#define die(errnum, fmt, ...) \
do { \
	LOGF(LOG_CRIT, errnum, fmt, ##__VA_ARGS__); \
	abort(); \
} while (0)

int log_mod_init();

void log_scope_init(struct log_scope *, const char *);
void log_scope_deinit(struct log_scope *);

int init_log();
int fini_log();

void log_set_level(int);
int log_is_enabled(struct log_scope *, int, int);
void log_vprintf(int,  int, const char *, va_list);
void log_printf(int, int, const char *, ...)
	__attribute__((format(printf, 3, 4)));
void log_hexdump_ascii(int, u_char *data, int cnt);

void log_buf_init();
struct strbuf *log_buf_alloc_space();
const char *log_add_ipaddr(int, const void *);
const char *log_add_ip_addr4(be32_t);
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
