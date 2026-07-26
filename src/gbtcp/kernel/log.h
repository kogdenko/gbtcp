// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_LOG_H
#define GBTCP_LOG_H

#include <syslog.h>

#include <gbtcp/kernel/global.h>
#include <gbtcp/kernel/strbuf.h>
#include <gbtcp/kernel/subr.h>

#define LOG_BUFSIZ 1024

#define gt_logf4(logger, level, errnum, fmt, ...) \
	({ \
		if (log_is_enabled(logger, level, 0)) { \
			log_buf_init(); \
			log_printf(level, __func__, errnum, fmt, \
				   ##__VA_ARGS__); \
		} \
	})

#define gt_debug3(logger, errnum, ...) \
	gt_logf4(logger, LOG_DEBUG, errnum, __VA_ARGS__)

#define gt_info3(logger, errnum, ...) \
	gt_logf4(logger, LOG_INFO, errnum, __VA_ARGS__)

#define gt_die(errnum, fmt, ...) \
	({ \
		log_buf_init(); \
		log_printf(LOG_CRIT, __func__, errnum, fmt, ##__VA_ARGS__); \
		abort(); \
	})

#define gt_notice3(logger, errnum, ...) \
	gt_logf4(logger, LOG_NOTICE, errnum, __VA_ARGS__)

#define gt_warning3(logger, errnum, ...) \
	gt_logf4(logger, LOG_WARNING, errnum, __VA_ARGS__)

#define gt_err3(logger, errnum, ...) \
	gt_logf4(logger, LOG_ERR, errnum, __VA_ARGS__)

void log_init_early(void);

void log_scope_init(struct log_scope *, const char *);
void log_scope_deinit(struct log_scope *);

int log_get_level(void);
void log_set_level(int);

int log_is_enabled(struct log_scope *, int, int);

void log_vprintf(int, const char *, int, const char *, va_list);
void log_printf(int, const char *, int, const char *, ...)
	__attribute__((format(printf, 4, 5)));

void log_hexdump_ascii(uint8_t *data, int cnt);

void log_buf_init(void);
struct strbuf *log_buf_alloc_space(void);

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
