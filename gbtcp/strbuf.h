#ifndef GBTCP_STRBUF_H
#define GBTCP_STRBUF_H

#include "subr.h"

struct strbuf {
	u_int sb_cap;
	u_int sb_len;
	char *sb_buf;
};

void strbuf_init(struct strbuf *, void *, int);
int strbuf_space(struct strbuf *);
char *strbuf_cstr(struct strbuf *);
void strbuf_remove(struct strbuf *, int, int);
void strbuf_insert(struct strbuf *, int, const void *, int);
void strbuf_add(struct strbuf *, const void *, int);
void strbuf_add_ch(struct strbuf *, char);
void strbuf_add_ch3(struct strbuf *, int, int);
void strbuf_add_str(struct strbuf *, const char *);
void strbuf_vaddf(struct strbuf *, const char *, va_list);
void strbuf_addf(struct strbuf *, const char *, ...)
	__attribute__((format(printf, 2, 3)));
void strbuf_add_ethaddr(struct strbuf *, struct ethaddr *);
void strbuf_add_ipaddr(struct strbuf *, int, const void *);
void strbuf_add_rsskey(struct strbuf *, u_char *);
void strbuf_add_flag_end(struct strbuf *, int);
void strbuf_add_backtrace(struct strbuf *, int);
void strbuf_add_recv_flags(struct strbuf *, int);
void strbuf_add_send_flags(struct strbuf *, int);
void strbuf_add_tcp_state(struct strbuf *, int);
void strbuf_add_socket_domain(struct strbuf *, int);
void strbuf_add_socket_type(struct strbuf *, int);
void strbuf_add_socket_flags(struct strbuf *, int);
void strbuf_add_shutdown_how(struct strbuf *, int);
void strbuf_add_fcntl_cmd(struct strbuf *, int);
void strbuf_add_fcntl_setfl(struct strbuf *, int);
void strbuf_add_ioctl_req(struct strbuf *, u_long);
void strbuf_add_sockopt_level(struct strbuf *, int level);
void strbuf_add_sockopt_optname(struct strbuf *, int, int);
void strbuf_add_poll_events(struct strbuf *, short);
void strbuf_add_pollfds_events(struct strbuf *, struct pollfd *, int);
void strbuf_add_pollfds_revents(struct strbuf *, struct pollfd *, int);
void strbuf_add_sighandler(struct strbuf *, void *);
void strbuf_add_sigprocmask_how(struct strbuf *, int);

#ifdef __linux__
void strbuf_add_epoll_event_events(struct strbuf *, short);
void strbuf_add_epoll_op(struct strbuf *, int);
void strbuf_add_clone_flags(struct strbuf *, int);
#endif /* __linux__ */

#endif /* GBTCP_STRBUF_H */
