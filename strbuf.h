#ifndef GBTCP_STRBUF_H
#define GBTCP_STRBUF_H

#include "subr.h"

struct gt_strbuf {
	unsigned int sb_cap;
	unsigned int sb_len;
	char *sb_buf;
};

void gt_strbuf_init(struct gt_strbuf *sb, void *buf, int cap);

int gt_strbuf_space(struct gt_strbuf *sb);

char *gt_strbuf_cstr(struct gt_strbuf *sb);

void gt_strbuf_remove(struct gt_strbuf *sb, int pos, int len);

void gt_strbuf_insert(struct gt_strbuf *sb, int pos, const void *data,
	int len);

void gt_strbuf_add(struct gt_strbuf *sb, const void *buf, int size);

void gt_strbuf_add_ch(struct gt_strbuf *sb, char ch);

void gt_strbuf_add_ch3(struct gt_strbuf *sb, int ch, int n);

void gt_strbuf_add_str(struct gt_strbuf *sb, const char *str);

void gt_strbuf_vaddf(struct gt_strbuf *sb, const char *fmt, va_list ap);

void gt_strbuf_addf(struct gt_strbuf *sb, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

void gt_strbuf_add_eth_addr(struct gt_strbuf *sb, struct gt_eth_addr *a);

void gt_strbuf_add_ip_addr(struct gt_strbuf *sb, int af, const void *ip);

void gt_strbuf_add_rss_key(struct gt_strbuf *sb, uint8_t *rss_key);

void gt_strbuf_add_flag_end(struct gt_strbuf *sb, int flags);

void gt_strbuf_add_backtrace(struct gt_strbuf *sb, int depth_off);

void gt_strbuf_add_recv_flags(struct gt_strbuf *sb, int flags);

void gt_strbuf_add_send_flags(struct gt_strbuf *sb, int flags);

void gt_strbuf_add_tcp_state(struct gt_strbuf *sb, int tcp_state);

void gt_strbuf_add_socket_domain(struct gt_strbuf *sb, int domain);

void gt_strbuf_add_socket_type(struct gt_strbuf *sb, int type);

void gt_strbuf_add_socket_flags(struct gt_strbuf *sb, int flags);

void gt_strbuf_add_shutdown_how(struct gt_strbuf *sb, int how);

void gt_strbuf_add_fcntl_cmd(struct gt_strbuf *sb, int cmd);

void gt_strbuf_add_fcntl_setfl(struct gt_strbuf *sb, int flags);

void gt_strbuf_add_ioctl_req(struct gt_strbuf *sb, unsigned long request);

void gt_strbuf_add_sockopt_level(struct gt_strbuf *sb, int level);

void gt_strbuf_add_sockopt_optname(struct gt_strbuf *sb, int level,
	int optname);

void gt_strbuf_add_poll_events(struct gt_strbuf *sb, short events);

void gt_strbuf_add_pollfds_events(struct gt_strbuf *sb,
	struct pollfd *pfds, int npfds);

void gt_strbuf_add_pollfds_revents(struct gt_strbuf *sb,
	struct pollfd *pfds, int npfds);

void gt_strbuf_add_sighandler(struct gt_strbuf *sb, void *fn);

void gt_strbuf_add_sigprocmask_how(struct gt_strbuf *sb, int how);

#ifdef __linux__
void gt_strbuf_add_epoll_event_events(struct gt_strbuf *sb, short events);

void gt_strbuf_add_epoll_op(struct gt_strbuf *sb, int op);

void gt_strbuf_add_clone_flags(struct gt_strbuf *sb, int flags);
#endif /* __linux__ */

#endif /* GBTCP_STRBUF_H */
