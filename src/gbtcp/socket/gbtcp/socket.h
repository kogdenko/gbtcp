// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_GBTCP_SOCKET_H
#define GBTCP_GBTCP_SOCKET_H

#include <gbtcp/kernel/subr.h>

struct gt_file;
struct route_if;
struct gt_timer;

int gt_gbtcp_so_struct_size(void);

int gt_gbtcp_so_get(int, struct gt_file **);

int gt_gbtcp_so_get_err(struct gt_file *);

short gt_gbtcp_so_get_events(struct gt_file *);

void gt_gbtcp_tcp_timer_delack(struct gt_timer *timer);
void gt_gbtcp_tcp_timer_rexmit(struct gt_timer *timer);
void gt_gbtcp_tcp_timer_persist(struct gt_timer *timer);
void gt_gbtcp_tcp_timer_fin(struct gt_timer *timer);
void gt_gbtcp_tcp_timer_time_wait(struct gt_timer *timer);

int gt_gbtcp_so_nread(struct gt_file *);

int gt_gbtcp_so_tx_flush(void);

int gt_gbtcp_so_socket(struct gt_file **, int, int, int, int);

int gt_gbtcp_so_connect(struct gt_file *, const struct sockaddr_in *);

int gt_gbtcp_so_bind(struct gt_file *, const struct sockaddr_in *);

int gt_gbtcp_so_listen(struct gt_file *, int);

int gt_gbtcp_so_accept(struct gt_file **, struct gt_file *);

int gt_gbtcp_so_close(struct gt_file *);

int gt_gbtcp_so_recvfrom(struct gt_file *, const struct iovec *, int, int,
			 struct sockaddr *, socklen_t *);

int gt_gbtcp_so_aio_recvfrom(struct gt_file *, struct iovec *, int,
			     struct sockaddr *, socklen_t *);

int gt_gbtcp_so_recvdrain(struct gt_file *, int);

int gt_gbtcp_so_sendto(struct gt_file *, const struct iovec *, int, int,
		       const struct sockaddr_in *);

int gt_gbtcp_so_ioctl(struct gt_file *, unsigned long, uintptr_t);

int gt_gbtcp_so_getsockopt(struct gt_file *, int, int, void *, socklen_t *);

int gt_gbtcp_so_setsockopt(struct gt_file *, int, int, const void *, socklen_t);

int gt_gbtcp_so_getsockname(struct gt_file *, struct sockaddr *, socklen_t *);

int gt_gbtcp_so_getpeername(struct gt_file *, struct sockaddr *, socklen_t *);

int gt_gbtcp_so_rx(struct route_if *, void *, int);

#endif // GBTCP_GBTCP_SOCKET_H
