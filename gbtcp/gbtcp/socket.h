// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_GBTCP_SOCKET_H
#define GBTCP_GBTCP_SOCKET_H

#include "../subr.h"

struct file;
struct route_if;
struct timer;

int gt_gbtcp_so_struct_size(void);

int gt_gbtcp_so_get(int, struct file **);

int gt_gbtcp_so_get_err(struct file *);

short gt_gbtcp_so_get_events(struct file *);

void gt_gbtcp_so_timer(struct timer *timer, u_char fn_id);

int gt_gbtcp_so_nread(struct file *);

void gt_gbtcp_so_tx_flush(void);

int gt_gbtcp_so_socket6(struct file **, int, int, int, int, int);

int gt_gbtcp_so_connect(struct file *, const struct sockaddr_in *, struct sockaddr_in *);

int gt_gbtcp_so_bind(struct file *, const struct sockaddr_in *);

int gt_gbtcp_so_listen(struct file *, int);

int gt_gbtcp_so_accept(struct file **, struct file *, struct sockaddr *, socklen_t *, int);

void gt_gbtcp_so_close(struct file *);

int gt_gbtcp_so_recvfrom(struct file *, const struct iovec *, int, int,
		struct sockaddr *, socklen_t *);

int gt_gbtcp_so_aio_recvfrom(struct file *, struct iovec *, int, struct sockaddr *, socklen_t *);

int gt_gbtcp_so_recvdrain(struct file *, int);

int gt_gbtcp_so_sendto(struct file *, const struct iovec *, int, int, be32_t, be16_t);

int gt_gbtcp_so_ioctl(struct file *, unsigned long, uintptr_t);

int gt_gbtcp_so_getsockopt(struct file *, int, int, void *, socklen_t *);

int gt_gbtcp_so_setsockopt(struct file *, int, int, const void *, socklen_t);

int gt_gbtcp_so_getsockname(struct file *, struct sockaddr *, socklen_t *);

int gt_gbtcp_so_getpeername(struct file *, struct sockaddr *, socklen_t *);

int gt_gbtcp_so_rx(struct route_if *, void *, int);

#endif // GBTCP_GBTCP_SOCKET_H
