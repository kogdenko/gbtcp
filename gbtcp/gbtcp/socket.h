// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_GBTCP_SOCKET_H
#define GBTCP_GBTCP_SOCKET_H

#include "../file.h"
#include "../timer.h"
#include "../sockbuf.h"
#include "../htable.h"

struct route_if;

struct gt_sock {
	struct file sobase_file;
	struct dlist sobase_connect_list;
	struct dlist sobase_bind_list;
};

int socket_mod_init(void);
void socket_mod_deinit(void);
void socket_mod_timer(struct timer *, u_char);

#define gt_vso_struct_size gt_gbtcp_so_struct_size
int gt_gbtcp_so_struct_size(void);

#define gt_vso_get gt_gbtcp_so_get
int gt_gbtcp_so_get(int, struct file **);

typedef int (*gt_foreach_socket_f)(struct file *, void *);
int gt_foreach_binded_socket(gt_foreach_socket_f, void *);

#define gt_vso_get_err gt_gbtcp_so_get_err
int gt_gbtcp_so_get_err(struct file *);

#define gt_vso_get_events gt_gbtcp_so_get_events
short gt_gbtcp_so_get_events(struct file *);

#define gt_vso_nread gt_gbtcp_so_nread
int gt_gbtcp_so_nread(struct file *);

#define gt_vso_tx_flush gt_gbtcp_so_tx_flush
void gt_gbtcp_so_tx_flush(void);

#define gt_vso_socket6 gt_gbtcp_so_socket6
int gt_gbtcp_so_socket6(struct file **, int, int, int, int, int);

#define gt_vso_socket(pso, domain, type, flags, ipproto) \
	gt_vso_socket6(pso, 0, domain, type, flags, ipproto)

#define gt_vso_connect gt_gbtcp_so_connect
int gt_gbtcp_so_connect(struct file *, const struct sockaddr_in *, struct sockaddr_in *);

#define gt_vso_bind gt_gbtcp_so_bind
int gt_gbtcp_so_bind(struct file *, const struct sockaddr_in *);

#define gt_vso_listen gt_gbtcp_so_listen
int gt_gbtcp_so_listen(struct file *, int);

#define gt_vso_accept gt_gbtcp_so_accept
int gt_gbtcp_so_accept(struct file **, struct file *, struct sockaddr *, socklen_t *, int);

#define gt_vso_close gt_gbtcp_so_close
void gt_gbtcp_so_close(struct file *);

#define gt_vso_recvfrom gt_gbtcp_so_recvfrom
int gt_gbtcp_so_recvfrom(struct file *, const struct iovec *, int, int,
		struct sockaddr *, socklen_t *);

#define gt_vso_aio_recvfrom gt_gbtcp_so_aio_recvfrom
int gt_gbtcp_so_aio_recvfrom(struct file *, struct iovec *, int, struct sockaddr *, socklen_t *);

#define gt_vso_recvdrain gt_gbtcp_so_recvdrain
int gt_gbtcp_so_recvdrain(struct file *, int);

#define gt_vso_sendto gt_gbtcp_so_sendto
int gt_gbtcp_so_sendto(struct file *, const struct iovec *, int, int, be32_t, be16_t);

#define gt_vso_ioctl gt_gbtcp_so_ioctl
int gt_gbtcp_so_ioctl(struct file *, unsigned long, uintptr_t);

#define gt_vso_getsockopt gt_gbtcp_so_getsockopt
int gt_gbtcp_so_getsockopt(struct file *, int, int, void *, socklen_t *);

#define gt_vso_setsockopt gt_gbtcp_so_setsockopt
int gt_gbtcp_so_setsockopt(struct file *, int, int, const void *, socklen_t);

#define gt_vso_getsockname gt_gbtcp_so_getsockname
int gt_gbtcp_so_getsockname(struct file *, struct sockaddr *, socklen_t *);

#define gt_vso_getpeername gt_gbtcp_so_getpeername
int gt_gbtcp_so_getpeername(struct file *, struct sockaddr *, socklen_t *);

#define gt_vso_rx gt_gbtcp_so_rx
int gt_gbtcp_so_rx(struct route_if *, void *, int);

#endif // GBTCP_GBTCP_SOCKET_H
