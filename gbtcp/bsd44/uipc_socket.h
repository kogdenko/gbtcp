#ifndef GBTCP_BSD44_UIPC_SOCKET_H
#define GBTCP_BSD44_UIPC_SOCKET_H

#include "types.h"

struct file;
struct route_if;
struct sockaddr_in;

int gt_bsd44_so_connect(struct file *, const struct sockaddr_in *);
int gt_bsd44_so_close(struct file *);
int gt_bsd44_so_sendto(struct file *, const void *, int, int, const struct sockaddr_in *);
int gt_bsd44_so_setsockopt(struct file *, int, int, const void *, socklen_t);
int gt_bsd44_so_getsockopt(struct file *, int, int, void *, socklen_t *);
int gt_bsd44_so_rx(struct route_if *, void *, int);
int gt_bsd44_so_accept(struct file **, struct file *);
int gt_bsd44_so_listen(struct file *, int);
int gt_bsd44_so_socket(struct file **, int, int, int, int);
int gt_bsd44_so_timer(struct timer *, u_char);
int gt_bsd44_so_get_err(struct file *);
int gt_bsd44_so_getsockname(struct file *, struct sockaddr *, socklen_t *);
int gt_bsd44_so_getpeername(struct file *, struct sockaddr *, socklen_t *);
int gt_bsd44_so_tx_flush(void);
short gt_bsd44_so_get_events(struct file *);
int gt_bsd44_so_nread(struct file *);
int gt_bsd44_so_recvfrom(struct file *, const struct iovec *, int, int,
		struct sockaddr *, socklen_t *);
int gt_bsd44_so_aio_recvfrom(struct file *, struct iovec *, int,
		struct sockaddr *, socklen_t *);
int gt_bsd44_so_recvdrain(struct file *, int);
int gt_bsd44_so_ioctl(struct file *, unsigned long, uintptr_t);
int gt_bsd44_so_struct_size(void);

#endif
