#ifndef GBTCP_BSD44_UIPC_SOCKET_H
#define GBTCP_BSD44_UIPC_SOCKET_H

#include <gbtcp/socket/bsd44/types.h>

struct gt_file;
struct route_if;
struct sockaddr_in;

int gt_bsd44_so_connect(struct gt_file *, const struct sockaddr_in *);
int gt_bsd44_so_close(struct gt_file *);
int gt_bsd44_so_sendto(struct gt_file *, const struct iovec *, int, int,
		       const struct sockaddr_in *);
int gt_bsd44_so_setsockopt(struct gt_file *, int, int, const void *, socklen_t);
int gt_bsd44_so_getsockopt(struct gt_file *, int, int, void *, socklen_t *);
int gt_bsd44_so_rx(struct route_if *, void *, int);
int gt_bsd44_so_accept(struct gt_file **, struct gt_file *);
int gt_bsd44_so_listen(struct gt_file *, int);
int gt_bsd44_so_socket(struct gt_file **, int, int, int, int);
int gt_bsd44_so_get_err(struct gt_file *);
int gt_bsd44_so_getsockname(struct gt_file *, struct sockaddr *, socklen_t *);
int gt_bsd44_so_getpeername(struct gt_file *, struct sockaddr *, socklen_t *);
int gt_bsd44_so_tx_flush(void);
short gt_bsd44_so_get_events(struct gt_file *);
int gt_bsd44_so_nread(struct gt_file *);
int gt_bsd44_so_recvfrom(struct gt_file *, const struct iovec *, int, int,
			 struct sockaddr *, socklen_t *);
int gt_bsd44_so_aio_recvfrom(struct gt_file *, struct iovec *, int,
			     struct sockaddr *, socklen_t *);
int gt_bsd44_so_recvdrain(struct gt_file *, int);
int gt_bsd44_so_ioctl(struct gt_file *, unsigned long, uintptr_t);
int gt_bsd44_so_struct_size(void);

#endif
