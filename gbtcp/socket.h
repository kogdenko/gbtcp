// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_SOCKET_H
#define GBTCP_SOCKET_H

#include "file.h"
#include "htable.h"
#include "log.h"

struct route_entry;
struct route_if;
struct timer;

#define GT_VSO_HASH(faddr, lport, fport) \
	((faddr) ^ ((faddr) >> 16) ^ ntoh16((lport) ^ (fport)))

struct gt_sock {
	struct file sobase_file;
	struct gt_dlist sobase_connect_list;
	struct gt_dlist sobase_bind_list;
	be32_t sobase_laddr;
	be32_t sobase_faddr;
	be16_t sobase_lport;
	be16_t sobase_fport;
	uint8_t sobase_proto;
	uint8_t sobase_state;
};

struct gt_module_socket {
	struct log_scope log_scope;
	uint64_t tcp_fin_timeout;
	uint64_t tcp_time_wait_timeout;
	struct htable tbl_connected;
	struct htable tbl_binded;
	int impl;
};

int socket_mod_init(void);
void socket_mod_deinit(void);
void socket_mod_timer(struct timer *, u_char);

int gt_so_route(be32_t, be32_t, struct route_entry *);

typedef int (*gt_foreach_socket_f)(struct file *, void *);
int gt_foreach_binded_socket(gt_foreach_socket_f, void *);

struct gt_sock *gt_so_lookup_connected(struct htable_bucket *,
		int, be32_t, be32_t, be16_t, be16_t);
struct gt_sock *gt_so_lookup_binded(struct htable_bucket *,
		int, be32_t, be32_t, be16_t, be16_t);

void gt_so_base_init(struct gt_sock *);

int gt_so_struct_size(void);

int gt_so_get(int, struct file **);

int gt_so_get_err(struct file *);

short gt_so_get_events(struct file *);

int gt_so_nread(struct file *);

void gt_so_tx_flush(void);

int gt_so_socket6(struct file **, int, int, int, int, int);

int gt_so_connect(struct file *, const struct sockaddr_in *, struct sockaddr_in *);

int gt_so_bind(struct file *, const struct sockaddr_in *);
int gt_so_bind_ephemeral(struct gt_sock *, be32_t, be16_t);

int gt_so_listen(struct file *, int);

int gt_so_accept(struct file **, struct file *, struct sockaddr *, socklen_t *, int);

void gt_so_close(struct file *);

int gt_so_recvfrom(struct file *, const struct iovec *, int, int,
		struct sockaddr *, socklen_t *);

int gt_so_aio_recvfrom(struct file *, struct iovec *, int, struct sockaddr *, socklen_t *);

int gt_so_recvdrain(struct file *, int);

int gt_so_sendto(struct file *, const struct iovec *, int, int, be32_t, be16_t);

int gt_so_ioctl(struct file *, unsigned long, uintptr_t);

int gt_so_getsockopt(struct file *, int, int, void *, socklen_t *);

int gt_so_setsockopt(struct file *, int, int, const void *, socklen_t);

int gt_so_getsockname(struct file *, struct sockaddr *, socklen_t *);

int gt_so_getpeername(struct file *, struct sockaddr *, socklen_t *);

int gt_so_rx(struct route_if *, void *, int);

#define gt_so_socket(fpp, domain, type, flags, ipproto) \
	gt_so_socket6(fpp, 0, domain, type, flags, ipproto)

#endif // GBTCP_SOCKET_H
