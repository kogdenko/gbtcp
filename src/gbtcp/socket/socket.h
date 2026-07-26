// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_SOCKET_H
#define GBTCP_SOCKET_H

#include <gbtcp/socket/file.h>
#include <gbtcp/kernel/htable.h>
#include <gbtcp/kernel/log.h>
#include <gbtcp/kernel/mod.h>

struct gt_api_conn;
struct route_entry;
struct route_if;
struct service;
struct gt_timer;

#define GT_SO_HASH(faddr, lport, fport) \
	((faddr) ^ ((faddr) >> 16) ^ ntoh16((lport) ^ (fport)))

struct gt_so_ops {
	int (*so_struct_size)(void);
	int (*so_get_err)(struct gt_file *);
	short (*so_get_events)(struct gt_file *);
	int (*so_nread)(struct gt_file *);
	int (*so_tx_flush)(void);
	int (*so_socket)(struct gt_file **, int, int, int, int);
	int (*so_connect)(struct gt_file *, const struct sockaddr_in *);
	int (*so_listen)(struct gt_file *, int);
	int (*so_accept)(struct gt_file **, struct gt_file *);
	int (*so_close)(struct gt_file *);
	int (*so_recvfrom)(struct gt_file *, const struct iovec *, int, int,
			   struct sockaddr *, socklen_t *);
	int (*so_aio_recvfrom)(struct gt_file *, struct iovec *, int,
			       struct sockaddr *, socklen_t *);
	int (*so_recvdrain)(struct gt_file *, int);
	int (*so_sendto)(struct gt_file *, const struct iovec *, int, int,
			 const struct sockaddr_in *);
	int (*so_ioctl)(struct gt_file *, unsigned long, uintptr_t);
	int (*so_getsockopt)(struct gt_file *, int, int, void *, socklen_t *);
	int (*so_setsockopt)(struct gt_file *, int, int, const void *,
			     socklen_t);
	int (*so_getpeername)(struct gt_file *, struct sockaddr *, socklen_t *);
	int (*so_rx)(struct route_if *, void *, int);
};

struct gt_sock {
	struct gt_file sobase_file;
	struct gt_dlist sobase_connect_list;
	struct gt_dlist sobase_bind_list;
	be32_t sobase_laddr;
	be32_t sobase_faddr;
	be16_t sobase_lport;
	be16_t sobase_fport;
	uint8_t sobase_proto;
};

struct gt_socket_worker {
	struct gt_dlist sow_tx_pending_head;
	struct gt_file **sow_file_table;
	struct gt_dlist sow_file_head;
	u32 sow_file_max;
	u32 sow_file_cur;
	const struct gt_so_ops *impl;
};

struct gt_so_main {
	u8 so_module_id;

	struct log_scope so_logger;

	u64 tcp_fin_timeout;
	u64 tcp_time_wait_timeout;
	struct htable tbl_connected;
	struct htable tbl_binded;
	char so_impl_name[16];

	// Registered handles for gt_socket_module_rx/tx, added to
	// gt_main->rx_callbacks/tx_callbacks from gt_socket_module_postinit().
	// Filled once by gt_socket_module_init() in the controller.
	struct gt_worker_func so_rx_fn;
	struct gt_worker_func so_tx_fn;

	// Registered handles for the gbtcp TCP implementation's individual
	// timer callbacks (see gbtcp/socket.c). Resolved via
	// GT_WORKER_FUNC_EXEC() when the timer fires. Filled once
	// by gt_socket_module_init() in the controller; gt_so_main lives in
	// shm, so every worker later reads back the same values.
	struct gt_worker_func so_timer_delack_fn;
	struct gt_worker_func so_timer_rexmit_fn;
	struct gt_worker_func so_timer_persist_fn;
	struct gt_worker_func so_timer_fin_fn;
	struct gt_worker_func so_timer_time_wait_fn;

	// Same idea for the bsd44 TCP implementation's timer callbacks (see
	// bsd44/tcp_timer.c), indexed by the TCPT_* constants also used as
	// tp->t_timer[] indices (bsd44/tcp_timer.h: TCPT_NTIMERS == 5).
	struct gt_worker_func so_bsd44_timer_fn[5];

	struct gt_socket_worker so_workers[GT_SERVICES_MAX];
};

extern struct gt_so_main *gt_so_main;

int gt_socket_module_init(u8 module_id, void **puser);
int gt_socket_module_postinit(void *mod);
void gt_socket_module_deinit(void *user);
void gt_socket_module_worker_start(void *);
void gt_socket_module_worker_stop(void);
void gt_socket_module_tx(void);
int gt_socket_module_rx(struct route_if *ifp, void *data, int len);
int gt_socket_module_worker_init(struct service *s, int pid, int tid,
				 struct gt_api_conn *cp);
void gt_socket_module_worker_deinit(u8 worker_index);

int gt_set_sockaddr(struct sockaddr *, socklen_t *, be32_t, be16_t);

int gt_so_route(be32_t, be32_t, struct route_entry *);

typedef int (*gt_foreach_socket_f)(struct gt_file *, void *);
int gt_foreach_binded_socket(gt_foreach_socket_f, void *);

void gt_so_rmfrom_binded(struct gt_sock *);

struct gt_sock *gt_so_lookup_binded(struct htable_bucket *, int, be32_t, be32_t,
				    be16_t, be16_t);

void gt_so_addto_connected(struct gt_sock *, uint32_t *);
void gt_so_rmfrom_connected(struct gt_sock *);

struct gt_sock *gt_so_lookup_connected(struct htable_bucket *, int, be32_t,
				       be32_t, be16_t, be16_t);

int gt_so_lookup(struct gt_sock **, int, be32_t, be32_t, be16_t, be16_t);

void gt_so_base_init(struct gt_sock *);

int gt_so_struct_size(void);

int gt_so_get(int, struct gt_file **);

int gt_so_get_err(struct gt_file *);

short gt_so_get_events(struct gt_file *);

int gt_so_nread(struct gt_file *);

void gt_so_tx_flush(void);

int gt_so_socket6(struct gt_file **, int, int, int, int, int);

int gt_so_connect(struct gt_file *, const struct sockaddr_in *,
		  struct sockaddr_in *);

int gt_so_bind(struct gt_file *, const struct sockaddr_in *);
int gt_so_bind_ephemeral(struct gt_sock *, be32_t, be16_t);

int gt_so_listen(struct gt_file *, int);

int gt_so_accept(struct gt_file **, struct gt_file *, struct sockaddr *,
		 socklen_t *, int);

void gt_so_close(struct gt_file *);

int gt_so_recvfrom(struct gt_file *, const struct iovec *, int, int,
		   struct sockaddr *, socklen_t *);

int gt_so_aio_recvfrom(struct gt_file *, struct iovec *, int, struct sockaddr *,
		       socklen_t *);

int gt_so_recvdrain(struct gt_file *, int);

int gt_so_sendto(struct gt_file *, const struct iovec *, int, int,
		 const struct sockaddr_in *);

int gt_so_ioctl(struct gt_file *, unsigned long, uintptr_t);

int gt_so_getsockopt(struct gt_file *, int, int, void *, socklen_t *);

int gt_so_setsockopt(struct gt_file *, int, int, const void *, socklen_t);

int gt_so_getsockname(struct gt_file *, struct sockaddr *, socklen_t *);

int gt_so_getpeername(struct gt_file *, struct sockaddr *, socklen_t *);

#define gt_so_socket(fpp, domain, type, flags, ipproto) \
	gt_so_socket6(fpp, 0, domain, type, flags, ipproto)

#endif // GBTCP_SOCKET_H
