#ifndef GBTCP_CTL_H
#define GBTCP_CTL_H

#include "subr.h"

#define GT_CTL_RD 0
#define GT_CTL_LD 1
#define GT_CTL_WR 2

#define GT_CTL_UNSUB 0
#define GT_CTL_SUB 1

#define GT_CTL_FILE_FIRST_FD "file.first_fd"
#define GT_CTL_INET_RX_CKSUM_OFFLOAD "inet.rx_cksum_offload"
#define GT_CTL_INET_TX_CKSUM_OFFLOAD "inet.tx_cksum_offload"
#define GT_CTL_ROUTE_MONITOR "route.monitor"
#define GT_CTL_ROUTE_RSS_KEY "route.rss.key"
#define GT_CTL_ROUTE_RSS_QUEUE_ID "route.rss.queue.id"
#define GT_CTL_ROUTE_RSS_QUEUE_CNT "route.rss.queue.cnt"
#define GT_CTL_ROUTE_PORT_PAIRITY "route.port_pairity"
#define GT_CTL_ROUTE_IF_LIST "route.if.list"
#define GT_CTL_ROUTE_IF_ADD "route.if.add"
#define GT_CTL_ROUTE_IF_DEL "route.if.del"
#define GT_CTL_ROUTE_ADDR_LIST "route.addr.list"
#define GT_CTL_ROUTE_ADDR_ADD "route.addr.add"
#define GT_CTL_ROUTE_ADDR_DEL "route.addr.del"
#define GT_CTL_ROUTE_ROUTE_LIST "route.route.list"
#define GT_CTL_ROUTE_ROUTE_ADD "route.route.add"
#define GT_CTL_ROUTE_ROUTE_DEL "route.route.del"
#define GT_CTL_SERVICE_ADD "service.add"
#define GT_CTL_SERVICE_DEL "service.del"
#define GT_CTL_SERVICE_LIST "service.list"
#define GT_CTL_SERVICE_STATUS "service.status"
#define GT_CTL_SERVICE_CHILD_CLOSE_LISTEN_SOCKS \
	"service.child_close_listen_socks"
#define GT_CTL_SERVICE_POLLING "service.polling"
#define GT_CTL_SOCK_LIST "sock.list"

struct gt_strbuf;

typedef int (*gt_ctl_f)(struct gt_log *log, void *udata, int eno, char *old);

typedef int (*gt_ctl_node_f)(struct gt_log *log, void *udata, const char *new,
	struct gt_strbuf *out);

typedef int (*gt_ctl_list_next_f)(void *udata, int id);

typedef int (*gt_ctl_list_f)(void *udata, int id, const char *new,
	struct gt_strbuf *out);

typedef void (*gt_ctl_sub_f)(int pid, int action);

extern gt_ctl_sub_f gt_ctl_sub_fn;

int gt_ctl_mod_init();

void gt_ctl_mod_deinit();

int gt_ctl_read_file(struct gt_log *log);

int gt_ctl(struct gt_log *log, int pid, const char *path,
	char *old, int cnt, const char *new);

int gt_ctl_r(struct gt_log *log, int pid, const char *path,
	void *udata, gt_ctl_f fn, const char *new);

int gt_ctl_me(struct gt_log *log, const char *path,
	const char *new, struct gt_strbuf *old);

int gt_ctl_get_pids(int *pids, int cnt);

int gt_ctl_bind(struct gt_log *log, int pid);

void gt_ctl_unbind();

int gt_ctl_binded_pid(struct gt_log *log);

int gt_ctl_sub(struct gt_log *log, void (*close_fn)());

void gt_ctl_unsub(struct gt_log *log, int pid);

void gt_ctl_unsub_me();

int gt_ctl_sync(struct gt_log *log, const char *path);

int gt_ctl_syncf(struct gt_log *log, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

void gt_ctl_add(struct gt_log *log, const char *path, int mode, void *udata,
	void (*free_fn)(void *), gt_ctl_node_f fn);

void gt_ctl_add_intfn(struct gt_log *log, const char *path, int mode,
	int (*intfn)(const long long *, long long *), int min, int max);

void gt_ctl_add_int(struct gt_log *log, const char *path, int mode,
	int *ptr, int min, int max);

void gt_ctl_add_int64(struct gt_log *log, const char *path, int mode,
	int64_t *ptr, int64_t min, int64_t max);

void gt_ctl_add_uint64(struct gt_log *log, const char *path, int mode,
	uint64_t *ptr, int64_t min, int64_t max);

void gt_ctl_add_list(struct gt_log *log, const char *path, int mode,
	void *udata, gt_ctl_list_next_f next_fn, gt_ctl_list_f fn);

int gt_ctl_del(struct gt_log *log, const char *path);

int gt_ctl_delf(struct gt_log *log, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

#endif /* GBTCP_CTL_H */
