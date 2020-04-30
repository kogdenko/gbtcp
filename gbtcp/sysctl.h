/* GPL2 license */
#ifndef GBTCP_SYSCTL_H
#define GBTCP_SYSCTL_H

#include "log.h"

#define SYSCTL_RD 0
#define SYSCTL_LD 1
#define SYSCTL_WR 2

#define GT_CTL_UNSUB 0
#define GT_CTL_SUB 1

#define SYSCTL_FILE_FIRST_FD "file.first_fd"
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
#define GT_CTL_SOCK_LIST "sock.list"

struct strbuf;

typedef int (*sysctl_f)(struct log *log, void *udata, int eno, char *old);

typedef int (*sysctl_node_f)(struct log *log, void *udata, const char *new,
	struct strbuf *out);

typedef int (*sysctl_list_next_f)(void *udata, int id);

typedef int (*sysctl_list_f)(void *udata, int id, const char *new,
	struct strbuf *out);

typedef void (*sysctl_sub_f)(int pid, int action);

extern sysctl_sub_f sysctl_sub_fn;

int sysctl_mod_init(struct log *, void **);
int sysctl_mod_attach(struct log *, void *);
void sysctl_mod_deinit(struct log *, void *);
void sysctl_mod_detach(struct log *);

int sysctl_read_file(struct log *log, const char *path);

int usysctl(struct log *log, int pid, const char *path,
	char *old, int cnt, const char *new);

int usysctl_r(struct log *log, int pid, const char *path,
	void *udata, sysctl_f fn, const char *new);

int sysctl_bind(struct log *log, int pid);

void sysctl_unbind();

void sysctl_add(struct log *, const char *, int, void *,
	void (*)(void *), sysctl_node_f fn);

void sysctl_add_intfn(struct log *, const char *, int mode,
	int (*intfn)(const long long *, long long *), int, int);

void sysctl_add_int(struct log *log, const char *, int,	int *, int, int);

void sysctl_add_int64(struct log *log, const char *path, int mode,
	int64_t *ptr, int64_t min, int64_t max);

void sysctl_add_uint64(struct log *, const char *, int,
	uint64_t *, int64_t, int64_t);

void sysctl_add_list(struct log *, const char *, int, void *,
	sysctl_list_next_f, sysctl_list_f);

int sysctl_del(struct log *, const char *);

int sysctl_delf(struct log *, const char *, ...)
	__attribute__((format(printf, 2, 3)));

#endif /* GBTCP_SYSCTL_H */
