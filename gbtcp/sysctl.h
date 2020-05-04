// GPL2 license
#ifndef GBTCP_SYSCTL_H
#define GBTCP_SYSCTL_H

#include "log.h"
#include "sockbuf.h"

#define SYSCTL_RD 0
#define SYSCTL_LD 1
#define SYSCTL_WR 2

#define SYSCTL_PATH GT_PREFIX"/sock"
#define SYSCTL_CONTROLLER_PATH SYSCTL_PATH"/controller.sock"

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

struct sysctl_conn {
	void (*sccn_close_fn)(struct log *, struct sysctl_conn *);
	int (*sccn_accept_fn)(struct log *, struct sysctl_conn *);
	struct gt_fd_event *sccn_event;
};

struct strbuf;

typedef int (*sysctl_f)(struct log *, void *, int, char *);
typedef int (*sysctl_node_f)(struct log *, void *, const char *,
	struct strbuf *);
typedef int (*sysctl_list_next_f)(void *, int);
typedef int (*sysctl_list_f)(void *, int, const char *, struct strbuf *out);

int sysctl_mod_init(struct log *, void **);
int sysctl_mod_attach(struct log *, void *);
int sysctl_proc_init(struct log *, struct proc *);
void sysctl_mod_deinit(struct log *, void *);
void sysctl_mod_detach(struct log *);

void sysctl_make_sockaddr_un(struct sockaddr_un *, int);

int sysctl_read_file(struct log *, const char *);

int sysctl_bind(struct log *, const struct sockaddr_un *);
int sysctl_conn_open(struct log *, struct sysctl_conn *, int);
int sysctl_conn_accept(struct log *, struct sysctl_conn *, int *);
void sysctl_conn_close(struct log *, struct sysctl_conn *);

void sysctl_add(struct log *, const char *, int, void *,
	void (*)(void *), sysctl_node_f);

void sysctl_add_intfn(struct log *, const char *, int mode,
	int (*intfn)(const long long *, long long *), int, int);

void sysctl_add_int(struct log *log, const char *, int,	int *, int, int);

void sysctl_add_int64(struct log *, const char *, int, int64_t *,
	int64_t, int64_t);

void sysctl_add_uint64(struct log *, const char *, int,
	uint64_t *, int64_t, int64_t);

void sysctl_add_list(struct log *, const char *, int, void *,
	sysctl_list_next_f, sysctl_list_f);

int sysctl_del(struct log *, const char *);

int sysctl_delf(struct log *, const char *, ...)
	__attribute__((format(printf, 2, 3)));

#endif // GBTCP_SYSCTL_H
