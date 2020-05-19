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
#define SYSCTL_CONTROLLER_SERVICE_INIT "controller.service.init"
#define SYSCTL_ROUTE "route"
#define SYSCTL_ROUTE_MONITOR "route.monitor"
#define SYSCTL_ROUTE_RSS_QID "route.rss.qid"
#define SYSCTL_ROUTE_IF_LIST "route.if.list"
#define SYSCTL_ROUTE_IF_ADD "route.if.add"
#define SYSCTL_ROUTE_IF_DEL "route.if.del"
#define SYSCTL_ROUTE_ADDR_LIST "route.addr.list"
#define SYSCTL_ROUTE_ROUTE_LIST "route.route.list"

#define GT_CTL_INET_RX_CKSUM_OFFLOAD "inet.rx_cksum_offload"
#define GT_CTL_INET_TX_CKSUM_OFFLOAD "inet.tx_cksum_offload"

#define GT_CTL_SOCK_LIST "sock.list"

struct sysctl_conn {
	void (*sccn_close_fn)(struct log *, struct sysctl_conn *);
	struct fd_event *sccn_event;
	int sccn_accept_conn;
	int sccn_peer_pid;
};

typedef int (*sysctl_f)(struct log *, struct sysctl_conn *, void *,
	const char *, struct strbuf *);
typedef int (*sysctl_list_next_f)(void *, int);
typedef int (*sysctl_list_f)(void *, int, const char *, struct strbuf *);

int sysctl_mod_init(struct log *, void **);
int sysctl_mod_attach(struct log *, void *);
int sysctl_root_init(struct log *);
void sysctl_mod_deinit(struct log *, void *);
void sysctl_mod_detach(struct log *);

void sysctl_root_deinit(struct log *);

void sysctl_make_sockaddr_un(struct sockaddr_un *, int);

int sysctl_read_file(struct log *, const char *);

int sysctl_conn_fd(struct sysctl_conn *);
int sysctl_conn_open(struct log *, struct sysctl_conn **, int);
void sysctl_conn_close(struct log *, struct sysctl_conn *);

int sysctl_connect(struct log *, int);
int sysctl_can_connect(struct log *, int);
int sysctl_bind(struct log *, const struct sockaddr_un *, int);
int sysctl_send_req(struct log *, int, const char *, const char *);
int sysctl_recv_rpl(struct log *, int, char *);
int sysctl_req(struct log *, int, const char *, char *, const char *);

void sysctl_add(struct log *, const char *, int, void *,
	void (*)(void *), sysctl_f);

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
