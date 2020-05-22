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
#define SYSCTL_TCP_FIN_TIMEOUT "tcp.fin_timeout"

#define GT_CTL_INET_RX_CKSUM_OFFLOAD "inet.rx_cksum_offload"
#define GT_CTL_INET_TX_CKSUM_OFFLOAD "inet.tx_cksum_offload"

#define GT_CTL_SOCK_LIST "sock.list"

struct sysctl_conn {
	void (*sccn_close_fn)(struct sysctl_conn *);
	struct fd_event *sccn_event;
	int sccn_accept_conn;
	int sccn_peer_pid;
};

typedef int (*sysctl_f)(struct sysctl_conn *, void *,
	const char *, struct strbuf *);
typedef int (*sysctl_list_next_f)(void *, int);
typedef int (*sysctl_list_f)(void *, int, const char *, struct strbuf *);

int sysctl_mod_init(void **);
int sysctl_mod_attach(void *);
int sysctl_root_init();
void sysctl_mod_deinit(void *);
void sysctl_mod_detach();

void sysctl_root_deinit();

void sysctl_make_sockaddr_un(struct sockaddr_un *, int);

int sysctl_read_file(const char *);

int sysctl_conn_fd(struct sysctl_conn *);
int sysctl_conn_open(struct sysctl_conn **, int);
void sysctl_conn_close(struct sysctl_conn *);

int sysctl_connect(int);
int sysctl_bind(const struct sockaddr_un *, int);
int sysctl_send_req(int, const char *, const char *);
int sysctl_recv_rpl(int, char *);
int sysctl_req(int, const char *, char *, const char *);

void sysctl_add(const char *, int, void *, void (*)(void *), sysctl_f);

void sysctl_add_intfn(const char *, int mode,
	int (*)(const long long *, long long *), int, int);

void sysctl_add_int(const char *, int, int *, int, int);
void sysctl_add_int64(const char *, int, int64_t *, int64_t, int64_t);
void sysctl_add_uint64(const char *, int, uint64_t *, int64_t, int64_t);

void sysctl_add_list(const char *, int, void *,
	sysctl_list_next_f, sysctl_list_f);

int sysctl_del(const char *);

int sysctl_delf(const char *, ...)
	__attribute__((format(printf, 1, 2)));

#endif // GBTCP_SYSCTL_H
