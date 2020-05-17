#ifndef GBTCP_TCP_H
#define GBTCP_TCP_H

#include "file.h"
#include "timer.h"
#include "sockbuf.h"

#define GT_SOCK_GRACEFULL 0
#define GT_SOCK_RESET 1

struct gt_tcpcb;
struct file;
struct route_if;

struct gt_sockcb {
	int socb_fd;
	int socb_flags;
	int socb_ipproto;
	int socb_state;
	be32_t socb_laddr;
	be32_t socb_faddr;
	be16_t socb_lport;
	be16_t socb_fport;
	int socb_acceptq_len;
	int socb_incompleteq_len;
	int socb_backlog;
};

struct gt_sock {
	struct file so_file;
#define so_list so_file.fl_mbuf.mb_list
	union {
		uint64_t so_flags;
		struct {
			u_int so_err : 4;
			u_int so_binded : 1;
			u_int so_hashed : 1;
			u_int so_proto : 2;
			// TCP
			u_int so_is_listen : 1;
			u_int so_passive_open : 1;
			u_int so_accepted : 1;
			u_int so_ack : 1;
			u_int so_rst : 1;
			u_int so_reuseaddr : 1;
			u_int so_reuseport : 1;
			u_int so_state : 4;
			u_int so_wprobe : 1;
			u_int so_rexmit : 1;
			u_int so_rexmited : 1;
			u_int so_swndup : 1;
			u_int so_nr_rexmit_tries : 3;
			u_int so_dont_frag : 1;
			u_int so_wshut : 1;
			u_int so_rshut : 1;
			u_int so_rsyn : 1;
			u_int so_rfin : 1;
			u_int so_ssyn : 1;
			u_int so_ssyn_acked : 1;
			u_int so_sfin : 1;
			u_int so_sfin_sent : 1;
			u_int so_sfin_acked : 1;
			u_int so_nagle : 1;
			u_int so_nagle_acked : 1;
		};
	};
	struct dlist so_bindl;
	struct sock_tuple so_tuple;
	be32_t so_next_hop;
	uint16_t so_lmss;
	uint16_t so_rmss;
	struct timer so_timer;
	struct timer so_timer_delack;
	union {
		struct {
			uint32_t so_rseq;
			uint32_t so_sack;
			uint16_t so_ssnt;
			uint16_t so_swnd;
			uint16_t so_rwnd;
			uint16_t so_rwnd_max;
			uint16_t so_ip_id;
			struct dlist so_acceptl;
			struct dlist so_txl;
		};
		struct {
			// Listen
			struct dlist so_incompleteq;
			struct dlist so_completeq;
			int so_backlog;
			int so_acceptq_len;
		};
	};
	struct gt_sock *so_listen;
	struct sockbuf so_rcvbuf;
	union {
		struct sockbuf so_sndbuf; // TCP
		struct sockbuf so_msgbuf; // UDP
	};
};

extern void (*gt_sock_no_opened_fn)();
extern int gt_sock_nr_opened;
extern struct dlist gt_sock_binded[65536];

#define GT_SOCK_FOREACH_BINDED(so) \
	for (int GT_UNIQV(i) = 0; \
	     GT_UNIQV(i) < ARRAY_SIZE(gt_sock_binded); \
	     GT_UNIQV(i)++) \
		DLIST_FOREACH(so, gt_sock_binded + GT_UNIQV(i), so_bindl)

int tcp_mod_init(struct log *, void **);
int tcp_mod_attach(struct log *, void *);
int tcp_mod_service_init(struct log *, struct proc *);
void tcp_mod_deinit(struct log *, void *);
void tcp_mod_detach(struct log *);
void tcp_mod_service_deinit(struct log *, struct proc *);

int gt_sock_get(int fd, struct file **fpp);

int gt_sock_get_eno(struct gt_sock *so);

short gt_sock_get_events(struct file *fp);

void gt_sock_get_sockcb(struct gt_sock *so, struct gt_sockcb *socb);

int gt_sock_nread(struct file *fp);

int gt_sock_in(int ipproto, struct sock_tuple *so_tuple, struct gt_tcpcb *tcb,
	void *payload);

void gt_sock_in_err(int ipproto, struct sock_tuple *so_tuple, int eno);

void sock_tx_flush();

int gt_sock_socket(struct log *log, int fd,
	int domain, int type, int flags, int proto);

int gt_sock_connect(struct file *fp, const struct sockaddr_in *f_addr_in,
	struct sockaddr_in *l_addr_in);

int gt_sock_bind(struct file *fp, const struct sockaddr_in *addr);

int gt_sock_listen(struct file *fp, int backlog);

int gt_sock_accept(struct file *fp, struct sockaddr *addr,
	socklen_t *addrlen, int flags);

void gt_sock_close(struct file *fp, int how);

int gt_sock_recvfrom(struct file *fp, const struct iovec *iov, int iovcnt,
	int flags, struct sockaddr *addr, socklen_t *addrlen);

int gt_sock_sendto(struct file *fp, const struct iovec *iov, int iovcnt,
	int flags, be32_t daddr, be16_t dport);

int gt_sock_ioctl(struct file *fp, unsigned long request, uintptr_t arg);

int gt_sock_getsockopt(struct file *fp, int level, int optname,
	void *optval, socklen_t *optlen);

int gt_sock_setsockopt(struct file *fp, int level, int optname,
	const void *optval, socklen_t optlen);

int gt_sock_getpeername(struct file *fp, struct sockaddr *addr,
	socklen_t *addrlen);

#endif /* GBTCP_TCP_H */
