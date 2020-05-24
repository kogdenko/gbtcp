#ifndef GBTCP_TCP_H
#define GBTCP_TCP_H

#include "file.h"
#include "timer.h"
#include "sockbuf.h"
#include "htable.h"

struct gt_tcpcb;

struct socb {
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
#define so_blocked so_file.fl_blocked
#define so_service_id so_file.fl_mbuf.mb_service_id
	struct htable_bucket *so_bucket;
	union {
		uint64_t so_flags;
		struct {
			u_int so_err : 4;
			u_int so_ipproto : 2;
			u_int so_binded : 1;
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
			u_int so_retx : 1;
			u_int so_retxed : 1;
			u_int so_swndup : 1;
			u_int so_ntx_tries : 3;
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
	struct dlist so_bind_list;
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


int tcp_mod_init(void **);
int tcp_mod_attach(void *);
int tcp_mod_service_init(struct service *);
void tcp_mod_deinit(void *);
void tcp_mod_detach();
void tcp_mod_service_deinit(struct service *);

int so_get(int, struct gt_sock **);
int so_get_fd(struct gt_sock *);

int gt_sock_get_eno(struct gt_sock *so);

short so_get_events(struct file *fp);

void so_get_socb(struct gt_sock *so, struct socb *);

int gt_sock_nread(struct file *fp);

int so_in(int ipproto, struct sock_tuple *so_tuple, struct gt_tcpcb *tcb,
	void *payload);

int so_in_err(int ipproto, struct sock_tuple *so_tuple, int eno);

void sock_tx_flush();

int so_socket(int domain, int type, int flags, int proto);

int so_connect(struct gt_sock *so, const struct sockaddr_in *f_addr_in,
	struct sockaddr_in *l_addr_in);

int so_bind(struct gt_sock *, const struct sockaddr_in *);

int so_listen(struct gt_sock *, int);

int so_accept(struct gt_sock *, struct sockaddr *, socklen_t *, int);

void so_close(struct gt_sock *);

int so_recvfrom(struct gt_sock *, const struct iovec *, int,
	int, struct sockaddr *, socklen_t *);

int so_sendto(struct gt_sock *, const struct iovec *, int, int, be32_t, be16_t);

int gt_sock_ioctl(struct file *fp, unsigned long request, uintptr_t arg);

int so_getsockopt(struct gt_sock *, int, int, void *, socklen_t *);
int so_setsockopt(struct gt_sock *, int, int, const void *, socklen_t);

int so_getpeername(struct gt_sock *, struct sockaddr *, socklen_t *);

#endif // GBTCP_TCP_H
