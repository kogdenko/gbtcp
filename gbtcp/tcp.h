#ifndef GBTCP_TCP_H
#define GBTCP_TCP_H

#include "file.h"
#include "timer.h"
#include "sockbuf.h"
#include "htable.h"

#define SO_IPPROTO_UDP 0
#define SO_IPPROTO_TCP 1

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

struct sock {
	struct file so_file;
#define so_blocked so_file.fl_blocked
#define so_referenced so_file.fl_referenced
#define so_service_id so_file.fl_service_id
	union {
		uint64_t so_flags;
		struct {
			u_int so_err : 4;
			u_int so_ipproto : 2;
			u_int so_binded : 1;
			u_int so_is_attached : 1;
			u_int so_processing : 1;
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
			u_int so_tx_timo : 1;
			u_int so_swndup : 1;
			u_int so_ntries : 3;
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
	struct dlist so_attached_list;
	struct dlist so_binded_list;
	be32_t so_laddr;
	be32_t so_faddr;
	be32_t so_lport;
	be32_t so_fport;
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
			struct dlist so_accept_list;
			struct dlist so_tx_list;
		};
		struct {
			// Listen
			struct dlist so_incompleteq;
			struct dlist so_completeq;
			int so_backlog;
			int so_acceptq_len;
		};
	};
	struct sock *so_listen;
	struct sockbuf so_rcvbuf;
	union {
		struct sockbuf so_sndbuf; // TCP
		struct sockbuf so_msgbuf; // UDP
	};
};

#define SO_FOREACH_BINDED(so) \
	for (int UNIQV(i) = 0; UNIQV(i) < EPHEMERAL_PORT_MAX; ++UNIQV(i)) \
		DLIST_FOREACH_RCU(so, \
			&so_get_binded_bucket(UNIQV(i))->htb_head, \
		        so_binded_list)

int tcp_mod_init();
int tcp_mod_service_init(struct service *);
void tcp_mod_deinit();
void tcp_mod_service_deinit(struct service *);

int so_get(int, struct sock **);
int so_get_fd(struct sock *);

struct htable_bucket *so_get_binded_bucket(uint16_t);

int sock_get_eno(struct sock *so);

short so_get_events(struct file *fp);

void so_get_socb(struct sock *so, struct socb *);

int sock_nread(struct file *fp);

int so_in(int, struct in_context *, be32_t, be32_t, be16_t, be16_t);
int so_in_err(int, struct in_context *, be32_t, be32_t, be16_t, be16_t);

void sock_tx_flush();

int so_socket6(struct sock **, int, int, int, int, int);
#define so_socket(pso, domain, type, flags, ipproto) \
	so_socket6(pso, 0, domain, type, flags, ipproto)

int so_connect(struct sock *so, const struct sockaddr_in *f_addr_in,
	struct sockaddr_in *l_addr_in);

int so_bind(struct sock *, const struct sockaddr_in *);

int so_listen(struct sock *, int);

int so_accept(struct sock **, struct sock *,
	struct sockaddr *, socklen_t *, int);

void so_close(struct sock *);

int so_recvfrom(struct sock *, const struct iovec *, int, int,
	struct sockaddr *, socklen_t *);

int so_recvfrom_zerocopy(struct sock *, struct iovec *, int,
	struct sockaddr *, socklen_t *);

int so_recv_drain(struct sock *, int);

int so_sendto(struct sock *, const struct iovec *, int, int, be32_t, be16_t);

int sock_ioctl(struct file *fp, unsigned long request, uintptr_t arg);

int so_getsockopt(struct sock *, int, int, void *, socklen_t *);
int so_setsockopt(struct sock *, int, int, const void *, socklen_t);

int so_getpeername(struct sock *, struct sockaddr *, socklen_t *);

#endif // GBTCP_TCP_H
