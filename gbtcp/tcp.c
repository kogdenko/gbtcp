// TODO:
// 1) del ack: with a stream of full-sized incoming segments,
//    ACK responses must be sent for every second segment.
#include "tcp.h"
#include "log.h"
#include "sys.h"
#include "strbuf.h"
#include "timer.h"
#include "htable.h"
#include "gbtcp.h"
#include "ctl.h"
#include "inet.h"
#include "fd_event.h"
#include "file.h"
#include "sockbuf.h"

#define GT_SO_IPPROTO_UDP 0
#define GT_SO_IPPROTO_TCP 1

#define GT_TCP_FLAG_FOREACH(x) \
	x(GT_TCP_FLAG_FIN, 'F') \
	x(GT_TCP_FLAG_SYN, 'S') \
	x(GT_TCP_FLAG_RST, 'R') \
	x(GT_TCP_FLAG_PSH, 'P') \
	x(GT_TCP_FLAG_ACK, '.') \
	x(GT_TCP_FLAG_URG, 'U') 

#define GT_TCP_LOG_NODE_FOREACH(x) \
	x(mod_init) \
	x(mod_deinit) \
	x(rcvbuf_add) \
	x(rcvbuf_pop) \
	x(sndbuf_add) \
	x(sndbuf_pop) \
	x(new) \
	x(del) \
	x(connect) \
	x(in) \
	x(in_err) \
	x(tcp_set_state) \
	x(tcp_snd) \
	x(tcp_rcv) \
	x(tcp_rcv_syn) \
	x(tcp_process_ack) \
	x(tcp_timeout_rexmit) \
	x(udp_rcvbuf_pop)

enum gt_sock_error {
	GT_SOCK_OK,
	GT_SOCK_EINPROGRESS,
	GT_SOCK_ENETUNREACH,
	GT_SOCK_ETIMEDOUT,
	GT_SOCK_ECONNREFUSED,
	GT_SOCK_ECONNRESET,
	GT_SOCK_EADDRINUSE,
	GT_SOCK_EADDRNOTAVAIL,
	GT_SOCK_EHOSTUNREACH,
	GT_SOCK_EMSGSIZE,
	GT_SOCK_E_MAX
};

struct gt_sockbuf_msg {
	uint16_t sobm_trunc;
	uint16_t sobm_len;
	be16_t sobm_fport;
	be32_t sobm_faddr;
};

int gt_sock_nr_opened;
void (*gt_sock_no_opened_fn)();
struct gt_list_head gt_sock_binded[65536];
	
static gt_htable_t gt_sock_htable;
static gt_time_t gt_tcp_fin_timeout;
static struct gt_log_scope this_log;
GT_TCP_LOG_NODE_FOREACH(GT_LOG_NODE_STATIC);

// subr
static const char *gt_tcp_flags_str(struct gt_strbuf *sb, int proto,
	uint8_t tcp_flags);

static const char *gt_log_add_tcp_flags(int proto, uint8_t tcp_flags)
	__attribute__((unused));

static const char *gt_log_add_sock(struct gt_sock *so)
	__attribute__((unused));

int gt_calc_rss_q_id(struct gt_sock_tuple *so_tuple);

static void gt_set_sockaddr(struct sockaddr *addr, socklen_t *addrlen,
	be32_t s_addr, be16_t port);

// tcp
static uint32_t gt_tcp_diff_seq(uint32_t start, uint32_t end);

static uint16_t gt_tcp_emss(struct gt_sock *so);

static void gt_tcp_set_risn(struct gt_sock *so, uint32_t seq);

static void gt_tcp_set_rmss(struct gt_sock *so, struct gt_tcp_opts *opts);

static int gt_tcp_set_swnd(struct gt_sock *so);

static int gt_tcp_set_state(struct gt_sock *so, int state);

static int gt_tcp_rcvbuf_recv(struct gt_sock *so, const struct iovec *iov,
	int iovcnt, int peek);

static void gt_tcp_rcvbuf_set_max(struct gt_sock *so, int max);

static void gt_tcp_open(struct gt_sock *so);

static void gt_tcp_close(struct gt_sock *so);

static void gt_tcp_close_not_accepted(struct gt_list_head *q);

static void gt_tcp_reset(struct gt_sock *so, struct gt_tcpcb *tcb);

static void gt_tcp_wshut(struct gt_sock *so);

static void gt_tcp_delack(struct gt_sock *so);

static void gt_tcp_timer_set_rexmit(struct gt_sock *so);

static int gt_tcp_timer_set_wprobe(struct gt_sock *so);

static void gt_tcp_timer_set_tcp_fin_timeout(struct gt_sock *so);

static void gt_tcp_timeout_delack(struct gt_timer *timer);

static void gt_tcp_timeout_rexmit(struct gt_timer *timer);

static void gt_tcp_timeout_wprobe(struct gt_timer *timer);

static void gt_tcp_timeout_tcp_fin_timeout(struct gt_timer *timer);

static void gt_tcp_rcv_syn_sent(struct gt_sock *so, struct gt_tcpcb *tcb);

static void gt_tcp_rcv_syn(struct gt_sock *lso, struct gt_sock_tuple *so_tuple,
	struct gt_tcpcb *tcb);

static void gt_tcp_rcv_data(struct gt_sock *so, struct gt_tcpcb *tcb,
	uint8_t *payload);

static void gt_tcp_rcv_established(struct gt_sock *so, struct gt_tcpcb *tcb,
	void *payload);

static void gt_tcp_rcv_open(struct gt_sock *so, struct gt_tcpcb *tcb,
	void *payload);

static int gt_tcp_is_in_order(struct gt_sock *so, struct gt_tcpcb *tcb);

static int gt_tcp_process_badack(struct gt_sock *so, uint32_t acked);

static void gt_tcp_establish(struct gt_sock *so);

static int gt_tcp_enter_TIME_WAIT(struct gt_sock *so);

static void gt_tcp_process_TIME_WAIT(struct gt_sock *so);

static int gt_tcp_process_ack(struct gt_sock *so, struct gt_tcpcb *tcb);

static int gt_tcp_process_ack_complete(struct gt_sock *so);

static void gt_tcp_into_sndq(struct gt_sock *so);

static void gt_tcp_into_ackq(struct gt_sock *so);

static void gt_tcp_into_rstq(struct gt_sock *so);

static int gt_tcp_send(struct gt_sock *so, const struct iovec *iov,
	int iovcnt, int flags);

static int gt_tcp_sender(struct gt_sock *so, int cnt);

static int gt_tcp_xmit_established(struct gt_route_if *ifp,
	struct gt_dev_pkt *pkt, struct gt_sock *so);

static int gt_tcp_xmit(struct gt_route_if *ifp, struct gt_dev_pkt *pkt,
	struct gt_sock *so);

static int gt_tcp_fill(struct gt_sock *so, struct gt_eth_hdr *eth_h,
	struct gt_tcpcb *tcb, uint8_t tcp_flags, u_int len);

static void gt_tcp_flush_if(struct gt_route_if *ifp);

// udp
static int gt_udp_rcvbuf_recv(struct gt_sock *so, const struct iovec *iov,
	int iovcnt, struct sockaddr *addr, socklen_t *addrlen, int peek);

int gt_udp_sendto(struct gt_sock *so, const struct iovec *iov, int iovcnt,
	int flags, be32_t faddr, be16_t fport);

// sock
static int gt_sock_err_from_errno(int eno);

static const char *gt_sock_str(struct gt_strbuf *sb, struct gt_sock *so);

static void gt_sock_dec_nr_opened();

static uint32_t gt_sock_tuple_hash(struct gt_sock_tuple *so_tuple);

static uint32_t gt_sock_hash(void *elem);

static void gt_sock_set_err(struct gt_sock *so, int err);

static int gt_sock_clear_eno(struct gt_sock *so);

static void gt_sock_htable_add(struct gt_sock *so);

static int gt_sock_fd(struct gt_sock *so);

static struct gt_sock *gt_sock_find(int proto, struct gt_sock_tuple *so_tuple);

static struct gt_sock *gt_sock_get_binded(int proto,
	struct gt_sock_tuple *so_tuple);

static int gt_sock_bind_ephemeral_port(struct gt_sock *so,
	struct gt_route_if_addr *ifa);

static int gt_sock_connect_check_state(struct gt_sock *so);

static int gt_sock_route(struct gt_sock *so, struct gt_route_entry *r);

static int gt_sock_in_txq(struct gt_sock *so);

static void gt_sock_add_txq(struct gt_route_if *ifp, struct gt_sock *so);

static void gt_sock_del_txq(struct gt_sock *so);

static void gt_sock_wakeup(struct gt_sock *so, short revents);

static int gt_sock_is_closed(struct gt_sock *so);

static void gt_sock_open(struct gt_sock *so);

static struct gt_sock *gt_sock_new(struct gt_log *log, int fd, int so_proto);

static void gt_sock_del(struct gt_sock *so);

static int gt_sock_rcvbuf_add(struct gt_sock *so, const void *src, int cnt,
	int all);

static int gt_sock_on_rcv(struct gt_sock *so, void *buf, int len,
	struct gt_sock_tuple *so_tuple);

static int gt_sock_xmit(struct gt_route_if *ifp, struct gt_dev_pkt *pkt,
	struct gt_sock *so);

static void gt_sock_xmit_data(struct gt_route_if *ifp, struct gt_dev_pkt *pkt,
	struct gt_sock *so, uint8_t tcp_flags, u_int len);

static int gt_sock_sndbuf_add(struct gt_sock *so, const void *src, int cnt);

static void gt_sock_sndbuf_pop(struct gt_sock *so, int cnt);

static struct gt_file *gt_sock_next(int fd);

static int gt_sock_ctl_sock_list_next(void *udata, int fd);

static int gt_sock_ctl_sock_list(void *udata, int fd, const char *new,
	struct gt_strbuf *out);

static void gt_sock_ctl_init_sock_list(struct gt_log *log);

static int gt_sock_ctl_tcp_fin_timeout(const long long *new, long long *old);

#define GT_SOCK_ALIVE(so) ((so)->so_file.fl_mbuf.mb_used)

#define GT_TCP_FLAG_ADD(val, name) \
	if (tcp_flags & val) { \
		gt_strbuf_add_ch(sb, name); \
	}

int
gt_tcp_mod_init()
{
	int i, rc;
	struct gt_log *log;

	gt_log_scope_init(&this_log, "tcp");
	GT_TCP_LOG_NODE_FOREACH(GT_LOG_NODE_INIT);
	log = GT_LOG_TRACE1(mod_init);
	gt_sock_nr_opened = 0;
	rc = gt_htable_create(log, &gt_sock_htable, 2048, gt_sock_hash);
	if (rc) {
		return rc;
	}
	for (i = 0; i < GT_ARRAY_SIZE(gt_sock_binded); ++i) {
		gt_list_init(gt_sock_binded + i);
	}
	gt_sock_ctl_init_sock_list(log);
	gt_tcp_fin_timeout = GT_SEC;
	gt_ctl_add_intfn(log, "tcp.fin_timeout", GT_CTL_WR,
	                 &gt_sock_ctl_tcp_fin_timeout, 1, 24 * 60 * 60);
	return 0;
}

void
gt_tcp_mod_deinit(struct gt_log *log)
{
//	struct gt_file *fp;

	log = GT_LOG_TRACE(log, mod_deinit);
	// TODO: delete all
	//GT_FILE_FOREACH(fp) {
	//	gt_file_close(fp, GT_SOCK_RESET);
	//}
	gt_ctl_del(log, "tcp.fin_timeout");
	gt_htable_free(&gt_sock_htable);
	gt_ctl_del(log, GT_CTL_SOCK_LIST);
	gt_log_scope_deinit(log, &this_log);
}

int
gt_sock_get(int fd, struct gt_file **fpp)
{
	int rc;

	rc = gt_file_get(fd, fpp);
	if (rc) {
		return rc;
	}
	if ((*fpp)->fl_type != GT_FILE_SOCK) {
		return -ENOTSOCK;
	}
	return 0;
}

int
gt_sock_get_eno(struct gt_sock *so)
{
	switch (so->so_err) {
	case GT_SOCK_OK: return 0;
	case GT_SOCK_EINPROGRESS: return EINPROGRESS;
	case GT_SOCK_ENETUNREACH: return ENETUNREACH;
	case GT_SOCK_ETIMEDOUT: return ETIMEDOUT;
	case GT_SOCK_ECONNREFUSED: return ECONNREFUSED;
	case GT_SOCK_ECONNRESET: return ECONNRESET;
	case GT_SOCK_EADDRINUSE: return EADDRINUSE;
	case GT_SOCK_EADDRNOTAVAIL: return EADDRNOTAVAIL;
	case GT_SOCK_EHOSTUNREACH: return EHOSTUNREACH;
	case GT_SOCK_EMSGSIZE: return EMSGSIZE;
	default:
		GT_BUG;
		return EINVAL;
	}
}

short
gt_sock_get_events(struct gt_file *fp)
{
	short events;
	struct gt_sock *so;

	so = (struct gt_sock *)fp;
	if (so->so_err && so->so_err != GT_SOCK_EINPROGRESS) {
		events = POLLERR;
	} else {
		events = 0;
	}
	switch (so->so_proto) {
	case GT_SO_IPPROTO_TCP:
		switch (so->so_state) {
		case GT_TCP_S_CLOSED:
			break;
		case GT_TCP_S_LISTEN:
			if (!gt_list_empty(&so->so_completeq)) {
				events |= POLLIN;
			}
			break;
		default:
			if (so->so_rshut || so->so_rfin || gt_sock_nread(fp)) {
				events |= POLLIN;
			}
			if (so->so_state >= GT_TCP_S_ESTABLISHED &&
			    !gt_sockbuf_full(&so->so_sndbuf)) {
				events |= POLLOUT;
			}
			break;
		}
		break;
	case GT_SO_IPPROTO_UDP:
		if (so->so_tuple.sot_faddr != 0) {
			events |= POLLOUT;
		}
		if (gt_sock_nread(fp)) {
			events |= POLLIN;
		}
		break;
	default:
		GT_BUG;
	}	
	return events;
}

void
gt_sock_get_sockcb(struct gt_sock *so, struct gt_sockcb *socb)
{
	socb->socb_fd = gt_sock_fd(so);
	socb->socb_flags = gt_file_cntl(&so->so_file, F_GETFL, 0);
	socb->socb_state = so->so_state;
	socb->socb_laddr = so->so_tuple.sot_laddr;
	socb->socb_faddr = so->so_tuple.sot_faddr;
	socb->socb_lport = so->so_tuple.sot_lport;
	socb->socb_fport = so->so_tuple.sot_fport;
	socb->socb_ipproto = so->so_proto == GT_SO_IPPROTO_TCP ?
	                                     IPPROTO_TCP : IPPROTO_UDP;
	if (so->so_is_listen) {
		socb->socb_acceptq_len = so->so_acceptq_len;
		socb->socb_incompleteq_len = gt_list_size(&so->so_incompleteq);
		socb->socb_backlog = so->so_backlog;
	} else {
		socb->socb_acceptq_len = 0;
		socb->socb_incompleteq_len = 0;
		socb->socb_backlog = 0;
	}
}

int
gt_sock_nread(struct gt_file *fp)
{
	struct gt_sock *so;

	so = (struct gt_sock *)fp;
	return so->so_rcvbuf.sob_len;
}

int
gt_sock_in(int ipproto, struct gt_sock_tuple *so_tuple, struct gt_tcpcb *tcb,
	void *payload)
{
	int proto;
	struct gt_sock *so;

	switch (ipproto) {
	case IPPROTO_UDP:
		proto = GT_SO_IPPROTO_UDP;
		break;
	case IPPROTO_TCP:
		gt_tcps.tcps_rcvtotal++;
		proto = GT_SO_IPPROTO_TCP;
		break;
	default:
		return GT_INET_BYPASS;
	}
#if 0
	int x = calc_rss_q_id(so_tuple);
	GT_ASSERT(x == route_rss_q_id);
#endif
	so = gt_sock_find(proto, so_tuple);
	if (so == NULL) {
		so = gt_sock_get_binded(proto, so_tuple);
	}
	if (so == NULL) {
		GT_DBG(in, 0, "bypass; flags=%s, tuple=%s:%hu>%s:%hu",
		       gt_log_add_tcp_flags(proto, tcb->tcb_flags),	    
		       gt_log_add_ip_addr(AF_INET, &so_tuple->sot_laddr),
		       GT_NTOH16(so_tuple->sot_lport),
		       gt_log_add_ip_addr(AF_INET, &so_tuple->sot_faddr),
		       GT_NTOH16(so_tuple->sot_fport));
		return GT_INET_BYPASS;
	}
	GT_DBG(in, 0, "hit; flags=%s, len=%d, seq=%u, ack=%u, fd=%d",
	       gt_log_add_tcp_flags(proto, tcb->tcb_flags),
	       tcb->tcb_len, tcb->tcb_seq, tcb->tcb_ack,
	       gt_sock_fd(so));
	switch (proto) {
	case GT_SO_IPPROTO_UDP:
		gt_sock_on_rcv(so, payload, tcb->tcb_len, so_tuple);
		break;
	case GT_SO_IPPROTO_TCP:
		switch (so->so_state) {
		case GT_TCP_S_CLOSED:
			return GT_INET_OK;
		case GT_TCP_S_LISTEN:
			gt_tcp_rcv_syn(so, so_tuple, tcb);
			break;
		case GT_TCP_S_TIME_WAIT:
			gt_tcp_process_TIME_WAIT(so);
			break;
		default:
			gt_tcp_rcv_open(so, tcb, payload);
			break;
		}
	}
	return GT_INET_OK;
}

void
gt_sock_in_err(int ipproto, struct gt_sock_tuple *so_tuple, int eno)
{
	int err, proto;
	struct gt_sock *so;

	if (ipproto == IPPROTO_UDP) {
		proto = GT_SO_IPPROTO_UDP;
	} else {
		proto = GT_SO_IPPROTO_TCP;
	}
	so = gt_sock_find(proto, so_tuple);
	if (so == NULL) {
		so = gt_sock_get_binded(proto, so_tuple);
		if (so == NULL) {
			return;
		}
	}
	GT_DBG(in_err, 0, "hit; fd=%d, err=%d", gt_sock_fd(so), eno);
	err = gt_sock_err_from_errno(eno);
	GT_ASSERT(err);
	gt_sock_set_err(so, err);
}

void
gt_sock_tx_flush()
{
	struct gt_route_if *ifp;

	GT_ROUTE_IF_FOREACH(ifp) {
		gt_tcp_flush_if(ifp);
	}
}

int
gt_sock_socket(struct gt_log *log, int fd,
	int domain, int type, int flags, int proto)
{
	int so_fd, so_proto;
	struct gt_sock *so;

	if (domain != AF_INET) {
		return -EINVAL;
	}
	switch (type) {
	case SOCK_STREAM:
		if (proto != 0 && proto != IPPROTO_TCP) {
			return -EINVAL;
		}
		so_proto = GT_SO_IPPROTO_TCP;
		break;
	case SOCK_DGRAM:
		if (proto != 0 && proto != IPPROTO_UDP) {
			return -EINVAL;
		}
		so_proto = GT_SO_IPPROTO_UDP;
		break;
	default:
		return -EINVAL;
	}
	so = gt_sock_new(log, fd, so_proto);
	if (so == NULL) {
		return -ENOMEM;
	}
	if (flags & SOCK_NONBLOCK) {
		so->so_file.fl_blocked = 0;
	}
	so->so_file.fl_opened = 1;
	so_fd = gt_sock_fd(so);
	return so_fd;
}

int
gt_sock_connect(struct gt_file *fp, const struct sockaddr_in *faddr_in,
	struct sockaddr_in *laddr_in)
{
	int rc;
	struct gt_route_entry r;
	struct gt_sock *so;

	so = (struct gt_sock *)fp;
	if (faddr_in->sin_port == 0 || faddr_in->sin_addr.s_addr == 0) {
		return -EINVAL;
	}
	rc = gt_sock_connect_check_state(so);
	if (rc) {
		return rc;
	}
	GT_ASSERT(!gt_sock_in_txq(so));
	if (so->so_tuple.sot_lport) {
		return -ENOTSUP;
	}
	so->so_tuple.sot_faddr = faddr_in->sin_addr.s_addr;
	so->so_tuple.sot_fport = faddr_in->sin_port;
	rc = gt_sock_route(so, &r);
	if (rc) {
		return rc;
	}
	so->so_tuple.sot_laddr = r.rt_ifa->ria_addr.ipa_4;
	rc = gt_sock_bind_ephemeral_port(so, r.rt_ifa);
	if (rc < 0) {
		return rc;
	}
	GT_DBG(connect, 0, "ok; tuple=%s:%hu>%s:%hu, fd=%d",
	       gt_log_add_ip_addr(AF_INET, &so->so_tuple.sot_laddr),
	       GT_NTOH16(so->so_tuple.sot_lport),
	       gt_log_add_ip_addr(AF_INET, &so->so_tuple.sot_faddr),
	       GT_NTOH16(so->so_tuple.sot_fport),
	       gt_sock_fd(so));
	gt_sock_htable_add(so);
	laddr_in->sin_family = AF_INET;
	laddr_in->sin_addr.s_addr = so->so_tuple.sot_laddr;
	laddr_in->sin_port = so->so_tuple.sot_lport;
	if (so->so_proto == GT_SO_IPPROTO_UDP) {
		return 0;
	}
	gt_tcp_open(so);
	gt_tcp_set_swnd(so);
	gt_tcp_set_state(so, GT_TCP_S_SYN_SENT);
	gt_tcp_into_sndq(so);
	return -EINPROGRESS;
}

int
gt_sock_bind(struct gt_file *fp, const struct sockaddr_in *addr)
{
	be32_t laddr;
	be16_t lport;
	struct gt_sock *so;

	so = (struct gt_sock *)fp;
	if (so->so_state != GT_TCP_S_CLOSED) {
		return -EINVAL;
	}
	GT_ASSERT(so->so_binded == 0);
	GT_ASSERT(so->so_hashed == 0);
	laddr = addr->sin_addr.s_addr;
	lport = addr->sin_port;
	if (lport == 0 && laddr == 0) {
		return -EINVAL;
	}
	if (so->so_tuple.sot_laddr != 0 || so->so_tuple.sot_lport != 0) {
		return -EINVAL;
	}
	GT_ASSERT(so->so_state == GT_TCP_S_CLOSED);
	so->so_tuple.sot_laddr = laddr;
	so->so_tuple.sot_lport = lport;
	so->so_binded = 1;
	GT_LIST_INSERT_TAIL(gt_sock_binded + GT_NTOH16(lport),
	                    so, so_bindl);
	return 0;
}

int 
gt_sock_listen(struct gt_file *fp, int backlog)
{
	struct gt_sock *lso;

	lso = (struct gt_sock *)fp;
	if (lso->so_state == GT_TCP_S_LISTEN) {
		return 0;
	}
	if (lso->so_proto != GT_SO_IPPROTO_TCP) {
		return -ENOTSUP;
	}
	if (lso->so_state != GT_TCP_S_CLOSED) {
		return -EINVAL;
	}
	if (lso->so_tuple.sot_lport == 0) {
		return -EADDRINUSE;
	}
	gt_list_init(&lso->so_incompleteq);
	gt_list_init(&lso->so_completeq);
	lso->so_acceptq_len = 0;
	lso->so_backlog = backlog > 0 ? backlog : 32;
	gt_tcp_set_state(lso, GT_TCP_S_LISTEN);
	lso->so_is_listen = 1;
	return 0;
}

int
gt_sock_accept(struct gt_file *fp, struct sockaddr *addr, socklen_t *addrlen,
	int flags)
{
	int fd;
	struct gt_sock *lso, *so;

	lso = (struct gt_sock *)fp;
	if (lso->so_state != GT_TCP_S_LISTEN) {
		return -EINVAL;
	}
	if (gt_list_empty(&lso->so_completeq)) {
		return -EAGAIN;
	}
	GT_ASSERT(lso->so_acceptq_len);
	so = GT_LIST_FIRST(&lso->so_completeq, struct gt_sock, so_acceptl);
	GT_ASSERT(so->so_state >= GT_TCP_S_ESTABLISHED);
	GT_ASSERT(so->so_accepted == 0);
	so->so_accepted = 1;
	GT_LIST_REMOVE(so, so_acceptl);
	lso->so_acceptq_len--;
	gt_set_sockaddr(addr, addrlen, so->so_tuple.sot_faddr,
	                so->so_tuple.sot_fport);
	if (flags & SOCK_NONBLOCK) {
		so->so_file.fl_blocked = 0;
	}
	so->so_file.fl_opened = 1;
	fd = gt_sock_fd(so);
	gt_tcps.tcps_accepts++;
	return fd;
}

void
gt_sock_close(struct gt_file *fp, int how)
{
	struct gt_sock *so;

	so = (struct gt_sock *)fp;
	GT_ASSERT(so->so_file.fl_opened == 0);
	switch (so->so_state) {
	case GT_TCP_S_CLOSED:
		gt_sock_del(so);
		break;
	case GT_TCP_S_LISTEN:
		gt_tcp_close_not_accepted(&so->so_incompleteq);
		gt_tcp_close_not_accepted(&so->so_completeq);
		gt_tcp_set_state(so, GT_TCP_S_CLOSED);
		break;
	case GT_TCP_S_SYN_SENT:
		if (gt_sock_in_txq(so)) {
			gt_sock_del_txq(so);
		}
		gt_tcp_set_state(so, GT_TCP_S_CLOSED);
		break;
	default:
		if (how == GT_SOCK_GRACEFULL) {
			so->so_rshut = 1;
			so->so_wshut = 1;
			if (so->so_state >= GT_TCP_S_ESTABLISHED) {
				gt_tcp_wshut(so);	
			}
		} else {
			gt_tcp_into_rstq(so);
			gt_tcp_set_state(so, GT_TCP_S_CLOSED);
		}
		break;
	}
}

int
gt_sock_recvfrom(struct gt_file *fp, const struct iovec *iov, int iovcnt,
	int flags, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc, peek;
	struct gt_sock *so;

	so = (struct gt_sock *)fp;
	if (flags & ~MSG_PEEK) {
		return -ENOTSUP;
	}
	if (so->so_err) {
		rc = -gt_sock_clear_eno(so);
		return rc;
	}
	if (so->so_rshut) {
		return 0;
	}
	if (so->so_proto == GT_SO_IPPROTO_TCP) {
		if (so->so_state < GT_TCP_S_ESTABLISHED) {
			return -EAGAIN;
		}
	}
	peek = flags & MSG_PEEK;
	switch (so->so_proto) {
	case GT_SO_IPPROTO_UDP:
		rc = gt_udp_rcvbuf_recv(so, iov, iovcnt, addr, addrlen, peek);
		break;
	case GT_SO_IPPROTO_TCP:
		rc = gt_tcp_rcvbuf_recv(so, iov, iovcnt, peek);
		if (rc == -EAGAIN) {
			if (so->so_rfin) {
				rc = 0;
			}
		}
		break;
	default:
		rc = 0;
		GT_BUG;
		break;
	}
	return rc;
}

int
gt_sock_sendto(struct gt_file *fp, const struct iovec *iov, int iovcnt,
	int flags, be32_t daddr, be16_t dport)
{
	int rc;
	struct gt_sock *so;

	so = (struct gt_sock *)fp;
	if (flags & ~(MSG_NOSIGNAL)) {
		return -ENOTSUP;
	}
	switch (so->so_proto) {
	case GT_SO_IPPROTO_UDP:
		rc = gt_udp_sendto(so, iov, iovcnt, flags, daddr, dport);
		break;
	case GT_SO_IPPROTO_TCP:
		rc = gt_tcp_send(so, iov, iovcnt, flags);
		break;
	default:
		rc = -ENOTSUP;
		break;
	}
	return rc;
}

#ifdef __linux__
int
gt_sock_ioctl(struct gt_file *fp, unsigned long request, uintptr_t arg)
{
	return -ENOTSUP;
}
#else /* __linux */
int
gt_sock_ioctl(struct gt_file *fp, unsigned long request, uintptr_t arg)
{
	int v;
	struct gt_sock *so;

	so = (struct gt_sock *)fp;
	switch (request) {
	case FIONSPACE:
		v = 0;
		if (so->so_wshut == 0) {
			// TODO: real buffer size
			v = 100;
		}
		*((int *)arg) = v;
		return 0;
	default:
		return -ENOTSUP;
	}
}
#endif /* __linux__ */

int
gt_sock_getsockopt(struct gt_file *fp, int level, int optname, void *optval,
	socklen_t *optlen)
{
	struct gt_sock *so;

	so = (struct gt_sock *)fp;
	switch (level) {
	case IPPROTO_TCP:
		switch (optname) {
		case TCP_NODELAY:
			if (*optlen < sizeof(int)) {
				return -EINVAL;
			}
			*optlen = sizeof(int);
			*((int *)optval) = so->so_nagle;
			return 0;
		}
		break;
	case SOL_SOCKET:
		switch (optname) {
		case SO_ERROR:
			if (*optlen < sizeof(int)) {
				return -EINVAL;
			}
			*optlen = sizeof(int);
			*((int *)optval) = gt_sock_clear_eno(so);
			return 0;
		}
	}
	return -ENOPROTOOPT;
}

int
gt_sock_setsockopt(struct gt_file *fp, int level, int optname, const void *optval,
	socklen_t optlen)
{
	int optint;
	struct gt_sock *so;

	so = (struct gt_sock *)fp;
	switch (level) {
	case IPPROTO_TCP:
		if (so->so_proto != GT_SO_IPPROTO_TCP) {
			return -ENOPROTOOPT;
		}
		switch (optname) {
		case TCP_NODELAY:
			if (optlen != sizeof(int)) {
				return -EINVAL;
			}		
			optint = (*(int *)optval) == 0 ? 0 : 1;
			if (so->so_nagle != optint) {
				so->so_nagle_acked = 1;
			}
			so->so_nagle = optint;
			return 0;
		case TCP_KEEPIDLE:
			// TODO:
			return 0;
		case TCP_KEEPINTVL:
			// TODO:
			return 0;
		case TCP_KEEPCNT:
			return 0;
		case GT_TCP_CORK:
			return 0;
		}
		break;
	case SOL_SOCKET:
		switch (optname) {
		case SO_REUSEADDR:
			if (optlen != sizeof(int)) {
				return -EINVAL;
			}
			so->so_reuseaddr = *(int *)optval;
			return 0;
		case SO_REUSEPORT:
			if (optlen != sizeof(int)) {
				return -EINVAL;
			}
			so->so_reuseport = *(int *)optval;
			return 0;
		case SO_KEEPALIVE:
			// TODO
			return 0;
		case SO_LINGER:
			// TODO:
			return 0;
		}
		break;
	}
	return -ENOPROTOOPT;
}

int
gt_sock_getpeername(struct gt_file *fp, struct sockaddr *addr,
	socklen_t *addrlen)
{
	struct gt_sock *so;

	so = (struct gt_sock *)fp;
	if (so->so_tuple.sot_faddr == 0) {
		return -ENOTCONN;
	}
	if (so->so_proto == GT_SO_IPPROTO_TCP) {
		if (so->so_state < GT_TCP_S_ESTABLISHED) {
			return -ENOTCONN;
		}
	}
	gt_set_sockaddr(addr, addrlen, so->so_tuple.sot_faddr,
	                so->so_tuple.sot_fport);
	return 0;
}

// static
static const char *
gt_tcp_flags_str(struct gt_strbuf *sb, int proto, uint8_t tcp_flags)
{
	const char *s;

	if (proto == GT_SO_IPPROTO_UDP) {
		return "UDP";
	}
	GT_TCP_FLAG_FOREACH(GT_TCP_FLAG_ADD);
	s = gt_strbuf_cstr(sb);
	return s;
}

int
gt_calc_rss_q_id(struct gt_sock_tuple *so_tuple)
{
	uint32_t h;
	struct gt_sock_tuple tmp;

	tmp.sot_laddr = so_tuple->sot_faddr;
	tmp.sot_faddr = so_tuple->sot_laddr;
	tmp.sot_lport = so_tuple->sot_fport;
	tmp.sot_fport = so_tuple->sot_lport;
	h = gt_toeplitz_hash((uint8_t *)&tmp, sizeof(tmp), gt_route_rss_key);
	h &= 0x0000007F;
	return h % gt_route_rss_q_cnt;
}

void
gt_set_sockaddr(struct sockaddr *addr, socklen_t *addrlen,
	be32_t s_addr, be16_t port)
{
	struct sockaddr_in *addr_in;

	if (addrlen != NULL) {
		if (*addrlen >= sizeof(*addr_in)) {
			addr_in = (struct sockaddr_in *)addr;
			addr_in->sin_family = AF_INET;
			addr_in->sin_addr.s_addr = s_addr;
			addr_in->sin_port = port;
		}
		*addrlen = sizeof(*addr_in);
	}
}

// tcp
static const char *
gt_log_add_tcp_flags(int proto, uint8_t tcp_flags)
{
	return gt_tcp_flags_str(gt_log_buf_alloc_space(), proto, tcp_flags);
}

static const char *
gt_log_add_sock(struct gt_sock *so)
{
	return gt_sock_str(gt_log_buf_alloc_space(), so);
}

static uint32_t
gt_tcp_diff_seq(uint32_t start, uint32_t end)
{
	return end - start;
}

// Effective mss
static uint16_t
gt_tcp_emss(struct gt_sock *so)
{
	uint16_t emss;

	GT_ASSERT(so->so_rmss);
	GT_ASSERT(so->so_lmss);
	emss = GT_MIN(so->so_lmss, so->so_rmss);
	GT_ASSERT(emss >= GT_IP4_MTU_MIN - 40);
	return emss;
}

static void
gt_tcp_set_risn(struct gt_sock *so, uint32_t seq)
{
	so->so_rsyn = 1;
	so->so_rseq = seq + 1;
}

// Receive mss
static void
gt_tcp_set_rmss(struct gt_sock *so, struct gt_tcp_opts *opts)
{
	if (opts->tcpo_flags & (1 << GT_TCP_OPT_MSS)) {
		so->so_rmss = GT_MAX(GT_IP4_MTU_MIN - 20, opts->tcpo_mss);
	} else {
		so->so_rmss = 536;
	}
}

// Sending window
static int
gt_tcp_set_swnd(struct gt_sock *so)
{
	unsigned int emss, new_swnd, old_swnd, thresh;

	emss = so->so_rmss ? gt_tcp_emss(so) : so->so_lmss;
	if (so->so_rcvbuf.sob_max < so->so_rcvbuf.sob_len) {
		so->so_swnd = 0;
		return 0;
	}
	new_swnd = so->so_rcvbuf.sob_max - so->so_rcvbuf.sob_len;
	if (so->so_swnd > new_swnd) {
		so->so_swnd = new_swnd;
		return 0;
	}
	thresh = GT_MIN(emss, so->so_rcvbuf.sob_max >> 1);
	old_swnd = so->so_swnd;
	if (new_swnd - old_swnd >= thresh) {
		so->so_swnd = new_swnd;
		if (old_swnd < thresh) {
			so->so_swndup = 1;
			return 1;
		}
	}
	return 0;
}

static int
gt_tcp_set_state(struct gt_sock *so, int state)
{
	GT_ASSERT(GT_SOCK_ALIVE(so));
	GT_ASSERT(state < GT_TCP_NSTATES);
	GT_ASSERT(state != so->so_state);
	GT_DBG(tcp_set_state, 0, "hit; state %s->%s, fd=%d",
	       gt_tcp_state_str(so->so_state), gt_tcp_state_str(state),
	       gt_sock_fd(so));
	if (state != GT_TCP_S_CLOSED) {
		GT_ASSERT(state > so->so_state);
		gt_tcps.tcps_states[state]++;
	}
	if (so->so_state != GT_TCP_S_CLOSED) {
		gt_tcps.tcps_states[so->so_state]--;
	}
	so->so_state = state;
	switch (so->so_state) {
	case GT_TCP_S_ESTABLISHED:
		gt_tcp_establish(so);
		break;
	case GT_TCP_S_CLOSED:
		gt_tcp_close(so);
		if (so->so_file.fl_opened == 0) {
			gt_sock_del(so);
			return -1;
		}
		break;
	}
	return 0;
}

static int
gt_tcp_rcvbuf_recv(struct gt_sock *so, const struct iovec *iov, int iovcnt,
	int peek)
{
	int rc, buflen;

	buflen = so->so_rcvbuf.sob_len;
	if (buflen == 0) {
		return -EAGAIN;
	}
	rc = gt_sockbuf_readv4(&so->so_rcvbuf, iov, iovcnt, peek);
	GT_DBG(rcvbuf_pop, 0, "hit; fd=%d, peek=%d, cnt=%d, buflen=%d",
	       gt_sock_fd(so), peek, rc, so->so_rcvbuf.sob_len);
	if (buflen != so->so_rcvbuf.sob_len) {
		if (gt_tcp_set_swnd(so)) {
			gt_tcp_into_ackq(so);
		}
	}
	return rc;
}

static void
gt_tcp_rcvbuf_set_max(struct gt_sock *so, int max)
{
	gt_sockbuf_set_max(&so->so_rcvbuf, max);
	gt_tcp_set_swnd(so);
}

static void
gt_tcp_open(struct gt_sock *so)
{
	gt_sock_open(so);
	so->so_nagle = 1;
	so->so_nagle_acked = 1;
	// Must not overlap in 2 minutes (MSL)
	// Increment 1 seq at 16 ns (like in Linux)
	so->so_sack = gt_nsec >> 6;
	so->so_ssnt = 0;
	so->so_swnd = 0;
	so->so_rwnd = 0;
	so->so_rwnd_max = 0;
	so->so_ip_id = 1;
}

static void
gt_tcp_close(struct gt_sock *so)
{
	so->so_ssnt = 0;
	gt_timer_del(&so->so_timer);
	gt_timer_del(&so->so_timer_delack);
	gt_sockbuf_free(&so->so_rcvbuf);
	gt_sockbuf_free(&so->so_sndbuf);
	if (so->so_passive_open) {
		if (so->so_accepted == 0) { 
			GT_ASSERT(so->so_listen != NULL);
			so->so_listen->so_acceptq_len--;
			GT_LIST_REMOVE(so, so_acceptl);
			so->so_listen = NULL;
		}
	}
}

static void
gt_tcp_close_not_accepted(struct gt_list_head *q)
{
	struct gt_sock *so;

	while (!gt_list_empty(q)) {
		so = GT_LIST_FIRST(q, struct gt_sock, so_acceptl);
		GT_ASSERT(so->so_file.fl_opened == 0);
		so->so_listen = NULL;
		gt_sock_close(&so->so_file, GT_SOCK_GRACEFULL);
	}
}

static void
gt_tcp_reset(struct gt_sock *so, struct gt_tcpcb *tcb)
{
	so->so_ssnt = 0;
	so->so_sack = tcb->tcb_ack;
	so->so_rseq = tcb->tcb_seq;
	gt_tcp_into_rstq(so);
	gt_sock_del(so);
}

static void
gt_tcp_wshut(struct gt_sock *so)
{
	GT_ASSERT(so->so_state >= GT_TCP_S_ESTABLISHED);
	if (so->so_sfin) {
		return;
	}
	switch (so->so_state) {
	case GT_TCP_S_ESTABLISHED:
		gt_tcp_set_state(so, GT_TCP_S_FIN_WAIT_1);
		break;
	case GT_TCP_S_CLOSE_WAIT:
		gt_tcp_set_state(so, GT_TCP_S_LAST_ACK);
		break;
	default:
		GT_BUG;
		break;
	}
	so->so_sfin = 1;
	gt_tcp_into_sndq(so);
}

static void
gt_tcp_delack(struct gt_sock *so)
{
	if (gt_timer_is_running(&so->so_timer_delack)) {
		gt_timer_del(&so->so_timer_delack);
		gt_tcp_into_ackq(so);
	}
	gt_timer_set(&so->so_timer_delack, 200 * GT_MSEC,
	             gt_tcp_timeout_delack);
}

#if 0
static void
gt_tcp_timeout_TIME_WAIT(struct gt_timer *timer)
{
	struct gt_sock *so;

	so = gt_container_of(timer, struct gt_sock, timer);
	gt_tcp_set_state(so, TCP_S_CLOSED);
}
#endif

static void
gt_tcp_timer_set_rexmit(struct gt_sock *so)
{
	uint64_t expires;

	GT_ASSERT(so->so_sfin_acked == 0);
	if (so->so_rexmit == 0) {
		so->so_rexmit = 1;
		so->so_wprobe = 0;
		so->so_nr_rexmit_tries = 0;
	}
	if (so->so_state < GT_TCP_S_ESTABLISHED) {
		expires = GT_SEC;
	} else {
		expires = 500 * GT_MSEC;
	}
	expires <<= so->so_nr_rexmit_tries;
	gt_timer_set(&so->so_timer, expires, gt_tcp_timeout_rexmit);
}

static int
gt_tcp_timer_set_wprobe(struct gt_sock *so)
{
	uint64_t expires;

	if (so->so_rexmit) {
		return 0;
	}
	if (gt_timer_is_running(&so->so_timer)) {
		return 0;
	}
	expires = 10 * GT_SEC;
	gt_timer_set(&so->so_timer, expires, gt_tcp_timeout_wprobe);
	return 1;
}

static void
gt_tcp_timer_set_tcp_fin_timeout(struct gt_sock *so)
{
	GT_ASSERT(so->so_rexmit == 0);
	GT_ASSERT(so->so_wprobe == 0);
	GT_ASSERT(!gt_timer_is_running(&so->so_timer));
	gt_timer_set(&so->so_timer, gt_tcp_fin_timeout,
	             gt_tcp_timeout_tcp_fin_timeout); 
}

static void
gt_tcp_timeout_delack(struct gt_timer *timer)
{
	struct gt_sock *so;

	so = gt_container_of(timer, struct gt_sock, so_timer_delack);
	gt_tcp_into_ackq(so);
}

static void
gt_tcp_timeout_rexmit(struct gt_timer *timer)
{
	struct gt_sock *so;

	so = gt_container_of(timer, struct gt_sock, so_timer);
	GT_ASSERT(GT_SOCK_ALIVE(so));
	GT_ASSERT(so->so_sfin_acked == 0);
	GT_ASSERT(so->so_rexmit);
	so->so_ssnt = 0;
	so->so_sfin_sent = 0;
	gt_tcps.tcps_rexmttimeo++;
	GT_DBG(tcp_timeout_rexmit, 0,
	    "hit; fd=%d, state=%s",
	     gt_sock_fd(so), gt_tcp_state_str(so->so_state));
	if (so->so_nr_rexmit_tries++ > 6) {
		gt_tcps.tcps_timeoutdrop++;
		gt_sock_set_err(so, GT_SOCK_ETIMEDOUT);
		return;
	}
	// TODO: 
//	if (so->so_state == TCP_S_SYN_RCVD) {
//		cnt_tcp_timedout_syn_rcvd++;
//		gt_sock_set_err(so, GT_SOCK_ETIMEDOUT);
//		return;
//	}
	so->so_rexmited = 1;
	gt_tcp_into_sndq(so);
}

static void
gt_tcp_timeout_wprobe(struct gt_timer *timer)
{
	struct gt_sock *so;

	so = gt_container_of(timer, struct gt_sock, so_timer);
	GT_ASSERT(GT_SOCK_ALIVE(so));
	GT_ASSERT(so->so_sfin_acked == 0);
	GT_ASSERT(so->so_rexmit == 0);
	GT_ASSERT(so->so_wprobe);
	gt_tcps.tcps_sndprobe++;
	gt_tcp_into_ackq(so);
	GT_ASSERT(gt_tcp_timer_set_wprobe(so));
}

static void
gt_tcp_timeout_tcp_fin_timeout(struct gt_timer *timer)
{
	struct gt_sock *so;

	so = gt_container_of(timer, struct gt_sock, so_timer);
	gt_tcp_enter_TIME_WAIT(so);
}

static void
gt_tcp_rcv_syn_sent(struct gt_sock *so, struct gt_tcpcb *tcb)
{
	switch (tcb->tcb_flags) {
	case GT_TCP_FLAG_SYN|GT_TCP_FLAG_ACK:
		gt_tcp_set_state(so, GT_TCP_S_ESTABLISHED);
		so->so_ack = 1;
		break;
	case GT_TCP_FLAG_SYN:
		gt_tcp_set_state(so, GT_TCP_S_SYN_RCVD);
		break;
	default:
		return;
	}
	gt_tcp_set_risn(so, tcb->tcb_seq);
	gt_tcp_set_rmss(so, &tcb->tcb_opts);
	gt_tcp_into_sndq(so);
}

static void
gt_tcp_rcv_syn(struct gt_sock *lso, struct gt_sock_tuple *so_tuple,
	struct gt_tcpcb *tcb)
{
	struct gt_log *log;
	struct gt_sock *so;

	//GT_ASSERT(lso->so_acceptq_len <= lso->so_backlog);
	if (0 && lso->so_acceptq_len == lso->so_backlog) {
		gt_tcps.tcps_listendrop++;
		return;
	}
	log = GT_LOG_TRACE1(tcp_rcv_syn);
	so = gt_sock_new(log, 0, GT_SO_IPPROTO_TCP);
	if (so == NULL) {
		gt_tcps.tcps_rcvmemdrop++;
		return;
	}
	so->so_tuple = *so_tuple;
	gt_tcp_open(so);
	if (tcb->tcb_flags != GT_TCP_FLAG_SYN) {
		GT_DBG(tcp_rcv_syn, 0,
		       "not a SYN; tuple=%s:%hu>%s:%hu, lfd=%d, fd=%d",
		       gt_log_add_ip_addr(AF_INET, &so->so_tuple.sot_laddr),
		       GT_NTOH16(so->so_tuple.sot_lport),
	               gt_log_add_ip_addr(AF_INET, &so->so_tuple.sot_faddr),
		       GT_NTOH16(so->so_tuple.sot_fport),
		       gt_sock_fd(lso), gt_sock_fd(so));
		gt_tcps.tcps_badsyn++;
		gt_tcp_reset(so, tcb);
		return;
	} else {
		GT_DBG(tcp_rcv_syn, 0,
		       "ok; tuple=%s:%hu>%s:%hu, lfd=%d, fd=%d",
		       gt_log_add_ip_addr(AF_INET, &so->so_tuple.sot_laddr),
		       GT_NTOH16(so->so_tuple.sot_lport),
	               gt_log_add_ip_addr(AF_INET, &so->so_tuple.sot_faddr),
		       GT_NTOH16(so->so_tuple.sot_fport),
		       gt_sock_fd(lso), gt_sock_fd(so));
	}
	GT_LIST_INSERT_HEAD(&lso->so_incompleteq, so, so_acceptl);
	lso->so_acceptq_len++;
	so->so_passive_open = 1;
	so->so_listen = lso;
	if (lso->so_lmss) {
		so->so_lmss = lso->so_lmss;
	}
	gt_tcp_set_risn(so, tcb->tcb_seq);
	gt_tcp_set_rmss(so, &tcb->tcb_opts);
	gt_sockbuf_set_max(&so->so_sndbuf, lso->so_sndbuf.sob_max);
	gt_tcp_rcvbuf_set_max(so, lso->so_rcvbuf.sob_max);
	gt_tcp_set_swnd(so);
	gt_tcp_set_state(so, GT_TCP_S_SYN_RCVD);
	gt_tcp_into_sndq(so);
	gt_sock_htable_add(so);
}

static void
gt_tcp_rcv_data(struct gt_sock *so, struct gt_tcpcb *tcb, uint8_t *payload)
{
	int rc;
	uint32_t n, off;

	off = gt_tcp_diff_seq(tcb->tcb_seq, so->so_rseq);
	if (off == 0) {
		gt_tcps.tcps_rcvpack++;
		gt_tcps.tcps_rcvbyte += tcb->tcb_len;
		n = tcb->tcb_len;
	} else if (off == tcb->tcb_len) {
		gt_tcps.tcps_rcvduppack++;
		gt_tcps.tcps_rcvdupbyte += tcb->tcb_len;
		return;
	} else if (off > tcb->tcb_len) {
		gt_tcps.tcps_pawsdrop++;
		return;
	} else {	
		n = tcb->tcb_len - off;
		gt_tcps.tcps_rcvpartduppack++;
		gt_tcps.tcps_rcvpartdupbyte += n;
	}
	n = tcb->tcb_len - off;
	rc = gt_sock_on_rcv(so, payload, n, &so->so_tuple);
	if (rc < 0) {
		gt_tcps.tcps_rcvmemdrop++;
		return;
	} else if (rc < n) {
		gt_tcps.tcps_rcvpackafterwin++;
		gt_tcps.tcps_rcvbyteafterwin += n - rc;
	}
	if (rc > 0) {
		so->so_rseq += rc;
		gt_tcp_delack(so);
	}
}

static void
gt_tcp_rcv_established(struct gt_sock *so, struct gt_tcpcb *tcb, void *payload)
{
	int rc;

	GT_ASSERT(so->so_state >= GT_TCP_S_ESTABLISHED);
	if (so->so_rfin) {
		if (tcb->tcb_len || (tcb->tcb_flags & GT_TCP_FLAG_FIN)) {
			gt_tcp_into_ackq(so);
		}
		return;
	}
	if (tcb->tcb_len) {
		gt_tcp_rcv_data(so, tcb, payload);
	}
	if (tcb->tcb_flags & GT_TCP_FLAG_SYN) {
		gt_tcp_into_ackq(so);
	}
	if (tcb->tcb_flags & GT_TCP_FLAG_FIN) {
		so->so_rfin = 1;
		so->so_rseq++;
		gt_sock_wakeup(so, POLLIN|GT_POLLRDHUP);
		gt_tcp_into_ackq(so);
		switch (so->so_state) {
		case GT_TCP_S_ESTABLISHED:
			gt_tcp_set_state(so, GT_TCP_S_CLOSE_WAIT);
			break;
		case GT_TCP_S_FIN_WAIT_1:
			gt_tcp_set_state(so, GT_TCP_S_CLOSING);
			break;
		case GT_TCP_S_FIN_WAIT_2:
			gt_timer_del(&so->so_timer); // tcp_fin_timeout
			rc = gt_tcp_enter_TIME_WAIT(so);
			if (rc) {
				return;
			}
			break;
		}
	}
}

static void
gt_tcp_rcv_open(struct gt_sock *so, struct gt_tcpcb *tcb, void *payload)
{
	int rc;

	if (tcb->tcb_flags & GT_TCP_FLAG_RST) {
		// TODO: check seq
		gt_tcps.tcps_drops++;
		if (so->so_state < GT_TCP_S_ESTABLISHED) {
			gt_tcps.tcps_conndrops++;
			gt_sock_set_err(so, GT_SOCK_ECONNREFUSED);
		} else {
			gt_sock_set_err(so, GT_SOCK_ECONNRESET);
		}
		return;
	}
	if (so->so_rsyn) {
		rc = gt_tcp_is_in_order(so, tcb);
		if (rc == 0) {
			gt_tcp_into_ackq(so);
			return;
		}
	}
	if (tcb->tcb_flags & GT_TCP_FLAG_ACK) {
		rc = gt_tcp_process_ack(so, tcb);
		if (rc) {
			return;
		}
		so->so_rwnd = tcb->tcb_win;
		so->so_rwnd_max = GT_MAX(so->so_rwnd_max, so->so_rwnd);
	}
	switch (so->so_state) {
	case GT_TCP_S_SYN_SENT:
		gt_tcp_rcv_syn_sent(so, tcb);
		return;
	case GT_TCP_S_CLOSED:
		gt_tcps.tcps_rcvafterclose++;
		return;
	case GT_TCP_S_SYN_RCVD:
		break;
	default:
		GT_ASSERT(so->so_rsyn);
		gt_tcp_rcv_established(so, tcb, payload);
		break;
	}
	if (so->so_sfin_acked == 0) {
		gt_tcp_into_sndq(so);
	}
}

static int
gt_tcp_is_in_order(struct gt_sock *so, struct gt_tcpcb *tcb)
{
	uint32_t len, off;

	len = tcb->tcb_len;
	if (tcb->tcb_flags & (GT_TCP_FLAG_SYN|GT_TCP_FLAG_FIN)) {
		len++;
	}
	off = gt_tcp_diff_seq(tcb->tcb_seq, so->so_rseq);
	if (off > len) {
		GT_DBG(tcp_rcv, 0,
		       "out of order; flags=%s, seq=%u, len=%u, %s",
		       gt_log_add_tcp_flags(so->so_proto, tcb->tcb_flags),
		       tcb->tcb_seq, len, gt_log_add_sock(so));
		gt_tcps.tcps_rcvoopack++;
		gt_tcps.tcps_rcvoobyte += tcb->tcb_len;
		return 0;
	} else {
		return 1;
	}
}

static int
gt_tcp_process_badack(struct gt_sock *so, uint32_t acked)
{
	if (so->so_state >= GT_TCP_S_ESTABLISHED) {
		so->so_ssnt = 0;
	} else {
		// TODO
		//gt_tcp_out_rst(so, in);
	}
	if (acked > UINT32_MAX / 2) {
		gt_tcps.tcps_rcvdupack++;
	} else {
		gt_tcps.tcps_rcvacktoomuch++;
	}
	return -1;
}

static void
gt_tcp_establish(struct gt_sock *so)
{
	struct gt_sock *lso;

	gt_tcps.tcps_connects++;
	if (so->so_err == GT_SOCK_EINPROGRESS) {
		so->so_err = 0;
	}
	if (so->so_wshut) {
		gt_tcp_wshut(so);
	}
	if (so->so_passive_open && so->so_listen != NULL) {
		lso = so->so_listen;
		GT_ASSERT(lso->so_acceptq_len);
		GT_LIST_REMOVE(so, so_acceptl);
		GT_LIST_INSERT_HEAD(&lso->so_completeq, so, so_acceptl);
		gt_sock_wakeup(lso, POLLIN);
	} else {
		gt_sock_wakeup(so, POLLOUT);
	}
}

static int
gt_tcp_enter_TIME_WAIT(struct gt_sock *so)
{
	int rc;

#if 1
	rc = gt_tcp_set_state(so, GT_TCP_S_CLOSED);
	return rc;
#else
	gt_tcp_set_state(so, TCP_S_TIME_WAIT);
	gt_timer_set(&so->so_timer, 2 * MSL, gt_tcp_timeout_TIME_WAIT);
#endif
}

static void
gt_tcp_process_TIME_WAIT(struct gt_sock *so)
{
}

static int
gt_tcp_process_ack(struct gt_sock *so, struct gt_tcpcb *tcb)
{
	int rc;
	uint32_t acked;

	acked = gt_tcp_diff_seq(so->so_sack, tcb->tcb_ack);
	if (acked == 0) {
		return 0;
	}
	if (so->so_ssyn && so->so_ssyn_acked == 0) {
		acked--;
	}
	if (acked > so->so_ssnt) {
		if (so->so_sfin) {
			acked--;
		}
		if (acked > so->so_ssnt) {
			GT_DBG(tcp_process_ack, 0,
			       "bad ACK; flags=%s, ack=%u, %s",
		               gt_log_add_tcp_flags(so->so_proto,
			                            tcb->tcb_flags),
			       tcb->tcb_ack, gt_log_add_sock(so));
			rc = gt_tcp_process_badack(so, acked);
			return rc;
		}
	}
	if (so->so_state == GT_TCP_S_SYN_RCVD) {
		gt_tcp_set_state(so, GT_TCP_S_ESTABLISHED);
	}
	if (so->so_ssyn && so->so_ssyn_acked == 0) {
		so->so_ssyn_acked = 1;
		so->so_sack++;
	}
	if (acked) {
		so->so_sack += acked;
		so->so_ssnt -= acked;
		gt_sock_sndbuf_pop(so, acked);
		gt_tcps.tcps_rcvackpack++;
		gt_tcps.tcps_rcvackbyte += acked;
	}
	if (so->so_ssnt == 0) {
		rc = gt_tcp_process_ack_complete(so);
		if (rc) {
			return rc;
		}
	}
	if (so->so_sfin == 0) {
		gt_sock_wakeup(so, POLLOUT);
	}
	return 0;
}

static int
gt_tcp_process_ack_complete(struct gt_sock *so)
{
	int rc;

	so->so_rexmit = 0;
	so->so_nr_rexmit_tries = 0;
	gt_timer_del(&so->so_timer);
	so->so_nagle_acked = 1;
	if (so->so_sfin && so->so_sfin_acked == 0 &&
	    so->so_sndbuf.sob_len == 0) {
		so->so_sfin_acked = 1;
		switch (so->so_state) {
		case GT_TCP_S_FIN_WAIT_1:
			gt_tcp_timer_set_tcp_fin_timeout(so);
			gt_tcp_set_state(so, GT_TCP_S_FIN_WAIT_2);
			break;
		case GT_TCP_S_CLOSING:
			rc = gt_tcp_enter_TIME_WAIT(so);
			if (rc) {
				return rc;
			}
			break;
		case GT_TCP_S_LAST_ACK:
			gt_tcp_set_state(so, GT_TCP_S_CLOSED);
			return -1;
		default:
			GT_BUG;
			break;
		}
	}
	return 0;
}

static void
gt_tcp_into_sndq(struct gt_sock *so)
{
	int rc;
	struct gt_route_entry r;

	GT_ASSERT(GT_SOCK_ALIVE(so));
	if (!gt_sock_in_txq(so)) {
		rc = gt_sock_route(so, &r);
		if (rc != 0) {
			GT_ASSERT(0); // TODO: v0.1
			return;
		}
		gt_sock_add_txq(r.rt_ifp, so);
	}
}

static void
gt_tcp_into_ackq(struct gt_sock *so)
{
	so->so_ack = 1;
	gt_tcp_into_sndq(so);
}

static void
gt_tcp_into_rstq(struct gt_sock *so)
{
	so->so_rst = 1;
	gt_tcp_into_sndq(so);
}

int
gt_tcp_send(struct gt_sock *so, const struct iovec *iov, int iovcnt, int flags)
{
	int i, n, rc, cnt;

	if (so->so_err) {
		rc = -gt_sock_clear_eno(so);
		return rc;
	}
	if (so->so_sfin) {
		return -EPIPE;
	}
	if (so->so_state == GT_TCP_S_SYN_SENT ||
	    so->so_state == GT_TCP_S_SYN_RCVD) {
		return -EAGAIN;
	} else if (so->so_state < GT_TCP_S_ESTABLISHED) {
		if ((flags & MSG_NOSIGNAL) == 0) {
			raise(SIGPIPE);
		}
		return -EPIPE;
	}
	n = 0;
	for (i = 0; i < iovcnt; ++i) {
		cnt = iov[i].iov_len;
		if (cnt <= 0) {
			continue;
		}
		rc = gt_sock_sndbuf_add(so, iov[i].iov_base, cnt);
		if (rc < 0) {
			if (n == 0) {
				return rc;
			} else {
				break;
			}
		} else if (rc == 0) {
			if (n == 0) {
				return -EAGAIN;
			} else {
				break;
			}
		} else {
			n += rc;
		}
	}
	if (n) {
		gt_tcp_into_sndq(so);
	}
	return n;
}

static int
gt_tcp_sender(struct gt_sock *so, int cnt)
{
	int can, emss;

	GT_ASSERT(cnt);
//	return GT_MIN(cnt, tcp_emss(so));
	if (so->so_rwnd <= so->so_ssnt) {
		return 0;
	}
	emss = gt_tcp_emss(so);
	can = so->so_rwnd - so->so_ssnt;
	if (can >= emss && cnt >= emss) {
		return emss;
	}
	if (so->so_nagle_acked == 0) {
		return 0;
	}
	if (cnt <= can) {
		return cnt;
	}
	return can >= (so->so_rwnd_max >> 1) ? can : 0;
}

static int
gt_tcp_xmit_established(struct gt_route_if *ifp, struct gt_dev_pkt *pkt,
	struct gt_sock *so)
{
	int cnt, snt;
	uint8_t tcp_flags;

	if (so->so_state < GT_TCP_S_ESTABLISHED) {
		return 0;
	}
	if (so->so_sfin_acked || so->so_sfin_sent) {
		return 0;
	}
	tcp_flags = 0;
	cnt = so->so_sndbuf.sob_len - so->so_ssnt;
	if (cnt == 0) {
		snt = 0;
	} else {
		snt = gt_tcp_sender(so, cnt);
		if (snt) {
			tcp_flags = GT_TCP_FLAG_ACK;
		} else {
			if (gt_tcp_timer_set_wprobe(so)) {
				so->so_wprobe = 1;
			}
			return 0;
		}
	}
	if (snt == cnt && so->so_sfin) {
		switch (so->so_state) {
		case GT_TCP_S_ESTABLISHED:
			gt_tcp_set_state(so, GT_TCP_S_FIN_WAIT_1);
			break;
		case GT_TCP_S_CLOSE_WAIT:
			gt_tcp_set_state(so, GT_TCP_S_LAST_ACK);
			break;
		}
		so->so_sfin_sent = 1;
		tcp_flags |= GT_TCP_FLAG_FIN;
	}
	if (tcp_flags) {
		gt_sock_xmit_data(ifp, pkt, so, tcp_flags, snt);
		return 1;
	} else {
		return 0;
	}
}

//  0 - can send more
//  1 - sent all
static int
gt_tcp_xmit(struct gt_route_if *ifp, struct gt_dev_pkt *pkt, struct gt_sock *so)
{
	int rc;

	switch (so->so_state) {
	case GT_TCP_S_CLOSED:
	case GT_TCP_S_LISTEN:
		return 1;
	case GT_TCP_S_SYN_SENT:
		gt_sock_xmit_data(ifp, pkt, so, GT_TCP_FLAG_SYN, 0);
		return 1;
	case GT_TCP_S_SYN_RCVD:
		gt_sock_xmit_data(ifp, pkt, so,
		                  GT_TCP_FLAG_SYN|GT_TCP_FLAG_ACK, 0);
		return 1;
	default:
		rc = gt_tcp_xmit_established(ifp, pkt, so);
		if (rc == 0) {
			if (so->so_ack) {
				so->so_ack = 0;
				gt_sock_xmit_data(ifp, pkt, so,
				                  GT_TCP_FLAG_ACK, 0);
			}
			return 1;
		} else {
			so->so_ack = 0;
			return 0;
		}
	}
}

static int
gt_tcp_fill(struct gt_sock *so, struct gt_eth_hdr *eth_h, struct gt_tcpcb *tcb,
	uint8_t tcp_flags, u_int len)
{
	int cnt, emss, tcp_opts_len, tcp_h_len, total_len;
	void *payload;
	struct gt_ip4_hdr *ip4_h;
	struct gt_tcp_hdr *tcp_h;

	GT_ASSERT(so->so_ssnt + len <= so->so_sndbuf.sob_len);
	ip4_h = (struct gt_ip4_hdr *)(eth_h + 1);
	tcp_h = (struct gt_tcp_hdr *)(ip4_h + 1);
	tcb->tcb_opts.tcpo_flags = 0;
	if (tcp_flags & GT_TCP_FLAG_SYN) {
		tcb->tcb_opts.tcpo_flags |= (1 << GT_TCP_OPT_MSS);
		tcb->tcb_opts.tcpo_mss = so->so_lmss;
	}
	cnt = so->so_sndbuf.sob_len - so->so_ssnt;
	if (so->so_state >= GT_TCP_S_ESTABLISHED &&
		(tcp_flags & GT_TCP_FLAG_RST) == 0) {
		tcp_flags |= GT_TCP_FLAG_ACK;
		if (len == 0 && cnt && so->so_rwnd > so->so_ssnt) {
			len = GT_MIN(cnt, so->so_rwnd - so->so_ssnt);
		}
	}
	if (len) {
		GT_ASSERT(len <= cnt);
		GT_ASSERT(len <= so->so_rwnd - so->so_ssnt);
		if (so->so_ssnt + len == so->so_sndbuf.sob_len ||
		    (so->so_rwnd - so->so_ssnt) - len <= gt_tcp_emss(so)) {
			tcp_flags |= GT_TCP_FLAG_PSH;
		}
	}
	tcb->tcb_win = so->so_swnd;
	tcb->tcb_len = len;
	tcb->tcb_flags = tcp_flags;
	if (so->so_wprobe && len == 0) {
		tcb->tcb_seq = so->so_sack - 1;
	} else {
		tcb->tcb_seq = so->so_sack + so->so_ssnt;
		if (so->so_sfin_acked) {
			tcb->tcb_seq++;
		}
	}
	tcb->tcb_ack = so->so_rseq;
	tcp_opts_len = gt_tcp_opts_fill(&tcb->tcb_opts, tcp_h + 1);
	if (tcb->tcb_len) {
		emss = gt_tcp_emss(so);
		GT_ASSERT(tcp_opts_len <= emss);
		if (tcb->tcb_len + tcp_opts_len > emss) {
			tcb->tcb_len = emss - tcp_opts_len;
		}
		payload = (uint8_t *)(tcp_h + 1) + tcp_opts_len;
		gt_sockbuf_send(&so->so_sndbuf, so->so_ssnt,
		                payload, tcb->tcb_len);
	}
	tcp_h_len = sizeof(*tcp_h) + tcp_opts_len;
	total_len = sizeof(*ip4_h) + tcp_h_len + tcb->tcb_len;
	ip4_h->ip4h_ver_ihl = GT_IP4H_VER_IHL;
	ip4_h->ip4h_type_of_svc = 0;
	ip4_h->ip4h_total_len = GT_HTON16(total_len);
	ip4_h->ip4h_id = GT_HTON16(so->so_ip_id);
	ip4_h->ip4h_frag_off = 0;
	ip4_h->ip4h_ttl = 64;
	ip4_h->ip4h_proto = IPPROTO_TCP;
	ip4_h->ip4h_cksum = 0;
	ip4_h->ip4h_saddr = so->so_tuple.sot_laddr;
	ip4_h->ip4h_daddr = so->so_tuple.sot_faddr;
	tcp_h->tcph_sport = so->so_tuple.sot_lport;
	tcp_h->tcph_dport = so->so_tuple.sot_fport;
	tcp_h->tcph_seq = GT_HTON32(tcb->tcb_seq);
	tcp_h->tcph_ack = GT_HTON32(tcb->tcb_ack);
	tcp_h->tcph_data_off = tcp_h_len << 2;
	tcp_h->tcph_flags = tcb->tcb_flags;
	tcp_h->tcph_win_size = GT_HTON16(tcb->tcb_win);
	tcp_h->tcph_cksum = 0;
	tcp_h->tcph_urgent_ptr = 0;
	gt_inet_ip4_set_cksum(ip4_h, tcp_h);
	so->so_ip_id++;
	so->so_ssnt += tcb->tcb_len;
	if (tcp_flags & GT_TCP_FLAG_SYN) {
		so->so_ssyn = 1;
		GT_ASSERT(so->so_ssyn_acked == 0);
	}
	if (tcb->tcb_len || (tcp_flags & (GT_TCP_FLAG_SYN|GT_TCP_FLAG_FIN))) {
		if (so->so_rexmited) {
			so->so_rexmited = 0;
			gt_tcps.tcps_sndrexmitpack++;
			gt_tcps.tcps_sndrexmitbyte += tcb->tcb_len;
		}
		gt_tcp_timer_set_rexmit(so);
	}
	gt_timer_del(&so->so_timer_delack);
	return total_len;
}

static void
gt_tcp_flush_if(struct gt_route_if *ifp)
{
	int rc, n;
	struct gt_dev_pkt pkt;
	struct gt_sock *so;

	n = 0;
	while (!gt_list_empty(&ifp->rif_txq) && n < 128) {
		so = GT_LIST_FIRST(&ifp->rif_txq, struct gt_sock, so_txl);
		do {
			rc = gt_route_if_not_empty_txr(ifp, &pkt);
			if (rc) {
				return;
			}
			rc = gt_sock_xmit(ifp, &pkt, so);
			n++;
		} while (rc == 0);
		gt_sock_del_txq(so);
		if (gt_sock_is_closed(so)) {
			gt_sock_del(so);
		}
	}
}

static int
gt_udp_rcvbuf_recv(struct gt_sock *so, const struct iovec *iov, int iovcnt,
	struct sockaddr *addr, socklen_t *addrlen, int peek)
{
	int rc, cnt;
	struct gt_sockbuf_msg msg;

	if (so->so_msgbuf.sob_len == 0) {
		return -EAGAIN;
	}
	rc = gt_sockbuf_recv(&so->so_msgbuf, &msg, sizeof(msg), 1);
	if (rc == 0) {
		GT_ASSERT(so->so_rcvbuf.sob_len == 0);
		return 0;
	}
	GT_ASSERT(rc == sizeof(msg));
	GT_ASSERT(msg.sobm_len);
	GT_ASSERT(so->so_rcvbuf.sob_len >= msg.sobm_len);
	gt_set_sockaddr(addr, addrlen, msg.sobm_faddr, msg.sobm_fport);
	cnt = gt_sockbuf_readv(&so->so_rcvbuf, iov, iovcnt,
	                       msg.sobm_len, peek);
	GT_DBG(udp_rcvbuf_pop, 0, "hit; peek=%d, cnt=%d, buflen=%d, fd=%d",
	       peek, rc, so->so_rcvbuf.sob_len, gt_sock_fd(so));
	if (peek == 0) {
		if (msg.sobm_len > cnt) {
			msg.sobm_len -= cnt;
			rc = gt_sockbuf_rewrite(&so->so_msgbuf,
			                        &msg, sizeof(msg));
			GT_ASSERT(rc == sizeof(msg));
		} else {
			gt_sockbuf_pop(&so->so_msgbuf, sizeof(msg));
		}
	}
	return cnt;
}

int
gt_udp_sendto(struct gt_sock *so, const struct iovec *iov, int iovcnt,
	int flags, be32_t faddr, be16_t fport)
{
#if 1
	return 0;
#else
	u_int i, n, rc, cnt, off, len, frag, total_len, mtu;
	void *payload;
	const uint8_t *buf;
	struct netmap_ring *txr;
	struct gt_dev *dev;
	struct ip4_hdr *ip4_h;
	struct udp_hdr *udp_h;
	struct gt_dev_pkt pkt;
	struct msg_hdr *hdr;

	if (iovcnt > 1) {
		return -ENOTSUP;
	}
	if (iovcnt == 0) {
		cnt = 0;
		buf = NULL;
	} else {
		cnt = iov[0].iov_len;
		buf = iov[0].iov_base;
	}
	if (so->so_tuple.sot_faddr != 0) {
		faddr = so->so_tuple.sot_faddr;
		fport = so->so_tuple.sot_fport;
	}
	if (faddr == 0 || fport == 0) {
		return -EDESTADDRREQ;
	}
	rc = gt_sock_route(so, &dev);
	if (rc) {
		return rc;
	}
	txr = not_empty_txr(dev);
	if (txr == NULL) {
		return -ENOBUFS;
	}
	GT_ASSERT(so->so_lmss == 1460);
	n = 0;
	off = 0;
	mtu = so->so_lmss + 40;
	total_len = sizeof(*ip4_h) + sizeof(*udp_h) + cnt;
	while (off < cnt) {
		if (n == 0) {
			off += (mtu - sizeof(*ip4_h) - sizeof(*udp_h));
		} else {
			off += (mtu - sizeof(*ip4_h));
		}
		n++;
	}
	if (n > nm_ring_space(txr)) {
		return -ENOBUFS;
	}
	off = 0;
	for (i = 0; i < n; ++i) {
		GT_ASSERT(cnt > off);
		txr_slot(&pkt, txr);
		hdr = (struct msg_hdr *)pkt.data;
		GT_ASSERT(hdr != NULL);
		hdr->msg = MSG_DATA;
		hdr->flags = 0;
		hdr->proto = FILE_IPPROTO_UDP;
		hdr->eth_type = ETH_TYPE_IP4_BE;
		frag = n > 1 && i < n - 1 ? IPV4_FLAG_MF : 0;
		ip4_h = (struct ip4_hdr *)(hdr + 1);
		ip4_h->ver_ihl = IP4_VER_IHL;
		ip4_h->type_of_svc = 0;
		ip4_h->total_len = GT_HTON16(total_len);
		ip4_h->id = 0;
		ip4_h->frag_off = ip4_hdr_frag_off(off, frag);
		ip4_h->ttl = 64;
		ip4_h->proto = IPPROTO_UDP;
		ip4_h->cksum = 0;
		ip4_h->saddr = so->so_tuple.sot_laddr;
		ip4_h->daddr = faddr;
		pkt.len = sizeof(*hdr) + sizeof(*ip4_h);
		len = mtu - sizeof(*ip4_h);
		if (i == 0) {
			udp_h = (struct udp_hdr *)(ip4_h + 1);
			udp_h->sport = so->so_tuple.sot_lport;
			udp_h->dport = fport;
			udp_h->cksum = 0;
			udp_h->len = GT_HTON16(sizeof(*udp_h) + cnt);
			pkt.len += sizeof(*udp_h);
			payload = udp_h + 1;
			len -= sizeof(*udp_h);
		} else {
			payload = ip4_h + 1;
		}
		if (len > cnt - off) {
			len = cnt - off;
		}
		GT_PKT_COPY(payload, buf + off, len);
		pkt.len += len;
		off += len;
		transmit(dev, &pkt);
	}
	return cnt;
#endif
}

// sock
static int
gt_sock_err_from_errno(int eno)
{
	switch (eno) {
	case EINPROGRESS: return GT_SOCK_EINPROGRESS;
	case ENETUNREACH: return GT_SOCK_ENETUNREACH;
	case ETIMEDOUT: return GT_SOCK_ETIMEDOUT;
	case ECONNREFUSED: return GT_SOCK_ECONNREFUSED;
	case ECONNRESET: return GT_SOCK_ECONNRESET;
	case EADDRINUSE: return GT_SOCK_EADDRINUSE;
	case EADDRNOTAVAIL: return GT_SOCK_EADDRNOTAVAIL;
	case EHOSTUNREACH: return GT_SOCK_EHOSTUNREACH;
	case EMSGSIZE: return GT_SOCK_EMSGSIZE;
	default: return 0;
	}
}

static const char *
gt_sock_str(struct gt_strbuf *sb, struct gt_sock *so)
{
	int is_tcp;

	is_tcp = so->so_proto == GT_SO_IPPROTO_TCP;
	gt_strbuf_addf(sb, "{ proto=%s, fd=%d, tuple=",
		is_tcp ? "tcp" : "udp", gt_sock_fd(so));
	gt_strbuf_add_ip_addr(sb, AF_INET, &so->so_tuple.sot_laddr);
	gt_strbuf_addf(sb, ".%hu>", GT_NTOH16(so->so_tuple.sot_lport));
	gt_strbuf_add_ip_addr(sb, AF_INET, &so->so_tuple.sot_faddr);
	gt_strbuf_addf(sb,
		".%hu"
		", in_txq=%u"
		", error=%u"
		", reuseaddr=%u"
		", reuseport=%u"
		", timer=%u"
		", lmss=%u"
		", rmss=%u"
		,
		GT_NTOH16(so->so_tuple.sot_fport),
		gt_sock_in_txq(so),
		so->so_err,
		so->so_reuseaddr,
		so->so_reuseport,
		gt_timer_is_running(&so->so_timer),
		so->so_lmss,
		so->so_rmss);
	if (is_tcp) {
		if (so->so_is_listen) {
			gt_strbuf_addf(sb,
				", backlog=%u"
				", acceptq_len=%u",
				so->so_backlog,
				so->so_acceptq_len);
		} else {
			gt_strbuf_addf(sb,
				", state=%s"
				", passive_open=%u"
				", accepted=%u"
				", ack=%u"
				", wprobe=%u"
				", rexmit=%u"
				", nr_rexmit_tries=%u"
				", dont_frag=%u"
				", rshut=%u"
				", rsyn=%u"
				", rfin=%u"
				", ssyn=%u"
				", ssyn_acked=%u"
				", sfin=%u"
				", sfin_sent=%u"
				", sfin_acked=%u"
				", nagle=%u"
				", nagle_acked=%u"
				", delack=%u"
				", rseq=%u"
				", sack=%u"
				", ssnt=%u"
				", swnd=%u"
				", rwnd=%u"
				", rwnd_max=%u"
				", ip_id=%u"
				", rcvbuf_len=%u"
				", sndbuf_len=%u",
				gt_tcp_state_str(so->so_state),
				so->so_passive_open,
				so->so_accepted,
				so->so_ack,
				so->so_wprobe,
				so->so_rexmit,
				so->so_nr_rexmit_tries,
				so->so_dont_frag,
				so->so_rshut,
				so->so_rsyn,
				so->so_rfin,
				so->so_ssyn,
				so->so_ssyn_acked,
				so->so_sfin,
				so->so_sfin_sent,
				so->so_sfin_acked,
				so->so_nagle,
				so->so_nagle_acked,
				gt_timer_is_running(&so->so_timer_delack),
				so->so_rseq,
				so->so_sack,
				so->so_ssnt,
				so->so_swnd,
				so->so_rwnd,
				so->so_rwnd_max,
				so->so_ip_id,
				so->so_rcvbuf.sob_len,
				so->so_sndbuf.sob_len);
			if (so->so_listen != NULL) {
				gt_strbuf_addf(sb, ", listen_fd=%d",
				               gt_sock_fd(so->so_listen));
			}
		}
	} else {
		gt_strbuf_addf(sb,
			", rcvbuf_len=%u"
			", msgbuf_len=%u",
			so->so_rcvbuf.sob_len,
			so->so_msgbuf.sob_len);
	}
	gt_strbuf_add_ch(sb, '}');
	return gt_strbuf_cstr(sb);
}

static void
gt_sock_dec_nr_opened()
{
	GT_ASSERT(gt_sock_nr_opened > 0);
	gt_sock_nr_opened--;
	if (gt_sock_nr_opened == 0 && gt_sock_no_opened_fn != NULL) {
		(*gt_sock_no_opened_fn)();
	}
}

static uint32_t
gt_sock_tuple_hash(struct gt_sock_tuple *so_tuple)
{
	uint32_t hash;

	hash = gt_custom_hash(so_tuple, sizeof(*so_tuple), 0);
	return hash;
}

static uint32_t
gt_sock_hash(void *elem)
{
	struct gt_sock *so;
	uint32_t hash;

	so = (struct gt_sock *)elem;
	hash = gt_sock_tuple_hash(&so->so_tuple);
	return hash;
}

static void
gt_sock_set_err(struct gt_sock *so, int err)
{
	int rc;

	so->so_err = err;
	rc = gt_tcp_set_state(so, GT_TCP_S_CLOSED);
	if (rc == 0) {
		gt_sock_wakeup(so, POLLERR);
	}
}

static int
gt_sock_clear_eno(struct gt_sock *so)
{
	int eno;

	eno = gt_sock_get_eno(so);
	if (so->so_err != GT_SOCK_EINPROGRESS) {
		so->so_err = 0;
	}
	return eno;
}

static void
gt_sock_htable_add(struct gt_sock *so) 
{
	GT_ASSERT(so->so_hashed == 0);
	so->so_hashed = 1;
	gt_htable_add(&gt_sock_htable, (struct gt_list_head *)so);
}

static int
gt_sock_fd(struct gt_sock *so)
{
	return gt_file_get_fd((struct gt_file *)so);
}

static struct gt_sock *
gt_sock_find(int proto, struct gt_sock_tuple *so_tuple)
{
	uint32_t hash;
	struct gt_list_head *bucket;
	struct gt_sock *so;

	hash = gt_custom_hash(so_tuple, sizeof(*so_tuple), 0);
	bucket = gt_htable_bucket(&gt_sock_htable, hash);
	GT_LIST_FOREACH(so, bucket, so_file.fl_mbuf.mb_list) {
		if (so->so_proto == proto &&
		    so->so_tuple.sot_laddr == so_tuple->sot_laddr &&
		    so->so_tuple.sot_faddr == so_tuple->sot_faddr &&
		    so->so_tuple.sot_lport == so_tuple->sot_lport &&
		    so->so_tuple.sot_fport == so_tuple->sot_fport) {
			return so;
		}
	}
	return NULL;
}

static struct gt_sock *
gt_sock_get_binded(int proto, struct gt_sock_tuple *so_tuple)
{
	uint32_t lport;
	struct gt_list_head *bucket;
	struct gt_sock *so, *binded;

	lport = GT_NTOH16(so_tuple->sot_lport);
	bucket = gt_sock_binded + lport;
	binded = NULL;
	GT_LIST_FOREACH(so, bucket, so_bindl) {
		if (so->so_proto == proto &&
		    (so->so_tuple.sot_laddr == 0 ||
		     so->so_tuple.sot_laddr == so_tuple->sot_laddr)) {
			binded = so;
			if (!gt_list_empty(&so->so_file.fl_cbq)) {
				break;
			}
		}
	}
	return binded;
}

static int
gt_sock_bind_ephemeral_port(struct gt_sock *so, struct gt_route_if_addr *ifa)
{
	int i, n, rss_q_id, ephemeral_port;
	struct gt_sock *x;

	n = GT_EPHEMERAL_PORT_MAX - GT_EPHEMERAL_PORT_MIN + 1;
	for (i = 0; i < n; ++i) {
		ephemeral_port = ifa->ria_cur_ephemeral_port;
		so->so_tuple.sot_lport = GT_HTON16(ephemeral_port);
		if (gt_route_rss_q_cnt > 1) {
			rss_q_id = gt_calc_rss_q_id(&so->so_tuple);
		} else {
			rss_q_id = 0;
		}
		if (ephemeral_port == GT_EPHEMERAL_PORT_MAX) {
			ifa->ria_cur_ephemeral_port = GT_EPHEMERAL_PORT_MIN;
		} else {
			ifa->ria_cur_ephemeral_port++;
		}
		if (rss_q_id == gt_route_rss_q_id) {
			x = gt_sock_find(so->so_proto, &so->so_tuple);
			if (x == NULL) {
				return 0;
			}
		}
	}
	return -EADDRINUSE;
}

static int
gt_sock_connect_check_state(struct gt_sock *so)
{
	if (so->so_proto == GT_SO_IPPROTO_UDP) {
		if (so->so_tuple.sot_faddr == 0) {
			return 0;
		} else {
			return -EISCONN;			
		}
	} else {
		switch (so->so_state) {
		case GT_TCP_S_CLOSED:
			return 0;
		case GT_TCP_S_LISTEN:
		case GT_TCP_S_SYN_SENT:
		case GT_TCP_S_SYN_RCVD:
			return -EALREADY;
		default:
			return -EISCONN;
		}
	}
}

static int
gt_sock_route(struct gt_sock *so, struct gt_route_entry *r)
{
	int rc;

	r->rt_dst.ipa_4 = so->so_tuple.sot_faddr;
	rc = gt_route_get4(so->so_tuple.sot_laddr, r);
	if (rc) {
		gt_ips.ips_noroute++;
	} else {
		so->so_next_hop = gt_route_get_next_hop4(r);
	}
	return rc;
}

static int
gt_sock_in_txq(struct gt_sock *so)
{
	return so->so_txl.ls_next != NULL;
}

static void
gt_sock_add_txq(struct gt_route_if *ifp, struct gt_sock *so)
{
	GT_LIST_INSERT_TAIL(&ifp->rif_txq, so, so_txl);
}

static void
gt_sock_del_txq(struct gt_sock *so)
{
	GT_ASSERT(gt_sock_in_txq(so));
	GT_LIST_REMOVE(so, so_txl);
	so->so_txl.ls_next = NULL;
}

static void
gt_sock_wakeup(struct gt_sock *so, short revents)
{
	gt_file_wakeup(&so->so_file, revents);
}

static int
gt_sock_is_closed(struct gt_sock *so)
{
	return so->so_state == GT_TCP_S_CLOSED && so->so_file.fl_opened == 0;
}

static void
gt_sock_open(struct gt_sock *so)
{
	GT_ASSERT(so->so_state == GT_TCP_S_CLOSED);
	so->so_dont_frag = 1;
	so->so_rmss = 0;
	so->so_lmss = 1460; // TODO:!!!!
}

static struct gt_sock *
gt_sock_new(struct gt_log *log, int fd, int so_proto)
{
	int rc;
	struct gt_file *fp;
	struct gt_sock *so;

	log = GT_LOG_TRACE(log, new);
	if (fd) {
		rc = gt_file_alloc4(log, &fp, GT_FILE_SOCK, fd);
	} else {
		rc = gt_file_alloc(log, &fp, GT_FILE_SOCK);
	}
	if (rc) {
		return NULL;
	}
	so = (struct gt_sock *)fp;
	GT_DBG(new, 0, "hit; fd=%d", gt_sock_fd(so));
	so->so_flags = 0;
	so->so_proto = so_proto;
	so->so_tuple.sot_laddr = 0;
	so->so_tuple.sot_lport = 0;
	so->so_tuple.sot_faddr = 0;
	so->so_tuple.sot_fport = 0;
	so->so_listen = NULL;
	so->so_txl.ls_next = NULL;
	gt_timer_init(&so->so_timer);
	gt_timer_init(&so->so_timer_delack);
	switch (so_proto) {
	case GT_SO_IPPROTO_UDP:
		gt_sockbuf_init(&so->so_msgbuf, 16384);
		gt_sock_open(so);
		break;
	case GT_SO_IPPROTO_TCP:
		gt_sockbuf_init(&so->so_sndbuf, 16384);
		break;
	default:
		GT_BUG;
		break;
	}
	gt_sockbuf_init(&so->so_rcvbuf, 16384);
	gt_sock_nr_opened++;
	return so;
}

static void
gt_sock_del(struct gt_sock *so)
{
	GT_ASSERT(GT_SOCK_ALIVE(so));
	GT_ASSERT(so->so_file.fl_opened == 0);
	GT_ASSERT(so->so_state == GT_TCP_S_CLOSED);
	if (so->so_hashed) {
		gt_htable_del(&gt_sock_htable, (struct gt_list_head *)so);
		so->so_hashed = 0;
	}
	if (so->so_binded) {
		GT_LIST_REMOVE(so, so_bindl);
		so->so_binded = 0;
	}
	if (gt_sock_in_txq(so)) {
		return;
	}
	GT_DBG(del, 0, "hit; fd=%d", gt_sock_fd(so));
	if (so->so_proto == GT_SO_IPPROTO_TCP) {
		gt_tcps.tcps_closed++;
	}
	gt_file_free(&so->so_file);
	gt_sock_dec_nr_opened();
}

static int
gt_sock_rcvbuf_add(struct gt_sock *so, const void *src, int cnt, int all)
{
	int rc, len;

	len = so->so_rcvbuf.sob_len;
	rc = gt_sockbuf_add(&so->so_rcvbuf, src, cnt, all);
	rc = so->so_rcvbuf.sob_len - len;
	GT_DBG(rcvbuf_add, 0, "hit; fd=%d, cnt=%d, buflen=%d",
	       gt_sock_fd(so), rc, so->so_rcvbuf.sob_len);
	if (rc) {
		gt_tcp_set_swnd(so);
	}
	return rc;
}

static int
gt_sock_on_rcv(struct gt_sock *so, void *buf, int len,
	struct gt_sock_tuple *so_tuple)
{
	int rc, rem;
	struct gt_sockbuf_msg msg;

	if (so->so_rshut) {
		return len;
	}
	rem = len;
	rc = gt_sock_rcvbuf_add(so, buf, rem, 0);
	if (rc < 0) {
		return rc;
	} else {
		GT_ASSERT(rc >= 0);
		GT_ASSERT(rc <= rem);
		if (so->so_proto == GT_SO_IPPROTO_UDP && rc > 0) {
			msg.sobm_trunc = rc < rem;
			msg.sobm_faddr = so_tuple->sot_faddr;
			msg.sobm_fport = so_tuple->sot_fport;
			msg.sobm_len = rc;
			rc = gt_sockbuf_add(&so->so_msgbuf, &msg, sizeof(msg), 1);
			if (rc <= 0) {
				gt_sockbuf_pop(&so->so_rcvbuf, msg.sobm_len);
				rc = 0;
			}
		}
		rem -= rc;
		gt_sock_wakeup(so, POLLIN);
	}
	return len - rem;
}

static int
gt_sock_xmit(struct gt_route_if *ifp, struct gt_dev_pkt *pkt,
	struct gt_sock *so)
{
	int rc;
	uint8_t tcp_flags;

	if (gt_sock_is_closed(so)) {
		tcp_flags = 0;
		if (so->so_ack) {
			tcp_flags |= GT_TCP_FLAG_ACK;
		}
		if (so->so_rst) {
			tcp_flags |= GT_TCP_FLAG_RST;
		}
		if (tcp_flags) { // TODO: ????
			gt_sock_xmit_data(ifp, pkt, so, tcp_flags, 0);
		}
		return 1;
	} else {
		rc = gt_tcp_xmit(ifp, pkt, so);
		return rc;
	}
}

static void
gt_sock_xmit_data(struct gt_route_if *ifp, struct gt_dev_pkt *pkt,
	struct gt_sock *so, uint8_t tcp_flags, u_int len)
{
	int delack, sndwinup, total_len;
	struct gt_tcpcb tcb;
	struct gt_eth_hdr *eth_h;

	GT_ASSERT(tcp_flags);
	gt_ips.ips_localout++;
	gt_tcps.tcps_sndtotal++;
	delack = gt_timer_is_running(&so->so_timer_delack);
	sndwinup = so->so_swndup;
	eth_h = (struct gt_eth_hdr *)pkt->pkt_data;
	eth_h->ethh_type = GT_ETH_TYPE_IP4_BE;
	total_len = gt_tcp_fill(so, eth_h, &tcb, tcp_flags, len);
	pkt->pkt_len = sizeof(*eth_h) + total_len;
	if (tcb.tcb_len) {
		gt_tcps.tcps_sndpack++;
		gt_tcps.tcps_sndbyte += tcb.tcb_len;
	} else if (tcb.tcb_flags == GT_TCP_FLAG_ACK) {
		gt_tcps.tcps_sndacks++;
		if (delack) {
			gt_tcps.tcps_delack++;
		} else if (sndwinup) {
			gt_tcps.tcps_sndwinup++;
		}
	}
	GT_DBG(tcp_snd, 0, "hit; flags=%s, len=%d, seq=%u, ack=%u, fd=%d",
	       gt_log_add_tcp_flags(so->so_proto, tcb.tcb_flags),
	       tcb.tcb_len, tcb.tcb_seq, tcb.tcb_ack, gt_sock_fd(so));
	gt_arp_resolve(ifp, so->so_next_hop, pkt);
}

static int
gt_sock_sndbuf_add(struct gt_sock *so, const void *src, int cnt)
{
	int rc;

	rc = gt_sockbuf_add(&so->so_sndbuf, src, cnt, 0);
	GT_DBG(sndbuf_add, 0, "hit; cnt=%d, buflen=%d, fd=%d",
	       cnt, so->so_sndbuf.sob_len, gt_sock_fd(so));
	return rc;
}

static void
gt_sock_sndbuf_pop(struct gt_sock *so, int cnt)
{
	gt_sockbuf_pop(&so->so_sndbuf, cnt);
	GT_DBG(sndbuf_pop, 0, "hit; cnt=%d, buflen=%d, fd=%d",
	       cnt, so->so_sndbuf.sob_len, gt_sock_fd(so));
}

static struct gt_file *
gt_sock_next(int fd)
{
	struct gt_file *fp;

	while (1) {
		fp = gt_file_next(fd);
		if (fp == NULL) {
			return NULL;
		}
		if (fp->fl_type == GT_FILE_SOCK) {
			return fp;
		} else {
			++fd;
		}
	}
}

static int
gt_sock_ctl_sock_list_next(void *udata, int fd)
{
	struct gt_file *fp;

	fp = gt_sock_next(fd);
	if (fp == NULL) {
		return -ENOENT;
	} else {
		fd = gt_file_get_fd(fp);
		return fd;
	}
}


static int
gt_sock_ctl_sock_list(void *udata, int fd, const char *new,
	struct gt_strbuf *out)
{
	struct gt_file *fp;
	struct gt_sockcb socb;

	fp = gt_sock_next(fd);
	if (fp == NULL) {
		return -ENOENT;
	}
	if (gt_file_get_fd(fp) != fd) {
		return -ENOENT;
	}
	gt_sock_get_sockcb((struct gt_sock *)fp, &socb);
	gt_strbuf_addf(out, "%d,%d,%d,%x,%hu,%x,%hu,%d,%d,%d",
		socb.socb_fd,
		socb.socb_ipproto,
		socb.socb_state,
		GT_NTOH32(socb.socb_laddr),
		GT_NTOH16(socb.socb_lport),
		GT_NTOH32(socb.socb_faddr),
		GT_NTOH16(socb.socb_fport),
		socb.socb_acceptq_len,
		socb.socb_incompleteq_len,
		socb.socb_backlog);
	return 0;
}

static void
gt_sock_ctl_init_sock_list(struct gt_log *log)
{
	gt_ctl_add_list(log, GT_CTL_SOCK_LIST, GT_CTL_RD, NULL,
	                gt_sock_ctl_sock_list_next,
	                gt_sock_ctl_sock_list);
}

static int
gt_sock_ctl_tcp_fin_timeout(const long long *new, long long *old)
{
	*old = gt_tcp_fin_timeout / GT_SEC;
	if (new != NULL) {
		gt_tcp_fin_timeout = (*new) * GT_SEC;
	}
	return 0;
}
