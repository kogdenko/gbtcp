// TODO:
// 1) del ack: with a stream of full-sized incoming segments,
//    ACK responses must be sent for every second segment.
#include "internals.h"

#define SO_IPPROTO_UDP 0
#define SO_IPPROTO_TCP 1

#define GT_TCP_FLAG_FOREACH(x) \
	x(GT_TCP_FLAG_FIN, 'F') \
	x(GT_TCP_FLAG_SYN, 'S') \
	x(GT_TCP_FLAG_RST, 'R') \
	x(GT_TCP_FLAG_PSH, 'P') \
	x(GT_TCP_FLAG_ACK, '.') \
	x(GT_TCP_FLAG_URG, 'U') 

enum so_error {
	SO_OK,
	SO_EINPROGRESS,
	SO_ENETUNREACH,
	SO_ETIMEDOUT,
	SO_ECONNREFUSED,
	SO_ECONNRESET,
	SO_EADDRINUSE,
	SO_EADDRNOTAVAIL,
	SO_EHOSTUNREACH,
	SO_EMSGSIZE,
	SO_E_MAX
};

struct sockbuf_msg {
	uint16_t sobm_trunc;
	uint16_t sobm_len;
	be16_t sobm_fport;
	be32_t sobm_faddr;
};

struct tcp_mod {
	struct log_scope log_scope;
	uint64_t tcp_fin_timeout;
	struct htable htable;
	struct htable_bucket binded[EPHEMERAL_PORT_MIN];
};


static struct tcp_mod *curmod;

// subr
static const char *tcp_flags_str(struct strbuf *sb, int proto,
	uint8_t tcp_flags);

static const char *gt_log_add_sock(struct gt_sock *so)
	__attribute__((unused));

int gt_calc_rss_q_id(struct sock_tuple *so_tuple);

static void gt_set_sockaddr(struct sockaddr *addr, socklen_t *addrlen,
	be32_t s_addr, be16_t port);

// tcp
static uint32_t gt_tcp_diff_seq(uint32_t start, uint32_t end);

static uint16_t tcp_emss(struct gt_sock *so);

static void gt_tcp_set_risn(struct gt_sock *so, uint32_t seq);

static void gt_tcp_set_rmss(struct gt_sock *so, struct gt_tcp_opts *opts);

static int gt_tcp_set_swnd(struct gt_sock *so);

static int tcp_set_state(struct gt_sock *so, int state);

static int gt_tcp_rcvbuf_recv(struct gt_sock *so, const struct iovec *iov,
	int iovcnt, int peek);

static void gt_tcp_rcvbuf_set_max(struct gt_sock *so, int max);

static void gt_tcp_open(struct gt_sock *so);

static void gt_tcp_close(struct gt_sock *so);

static void gt_tcp_close_not_accepted(struct dlist *q);

static void gt_tcp_reset(struct gt_sock *so, struct gt_tcpcb *tcb);

static void gt_tcp_wshut(struct gt_sock *so);

static void gt_tcp_delack(struct gt_sock *so);

static void tcp_tx_timer_set(struct gt_sock *so);

static int tcp_wprobe_timer_set(struct gt_sock *so);

static void gt_tcp_timer_set_tcp_fin_timeout(struct gt_sock *so);

static void gt_tcp_timeout_delack(struct timer *timer);

static void tcp_tx_timo(struct timer *timer);

static void tcp_wprobe_timo(struct timer *timer);

static void gt_tcp_timeout_tcp_fin_timeout(struct timer *timer);

static void tcp_rcv_SYN_SENT(struct gt_sock *so, struct gt_tcpcb *tcb);

static void tcp_rcv_LISTEN(struct gt_sock *, struct sock_tuple *, struct gt_tcpcb *);


static void gt_tcp_rcv_data(struct gt_sock *so, struct gt_tcpcb *tcb,
	uint8_t *payload);

static void gt_tcp_rcv_established(struct gt_sock *so, struct gt_tcpcb *tcb,
	void *payload);

static void gt_tcp_rcv_open(struct gt_sock *so, struct gt_tcpcb *tcb,
	void *payload);

static int tcp_is_in_order(struct gt_sock *so, struct gt_tcpcb *tcb);

static int gt_tcp_process_badack(struct gt_sock *so, uint32_t acked);

static void gt_tcp_establish(struct gt_sock *so);

static int gt_tcp_enter_TIME_WAIT(struct gt_sock *so);

static void tcp_rcv_TIME_WAIT(struct gt_sock *so);

static int gt_tcp_process_ack(struct gt_sock *so, struct gt_tcpcb *tcb);

static int gt_tcp_process_ack_complete(struct gt_sock *so);

static void tcp_into_sndq(struct gt_sock *so);

static void gt_tcp_into_ackq(struct gt_sock *so);

static void gt_tcp_into_rstq(struct gt_sock *so);

static int gt_tcp_send(struct gt_sock *so, const struct iovec *iov,
	int iovcnt, int flags);

static int gt_tcp_sender(struct gt_sock *so, int cnt);

static int tcp_tx(struct route_if *ifp, struct dev_pkt *pkt,
	struct gt_sock *so);

static int tcp_fill(struct gt_sock *so, struct gt_eth_hdr *eth_h,
	struct gt_tcpcb *tcb, uint8_t tcp_flags, u_int len);

// udp
static int gt_udp_rcvbuf_recv(struct gt_sock *so, const struct iovec *iov,
	int iovcnt, struct sockaddr *addr, socklen_t *addrlen, int peek);

int gt_udp_sendto(struct gt_sock *so, const struct iovec *iov, int iovcnt,
	int flags, be32_t faddr, be16_t fport);

// sock
static const char *gt_sock_str(struct strbuf *sb, struct gt_sock *so);


static struct gt_sock *so_find(struct htable_bucket *, int, struct sock_tuple *);
static struct gt_sock *
so_find_binded(struct htable_bucket *b,
	int so_ipproto, struct sock_tuple *so_tuple);


static int so_bind_ephemeral_port(struct gt_sock *, struct route_entry *,
	struct htable_bucket **);

static int sock_route(struct gt_sock *so, struct route_entry *r);

static int sock_in_txq(struct gt_sock *so);

static void sock_add_txq(struct route_if *ifp, struct gt_sock *so);

static void gt_sock_del_txq(struct gt_sock *so);

static void so_wakeup(struct gt_sock *so, short revents);

static int gt_sock_is_closed(struct gt_sock *so);

static void sock_open(struct gt_sock *so);

static struct gt_sock *so_new(int);

static void sock_del(struct gt_sock *so);

static int gt_sock_rcvbuf_add(struct gt_sock *so, const void *src, int cnt,
	int all);

static int gt_sock_on_rcv(struct gt_sock *so, void *buf, int len,
	struct sock_tuple *so_tuple);

static int sock_tx(struct route_if *ifp, struct dev_pkt *pkt,
	struct gt_sock *so);

static void tcp_tx_data(struct route_if *ifp, struct dev_pkt *pkt,
	struct gt_sock *so, uint8_t tcp_flags, u_int len);

static int sock_sndbuf_add(struct gt_sock *so, const void *src, int cnt);

static void gt_sock_sndbuf_pop(struct gt_sock *so, int cnt);

static int sysctl_tcp_fin_timeout(const long long *new, long long *old);

#define GT_SOCK_ALIVE(so) ((so)->so_file.fl_mbuf.mb_used)

#define GT_TCP_FLAG_ADD(val, name) \
	if (tcp_flags & val) { \
		strbuf_add_ch(sb, name); \
	}

#define BUCKET_LOCK(b) spinlock_lock(&(b)->htb_lock)
#define BUCKET_UNLOCK(b) spinlock_unlock(&(b)->htb_lock)

static uint32_t
so_tuple_hash(struct sock_tuple *so_tuple)
{
	uint32_t hash;

	hash = custom_hash(so_tuple, sizeof(*so_tuple), 0);
	return hash;
}

static uint32_t
so_hash(void *e)
{
	struct gt_sock *so;
	uint32_t hash;

	so = (struct gt_sock *)e;
	hash = so_tuple_hash(&so->so_tuple);
	return hash;
}

int
tcp_mod_init(struct log *log, void **pp)
{
	int i, rc;
	struct htable_bucket *b;
	struct tcp_mod *mod;

	LOG_TRACE(log);
	rc = shm_malloc(log, pp, sizeof(*mod));
	if (rc) {
		return rc;
	}
	mod = *pp;
	log_scope_init(&mod->log_scope, "tcp");
	rc = htable_init(log, &mod->htable, 2048, so_hash,
	                 HTABLE_SHARED,
	                 field_off(struct gt_sock, so_bucket));
	if (rc) {
		log_scope_deinit(log, &mod->log_scope);
		shm_free(mod);
		return rc;
	}
	for (i = 0; i < ARRAY_SIZE(mod->binded); ++i) {
		b = mod->binded + i;
		htable_bucket_init(b);
	}
	mod->tcp_fin_timeout = NANOSECONDS_SECOND;
	sysctl_add_intfn(log, SYSCTL_TCP_FIN_TIMEOUT, SYSCTL_WR,
	                 &sysctl_tcp_fin_timeout, 1, 24 * 60 * 60);
	return 0;
}

int
tcp_mod_attach(struct log *log, void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

int
tcp_mod_service_init(struct log *log, struct proc *p)
{
	mbuf_pool_init(&p->p_sockbuf_pool, SOCKBUF_CHUNK_SIZE);
	return 0;
}

void
tcp_mod_deinit(struct log *log, void *raw_mod)
{
	struct tcp_mod *mod;

	LOG_TRACE(log);
	mod = raw_mod;
	sysctl_del(log, SYSCTL_TCP_FIN_TIMEOUT);
	mbuf_pool_deinit(&current->p_sockbuf_pool);
	htable_deinit(&mod->htable);
//	sysctl_del(log, GT_CTL_SOCK_LIST);
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}

void
tcp_mod_detach(struct log *log)
{
	curmod = NULL;
}

void
tcp_mod_service_deinit(struct log *log, struct proc *s)
{
}

const char *
log_add_tcp_flags(int proto, uint8_t tcp_flags)
{
	return tcp_flags_str(log_buf_alloc_space(), proto, tcp_flags);
}

static const char *
gt_log_add_sock(struct gt_sock *so)
{
	return gt_sock_str(log_buf_alloc_space(), so);
}


int
so_get(int fd, struct gt_sock **pso)
{
	int rc;
	struct file *fp;

	rc = file_get(fd, &fp);
	if (rc) {
		return rc;
	}
	if (fp->fl_type != FILE_SOCK) {
		return -ENOTSOCK;
	} else {
		*pso = (struct gt_sock *)fp;
		return 0;
	}
}

static void
so_wakeup(struct gt_sock *so, short revents)
{
	file_wakeup(&so->so_file, revents);
}

static inline int
so_err_pack(int errnum)
{
	switch (errnum) {
	case EINPROGRESS: return SO_EINPROGRESS;
	case ENETUNREACH: return SO_ENETUNREACH;
	case ETIMEDOUT: return SO_ETIMEDOUT;
	case ECONNREFUSED: return SO_ECONNREFUSED;
	case ECONNRESET: return SO_ECONNRESET;
	case EADDRINUSE: return SO_EADDRINUSE;
	case EADDRNOTAVAIL: return SO_EADDRNOTAVAIL;
	case EHOSTUNREACH: return SO_EHOSTUNREACH;
	case EMSGSIZE: return SO_EMSGSIZE;
	default: return SO_OK;
	}
}

static inline int
so_err_unpack(int so_errnum)
{
	switch (so_errnum) {
	case SO_OK: return 0;
	case SO_EINPROGRESS: return EINPROGRESS;
	case SO_ENETUNREACH: return ENETUNREACH;
	case SO_ETIMEDOUT: return ETIMEDOUT;
	case SO_ECONNREFUSED: return ECONNREFUSED;
	case SO_ECONNRESET: return ECONNRESET;
	case SO_EADDRINUSE: return EADDRINUSE;
	case SO_EADDRNOTAVAIL: return EADDRNOTAVAIL;
	case SO_EHOSTUNREACH: return EHOSTUNREACH;
	case SO_EMSGSIZE: return EMSGSIZE;
	default: return 0;
	}
}

int
so_get_err(struct gt_sock *so)
{
	int errnum;

	errnum = so_err_unpack(so->so_err);
	return errnum;
}

static void
so_set_err(struct gt_sock *so, int errnum)
{
	int rc;

	DBG(0, "hit; fd=%d, err=%d", so_get_fd(so), errnum);
	so->so_err = so_err_pack(errnum);
	rc = tcp_set_state(so, GT_TCP_S_CLOSED);
	if (rc == 0) {
		so_wakeup(so, POLLERR);
	}
}

static int
so_clr_errnum(struct gt_sock *so)
{
	int errnum;

	errnum = so_get_err(so);
	if (so->so_err != SO_EINPROGRESS) {
		so->so_err = 0;
	}
	return errnum;
}

short
so_get_events(struct file *fp)
{
	short events;
	struct gt_sock *so;

	so = (struct gt_sock *)fp;
	if (so->so_err && so->so_err != SO_EINPROGRESS) {
		events = POLLERR;
	} else {
		events = 0;
	}
	switch (so->so_ipproto) {
	case SO_IPPROTO_TCP:
		switch (so->so_state) {
		case GT_TCP_S_CLOSED:
			break;
		case GT_TCP_S_LISTEN:
			if (!dlist_is_empty(&so->so_completeq)) {
				events |= POLLIN;
			}
			break;
		default:
			if (so->so_rshut || so->so_rfin || gt_sock_nread(fp)) {
				events |= POLLIN;
			}
			if (so->so_state >= GT_TCP_S_ESTABLISHED &&
			    !sockbuf_full(&so->so_sndbuf)) {
				events |= POLLOUT;
			}
			break;
		}
		break;
	case SO_IPPROTO_UDP:
		if (so->so_tuple.sot_faddr != 0) {
			events |= POLLOUT;
		}
		if (gt_sock_nread(fp)) {
			events |= POLLIN;
		}
		break;
	default:
		BUG;
	}	
	return events;
}

#if 0
void
gt_sock_get_sockcb(struct gt_sock *so, struct gt_sockcb *socb)
{
	socb->socb_fd = so_get_fd(so);
	socb->socb_flags = file_fcntl(&so->so_file, F_GETFL, 0);
	socb->socb_state = so->so_state;
	socb->socb_laddr = so->so_tuple.sot_laddr;
	socb->socb_faddr = so->so_tuple.sot_faddr;
	socb->socb_lport = so->so_tuple.sot_lport;
	socb->socb_fport = so->so_tuple.sot_fport;
	socb->socb_ipproto = so->so_ipproto == GT_SO_IPPROTO_TCP ?
	                                     IPPROTO_TCP : IPPROTO_UDP;
	if (so->so_is_listen) {
		socb->socb_acceptq_len = so->so_acceptq_len;
		socb->socb_incompleteq_len = dlist_size(&so->so_incompleteq);
		socb->socb_backlog = so->so_backlog;
	} else {
		socb->socb_acceptq_len = 0;
		socb->socb_incompleteq_len = 0;
		socb->socb_backlog = 0;
	}
}
#endif

int
gt_sock_nread(struct file *fp)
{
	struct gt_sock *so;

	so = (struct gt_sock *)fp;
	return so->so_rcvbuf.sob_len;
}

static void
so_in_locked(struct gt_sock *so, struct sock_tuple *so_tuple,
	struct gt_tcpcb *tcb, void *payload)
{
	DBG(0, "hit; flags=%s, len=%d, seq=%u, ack=%u, fd=%d",
	    log_add_tcp_flags(so->so_ipproto, tcb->tcb_flags),
	    tcb->tcb_len, tcb->tcb_seq, tcb->tcb_ack, so_get_fd(so));
	switch (so->so_ipproto) {
	case SO_IPPROTO_UDP:
		gt_sock_on_rcv(so, payload, tcb->tcb_len, so_tuple);
		break;
	case SO_IPPROTO_TCP:
		switch (so->so_state) {
		case GT_TCP_S_CLOSED:
			break;
		case GT_TCP_S_LISTEN:
			tcp_rcv_LISTEN(so, so_tuple, tcb);
			break;
		case GT_TCP_S_TIME_WAIT:
			tcp_rcv_TIME_WAIT(so);
			break;
		default:
			gt_tcp_rcv_open(so, tcb, payload);
			break;
		}
	}
}

int
so_in(int ipproto, struct sock_tuple *so_tuple, struct gt_tcpcb *tcb,
	void *payload)
{
	int so_ipproto, lport;
	uint32_t h;
	struct htable_bucket *b;
	struct gt_sock *so;

	switch (ipproto) {
	case IPPROTO_UDP:
		so_ipproto = SO_IPPROTO_UDP;
		break;
	case IPPROTO_TCP:
		tcps.tcps_rcvtotal++;
		so_ipproto = SO_IPPROTO_TCP;
		break;
	default:
		return IP_BYPASS;
	}
	h = so_tuple_hash(so_tuple);
	b = htable_bucket_get(&curmod->htable, h);
	BUCKET_LOCK(b);
	so = so_find(b, so_ipproto, so_tuple);
	if (so != NULL) {
		so_in_locked(so, so_tuple, tcb, payload);
	}
	BUCKET_UNLOCK(b);
	if (so != NULL) {
		return IP_OK;
	}
	lport = hton16(so_tuple->sot_lport);
	if (lport >= ARRAY_SIZE(curmod->binded)) {
		return IP_BYPASS;
	}
	b = curmod->binded + lport; // rcv_LISTEN
	so = so_find_binded(b, so_ipproto, so_tuple);
	//ASSERT(0);
	if (so == NULL) {
		return IP_BYPASS;
	} else {
		return IP_OK;
	}
}

int
so_in_err(int ipproto, struct sock_tuple *so_tuple, int errnum)
{
#if 0
	int rc, lport;
	uint32_t h;
	int so_ipproto, lport;
	struct htable_bucket *b;
	struct gt_sock *so;

	if (ipproto == IPPROTO_UDP) {
		so_ipproto = SO_IPPROTO_UDP;
	} else {
		so_ipproto = SO_IPPROTO_TCP;
	}
	h = so_tuple_hash(so_tuple);
	b = htable_bucket_get(&curmod->htable, h);
	BUCKET_LOCK(b);
	so = so_find(b, so_ipproto, so_tuple);
	if (so != NULL) {
		so_set_err(so, errnum); 
	}
	BUCKET_UNLOCK(b);
	if (so != NULL) {
		return IP_OK;
	}
	if (ipproto == SO_IPPROTO_TCP) {
		return IP_BYPASS;
	}
	lport = ntoh16(so_tuple->sot_lport);
	if (lport >= ARRAY_SIZE(curmod->binded)) {
		return IP_BYPASS;
	}
	b = curmod->binded + lport;
	BUCKET_LOCK(b);
	rc = IP_BYPASS;
	DLIST_FOREACH(so, b, so_bind_list) {
		if (so->so_ipproto == SO_IPPROTO_UDP &&
		    (so->so_tuple.sot_laddr == 0 ||
		     so->so_tuple.sot_laddr == so_tuple->sot_laddr)) {
			so_set_err(so, errnum);
			rc = IP_OK;
		}
	}
	BUCKET_UNLOCK(b);
	return rc;
#else
	return IP_OK;
#endif
}

int
so_socket(int domain, int type, int flags, int ipproto)
{
	int so_fd, so_ipproto;
	struct gt_sock *so;

	if (domain != AF_INET) {
		return -EINVAL;
	}
	switch (type) {
	case SOCK_STREAM:
		if (ipproto != 0 && ipproto != IPPROTO_TCP) {
			return -EINVAL;
		}
		so_ipproto = SO_IPPROTO_TCP;
		break;
	case SOCK_DGRAM:
		if (ipproto != 0 && ipproto != IPPROTO_UDP) {
			return -EINVAL;
		}
		so_ipproto = SO_IPPROTO_UDP;
		break;
	default:
		return -EINVAL;
	}
	so = so_new(so_ipproto);
	if (so == NULL) {
		return -ENOMEM;
	}
	if (flags & SOCK_NONBLOCK) {
		so->so_blocked = 0;
	}
	so->so_file.fl_opened = 1;
	so_fd = so_get_fd(so);
	return so_fd;
}

int
so_connect(struct gt_sock *so, const struct sockaddr_in *faddr_in,
	struct sockaddr_in *laddr_in)
{
	int rc;
	struct route_entry r;
	struct htable_bucket *b;

	if (faddr_in->sin_port == 0 || faddr_in->sin_addr.s_addr == 0) {
		return -EINVAL;
	}
	if (so->so_ipproto == SO_IPPROTO_UDP) {
		if (so->so_tuple.sot_faddr) {
			return -EISCONN;			
		}
	} else {
		switch (so->so_state) {
		case GT_TCP_S_CLOSED:
			break;
		case GT_TCP_S_LISTEN:
		case GT_TCP_S_SYN_SENT:
		case GT_TCP_S_SYN_RCVD:
			return -EALREADY;
		default:
			return -EISCONN;
		}
	}
	ASSERT(!sock_in_txq(so));
	if (so->so_tuple.sot_lport) {
		return -ENOTSUP;
	}
	so->so_tuple.sot_faddr = faddr_in->sin_addr.s_addr;
	so->so_tuple.sot_fport = faddr_in->sin_port;
	rc = sock_route(so, &r);
	if (rc) {
		return rc;
	}
	so->so_tuple.sot_laddr = r.rt_ifa->ria_addr.ipa_4;
	rc = so_bind_ephemeral_port(so, &r, &b);
	if (rc < 0) {
		return rc;
	}
	htable_add(&curmod->htable, b, (htable_entry_t *)so);
	BUCKET_UNLOCK(b);
	DBG(0, "ok; tuple=%s:%hu>%s:%hu, fd=%d",
	    log_add_ipaddr(AF_INET, &so->so_tuple.sot_laddr),
	    ntoh16(so->so_tuple.sot_lport),
	    log_add_ipaddr(AF_INET, &so->so_tuple.sot_faddr),
	    ntoh16(so->so_tuple.sot_fport), so_get_fd(so));
	laddr_in->sin_family = AF_INET;
	laddr_in->sin_addr.s_addr = so->so_tuple.sot_laddr;
	laddr_in->sin_port = so->so_tuple.sot_lport;
	if (so->so_ipproto == SO_IPPROTO_UDP) {
		return 0;
	}
	gt_tcp_open(so);
	gt_tcp_set_swnd(so);
	tcp_set_state(so, GT_TCP_S_SYN_SENT);
	tcp_into_sndq(so);
	return -EINPROGRESS;
}

int
so_bind(struct gt_sock *so, const struct sockaddr_in *addr)
{
	be16_t lport;
	struct htable_bucket *b;

	if (so->so_state != GT_TCP_S_CLOSED) {
		return -EINVAL;
	}
	ASSERT(so->so_bucket == NULL);
	lport = hton16(addr->sin_port);
	if (lport == 0) {
		return -EINVAL;
	}
	if (so->so_tuple.sot_laddr != 0 || so->so_tuple.sot_lport != 0) {
		return -EINVAL;
	}
	if (lport >= ARRAY_SIZE(curmod->binded)) {
		return -EADDRNOTAVAIL;
	}
	so->so_tuple.sot_laddr = addr->sin_addr.s_addr;
	so->so_tuple.sot_lport = addr->sin_port;
	b = curmod->binded + lport;
	BUCKET_LOCK(b);
	DLIST_INSERT_TAIL(&b->htb_head, so, so_bind_list);
	BUCKET_UNLOCK(b);
	return 0;
}

int 
so_listen(struct gt_sock *so, int backlog)
{
	if (so->so_state == GT_TCP_S_LISTEN) {
		return 0;
	}
	if (so->so_ipproto != SO_IPPROTO_TCP) {
		return -ENOTSUP;
	}
	if (so->so_state != GT_TCP_S_CLOSED) {
		return -EINVAL;
	}
	if (so->so_tuple.sot_lport == 0) {
		return -EADDRINUSE;
	}
	dlist_init(&so->so_incompleteq);
	dlist_init(&so->so_completeq);
	so->so_acceptq_len = 0;
	so->so_backlog = backlog > 0 ? backlog : 32;
	tcp_set_state(so, GT_TCP_S_LISTEN);
	so->so_is_listen = 1;
	return 0;
}

int
so_accept(struct gt_sock *lso, struct sockaddr *addr, socklen_t *addrlen,
	int flags)
{
	int fd;
	struct gt_sock *so;

	if (lso->so_state != GT_TCP_S_LISTEN) {
		return -EINVAL;
	}
	if (dlist_is_empty(&lso->so_completeq)) {
		return -EAGAIN;
	}
	ASSERT(lso->so_acceptq_len);
	so = DLIST_FIRST(&lso->so_completeq, struct gt_sock, so_acceptl);
	ASSERT(so->so_state >= GT_TCP_S_ESTABLISHED);
	ASSERT(so->so_accepted == 0);
	so->so_accepted = 1;
	DLIST_REMOVE(so, so_acceptl);
	lso->so_acceptq_len--;
	gt_set_sockaddr(addr, addrlen, so->so_tuple.sot_faddr,
	                so->so_tuple.sot_fport);
	if (flags & SOCK_NONBLOCK) {
		so->so_file.fl_blocked = 0;
	}
	so->so_file.fl_opened = 1;
	fd = so_get_fd(so);
	tcps.tcps_accepts++;
	return fd;
}

void
so_close(struct gt_sock *so)
{
	ASSERT(so->so_file.fl_opened == 0);
	switch (so->so_state) {
	case GT_TCP_S_CLOSED:
		sock_del(so);
		break;
	case GT_TCP_S_LISTEN:
		gt_tcp_close_not_accepted(&so->so_incompleteq);
		gt_tcp_close_not_accepted(&so->so_completeq);
		tcp_set_state(so, GT_TCP_S_CLOSED);
		break;
	case GT_TCP_S_SYN_SENT:
		if (sock_in_txq(so)) {
			gt_sock_del_txq(so);
		}
		tcp_set_state(so, GT_TCP_S_CLOSED);
		break;
	default:
		if (1) { // Gracefull
			so->so_rshut = 1;
			so->so_wshut = 1;
			if (so->so_state >= GT_TCP_S_ESTABLISHED) {
				gt_tcp_wshut(so);	
			}
		} else {
			gt_tcp_into_rstq(so);
			tcp_set_state(so, GT_TCP_S_CLOSED);
		}
		break;
	}
}

int
so_recvfrom(struct gt_sock *so, const struct iovec *iov, int iovcnt,
	int flags, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc, peek;

	if (flags & ~MSG_PEEK) {
		return -ENOTSUP;
	}
	if (so->so_err) {
		rc = -so_clr_errnum(so);
		return rc;
	}
	if (so->so_rshut) {
		return 0;
	}
	if (so->so_ipproto == SO_IPPROTO_TCP) {
		if (so->so_state < GT_TCP_S_ESTABLISHED) {
			return -EAGAIN;
		}
	}
	peek = flags & MSG_PEEK;
	switch (so->so_ipproto) {
	case SO_IPPROTO_UDP:
		rc = gt_udp_rcvbuf_recv(so, iov, iovcnt, addr, addrlen, peek);
		break;
	case SO_IPPROTO_TCP:
		rc = gt_tcp_rcvbuf_recv(so, iov, iovcnt, peek);
		if (rc == -EAGAIN) {
			if (so->so_rfin) {
				rc = 0;
			}
		}
		break;
	default:
		rc = 0;
		BUG;
		break;
	}
	return rc;
}

int
so_sendto(struct gt_sock *so, const struct iovec *iov, int iovcnt,
	int flags, be32_t daddr, be16_t dport)
{
	int rc;

	if (flags & ~(MSG_NOSIGNAL)) {
		return -ENOTSUP;
	}
	switch (so->so_ipproto) {
	case SO_IPPROTO_UDP:
		rc = gt_udp_sendto(so, iov, iovcnt, flags, daddr, dport);
		break;
	case SO_IPPROTO_TCP:
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
gt_sock_ioctl(struct file *fp, unsigned long request, uintptr_t arg)
{
	return -ENOTSUP;
}
#else /* __linux */
int
gt_sock_ioctl(struct file *fp, unsigned long request, uintptr_t arg)
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
so_getsockopt(struct gt_sock *so, int level, int optname, void *optval,
	socklen_t *optlen)
{
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
			*((int *)optval) = so_clr_errnum(so);
			return 0;
		}
	}
	return -ENOPROTOOPT;
}

int
so_setsockopt(struct gt_sock *so, int level, int optname, const void *optval,
	socklen_t optlen)
{
	int optint;

	switch (level) {
	case IPPROTO_TCP:
		if (so->so_ipproto != SO_IPPROTO_TCP) {
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
so_getpeername(struct gt_sock *so, struct sockaddr *addr, socklen_t *addrlen)
{
	if (so->so_tuple.sot_faddr == 0) {
		return -ENOTCONN;
	}
	if (so->so_ipproto == SO_IPPROTO_TCP) {
		if (so->so_state < GT_TCP_S_ESTABLISHED) {
			return -ENOTCONN;
		}
	}
	gt_set_sockaddr(addr, addrlen, so->so_tuple.sot_faddr,
	                so->so_tuple.sot_fport);
	return 0;
}

static const char *
tcp_flags_str(struct strbuf *sb, int proto, uint8_t tcp_flags)
{
	const char *s;

	if (proto == SO_IPPROTO_UDP) {
		return "UDP";
	}
	GT_TCP_FLAG_FOREACH(GT_TCP_FLAG_ADD);
	s = strbuf_cstr(sb);
	return s;
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
static uint32_t
gt_tcp_diff_seq(uint32_t start, uint32_t end)
{
	return end - start;
}

// Effective mss
static uint16_t
tcp_emss(struct gt_sock *so)
{
	uint16_t emss;

	ASSERT(so->so_rmss);
	ASSERT(so->so_lmss);
	emss = MIN(so->so_lmss, so->so_rmss);
	ASSERT(emss >= GT_IP4_MTU_MIN - 40);
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
		so->so_rmss = MAX(GT_IP4_MTU_MIN - 20, opts->tcpo_mss);
	} else {
		so->so_rmss = 536;
	}
}

// Sending window
static int
gt_tcp_set_swnd(struct gt_sock *so)
{
	unsigned int emss, new_swnd, old_swnd, thresh;

	emss = so->so_rmss ? tcp_emss(so) : so->so_lmss;
	if (so->so_rcvbuf.sob_max < so->so_rcvbuf.sob_len) {
		so->so_swnd = 0;
		return 0;
	}
	new_swnd = so->so_rcvbuf.sob_max - so->so_rcvbuf.sob_len;
	if (so->so_swnd > new_swnd) {
		so->so_swnd = new_swnd;
		return 0;
	}
	thresh = MIN(emss, so->so_rcvbuf.sob_max >> 1);
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
tcp_set_state(struct gt_sock *so, int state)
{
	ASSERT(GT_SOCK_ALIVE(so));
	ASSERT(state < GT_TCP_NSTATES);
	ASSERT(state != so->so_state);
	DBG(0, "hit; state %s->%s, fd=%d",
	    tcp_state_str(so->so_state), tcp_state_str(state), so_get_fd(so));
	if (state != GT_TCP_S_CLOSED) {
		ASSERT(state > so->so_state);
		tcps.tcps_states[state]++;
	}
	if (so->so_state != GT_TCP_S_CLOSED) {
		tcps.tcps_states[so->so_state]--;
	}
	so->so_state = state;
	switch (so->so_state) {
	case GT_TCP_S_ESTABLISHED:
		gt_tcp_establish(so);
		break;
	case GT_TCP_S_CLOSED:
		gt_tcp_close(so);
		if (so->so_file.fl_opened == 0) {
			sock_del(so);
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
	rc = sockbuf_readv4(&so->so_rcvbuf, iov, iovcnt, peek);
	DBG(0, "hit; fd=%d, peek=%d, cnt=%d, buflen=%d",
	    so_get_fd(so), peek, rc, so->so_rcvbuf.sob_len);
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
	sockbuf_set_max(&so->so_rcvbuf, max);
	gt_tcp_set_swnd(so);
}

static void
gt_tcp_open(struct gt_sock *so)
{
	sock_open(so);
	so->so_nagle = 1;
	so->so_nagle_acked = 1;
	// Must not overlap in 2 minutes (MSL)
	// Increment 1 seq at 16 ns (like in Linux)
	so->so_sack = nanoseconds >> 6;
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
	timer_del(&so->so_timer);
	timer_del(&so->so_timer_delack);
	sockbuf_free(&so->so_rcvbuf);
	sockbuf_free(&so->so_sndbuf);
	if (so->so_passive_open) {
		if (so->so_accepted == 0) { 
			ASSERT(so->so_listen != NULL);
			so->so_listen->so_acceptq_len--;
			DLIST_REMOVE(so, so_acceptl);
			so->so_listen = NULL;
		}
	}
}

static void
gt_tcp_close_not_accepted(struct dlist *q)
{
	struct gt_sock *so;

	while (!dlist_is_empty(q)) {
		so = DLIST_FIRST(q, struct gt_sock, so_acceptl);
		ASSERT(so->so_file.fl_opened == 0);
		so->so_listen = NULL;
		so_close(so);
	}
}

static void
gt_tcp_reset(struct gt_sock *so, struct gt_tcpcb *tcb)
{
	so->so_ssnt = 0;
	so->so_sack = tcb->tcb_ack;
	so->so_rseq = tcb->tcb_seq;
	gt_tcp_into_rstq(so);
	sock_del(so);
}

static void
gt_tcp_wshut(struct gt_sock *so)
{
	ASSERT(so->so_state >= GT_TCP_S_ESTABLISHED);
	if (so->so_sfin) {
		return;
	}
	switch (so->so_state) {
	case GT_TCP_S_ESTABLISHED:
		tcp_set_state(so, GT_TCP_S_FIN_WAIT_1);
		break;
	case GT_TCP_S_CLOSE_WAIT:
		tcp_set_state(so, GT_TCP_S_LAST_ACK);
		break;
	default:
		BUG;
		break;
	}
	so->so_sfin = 1;
	tcp_into_sndq(so);
}

static void
gt_tcp_delack(struct gt_sock *so)
{
	if (timer_is_running(&so->so_timer_delack)) {
		timer_del(&so->so_timer_delack);
		gt_tcp_into_ackq(so);
	}
	timer_set(&so->so_timer_delack, 200 * NANOSECONDS_MILLISECOND,
	          gt_tcp_timeout_delack);
}

#if 0
static void
gt_tcp_timeout_TIME_WAIT(struct timer *timer)
{
	struct gt_sock *so;

	so = gt_container_of(timer, struct gt_sock, timer);
	tcp_set_state(so, TCP_S_CLOSED);
}
#endif

static void
tcp_tx_timer_set(struct gt_sock *so)
{
	uint64_t expires;

	ASSERT(so->so_sfin_acked == 0);
	if (so->so_retx == 0) {
		so->so_retx = 1;
		so->so_wprobe = 0;
		so->so_ntx_tries = 0;
	}
	if (so->so_state < GT_TCP_S_ESTABLISHED) {
		expires = NANOSECONDS_SECOND;
	} else {
		expires = 500 * NANOSECONDS_MILLISECOND;
	}
	expires <<= so->so_ntx_tries;
	timer_set(&so->so_timer, expires, tcp_tx_timo);
}

static int
tcp_wprobe_timer_set(struct gt_sock *so)
{
	uint64_t expires;

	if (so->so_retx) {
		return 0;
	}
	if (timer_is_running(&so->so_timer)) {
		return 0;
	}
	expires = 10 * NANOSECONDS_SECOND;
	timer_set(&so->so_timer, expires, tcp_wprobe_timo);
	return 1;
}

static void
gt_tcp_timer_set_tcp_fin_timeout(struct gt_sock *so)
{
	ASSERT(so->so_retx == 0);
	ASSERT(so->so_wprobe == 0);
	ASSERT(!timer_is_running(&so->so_timer));
	timer_set(&so->so_timer, curmod->tcp_fin_timeout,
	             gt_tcp_timeout_tcp_fin_timeout); 
}

static void
gt_tcp_timeout_delack(struct timer *timer)
{
	struct gt_sock *so;

	so = container_of(timer, struct gt_sock, so_timer_delack);
	gt_tcp_into_ackq(so);
}

static void
tcp_tx_timo(struct timer *timer)
{
	struct gt_sock *so;

	so = container_of(timer, struct gt_sock, so_timer);
	ASSERT(GT_SOCK_ALIVE(so));
	ASSERT(so->so_sfin_acked == 0);
	ASSERT(so->so_retx);
	so->so_ssnt = 0;
	so->so_sfin_sent = 0;
	tcps.tcps_rexmttimeo++;
	DBG(0, "hit; fd=%d, state=%s",
	    so_get_fd(so), tcp_state_str(so->so_state));
	if (so->so_ntx_tries++ > 6) {
		tcps.tcps_timeoutdrop++;
		so_set_err(so, ETIMEDOUT);
		return;
	}
	// TODO: 
//	if (so->so_state == TCP_S_SYN_RCVD) {
//		cnt_tcp_timedout_syn_rcvd++;
//		so_set_err(so, ETIMEDOUT);
//		return;
//	}
	so->so_retxed = 1;
	tcp_into_sndq(so);
}

static void
tcp_wprobe_timo(struct timer *timer)
{
	struct gt_sock *so;

	so = container_of(timer, struct gt_sock, so_timer);
	ASSERT(GT_SOCK_ALIVE(so));
	ASSERT(so->so_sfin_acked == 0);
	ASSERT(so->so_retx == 0);
	ASSERT(so->so_wprobe);
	tcps.tcps_sndprobe++;
	gt_tcp_into_ackq(so);
	tcp_wprobe_timer_set(so);
}

static void
gt_tcp_timeout_tcp_fin_timeout(struct timer *timer)
{
	struct gt_sock *so;

	so = container_of(timer, struct gt_sock, so_timer);
	gt_tcp_enter_TIME_WAIT(so);
}

static void
tcp_rcv_SYN_SENT(struct gt_sock *so, struct gt_tcpcb *tcb)
{
	switch (tcb->tcb_flags) {
	case GT_TCP_FLAG_SYN|GT_TCP_FLAG_ACK:
		tcp_set_state(so, GT_TCP_S_ESTABLISHED);
		so->so_ack = 1;
		break;
	case GT_TCP_FLAG_SYN:
		tcp_set_state(so, GT_TCP_S_SYN_RCVD);
		break;
	default:
		return;
	}
	gt_tcp_set_risn(so, tcb->tcb_seq);
	gt_tcp_set_rmss(so, &tcb->tcb_opts);
	tcp_into_sndq(so);
}

static void
tcp_rcv_LISTEN(struct gt_sock *lso, struct sock_tuple *so_tuple, struct gt_tcpcb *tcb)
{
	uint32_t h;
	struct htable_bucket *b;
	struct gt_sock *so;

	//ASSERT(lso->so_acceptq_len <= lso->so_backlog);
	if (0 && lso->so_acceptq_len == lso->so_backlog) {
		tcps.tcps_listendrop++;
		return;
	}
	so = so_new(SO_IPPROTO_TCP);
	if (so == NULL) {
		tcps.tcps_rcvmemdrop++;
		return;
	}
	so->so_tuple = *so_tuple;
	gt_tcp_open(so);
	if (tcb->tcb_flags != GT_TCP_FLAG_SYN) {
		DBG(0, "not a SYN; tuple=%s:%hu>%s:%hu, lfd=%d, fd=%d",
		    log_add_ipaddr(AF_INET, &so->so_tuple.sot_laddr),
		    ntoh16(so->so_tuple.sot_lport),
	            log_add_ipaddr(AF_INET, &so->so_tuple.sot_faddr),
		    ntoh16(so->so_tuple.sot_fport),
		    so_get_fd(lso), so_get_fd(so));
		tcps.tcps_badsyn++;
		gt_tcp_reset(so, tcb);
		return;
	} else {
		DBG(0, "ok; tuple=%s:%hu>%s:%hu, lfd=%d, fd=%d",
		    log_add_ipaddr(AF_INET, &so->so_tuple.sot_laddr),
		    ntoh16(so->so_tuple.sot_lport),
	            log_add_ipaddr(AF_INET, &so->so_tuple.sot_faddr),
		    ntoh16(so->so_tuple.sot_fport),
		    so_get_fd(lso), so_get_fd(so));
	}
	DLIST_INSERT_HEAD(&lso->so_incompleteq, so, so_acceptl);
	lso->so_acceptq_len++;
	so->so_passive_open = 1;
	so->so_listen = lso;
	if (lso->so_lmss) {
		so->so_lmss = lso->so_lmss;
	}
	gt_tcp_set_risn(so, tcb->tcb_seq);
	gt_tcp_set_rmss(so, &tcb->tcb_opts);
	sockbuf_set_max(&so->so_sndbuf, lso->so_sndbuf.sob_max);
	gt_tcp_rcvbuf_set_max(so, lso->so_rcvbuf.sob_max);
	gt_tcp_set_swnd(so);
	tcp_set_state(so, GT_TCP_S_SYN_RCVD);
	tcp_into_sndq(so);
	h = so_hash(so);
	b = htable_bucket_get(&curmod->htable, h);
	BUCKET_LOCK(b);
	htable_add(&curmod->htable, b, (htable_entry_t *)so);
	BUCKET_UNLOCK(b);
}

static void
gt_tcp_rcv_data(struct gt_sock *so, struct gt_tcpcb *tcb, u_char *payload)
{
	int rc;
	uint32_t n, off;

	off = gt_tcp_diff_seq(tcb->tcb_seq, so->so_rseq);
	if (off == 0) {
		tcps.tcps_rcvpack++;
		tcps.tcps_rcvbyte += tcb->tcb_len;
		n = tcb->tcb_len;
	} else if (off == tcb->tcb_len) {
		tcps.tcps_rcvduppack++;
		tcps.tcps_rcvdupbyte += tcb->tcb_len;
		return;
	} else if (off > tcb->tcb_len) {
		tcps.tcps_pawsdrop++;
		return;
	} else {	
		n = tcb->tcb_len - off;
		tcps.tcps_rcvpartduppack++;
		tcps.tcps_rcvpartdupbyte += n;
	}
	n = tcb->tcb_len - off;
	rc = gt_sock_on_rcv(so, payload, n, &so->so_tuple);
	if (rc < 0) {
		tcps.tcps_rcvmemdrop++;
		return;
	} else if (rc < n) {
		tcps.tcps_rcvpackafterwin++;
		tcps.tcps_rcvbyteafterwin += n - rc;
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

	ASSERT(so->so_state >= GT_TCP_S_ESTABLISHED);
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
		so_wakeup(so, POLLIN|GT_POLLRDHUP);
		gt_tcp_into_ackq(so);
		switch (so->so_state) {
		case GT_TCP_S_ESTABLISHED:
			tcp_set_state(so, GT_TCP_S_CLOSE_WAIT);
			break;
		case GT_TCP_S_FIN_WAIT_1:
			tcp_set_state(so, GT_TCP_S_CLOSING);
			break;
		case GT_TCP_S_FIN_WAIT_2:
			timer_del(&so->so_timer); // tcp_fin_timeout
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
		tcps.tcps_drops++;
		if (so->so_state < GT_TCP_S_ESTABLISHED) {
			tcps.tcps_conndrops++;
			so_set_err(so, ECONNREFUSED);
		} else {
			so_set_err(so, ECONNRESET);
		}
		return;
	}
	if (so->so_rsyn) {
		rc = tcp_is_in_order(so, tcb);
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
		so->so_rwnd_max = MAX(so->so_rwnd_max, so->so_rwnd);
	}
	switch (so->so_state) {
	case GT_TCP_S_SYN_SENT:
		tcp_rcv_SYN_SENT(so, tcb);
		return;
	case GT_TCP_S_CLOSED:
		tcps.tcps_rcvafterclose++;
		return;
	case GT_TCP_S_SYN_RCVD:
		break;
	default:
		ASSERT(so->so_rsyn);
		gt_tcp_rcv_established(so, tcb, payload);
		break;
	}
	if (so->so_sfin_acked == 0) {
		tcp_into_sndq(so);
	}
}

static int
tcp_is_in_order(struct gt_sock *so, struct gt_tcpcb *tcb)
{
	uint32_t len, off;

	len = tcb->tcb_len;
	if (tcb->tcb_flags & (GT_TCP_FLAG_SYN|GT_TCP_FLAG_FIN)) {
		len++;
	}
	off = gt_tcp_diff_seq(tcb->tcb_seq, so->so_rseq);
	if (off > len) {
		DBG(0, "out of order; flags=%s, seq=%u, len=%u, %s",
		    log_add_tcp_flags(so->so_ipproto, tcb->tcb_flags),
		    tcb->tcb_seq, len, gt_log_add_sock(so));
		tcps.tcps_rcvoopack++;
		tcps.tcps_rcvoobyte += tcb->tcb_len;
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
		tcps.tcps_rcvdupack++;
	} else {
		tcps.tcps_rcvacktoomuch++;
	}
	return -1;
}

static void
gt_tcp_establish(struct gt_sock *so)
{
	struct gt_sock *lso;

	tcps.tcps_connects++;
	if (so->so_err == SO_EINPROGRESS) {
		so->so_err = 0;
	}
	if (so->so_wshut) {
		gt_tcp_wshut(so);
	}
	if (so->so_passive_open && so->so_listen != NULL) {
		lso = so->so_listen;
		ASSERT(lso->so_acceptq_len);
		DLIST_REMOVE(so, so_acceptl);
		DLIST_INSERT_HEAD(&lso->so_completeq, so, so_acceptl);
		so_wakeup(lso, POLLIN);
	} else {
		so_wakeup(so, POLLOUT);
	}
}

static int
gt_tcp_enter_TIME_WAIT(struct gt_sock *so)
{
	int rc;

#if 1
	rc = tcp_set_state(so, GT_TCP_S_CLOSED);
	return rc;
#else
	tcp_set_state(so, TCP_S_TIME_WAIT);
	timer_set(&so->so_timer, 2 * MSL, gt_tcp_timeout_TIME_WAIT);
#endif
}

static void
tcp_rcv_TIME_WAIT(struct gt_sock *so)
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
			DBG(0, "bad ACK; flags=%s, ack=%u, %s",
		            log_add_tcp_flags(so->so_ipproto,
			                      tcb->tcb_flags),
			    tcb->tcb_ack, gt_log_add_sock(so));
			rc = gt_tcp_process_badack(so, acked);
			return rc;
		}
	}
	if (so->so_state == GT_TCP_S_SYN_RCVD) {
		tcp_set_state(so, GT_TCP_S_ESTABLISHED);
	}
	if (so->so_ssyn && so->so_ssyn_acked == 0) {
		so->so_ssyn_acked = 1;
		so->so_sack++;
	}
	if (acked) {
		so->so_sack += acked;
		so->so_ssnt -= acked;
		gt_sock_sndbuf_pop(so, acked);
		tcps.tcps_rcvackpack++;
		tcps.tcps_rcvackbyte += acked;
	}
	if (so->so_ssnt == 0) {
		rc = gt_tcp_process_ack_complete(so);
		if (rc) {
			return rc;
		}
	}
	if (so->so_sfin == 0) {
		so_wakeup(so, POLLOUT);
	}
	return 0;
}

static int
gt_tcp_process_ack_complete(struct gt_sock *so)
{
	int rc;

	so->so_retx = 0;
	so->so_ntx_tries = 0;
	timer_del(&so->so_timer);
	so->so_nagle_acked = 1;
	if (so->so_sfin && so->so_sfin_acked == 0 &&
	    so->so_sndbuf.sob_len == 0) {
		so->so_sfin_acked = 1;
		switch (so->so_state) {
		case GT_TCP_S_FIN_WAIT_1:
			gt_tcp_timer_set_tcp_fin_timeout(so);
			tcp_set_state(so, GT_TCP_S_FIN_WAIT_2);
			break;
		case GT_TCP_S_CLOSING:
			rc = gt_tcp_enter_TIME_WAIT(so);
			if (rc) {
				return rc;
			}
			break;
		case GT_TCP_S_LAST_ACK:
			tcp_set_state(so, GT_TCP_S_CLOSED);
			return -1;
		default:
			BUG;
			break;
		}
	}
	return 0;
}

static void
tcp_into_sndq(struct gt_sock *so)
{
	int rc;
	struct route_entry r;

	ASSERT(GT_SOCK_ALIVE(so));
	if (!sock_in_txq(so)) {
		rc = sock_route(so, &r);
		if (rc != 0) {
			ASSERT(0); // TODO: v0.1
			return;
		}
		sock_add_txq(r.rt_ifp, so);
	}
}

static void
gt_tcp_into_ackq(struct gt_sock *so)
{
	so->so_ack = 1;
	tcp_into_sndq(so);
}

static void
gt_tcp_into_rstq(struct gt_sock *so)
{
	so->so_rst = 1;
	tcp_into_sndq(so);
}

int
gt_tcp_send(struct gt_sock *so, const struct iovec *iov, int iovcnt, int flags)
{
	int i, n, rc, cnt;

	if (so->so_err) {
		rc = -so_clr_errnum(so);
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
		rc = sock_sndbuf_add(so, iov[i].iov_base, cnt);
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
		tcp_into_sndq(so);
	}
	return n;
}

static int
gt_tcp_sender(struct gt_sock *so, int cnt)
{
	int can, emss;

	ASSERT(cnt);
//	return GT_MIN(cnt, tcp_emss(so));
	if (so->so_rwnd <= so->so_ssnt) {
		return 0;
	}
	emss = tcp_emss(so);
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
tcp_tx_established(struct route_if *ifp, struct dev_pkt *pkt, struct gt_sock *so)
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
			if (tcp_wprobe_timer_set(so)) {
				so->so_wprobe = 1;
			}
			return 0;
		}
	}
	if (snt == cnt && so->so_sfin) {
		switch (so->so_state) {
		case GT_TCP_S_ESTABLISHED:
			tcp_set_state(so, GT_TCP_S_FIN_WAIT_1);
			break;
		case GT_TCP_S_CLOSE_WAIT:
			tcp_set_state(so, GT_TCP_S_LAST_ACK);
			break;
		}
		so->so_sfin_sent = 1;
		tcp_flags |= GT_TCP_FLAG_FIN;
	}
	if (tcp_flags) {
		tcp_tx_data(ifp, pkt, so, tcp_flags, snt);
		return 1;
	} else {
		return 0;
	}
}

//  0 - can send more
//  1 - sent all
static int
tcp_tx(struct route_if *ifp, struct dev_pkt *pkt, struct gt_sock *so)
{
	int rc;

	switch (so->so_state) {
	case GT_TCP_S_CLOSED:
	case GT_TCP_S_LISTEN:
		return 1;
	case GT_TCP_S_SYN_SENT:
		tcp_tx_data(ifp, pkt, so, GT_TCP_FLAG_SYN, 0);
		return 1;
	case GT_TCP_S_SYN_RCVD:
		tcp_tx_data(ifp, pkt, so, GT_TCP_FLAG_SYN|GT_TCP_FLAG_ACK, 0);
		return 1;
	default:
		rc = tcp_tx_established(ifp, pkt, so);
		if (rc == 0) {
			if (so->so_ack) {
				so->so_ack = 0;
				tcp_tx_data(ifp, pkt, so, GT_TCP_FLAG_ACK, 0);
			}
			return 1;
		} else {
			so->so_ack = 0;
			return 0;
		}
	}
}

static int
tcp_fill(struct gt_sock *so, struct gt_eth_hdr *eth_h, struct gt_tcpcb *tcb,
	uint8_t tcp_flags, u_int len)
{
	int cnt, emss, tcp_opts_len, tcp_h_len, total_len;
	void *payload;
	struct gt_ip4_hdr *ip4_h;
	struct gt_tcp_hdr *tcp_h;

	ASSERT(so->so_ssnt + len <= so->so_sndbuf.sob_len);
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
			len = MIN(cnt, so->so_rwnd - so->so_ssnt);
		}
	}
	if (len) {
		ASSERT(len <= cnt);
		ASSERT(len <= so->so_rwnd - so->so_ssnt);
		if (so->so_ssnt + len == so->so_sndbuf.sob_len ||
		    (so->so_rwnd - so->so_ssnt) - len <= tcp_emss(so)) {
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
		emss = tcp_emss(so);
		ASSERT(tcp_opts_len <= emss);
		if (tcb->tcb_len + tcp_opts_len > emss) {
			tcb->tcb_len = emss - tcp_opts_len;
		}
		payload = (uint8_t *)(tcp_h + 1) + tcp_opts_len;
		sockbuf_copy(&so->so_sndbuf, so->so_ssnt, payload, tcb->tcb_len);
	}
	tcp_h_len = sizeof(*tcp_h) + tcp_opts_len;
	total_len = sizeof(*ip4_h) + tcp_h_len + tcb->tcb_len;
	ip4_h->ip4h_ver_ihl = GT_IP4H_VER_IHL;
	ip4_h->ip4h_type_of_svc = 0;
	ip4_h->ip4h_total_len = hton16(total_len);
	ip4_h->ip4h_id = hton16(so->so_ip_id);
	ip4_h->ip4h_frag_off = 0;
	ip4_h->ip4h_ttl = 64;
	ip4_h->ip4h_proto = IPPROTO_TCP;
	ip4_h->ip4h_cksum = 0;
	ip4_h->ip4h_saddr = so->so_tuple.sot_laddr;
	ip4_h->ip4h_daddr = so->so_tuple.sot_faddr;
	tcp_h->tcph_sport = so->so_tuple.sot_lport;
	tcp_h->tcph_dport = so->so_tuple.sot_fport;
	tcp_h->tcph_seq = hton32(tcb->tcb_seq);
	tcp_h->tcph_ack = hton32(tcb->tcb_ack);
	tcp_h->tcph_data_off = tcp_h_len << 2;
	tcp_h->tcph_flags = tcb->tcb_flags;
	tcp_h->tcph_win_size = hton16(tcb->tcb_win);
	tcp_h->tcph_cksum = 0;
	tcp_h->tcph_urgent_ptr = 0;
	gt_inet_ip4_set_cksum(ip4_h, tcp_h);
	so->so_ip_id++;
	so->so_ssnt += tcb->tcb_len;
	if (tcp_flags & GT_TCP_FLAG_SYN) {
		so->so_ssyn = 1;
		ASSERT(so->so_ssyn_acked == 0);
	}
	if (tcb->tcb_len || (tcp_flags & (GT_TCP_FLAG_SYN|GT_TCP_FLAG_FIN))) {
		if (so->so_retxed) {
			so->so_retxed = 0;
			tcps.tcps_sndrexmitpack++;
			tcps.tcps_sndrexmitbyte += tcb->tcb_len;
		}
		tcp_tx_timer_set(so);
	}
	timer_del(&so->so_timer_delack);
	return total_len;
}

static void
sock_tx_flush_if(struct route_if *ifp)
{
	int rc, n;
	struct dev_pkt pkt;
	struct gt_sock *so;
	struct dlist *txq;

	n = 0;
	txq = ifp->rif_txq + current->p_id;
	while (!dlist_is_empty(txq) && n < 128) {
		so = DLIST_FIRST(txq, struct gt_sock, so_txl);
		do {
			rc = route_if_not_empty_txr(ifp, &pkt);
			if (rc) {
				return;
			}
			rc = sock_tx(ifp, &pkt, so);
			n++;
		} while (rc == 0);
		gt_sock_del_txq(so);
		if (gt_sock_is_closed(so)) {
			sock_del(so);
		}
	}
}

void
sock_tx_flush()
{
	struct route_if *ifp;

	ROUTE_IF_FOREACH(ifp) {
		sock_tx_flush_if(ifp);
	}
}

static int
gt_udp_rcvbuf_recv(struct gt_sock *so, const struct iovec *iov, int iovcnt,
	struct sockaddr *addr, socklen_t *addrlen, int peek)
{
	int rc, cnt;
	struct sockbuf_msg msg;

	if (so->so_msgbuf.sob_len == 0) {
		return -EAGAIN;
	}
	rc = sockbuf_recv(&so->so_msgbuf, &msg, sizeof(msg), 1);
	if (rc == 0) {
		ASSERT(so->so_rcvbuf.sob_len == 0);
		return 0;
	}
	ASSERT(rc == sizeof(msg));
	ASSERT(msg.sobm_len);
	ASSERT(so->so_rcvbuf.sob_len >= msg.sobm_len);
	gt_set_sockaddr(addr, addrlen, msg.sobm_faddr, msg.sobm_fport);
	cnt = sockbuf_readv(&so->so_rcvbuf, iov, iovcnt,
	                     msg.sobm_len, peek);
	DBG(0, "hit; peek=%d, cnt=%d, buflen=%d, fd=%d",
	    peek, rc, so->so_rcvbuf.sob_len, so_get_fd(so));
	if (peek == 0) {
		if (msg.sobm_len > cnt) {
			msg.sobm_len -= cnt;
			rc = sockbuf_rewrite(&so->so_msgbuf,
			                     &msg, sizeof(msg));
			ASSERT(rc == sizeof(msg));
		} else {
			sockbuf_drop(&so->so_msgbuf, sizeof(msg));
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
	struct dev *dev;
	struct ip4_hdr *ip4_h;
	struct udp_hdr *udp_h;
	struct dev_pkt pkt;
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
	rc = sock_route(so, &dev);
	if (rc) {
		return rc;
	}
	txr = not_empty_txr(dev);
	if (txr == NULL) {
		return -ENOBUFS;
	}
	ASSERT(so->so_lmss == 1460);
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
		ASSERT(cnt > off);
		txr_slot(&pkt, txr);
		hdr = (struct msg_hdr *)pkt.data;
		ASSERT(hdr != NULL);
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

static const char *
gt_sock_str(struct strbuf *sb, struct gt_sock *so)
{
	int is_tcp;

	is_tcp = so->so_ipproto == SO_IPPROTO_TCP;
	strbuf_addf(sb, "{ proto=%s, fd=%d, tuple=",
	            is_tcp ? "tcp" : "udp", so_get_fd(so));
	strbuf_add_ipaddr(sb, AF_INET, &so->so_tuple.sot_laddr);
	strbuf_addf(sb, ".%hu>", ntoh16(so->so_tuple.sot_lport));
	strbuf_add_ipaddr(sb, AF_INET, &so->so_tuple.sot_faddr);
	strbuf_addf(sb,
		".%hu"
		", in_txq=%u"
		", error=%u"
		", reuseaddr=%u"
		", reuseport=%u"
		", timer=%u"
		", lmss=%u"
		", rmss=%u"
		,
		ntoh16(so->so_tuple.sot_fport),
		sock_in_txq(so),
		so->so_err,
		so->so_reuseaddr,
		so->so_reuseport,
		timer_is_running(&so->so_timer),
		so->so_lmss,
		so->so_rmss);
	if (is_tcp) {
		if (so->so_is_listen) {
			strbuf_addf(sb,
				", backlog=%u"
				", acceptq_len=%u",
				so->so_backlog,
				so->so_acceptq_len);
		} else {
			strbuf_addf(sb,
				", state=%s"
				", passive_open=%u"
				", accepted=%u"
				", ack=%u"
				", wprobe=%u"
				", retx=%u"
				", ntx_tries=%u"
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
				tcp_state_str(so->so_state),
				so->so_passive_open,
				so->so_accepted,
				so->so_ack,
				so->so_wprobe,
				so->so_retx,
				so->so_ntx_tries,
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
				timer_is_running(&so->so_timer_delack),
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
				strbuf_addf(sb, ", listen_fd=%d",
				            so_get_fd(so->so_listen));
			}
		}
	} else {
		strbuf_addf(sb,
			", rcvbuf_len=%u"
			", msgbuf_len=%u",
			so->so_rcvbuf.sob_len,
			so->so_msgbuf.sob_len);
	}
	strbuf_add_ch(sb, '}');
	return strbuf_cstr(sb);
}

int
so_get_fd(struct gt_sock *so)
{
	return file_get_fd((struct file *)so);
}

static struct gt_sock *
so_find(struct htable_bucket *b, int so_ipproto, struct sock_tuple *so_tuple)
{
	struct gt_sock *so;

	DLIST_FOREACH(so, &b->htb_head, so_list) {
		if (so->so_ipproto == so_ipproto &&
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
so_find_binded(struct htable_bucket *b,
	int so_ipproto, struct sock_tuple *so_tuple)
{
	struct gt_sock *so;

	// TODO: rcu, rr, mb_service_id
	DLIST_FOREACH(so, &b->htb_head, so_bind_list) {
		if (so->so_ipproto == so_ipproto &&
		    (so->so_tuple.sot_laddr == 0 ||
		     so->so_tuple.sot_laddr == so_tuple->sot_laddr)) {
			return so;
		}
	}
	return NULL;
}


static int
so_bind_ephemeral_port(struct gt_sock *so, struct route_entry *r,
	struct htable_bucket **pb)
{
	int i, n, rc, lport;
	uint32_t h;
	struct gt_sock *tmp;
	struct htable_bucket *b;

	n = EPHEMERAL_PORT_MAX - EPHEMERAL_PORT_MIN + 1;
	for (i = 0; i < n; ++i) {
		lport = r->rt_ifa->ria_ephemeral_port;
		so->so_tuple.sot_lport = hton16(lport);
		if (lport == EPHEMERAL_PORT_MAX) {
			r->rt_ifa->ria_ephemeral_port = EPHEMERAL_PORT_MIN;
		} else {
			r->rt_ifa->ria_ephemeral_port++;
		}
		rc = service_is_appropriate_rss(r->rt_ifp, &so->so_tuple);
		if (rc) {
			h = so_hash(so);
			b = htable_bucket_get(&curmod->htable, h);
			BUCKET_LOCK(b);
			tmp = so_find(b, so->so_ipproto, &so->so_tuple);
			if (tmp == NULL) {
				*pb = b;
				return 0;
			}
			BUCKET_UNLOCK(b);
		}
	}
	return -EADDRINUSE;
}

static int
sock_route(struct gt_sock *so, struct route_entry *r)
{
	int rc;

	r->rt_dst.ipa_4 = so->so_tuple.sot_faddr;
	rc = route_get4(so->so_tuple.sot_laddr, r);
	if (rc) {
		ips.ips_noroute++;
	} else {
		so->so_next_hop = route_get_next_hop4(r);
	}
	return rc;
}

static int
sock_in_txq(struct gt_sock *so)
{
	return so->so_txl.dls_next != NULL;
}

static void
sock_add_txq(struct route_if *ifp, struct gt_sock *so)
{
	struct dlist *txq;

	txq = ifp->rif_txq + current->p_id;
	DLIST_INSERT_TAIL(txq, so, so_txl);
}

static void
gt_sock_del_txq(struct gt_sock *so)
{
	ASSERT(sock_in_txq(so));
	DLIST_REMOVE(so, so_txl);
	so->so_txl.dls_next = NULL;
}

static int
gt_sock_is_closed(struct gt_sock *so)
{
	return so->so_state == GT_TCP_S_CLOSED && so->so_file.fl_opened == 0;
}

static void
sock_open(struct gt_sock *so)
{
	ASSERT(so->so_state == GT_TCP_S_CLOSED);
	so->so_dont_frag = 1;
	so->so_rmss = 0;
	so->so_lmss = 1460; // TODO:!!!!
}

static struct gt_sock *
so_new(int so_ipproto)
{
	int rc;
	struct file *fp;
	struct gt_sock *so;

	rc = file_alloc(NULL, &fp, FILE_SOCK);
	if (rc) {
		return NULL;
	}
	so = (struct gt_sock *)fp;
	DBG(0, "hit; fd=%d", so_get_fd(so));
	so->so_flags = 0;
	so->so_ipproto = so_ipproto;
	so->so_tuple.sot_laddr = 0;
	so->so_tuple.sot_lport = 0;
	so->so_tuple.sot_faddr = 0;
	so->so_tuple.sot_fport = 0;
	so->so_listen = NULL;
	so->so_txl.dls_next = NULL;
	so->so_bucket = NULL;
	timer_init(&so->so_timer);
	timer_init(&so->so_timer_delack);
	switch (so_ipproto) {
	case SO_IPPROTO_UDP:
		sockbuf_init(&so->so_msgbuf, 16384);
		sock_open(so);
		break;
	case SO_IPPROTO_TCP:
		sockbuf_init(&so->so_sndbuf, 16384);
		break;
	default:
		BUG;
		break;
	}
	sockbuf_init(&so->so_rcvbuf, 16384);
	return so;
}

static void
sock_del(struct gt_sock *so)
{
	int lport;
	struct htable_bucket *b;

	ASSERT(GT_SOCK_ALIVE(so));
	ASSERT(so->so_file.fl_opened == 0);
	ASSERT(so->so_state == GT_TCP_S_CLOSED);
	if (so->so_bucket) {
		BUCKET_LOCK(so->so_bucket);
		htable_del(&curmod->htable, (htable_entry_t *)so);
		BUCKET_UNLOCK(so->so_bucket);
		so->so_bucket = NULL;
	}
	lport = ntoh16(so->so_tuple.sot_lport);
	if (lport > 0 && lport < ARRAY_SIZE(curmod->binded)) {
		b = curmod->binded + lport;
		BUCKET_LOCK(b);
		DLIST_REMOVE(so, so_bind_list);
		BUCKET_UNLOCK(b);
	}
	if (sock_in_txq(so)) {
		return;
	}
	DBG(0, "hit; fd=%d", so_get_fd(so));
	if (so->so_ipproto == SO_IPPROTO_TCP) {
		tcps.tcps_closed++;
	}
	file_free(&so->so_file);
}

static int
gt_sock_rcvbuf_add(struct gt_sock *so, const void *src, int cnt, int all)
{
	int rc, len;

	len = so->so_rcvbuf.sob_len;
	rc = sockbuf_add(&current->p_sockbuf_pool, &so->so_rcvbuf, src, cnt, all);
	rc = so->so_rcvbuf.sob_len - len;
	DBG(0, "hit; fd=%d, cnt=%d, buflen=%d",
	    so_get_fd(so), rc, so->so_rcvbuf.sob_len);
	if (rc) {
		gt_tcp_set_swnd(so);
	}
	return rc;
}

static int
gt_sock_on_rcv(struct gt_sock *so, void *buf, int len,
	struct sock_tuple *so_tuple)
{
	int rc, rem;
	struct sockbuf_msg msg;

	if (so->so_rshut) {
		return len;
	}
	rem = len;
	rc = gt_sock_rcvbuf_add(so, buf, rem, 0);
	if (rc < 0) {
		return rc;
	} else {
		ASSERT(rc >= 0);
		ASSERT(rc <= rem);
		if (so->so_ipproto == SO_IPPROTO_UDP && rc > 0) {
			msg.sobm_trunc = rc < rem;
			msg.sobm_faddr = so_tuple->sot_faddr;
			msg.sobm_fport = so_tuple->sot_fport;
			msg.sobm_len = rc;
			rc = sockbuf_add(&current->p_sockbuf_pool,
			                 &so->so_msgbuf, &msg, sizeof(msg), 1);
			if (rc <= 0) {
				sockbuf_drop(&so->so_rcvbuf, msg.sobm_len);
				rc = 0;
			}
		}
		rem -= rc;
		so_wakeup(so, POLLIN);
	}
	return len - rem;
}

static int
sock_tx(struct route_if *ifp, struct dev_pkt *pkt,
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
			tcp_tx_data(ifp, pkt, so, tcp_flags, 0);
		}
		return 1;
	} else {
		rc = tcp_tx(ifp, pkt, so);
		return rc;
	}
}

static void
tcp_tx_data(struct route_if *ifp, struct dev_pkt *pkt,
	struct gt_sock *so, uint8_t tcp_flags, u_int len)
{
	int delack, sndwinup, total_len;
	struct gt_tcpcb tcb;
	struct gt_eth_hdr *eth_h;

	ASSERT(tcp_flags);
	ips.ips_localout++;
	tcps.tcps_sndtotal++;
	delack = timer_is_running(&so->so_timer_delack);
	sndwinup = so->so_swndup;
	eth_h = (struct gt_eth_hdr *)pkt->pkt_data;
	eth_h->ethh_type = GT_ETH_TYPE_IP4_BE;
	total_len = tcp_fill(so, eth_h, &tcb, tcp_flags, len);
	pkt->pkt_len = sizeof(*eth_h) + total_len;
	if (tcb.tcb_len) {
		tcps.tcps_sndpack++;
		tcps.tcps_sndbyte += tcb.tcb_len;
	} else if (tcb.tcb_flags == GT_TCP_FLAG_ACK) {
		tcps.tcps_sndacks++;
		if (delack) {
			tcps.tcps_delack++;
		} else if (sndwinup) {
			tcps.tcps_sndwinup++;
		}
	}
	DBG(0, "hit; if='%s', flags=%s, len=%d, seq=%u, ack=%u, fd=%d",
	    ifp->rif_name, log_add_tcp_flags(so->so_ipproto, tcb.tcb_flags),
	    tcb.tcb_len, tcb.tcb_seq, tcb.tcb_ack, so_get_fd(so));
	gt_arp_resolve(ifp, so->so_next_hop, pkt);
}

static int
sock_sndbuf_add(struct gt_sock *so, const void *src, int cnt)
{
	int rc;

	rc = sockbuf_add(&current->p_sockbuf_pool,
	                 &so->so_sndbuf, src, cnt, 0);
	DBG(0, "hit; cnt=%d, buflen=%d, fd=%d",
	    cnt, so->so_sndbuf.sob_len, so_get_fd(so));
	return rc;
}

static void
gt_sock_sndbuf_pop(struct gt_sock *so, int cnt)
{
	sockbuf_drop(&so->so_sndbuf, cnt);
	DBG(0, "hit; cnt=%d, buflen=%d, fd=%d",
	    cnt, so->so_sndbuf.sob_len, so_get_fd(so));
}

#if 0
static struct file *
gt_sock_next(int fd)
{
	struct file *fp;

	while (1) {
		fp = file_next(fd);
		if (fp == NULL) {
			return NULL;
		}
		if (fp->fl_type == FILE_SOCK) {
			return fp;
		} else {
			++fd;
		}
	}
}

static int
gt_sock_ctl_sock_list_next(void *udata, int fd)
{
	struct file *fp;

	fp = gt_sock_next(fd);
	if (fp == NULL) {
		return -ENOENT;
	} else {
		fd = file_get_fd(fp);
		return fd;
	}
}


static int
gt_sock_ctl_sock_list(void *udata, int fd, const char *new,
	struct strbuf *out)
{
	struct file *fp;
	struct gt_sockcb socb;

	fp = gt_sock_next(fd);
	if (fp == NULL) {
		return -ENOENT;
	}
	if (file_get_fd(fp) != fd) {
		return -ENOENT;
	}
	gt_sock_get_sockcb((struct gt_sock *)fp, &socb);
	strbuf_addf(out, "%d,%d,%d,%x,%hu,%x,%hu,%d,%d,%d",
		socb.socb_fd,
		socb.socb_ipproto,
		socb.socb_state,
		ntoh32(socb.socb_laddr),
		ntoh16(socb.socb_lport),
		ntoh32(socb.socb_faddr),
		ntoh16(socb.socb_fport),
		socb.socb_acceptq_len,
		socb.socb_incompleteq_len,
		socb.socb_backlog);
	return 0;
}

static void
gt_sock_ctl_init_sock_list(struct log *log)
{
	sysctl_add_list(log, GT_CTL_SOCK_LIST, SYSCTL_RD, NULL,
	                gt_sock_ctl_sock_list_next,
	                gt_sock_ctl_sock_list);
}
#endif

static int
sysctl_tcp_fin_timeout(const long long *new, long long *old)
{
	*old = curmod->tcp_fin_timeout / NANOSECONDS_SECOND;
	if (new != NULL) {
		curmod->tcp_fin_timeout = (*new) * NANOSECONDS_SECOND;
	}
	return 0;
}
