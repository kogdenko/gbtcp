// TODO:
// 1) del ack: with a stream of full-sized incoming segments,
//    ACK responses must be sent for every second segment.
#include "internals.h"

#define SO_IPPROTO_UDP 0
#define SO_IPPROTO_TCP 1

#define TCP_FLAG_FOREACH(x) \
	x(TCP_FLAG_FIN, 'F') \
	x(TCP_FLAG_SYN, 'S') \
	x(TCP_FLAG_RST, 'R') \
	x(TCP_FLAG_PSH, 'P') \
	x(TCP_FLAG_ACK, '.') \
	x(TCP_FLAG_URG, 'U') 

#define tcps current->p_tcps
#define udps current->p_udps
#define ips current->p_ips

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

int gt_so_udata_size;

// subr
static const char *tcp_flags_str(struct strbuf *sb, int proto,
	uint8_t tcp_flags);

static const char *gt_log_add_sock(struct sock *so)
	__attribute__((unused));

static void gt_set_sockaddr(struct sockaddr *addr, socklen_t *addrlen,
	be32_t s_addr, be16_t port);

// tcp
static int tcp_set_swnd(struct sock *so);

static int tcp_set_state(struct sock *, struct in_context *, int);

static int tcp_rcvbuf_recv(struct sock *, const struct iovec *, int, int);

static void gt_tcp_rcvbuf_set_max(struct sock *so, int max);

static void gt_tcp_open(struct sock *so);

static void gt_tcp_close(struct sock *so);

static void gt_tcp_close_not_accepted(struct dlist *q);

static void tcp_wshut(struct sock *, struct in_context *);

static void tcp_tx_timer_set(struct sock *so);

static int tcp_wprobe_timer_set(struct sock *so);

static void gt_tcp_timer_set_tcp_fin_timeout(struct sock *so);

static void gt_tcp_timeout_delack(struct timer *timer);

static void tcp_tx_timo(struct timer *timer);

static void tcp_wprobe_timo(struct timer *timer);

static void gt_tcp_timeout_tcp_fin_timeout(struct timer *);

static void tcp_rcv_SYN_SENT(struct sock *, struct in_context *);

static int tcp_is_in_order(struct sock *, struct in_context *);

static int gt_tcp_process_badack(struct sock *so, uint32_t acked);

static int tcp_enter_TIME_WAIT(struct sock *, struct in_context *);

static void tcp_rcv_TIME_WAIT(struct sock *so);

static int tcp_process_ack(struct sock *, struct in_context *);

static int tcp_process_ack_complete(struct sock *, struct in_context *);

static void tcp_into_sndq(struct sock *so);

static void tcp_into_ackq(struct sock *so);

static void tcp_into_rstq(struct sock *so);

static int gt_tcp_send(struct sock *so, const struct iovec *iov,
	int iovcnt, int flags);


// udp
static int gt_udp_rcvbuf_recv(struct sock *so, const struct iovec *iov,
	int iovcnt, struct sockaddr *addr, socklen_t *addrlen, int peek);

int gt_udp_sendto(struct sock *so, const struct iovec *iov, int iovcnt,
	int flags, be32_t faddr, be16_t fport);

// sock
static const char *sock_str(struct strbuf *sb, struct sock *so);


static struct sock *so_find(struct htable_bucket *, int, be32_t, be32_t, be16_t, be16_t);
static struct sock *so_find_binded(struct htable_bucket *, int, be32_t, be32_t, be16_t, be16_t);


static int so_bind_ephemeral_port(struct sock *, struct route_entry *);

static int sock_route(struct sock *so, struct route_entry *r);

static int sock_in_txq(struct sock *so);

static void sock_add_txq(struct route_if *ifp, struct sock *so);

static void sock_del_txq(struct sock *so);

static void sock_open(struct sock *so);

static struct sock *so_new(int);

static int so_unref(struct sock *, struct in_context *);

//static int sock_on_rcv(struct sock *, struct in_context *, be32_t, be16_t);

static int sock_tx(struct route_if *, struct dev_pkt *, struct sock *);

static void tcp_tx_data(struct route_if *, struct dev_pkt *,
	struct sock *, uint8_t, u_int);

static int sock_sndbuf_add(struct sock *, const void *, int);

static void sock_sndbuf_drain(struct sock *, int);

static int sysctl_tcp_fin_timeout(const long long *new, long long *old);

#define GT_SOCK_ALIVE(so) ((so)->so_file.fl_mbuf.mb_used)

#define GT_TCP_FLAG_ADD(val, name) \
	if (tcp_flags & val) { \
		strbuf_add_ch(sb, name); \
	}

#if 0
#define BUCKET_LOCK(b) UNUSED(b)
#define BUCKET_UNLOCK(b)
#else
#define BUCKET_LOCK(b) spinlock_lock(&(b)->htb_lock)
#define BUCKET_UNLOCK(b) spinlock_unlock(&(b)->htb_lock)
#endif

#define SO_HASH(faddr, lport, fport) \
	((faddr) ^ ((faddr) >> 16) ^ ntoh16((lport) ^ (fport)))

static uint32_t
so_hash(void *e)
{
	struct sock *so;
	uint32_t hash;

	so = (struct sock *)e;
	hash = SO_HASH(so->so_faddr, so->so_lport, so->so_fport);
	return hash;
}

static void sysctl_socket(void *udata, const char *new, struct strbuf *out);

static int
sysctl_tcp_fin_timeout(const long long *new, long long *old)
{
	*old = curmod->tcp_fin_timeout / NANOSECONDS_SECOND;
	if (new != NULL) {
		curmod->tcp_fin_timeout = (*new) * NANOSECONDS_SECOND;
	}
	return 0;
}

int
tcp_mod_init( void **pp)
{
	int i, rc;
	struct htable_bucket *b;

	rc = shm_malloc(pp, sizeof(*curmod));
	if (rc) {
		return rc;
	}
	curmod = *pp;
	log_scope_init(&curmod->log_scope, "tcp");
	rc = htable_init(&curmod->htable, 2048, so_hash, HTABLE_SHARED);
	if (rc) {
		log_scope_deinit(&curmod->log_scope);
		shm_free(curmod);
		curmod = NULL;
		return rc;
	}
	for (i = 0; i < ARRAY_SIZE(curmod->binded); ++i) {
		b = curmod->binded + i;
		htable_bucket_init(b);
	}
	sysctl_add_htable(GT_SYSCTL_SOCKET_HTABLE, SYSCTL_RD,
	                  &curmod->htable, sysctl_socket);
	curmod->tcp_fin_timeout = NANOSECONDS_SECOND;
	sysctl_add_intfn(GT_SYSCTL_TCP_FIN_TIMEOUT, SYSCTL_WR,
	                 &sysctl_tcp_fin_timeout, 1, 24 * 60 * 60);
	return 0;
}

int
tcp_mod_attach(void *p)
{
	curmod = p;
	return 0;
}

int
tcp_mod_service_init(struct service *s)
{
	mbuf_pool_init(&s->p_sockbuf_pool, s->p_id, SOCKBUF_CHUNK_SIZE);
	return 0;
}

void
tcp_mod_deinit()
{
	if (curmod != NULL) {
		sysctl_del(GT_SYSCTL_TCP_FIN_TIMEOUT);
		sysctl_del(GT_SYSCTL_SOCKET_HTABLE);
		mbuf_pool_deinit(&current->p_sockbuf_pool);
		htable_deinit(&curmod->htable);
		log_scope_deinit(&curmod->log_scope);
		shm_free(curmod);
		curmod = NULL;
	}
}

void
tcp_mod_detach()
{
	curmod = NULL;
}

void
tcp_mod_service_deinit(struct service *s)
{
}

const char *
log_add_tcp_flags(int proto, uint8_t tcp_flags)
{
	return tcp_flags_str(log_buf_alloc_space(), proto, tcp_flags);
}

static const char *
gt_log_add_sock(struct sock *so)
{
	return sock_str(log_buf_alloc_space(), so);
}


int
so_get(int fd, struct sock **pso)
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
		*pso = (struct sock *)fp;
		return 0;
	}
}

static void
so_wakeup(struct sock *so, struct in_context *p, short revents)
{
	if (so->so_processing) {
		ASSERT(p != NULL);
		p->in_events |= revents;
	} else {
		file_wakeup(&so->so_file, revents);
	}
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
so_get_err(struct sock *so)
{
	int errnum;

	errnum = so_err_unpack(so->so_err);
	return errnum;
}

static void
so_set_err(struct sock *so, struct in_context *in, int errnum)
{
	int rc;

	DBG(0, "hit; fd=%d, err=%d", so_get_fd(so), errnum);
	so->so_err = so_err_pack(errnum);
	rc = tcp_set_state(so, in, GT_TCP_S_CLOSED);
	if (rc == 0) {
		so_wakeup(so, in, POLLERR);
	}
}

static int
so_pop_errnum(struct sock *so)
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
	struct sock *so;

	so = (struct sock *)fp;
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
			if (so->so_rshut || so->so_rfin || sock_nread(fp)) {
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
		if (so->so_faddr != 0) {
			events |= POLLOUT;
		}
		if (sock_nread(fp)) {
			events |= POLLIN;
		}
		break;
	default:
		BUG;
	}	
	return events;
}

void
so_get_socb(struct sock *so, struct socb *cb)
{
	cb->socb_fd = so_get_fd(so);
	cb->socb_flags = file_fcntl(&so->so_file, F_GETFL, 0);
	cb->socb_state = so->so_state;
	cb->socb_laddr = so->so_laddr;
	cb->socb_faddr = so->so_faddr;
	cb->socb_lport = so->so_lport;
	cb->socb_fport = so->so_fport;
	cb->socb_ipproto = so->so_ipproto == SO_IPPROTO_TCP ?
	                                   IPPROTO_TCP : IPPROTO_UDP;
	if (so->so_is_listen) {
		cb->socb_acceptq_len = so->so_acceptq_len;
		cb->socb_incompleteq_len = dlist_size(&so->so_incompleteq);
		cb->socb_backlog = so->so_backlog;
	} else {
		cb->socb_acceptq_len = 0;
		cb->socb_incompleteq_len = 0;
		cb->socb_backlog = 0;
	}
}

int
sock_nread(struct file *fp)
{
	struct sock *so;

	so = (struct sock *)fp;
	return so->so_rcvbuf.sob_len;
}

int
so_socket(struct sock **pso, int domain, int type, int flags, int ipproto)
{
	int so_fd, so_ipproto;
	struct sock *so;

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
	so->so_referenced = 1;
	so_fd = so_get_fd(so);
	*pso = so;
	return so_fd;
}

int
so_connect(struct sock *so, const struct sockaddr_in *faddr_in,
	struct sockaddr_in *laddr_in)
{
	int rc;
	struct route_entry r;

	if (faddr_in->sin_port == 0 || faddr_in->sin_addr.s_addr == 0) {
		return -EINVAL;
	}
	if (so->so_ipproto == SO_IPPROTO_UDP) {
		if (so->so_faddr) {
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
	if (so->so_lport) {
		return -ENOTSUP;
	}
	so->so_faddr = faddr_in->sin_addr.s_addr;
	so->so_fport = faddr_in->sin_port;
	rc = sock_route(so, &r);
	if (rc) {
		return rc;
	}
	so->so_laddr = r.rt_ifa->ria_addr.ipa_4;
	rc = so_bind_ephemeral_port(so, &r);
	if (rc < 0) {
		return rc;
	}
	DBG(0, "ok; tuple=%s:%hu>%s:%hu, fd=%d",
	    log_add_ipaddr(AF_INET, &so->so_laddr),
	    ntoh16(so->so_lport),
	    log_add_ipaddr(AF_INET, &so->so_faddr),
	    ntoh16(so->so_fport), so_get_fd(so));
	laddr_in->sin_family = AF_INET;
	laddr_in->sin_addr.s_addr = so->so_laddr;
	laddr_in->sin_port = so->so_lport;
	if (so->so_ipproto == SO_IPPROTO_UDP) {
		return 0;
	}
	gt_tcp_open(so);
	tcp_set_swnd(so);
	tcp_set_state(so, NULL, GT_TCP_S_SYN_SENT);
	tcp_into_sndq(so);
	return -EINPROGRESS;
}

int
so_bind(struct sock *so, const struct sockaddr_in *addr)
{
	be16_t lport;
	struct htable_bucket *b;

	if (so->so_state != GT_TCP_S_CLOSED) {
		return -EINVAL;
	}
	lport = hton16(addr->sin_port);
	if (lport == 0) {
		return -EINVAL;
	}
	if (so->so_laddr != 0 || so->so_lport != 0) {
		return -EINVAL;
	}
	if (lport >= ARRAY_SIZE(curmod->binded)) {
		return -EADDRNOTAVAIL;
	}
	so->so_laddr = addr->sin_addr.s_addr;
	so->so_lport = addr->sin_port;
	b = curmod->binded + lport;
	BUCKET_LOCK(b);
	so->so_binded = 1;
	DLIST_INSERT_TAIL(&b->htb_head, so, so_bind_list);
	BUCKET_UNLOCK(b);
	return 0;
}

int 
so_listen(struct sock *so, int backlog)
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
	if (so->so_lport == 0) {
		return -EADDRINUSE;
	}
	dlist_init(&so->so_incompleteq);
	dlist_init(&so->so_completeq);
	so->so_acceptq_len = 0;
	so->so_backlog = backlog > 0 ? backlog : 32;
	tcp_set_state(so, NULL, GT_TCP_S_LISTEN);
	so->so_is_listen = 1;
	return 0;
}

int
so_accept(struct sock **pso, struct sock *lso,
	struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	int fd;
	struct sock *so;

	if (lso->so_state != GT_TCP_S_LISTEN) {
		return -EINVAL;
	}
	if (dlist_is_empty(&lso->so_completeq)) {
		return -EAGAIN;
	}
	ASSERT(lso->so_acceptq_len);
	so = DLIST_FIRST(&lso->so_completeq, struct sock, so_accept_list);
	ASSERT(so->so_state >= GT_TCP_S_ESTABLISHED);
	ASSERT(so->so_accepted == 0);
	so->so_accepted = 1;
	DLIST_REMOVE(so, so_accept_list);
	lso->so_acceptq_len--;
	gt_set_sockaddr(addr, addrlen, so->so_faddr, so->so_fport);
	if (flags & SOCK_NONBLOCK) {
		so->so_blocked = 0;
	}
	so->so_referenced = 1;
	fd = so_get_fd(so);
	*pso = so;
	tcps.tcps_accepts++;
	return fd;
}

void
so_close(struct sock *so)
{
	so->so_referenced = 0;
	switch (so->so_state) {
	case GT_TCP_S_CLOSED:
		so_unref(so, NULL);
		break;
	case GT_TCP_S_LISTEN:
		gt_tcp_close_not_accepted(&so->so_incompleteq);
		gt_tcp_close_not_accepted(&so->so_completeq);
		tcp_set_state(so, NULL, GT_TCP_S_CLOSED);
		break;
	case GT_TCP_S_SYN_SENT:
		if (sock_in_txq(so)) {
			sock_del_txq(so);
		}
		tcp_set_state(so, NULL, GT_TCP_S_CLOSED);
		break;
	default:
		if (1) { // Gracefull
			so->so_rshut = 1;
			so->so_wshut = 1;
			if (so->so_state >= GT_TCP_S_ESTABLISHED) {
				tcp_wshut(so, NULL);	
			}
		} else {
			tcp_into_rstq(so);
			tcp_set_state(so, NULL, GT_TCP_S_CLOSED);
		}
		break;
	}
}

static int
so_can_recv(struct sock *so)
{
	int rc;

	if (so->so_err) {
		rc = -so_pop_errnum(so);
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
	return 1;
}

int
so_recvfrom(struct sock *so, const struct iovec *iov, int iovcnt,
	int flags, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc, peek;

	if (flags & ~MSG_PEEK) {
		return -ENOTSUP;
	}
	rc = so_can_recv(so);
	if (rc <= 0) {
		return rc;
	}
	peek = flags & MSG_PEEK;
	switch (so->so_ipproto) {
	case SO_IPPROTO_UDP:
		rc = gt_udp_rcvbuf_recv(so, iov, iovcnt, addr, addrlen, peek);
		break;
	case SO_IPPROTO_TCP:
		rc = tcp_rcvbuf_recv(so, iov, iovcnt, peek);
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

static struct in_context *cur_zerocopy_in;

int
so_recvfrom_zerocopy(struct sock *so, struct iovec *iov, int flags,
	struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;

	if (cur_zerocopy_in == NULL) {
		return -ENOTSUP;
	}
	if (flags) {
		return -ENOTSUP;
	}
	rc = so_can_recv(so);
	if (rc <= 0) {
		return rc;
	}
	ASSERT(so->so_ipproto == SO_IPPROTO_TCP); // TODO:
	if (so->so_rcvbuf.sob_len == 0) {
		if (cur_zerocopy_in->in_len == 0) {
			if (so->so_rfin) {
				return 0;
			} else {
				return -EAGAIN;
			}
		} else {
			iov->iov_base = cur_zerocopy_in->in_payload;
			iov->iov_len = cur_zerocopy_in->in_len;
			return cur_zerocopy_in->in_len;
		}
	} else {
		rc = sockbuf_read_zerocopy(&so->so_rcvbuf, &iov->iov_base);
		ASSERT(rc);
		iov->iov_len = rc;
		return rc;
	}
}

int
so_recv_drain(struct sock *so, int len)
{
	int rc, off;

	rc = so_can_recv(so);
	if (rc <= 0) {
		return rc;
	}
	off = 0;
	if (so->so_rcvbuf.sob_len) {
		off += sockbuf_drain(&so->so_rcvbuf, len);
	}
	if (off < len && cur_zerocopy_in != NULL) {
		rc = MAX(len - off, cur_zerocopy_in->in_len);
		cur_zerocopy_in->in_payload += rc;
		cur_zerocopy_in->in_len -= rc;
		off += rc;
	}
	return off;
}

int
so_sendto(struct sock *so, const struct iovec *iov, int iovcnt,
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
sock_ioctl(struct file *fp, unsigned long request, uintptr_t arg)
{
	return -ENOTSUP;
}
#else /* __linux */
int
sock_ioctl(struct file *fp, unsigned long request, uintptr_t arg)
{
	int v;
	struct sock *so;

	so = (struct sock *)fp;
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
so_getsockopt(struct sock *so, int level, int optname, void *optval,
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
			*((int *)optval) = so_pop_errnum(so);
			return 0;
		}
	}
	return -ENOPROTOOPT;
}

int
so_setsockopt(struct sock *so, int level, int optname, const void *optval,
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
so_getpeername(struct sock *so, struct sockaddr *addr, socklen_t *addrlen)
{
	if (so->so_faddr == 0) {
		return -ENOTCONN;
	}
	if (so->so_ipproto == SO_IPPROTO_TCP) {
		if (so->so_state < GT_TCP_S_ESTABLISHED) {
			return -ENOTCONN;
		}
	}
	gt_set_sockaddr(addr, addrlen, so->so_faddr, so->so_fport);
	return 0;
}

static const char *
tcp_flags_str(struct strbuf *sb, int proto, uint8_t tcp_flags)
{
	const char *s;

	if (proto == SO_IPPROTO_UDP) {
		return "UDP";
	}
	TCP_FLAG_FOREACH(GT_TCP_FLAG_ADD);
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
tcp_diff_seq(uint32_t start, uint32_t end)
{
	return end - start;
}

// Effective mss
static uint16_t
tcp_emss(struct sock *so)
{
	uint16_t emss;

	ASSERT(so->so_rmss);
	ASSERT(so->so_lmss);
	emss = MIN(so->so_lmss, so->so_rmss);
	ASSERT(emss >= IP4_MTU_MIN - 40);
	return emss;
}

static void
tcp_set_risn(struct sock *so, uint32_t seq)
{
	so->so_rsyn = 1;
	so->so_rseq = seq + 1;
}

// Receive mss
static void
tcp_set_rmss(struct sock *so, struct tcp_opts *opt)
{
	if (opt->tcp_opt_flags & (1 << TCP_OPT_MSS)) {
		so->so_rmss = MAX(IP4_MTU_MIN - 20, opt->tcp_opt_mss);
	} else {
		so->so_rmss = 536;
	}
}

// Sending window
static int
tcp_set_swnd(struct sock *so)
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

static void
tcp_set_state_ESTABLISHED(struct sock *so, struct in_context *in)
{
	struct sock *lso;

	tcps.tcps_connects++;
	if (so->so_err == SO_EINPROGRESS) {
		so->so_err = 0;
	}
	if (so->so_wshut) {
		tcp_wshut(so, in);
	}
	if (so->so_passive_open && so->so_listen != NULL) {
		lso = so->so_listen;
		ASSERT(lso->so_acceptq_len);
		DLIST_REMOVE(so, so_accept_list);
		DLIST_INSERT_HEAD(&lso->so_completeq, so, so_accept_list);
		so_wakeup(lso, in, POLLIN);
	} else {
		so_wakeup(so, in, POLLOUT);
	}
}

static int
tcp_set_state(struct sock *so, struct in_context *in, int state)
{
	int rc;

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
		tcp_set_state_ESTABLISHED(so, in);
		break;
	case GT_TCP_S_CLOSED:
		gt_tcp_close(so);
		rc = so_unref(so, in);
		return rc;
	}
	return 0;
}

static int
tcp_rcvbuf_recv(struct sock *so, const struct iovec *iov, int iovcnt, int peek)
{
	int rc, buflen;

	buflen = so->so_rcvbuf.sob_len;
	if (buflen == 0) {
		// TODO: curin ???
		return -EAGAIN;
	}
	rc = sockbuf_readv4(&so->so_rcvbuf, iov, iovcnt, peek);
	DBG(0, "hit; fd=%d, peek=%d, cnt=%d, buflen=%d",
	    so_get_fd(so), peek, rc, so->so_rcvbuf.sob_len);
	if (buflen != so->so_rcvbuf.sob_len) {
		if (tcp_set_swnd(so)) {
			tcp_into_ackq(so);
		}
	}
	return rc;
}


static void
gt_tcp_rcvbuf_set_max(struct sock *so, int max)
{
	sockbuf_set_max(&so->so_rcvbuf, max);
	tcp_set_swnd(so);
}

static void
gt_tcp_open(struct sock *so)
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
gt_tcp_close(struct sock *so)
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
			DLIST_REMOVE(so, so_accept_list);
			so->so_listen = NULL;
		}
	}
}

static void
gt_tcp_close_not_accepted(struct dlist *q)
{
	struct sock *so;

	while (!dlist_is_empty(q)) {
		so = DLIST_FIRST(q, struct sock, so_accept_list);
		ASSERT(so->so_referenced == 0);
		so->so_listen = NULL;
		so_close(so);
	}
}

static void
tcp_reset(struct sock *so, struct in_context *in)
{
	so->so_ssnt = 0;
	so->so_sack = in->in_tcp_ack;
	so->so_rseq = in->in_tcp_seq;
	tcp_into_rstq(so);
	so_unref(so, in);
}

static void
tcp_wshut(struct sock *so, struct in_context *in)
{
	ASSERT(so->so_state >= GT_TCP_S_ESTABLISHED);
	if (so->so_sfin) {
		return;
	}
	switch (so->so_state) {
	case GT_TCP_S_ESTABLISHED:
		tcp_set_state(so, in, GT_TCP_S_FIN_WAIT_1);
		break;
	case GT_TCP_S_CLOSE_WAIT:
		tcp_set_state(so, in, GT_TCP_S_LAST_ACK);
		break;
	default:
		BUG;
		break;
	}
	so->so_sfin = 1;
	tcp_into_sndq(so);
}

static void
tcp_delack(struct sock *so)
{
	if (timer_is_running(&so->so_timer_delack)) {
		timer_del(&so->so_timer_delack);
		tcp_into_ackq(so);
	}
	timer_set(&so->so_timer_delack, 200 * NANOSECONDS_MILLISECOND,
	          gt_tcp_timeout_delack);
}

#if 0
static void
gt_tcp_timeout_TIME_WAIT(struct timer *timer)
{
	struct sock *so;

	so = gt_container_of(timer, struct sock, timer);
	tcp_set_state(so, TCP_S_CLOSED);
}
#endif

static void
tcp_tx_timer_set(struct sock *so)
{
	uint64_t expires;

	ASSERT(so->so_sfin_acked == 0);
	if (so->so_retx == 0) {
		so->so_retx = 1;
		so->so_wprobe = 0;
		so->so_ntries = 0;
	}
	if (so->so_state < GT_TCP_S_ESTABLISHED) {
		expires = NANOSECONDS_SECOND;
	} else {
		expires = 500 * NANOSECONDS_MILLISECOND;
	}
	expires <<= so->so_ntries;
	timer_set(&so->so_timer, expires, tcp_tx_timo);
}

static int
tcp_wprobe_timer_set(struct sock *so)
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
gt_tcp_timer_set_tcp_fin_timeout(struct sock *so)
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
	struct sock *so;

	so = container_of(timer, struct sock, so_timer_delack);
	tcp_into_ackq(so);
}

static void
tcp_tx_timo(struct timer *timer)
{
	struct sock *so;

	so = container_of(timer, struct sock, so_timer);
	ASSERT(GT_SOCK_ALIVE(so));
	ASSERT(so->so_sfin_acked == 0);
	ASSERT(so->so_retx);
	so->so_ssnt = 0;
	so->so_sfin_sent = 0;
	tcps.tcps_rexmttimeo++;
	DBG(0, "hit; fd=%d, state=%s",
	    so_get_fd(so), tcp_state_str(so->so_state));
	if (so->so_ntries++ > 6) {
		tcps.tcps_timeoutdrop++;
		so_set_err(so, NULL, ETIMEDOUT);
		return;
	}
	// TODO: 
//	if (so->so_state == TCP_S_SYN_RCVD) {
//		cnt_tcp_timedout_syn_rcvd++;
//		so_set_err(so, NULL, ETIMEDOUT);
//		return;
//	}
	so->so_tx_timo = 1;
	tcp_into_sndq(so);
}

static void
tcp_wprobe_timo(struct timer *timer)
{
	struct sock *so;

	so = container_of(timer, struct sock, so_timer);
	ASSERT(GT_SOCK_ALIVE(so));
	ASSERT(so->so_sfin_acked == 0);
	ASSERT(so->so_retx == 0);
	ASSERT(so->so_wprobe);
	tcps.tcps_sndprobe++;
	tcp_into_ackq(so);
	tcp_wprobe_timer_set(so);
}

static void
gt_tcp_timeout_tcp_fin_timeout(struct timer *timer)
{
	struct sock *so;

	so = container_of(timer, struct sock, so_timer);
	tcp_enter_TIME_WAIT(so, NULL);
}

static void
tcp_rcv_SYN_SENT(struct sock *so, struct in_context *in)
{
	switch (in->in_tcp_flags) {
	case TCP_FLAG_SYN|TCP_FLAG_ACK:
		tcp_set_state(so, in, GT_TCP_S_ESTABLISHED);
		so->so_ack = 1;
		break;
	case TCP_FLAG_SYN:
		tcp_set_state(so, in, GT_TCP_S_SYN_RCVD);
		break;
	default:
		return;
	}
	tcp_set_risn(so, in->in_tcp_seq);
	tcp_set_rmss(so, &in->in_tcp_opts);
	tcp_into_sndq(so);
}

static void
tcp_rcv_LISTEN(struct sock *lso, struct in_context *in,
	be32_t laddr, be32_t faddr,
	be16_t lport, be16_t fport)
{
	uint32_t h;
	struct htable_bucket *b;
	struct sock *so;

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
	so->so_laddr = laddr;
	so->so_faddr = faddr;
	so->so_lport = lport;
	so->so_fport = fport;
	gt_tcp_open(so);
	if (in->in_tcp_flags != TCP_FLAG_SYN) {
		DBG(0, "not a SYN; tuple=%s:%hu>%s:%hu, lfd=%d, fd=%d",
		    log_add_ipaddr(AF_INET, &so->so_laddr),
		    ntoh16(so->so_lport),
	            log_add_ipaddr(AF_INET, &so->so_faddr),
		    ntoh16(so->so_fport),
		    so_get_fd(lso), so_get_fd(so));
		tcps.tcps_badsyn++;
		tcp_reset(so, in);
		return;
	} else {
		DBG(0, "ok; tuple=%s:%hu>%s:%hu, lfd=%d, fd=%d",
		    log_add_ipaddr(AF_INET, &so->so_laddr),
		    ntoh16(so->so_lport),
	            log_add_ipaddr(AF_INET, &so->so_faddr),
		    ntoh16(so->so_fport),
		    so_get_fd(lso), so_get_fd(so));
	}
	DLIST_INSERT_HEAD(&lso->so_incompleteq, so, so_accept_list);
	lso->so_acceptq_len++;
	so->so_passive_open = 1;
	so->so_listen = lso;
	if (lso->so_lmss) {
		so->so_lmss = lso->so_lmss;
	}
	tcp_set_risn(so, in->in_tcp_seq);
	tcp_set_rmss(so, &in->in_tcp_opts);
	sockbuf_set_max(&so->so_sndbuf, lso->so_sndbuf.sob_max);
	gt_tcp_rcvbuf_set_max(so, lso->so_rcvbuf.sob_max);
	tcp_set_swnd(so);
	tcp_set_state(so, in, GT_TCP_S_SYN_RCVD);
	tcp_into_sndq(so);
	h = so_hash(so);
	b = htable_bucket_get(&curmod->htable, h);
	BUCKET_LOCK(b);
	so->so_is_attached = 1;
	dlist_insert_tail_rcu(&b->htb_head, &so->so_hash_list);
	BUCKET_UNLOCK(b);
}

static void
tcp_rcv_data(struct sock *so, struct in_context *in)
{
	int space;
	uint32_t off;

	off = tcp_diff_seq(in->in_tcp_seq, so->so_rseq);
	if (off == 0) {
		tcps.tcps_rcvpack++;
		tcps.tcps_rcvbyte += in->in_len;
	} else if (off == in->in_len) {
		in->in_len = 0;
		tcps.tcps_rcvduppack++;
		tcps.tcps_rcvdupbyte += in->in_len;
		return;
	} else if (off > in->in_len) {
		in->in_len = 0;
		tcps.tcps_pawsdrop++;
		return;
	} else {
		in->in_len -= off;
		in->in_payload += off;
		tcps.tcps_rcvpartduppack++;
		tcps.tcps_rcvpartdupbyte += off;
	}
	space = sockbuf_space(&so->so_rcvbuf);
	if (space < in->in_len) {
		tcps.tcps_rcvpackafterwin++;
		tcps.tcps_rcvbyteafterwin += in->in_len - space;
		in->in_len = space;
	}
	if (in->in_len) {
		so_wakeup(so, in, POLLIN);
	}
}

static void
tcp_rcv_established(struct sock *so, struct in_context *in)
{
	int rc;

	ASSERT(so->so_state >= GT_TCP_S_ESTABLISHED);
	if (so->so_rfin) {
		if (in->in_len || (in->in_tcp_flags & TCP_FLAG_FIN)) {
			tcp_into_ackq(so);
		}
		return;
	}
	if (in->in_len) {
		tcp_rcv_data(so, in);
	}
	if (in->in_tcp_flags & TCP_FLAG_SYN) {
		tcp_into_ackq(so);
	}
	if (in->in_tcp_flags & TCP_FLAG_FIN) {
		so->so_rfin = 1;
		so->so_rseq++;
		so_wakeup(so, in, POLLIN|GT_POLLRDHUP);
		tcp_into_ackq(so);
		switch (so->so_state) {
		case GT_TCP_S_ESTABLISHED:
			tcp_set_state(so, in, GT_TCP_S_CLOSE_WAIT);
			break;
		case GT_TCP_S_FIN_WAIT_1:
			tcp_set_state(so, in, GT_TCP_S_CLOSING);
			break;
		case GT_TCP_S_FIN_WAIT_2:
			timer_del(&so->so_timer); // tcp_fin_timeout
			rc = tcp_enter_TIME_WAIT(so, in);
			if (rc) {
				return;
			}
			break;
		}
	}
}

static void
tcp_rcv_open(struct sock *so, struct in_context *in)
{
	int rc;

	if (in->in_tcp_flags & TCP_FLAG_RST) {
		// TODO: check seq
		tcps.tcps_drops++;
		if (so->so_state < GT_TCP_S_ESTABLISHED) {
			tcps.tcps_conndrops++;
			so_set_err(so, in, ECONNREFUSED);
		} else {
			so_set_err(so, in, ECONNRESET);
		}
		return;
	}
	if (so->so_rsyn) {
		rc = tcp_is_in_order(so, in);
		if (rc == 0) {
			tcp_into_ackq(so);
			return;
		}
	}
	if (in->in_tcp_flags & TCP_FLAG_ACK) {
		rc = tcp_process_ack(so, in);
		if (rc) {
			return;
		}
		so->so_rwnd = in->in_tcp_win;
		so->so_rwnd_max = MAX(so->so_rwnd_max, so->so_rwnd);
	}
	switch (so->so_state) {
	case GT_TCP_S_SYN_SENT:
		tcp_rcv_SYN_SENT(so, in);
		return;
	case GT_TCP_S_CLOSED:
		tcps.tcps_rcvafterclose++;
		return;
	case GT_TCP_S_SYN_RCVD:
		break;
	default:
		ASSERT(so->so_rsyn);
		tcp_rcv_established(so, in);
		break;
	}
	if (so->so_sfin_acked == 0) {
		tcp_into_sndq(so);
	}
}

static int
tcp_is_in_order(struct sock *so, struct in_context *in)
{
	uint32_t len, off;

	len = in->in_len;
	if (in->in_tcp_flags & (TCP_FLAG_SYN|TCP_FLAG_FIN)) {
		len++;
	}
	off = tcp_diff_seq(in->in_tcp_seq, so->so_rseq);
	if (off > len) {
		DBG(0, "out of order; flags=%s, seq=%u, len=%u, %s",
		    log_add_tcp_flags(so->so_ipproto, in->in_tcp_flags),
		    in->in_tcp_seq, len, gt_log_add_sock(so));
		tcps.tcps_rcvoopack++;
		tcps.tcps_rcvoobyte += in->in_len;
		return 0;
	} else {
		return 1;
	}
}

static int
gt_tcp_process_badack(struct sock *so, uint32_t acked)
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

static int
tcp_enter_TIME_WAIT(struct sock *so, struct in_context *in)
{
	int rc;

#if 1
	rc = tcp_set_state(so, in, GT_TCP_S_CLOSED);
	return rc;
#else
	tcp_set_state(so, TCP_S_TIME_WAIT);
	timer_set(&so->so_timer, 2 * MSL, gt_tcp_timeout_TIME_WAIT);
#endif
}

static void
tcp_rcv_TIME_WAIT(struct sock *so)
{
}

static int
tcp_process_ack(struct sock *so, struct in_context *in)
{
	int rc;
	uint32_t acked;

	acked = tcp_diff_seq(so->so_sack, in->in_tcp_ack);
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
			                      in->in_tcp_flags),
			    in->in_tcp_ack, gt_log_add_sock(so));
			rc = gt_tcp_process_badack(so, acked);
			return rc;
		}
	}
	if (so->so_state == GT_TCP_S_SYN_RCVD) {
		tcp_set_state(so, in, GT_TCP_S_ESTABLISHED);
	}
	if (so->so_ssyn && so->so_ssyn_acked == 0) {
		so->so_ssyn_acked = 1;
		so->so_sack++;
	}
	if (acked) {
		so->so_sack += acked;
		so->so_ssnt -= acked;
		sock_sndbuf_drain(so, acked);
		tcps.tcps_rcvackpack++;
		tcps.tcps_rcvackbyte += acked;
	}
	if (so->so_ssnt == 0) {
		rc = tcp_process_ack_complete(so, in);
		if (rc) {
			return rc;
		}
	}
	if (so->so_sfin == 0) {
		so_wakeup(so, in, POLLOUT);
	}
	return 0;
}

static int
tcp_process_ack_complete(struct sock *so, struct in_context *in)
{
	int rc;

	so->so_retx = 0;
	so->so_ntries = 0;
	timer_del(&so->so_timer);
	so->so_nagle_acked = 1;
	if (so->so_sfin && so->so_sfin_acked == 0 &&
	    so->so_sndbuf.sob_len == 0) {
		so->so_sfin_acked = 1;
		switch (so->so_state) {
		case GT_TCP_S_FIN_WAIT_1:
			gt_tcp_timer_set_tcp_fin_timeout(so);
			tcp_set_state(so, in, GT_TCP_S_FIN_WAIT_2);
			break;
		case GT_TCP_S_CLOSING:
			rc = tcp_enter_TIME_WAIT(so, in);
			if (rc) {
				return rc;
			}
			break;
		case GT_TCP_S_LAST_ACK:
			tcp_set_state(so, in, GT_TCP_S_CLOSED);
			return -1;
		default:
			BUG;
			break;
		}
	}
	return 0;
}

static void
tcp_into_sndq(struct sock *so)
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
tcp_into_ackq(struct sock *so)
{
	so->so_ack = 1;
	tcp_into_sndq(so);
}

static void
tcp_into_rstq(struct sock *so)
{
	so->so_rst = 1;
	tcp_into_sndq(so);
}

int
gt_tcp_send(struct sock *so, const struct iovec *iov, int iovcnt, int flags)
{
	int i, n, rc, cnt;

	if (so->so_err) {
		rc = -so_pop_errnum(so);
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
tcp_sender(struct sock *so, int cnt)
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
tcp_tx_established(struct route_if *ifp, struct dev_pkt *pkt, struct sock *so)
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
		snt = tcp_sender(so, cnt);
		if (snt) {
			tcp_flags = TCP_FLAG_ACK;
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
			tcp_set_state(so, NULL, GT_TCP_S_FIN_WAIT_1);
			break;
		case GT_TCP_S_CLOSE_WAIT:
			tcp_set_state(so, NULL, GT_TCP_S_LAST_ACK);
			break;
		}
		so->so_sfin_sent = 1;
		tcp_flags |= TCP_FLAG_FIN;
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
tcp_tx(struct route_if *ifp, struct dev_pkt *pkt, struct sock *so)
{
	int rc;

	switch (so->so_state) {
	case GT_TCP_S_CLOSED:
	case GT_TCP_S_LISTEN:
		return 1;
	case GT_TCP_S_SYN_SENT:
		tcp_tx_data(ifp, pkt, so, TCP_FLAG_SYN, 0);
		return 1;
	case GT_TCP_S_SYN_RCVD:
		tcp_tx_data(ifp, pkt, so, TCP_FLAG_SYN|TCP_FLAG_ACK, 0);
		return 1;
	default:
		rc = tcp_tx_established(ifp, pkt, so);
		if (rc == 0) {
			if (so->so_ack) {
				so->so_ack = 0;
				tcp_tx_data(ifp, pkt, so, TCP_FLAG_ACK, 0);
			}
			return 1;
		} else {
			so->so_ack = 0;
			return 0;
		}
	}
}

static int
tcp_fill(struct sock *so, struct eth_hdr *eh, struct tcpcb *tcb,
	uint8_t tcp_flags, u_int len)
{
	int cnt, emss, tcp_opts_len, th_len, total_len;
	void *payload;
	struct ip4_hdr *ih;
	struct tcp_hdr *th;

	ASSERT(so->so_ssnt + len <= so->so_sndbuf.sob_len);
	ih = (struct ip4_hdr *)(eh + 1);
	th = (struct tcp_hdr *)(ih + 1);
	tcb->tcb_opts.tcp_opt_flags = 0;
	if (tcp_flags & TCP_FLAG_SYN) {
		tcb->tcb_opts.tcp_opt_flags |= (1 << TCP_OPT_MSS);
		tcb->tcb_opts.tcp_opt_mss = so->so_lmss;
	}
	cnt = so->so_sndbuf.sob_len - so->so_ssnt;
	if (so->so_state >= GT_TCP_S_ESTABLISHED &&
		(tcp_flags & TCP_FLAG_RST) == 0) {
		tcp_flags |= TCP_FLAG_ACK;
		if (len == 0 && cnt && so->so_rwnd > so->so_ssnt) {
			len = MIN(cnt, so->so_rwnd - so->so_ssnt);
		}
	}
	if (len) {
		ASSERT(len <= cnt);
		ASSERT(len <= so->so_rwnd - so->so_ssnt);
		if (so->so_ssnt + len == so->so_sndbuf.sob_len ||
		    (so->so_rwnd - so->so_ssnt) - len <= tcp_emss(so)) {
			tcp_flags |= TCP_FLAG_PSH;
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
	tcp_opts_len = tcp_opts_fill(&tcb->tcb_opts, th + 1);
	if (tcb->tcb_len) {
		emss = tcp_emss(so);
		ASSERT(tcp_opts_len <= emss);
		if (tcb->tcb_len + tcp_opts_len > emss) {
			tcb->tcb_len = emss - tcp_opts_len;
		}
		payload = (u_char *)(th + 1) + tcp_opts_len;
		sockbuf_copy(&so->so_sndbuf, so->so_ssnt, payload, tcb->tcb_len);
	}
	th_len = sizeof(*th) + tcp_opts_len;
	total_len = sizeof(*ih) + th_len + tcb->tcb_len;
	ih->ih_ver_ihl = IP4_VER_IHL;
	ih->ih_type_of_svc = 0;
	ih->ih_total_len = hton16(total_len);
	ih->ih_id = hton16(so->so_ip_id);
	ih->ih_frag_off = 0;
	ih->ih_ttl = 64;
	ih->ih_proto = IPPROTO_TCP;
	ih->ih_cksum = 0;
	ih->ih_saddr = so->so_laddr;
	ih->ih_daddr = so->so_faddr;
	th->th_sport = so->so_lport;
	th->th_dport = so->so_fport;
	th->th_seq = hton32(tcb->tcb_seq);
	th->th_ack = hton32(tcb->tcb_ack);
	th->th_data_off = th_len << 2;
	th->th_flags = tcb->tcb_flags;
	th->th_win_size = hton16(tcb->tcb_win);
	th->th_cksum = 0;
	th->th_urgent_ptr = 0;
	ip4_set_cksum(ih, th);
	so->so_ip_id++;
	so->so_ssnt += tcb->tcb_len;
	if (tcp_flags & TCP_FLAG_SYN) {
		so->so_ssyn = 1;
		ASSERT(so->so_ssyn_acked == 0);
	}
	if (tcb->tcb_len || (tcp_flags & (TCP_FLAG_SYN|TCP_FLAG_FIN))) {
		if (so->so_tx_timo) {
			so->so_tx_timo = 0;
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
	struct sock *so;
	struct dlist *txq;

	n = 0;
	txq = ifp->rif_txq + current->p_id;
	while (!dlist_is_empty(txq)) {
		so = DLIST_FIRST(txq, struct sock, so_tx_list);
		do {
			rc = route_if_not_empty_txr(ifp, &pkt);
			if (rc) {
				return;
			}
			rc = sock_tx(ifp, &pkt, so);
			n++;
		} while (rc == 0);
		sock_del_txq(so);
		so_unref(so, NULL);
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
gt_udp_rcvbuf_recv(struct sock *so, const struct iovec *iov, int iovcnt,
	struct sockaddr *addr, socklen_t *addrlen, int peek)
{
	int rc, cnt;
	struct sockbuf_msg msg;

	if (so->so_msgbuf.sob_len == 0) {
		return -EAGAIN;
	}
	rc = sockbuf_read(&so->so_msgbuf, &msg, sizeof(msg), 1);
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
			sockbuf_drain(&so->so_msgbuf, sizeof(msg));
		}
	}
	return cnt;
}

int
gt_udp_sendto(struct sock *so, const struct iovec *iov, int iovcnt,
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
	struct ip4_hdr *ih;
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
	if (so->so_faddr != 0) {
		faddr = so->so_faddr;
		fport = so->so_fport;
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
	total_len = sizeof(*ih) + sizeof(*udp_h) + cnt;
	while (off < cnt) {
		if (n == 0) {
			off += (mtu - sizeof(*ih) - sizeof(*udp_h));
		} else {
			off += (mtu - sizeof(*ih));
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
		ih = (struct ip4_hdr *)(hdr + 1);
		ih->ver_ihl = IP4_VER_IHL;
		ih->type_of_svc = 0;
		ih->total_len = GT_HTON16(total_len);
		ih->id = 0;
		ih->frag_off = ip4_hdr_frag_off(off, frag);
		ih->ttl = 64;
		ih->proto = IPPROTO_UDP;
		ih->cksum = 0;
		ih->saddr = so->so_laddr;
		ih->daddr = faddr;
		pkt.len = sizeof(*hdr) + sizeof(*ih);
		len = mtu - sizeof(*ih);
		if (i == 0) {
			udp_h = (struct udp_hdr *)(ih + 1);
			udp_h->sport = so->so_lport;
			udp_h->dport = fport;
			udp_h->cksum = 0;
			udp_h->len = GT_HTON16(sizeof(*udp_h) + cnt);
			pkt.len += sizeof(*udp_h);
			payload = udp_h + 1;
			len -= sizeof(*udp_h);
		} else {
			payload = ih + 1;
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
sock_str(struct strbuf *sb, struct sock *so)
{
	int is_tcp;

	is_tcp = so->so_ipproto == SO_IPPROTO_TCP;
	strbuf_addf(sb, "{ proto=%s, fd=%d, tuple=",
	            is_tcp ? "tcp" : "udp", so_get_fd(so));
	strbuf_add_ipaddr(sb, AF_INET, &so->so_laddr);
	strbuf_addf(sb, ".%hu>", ntoh16(so->so_lport));
	strbuf_add_ipaddr(sb, AF_INET, &so->so_faddr);
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
		ntoh16(so->so_fport),
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
				so->so_ntries,
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
so_get_fd(struct sock *so)
{
	return file_get_fd((struct file *)so);
}

static struct sock *
so_find(struct htable_bucket *b, int so_ipproto,
	be32_t laddr, be32_t faddr, be16_t lport, be16_t fport)
{
	struct sock *so;

	DLIST_FOREACH_RCU(so, &b->htb_head, so_hash_list) {
		if (so->so_ipproto == so_ipproto &&
		    so->so_laddr == laddr && so->so_faddr == faddr &&
		    so->so_lport == lport && so->so_fport == fport) {
			return so;
		}
	}
	return NULL;
}

static struct sock *
so_find_binded(struct htable_bucket *b, int so_ipproto,
	be32_t laddr, be32_t faddr, be16_t lport, be16_t fport)
{
	struct sock *so, *found;

	// TODO: rcu
	found = NULL;
	//dbg(">>>>");
	DLIST_FOREACH_RCU(so, &b->htb_head, so_bind_list) {
		//dbg("! %d  current=%d", so->so_service_id, current->p_id);
		if (so->so_ipproto == so_ipproto &&
		    (so->so_laddr == 0 || so->so_laddr == laddr)) {
			//dbg("+");
			found = so;
			if (so->so_service_id == current->p_id) {
				break;
			}
		}
	}
	//dbg("<<<<");
	return found;
}


static int
so_bind_ephemeral_port(struct sock *so, struct route_entry *r)
{
	int i, n, rc, lport;
	uint32_t h;
	struct sock *tmp;
	struct htable_bucket *b;

	n = EPHEMERAL_PORT_MAX - EPHEMERAL_PORT_MIN + 1;
	for (i = 0; i < n; ++i) {
		lport = r->rt_ifa->ria_ephemeral_port;
		so->so_lport = hton16(lport);
		if (lport == EPHEMERAL_PORT_MAX) {
			r->rt_ifa->ria_ephemeral_port = EPHEMERAL_PORT_MIN;
		} else {
			r->rt_ifa->ria_ephemeral_port++;
		}
		rc = service_can_connect(r->rt_ifp, so->so_laddr, so->so_faddr,
		                         so->so_lport, so->so_fport);
		if (rc) {
			h = SO_HASH(so->so_faddr, so->so_lport, so->so_fport);
			b = htable_bucket_get(&curmod->htable, h);
			BUCKET_LOCK(b);
			tmp = so_find(b, so->so_ipproto, so->so_laddr, so->so_faddr,
			              so->so_lport, so->so_fport);
			if (tmp == NULL) {
				so->so_is_attached = 1;
				dlist_insert_tail_rcu(&b->htb_head, &so->so_hash_list);
				BUCKET_UNLOCK(b);
				return 0;
			}
			BUCKET_UNLOCK(b);
		}
	}
	return -EADDRINUSE;
}

static int
sock_route(struct sock *so, struct route_entry *r)
{
	int rc;

	r->rt_dst.ipa_4 = so->so_faddr;
	rc = route_get4(so->so_laddr, r);
	if (rc) {
		ips.ips_noroute++;
	} else {
		so->so_next_hop = route_get_next_hop4(r);
	}
	return rc;
}

static int
sock_in_txq(struct sock *so)
{
	return so->so_tx_list.dls_next != NULL;
}

static void
sock_add_txq(struct route_if *ifp, struct sock *so)
{
	struct dlist *txq;

	txq = ifp->rif_txq + current->p_id;
	DLIST_INSERT_TAIL(txq, so, so_tx_list);
}

static void
sock_del_txq(struct sock *so)
{
	ASSERT(sock_in_txq(so));
	DLIST_REMOVE(so, so_tx_list);
	so->so_tx_list.dls_next = NULL;
}

static void
sock_open(struct sock *so)
{
	ASSERT(so->so_state == GT_TCP_S_CLOSED);
	so->so_dont_frag = 1;
	so->so_rmss = 0;
	so->so_lmss = 1460; // TODO:!!!!
}

static struct sock *
so_new(int so_ipproto)
{
	int rc;
	struct file *fp;
	struct sock *so;

	rc = file_alloc(&fp, FILE_SOCK);
	if (rc) {
		return NULL;
	}
	so = (struct sock *)fp;
	DBG(0, "hit; fd=%d", so_get_fd(so));
	so->so_flags = 0;
	so->so_ipproto = so_ipproto;
	so->so_laddr = 0;
	so->so_lport = 0;
	so->so_faddr = 0;
	so->so_fport = 0;
	so->so_listen = NULL;
	so->so_tx_list.dls_next = NULL;
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

static int
so_unref(struct sock *so, struct in_context *in)
{
	int lport;
	uint32_t h;
	struct htable_bucket *b;

	ASSERT(GT_SOCK_ALIVE(so));
	if (so->so_state != GT_TCP_S_CLOSED || so->so_referenced) {
		return 0;
	}
	if (so->so_is_attached) {
		so->so_is_attached = 0;
		b = NULL;
		if (in == NULL) {
			h = so_hash(so);
			b = htable_bucket_get(&curmod->htable, h);
			BUCKET_LOCK(b);
		}
		dlist_remove_rcu(&so->so_hash_list);
		if (b != NULL) {
			BUCKET_UNLOCK(b);
		}
	}
	if (so->so_binded) {
		so->so_binded = 1;
		lport = ntoh16(so->so_lport);
		if (lport > 0 && lport < ARRAY_SIZE(curmod->binded)) {
			b = curmod->binded + lport;
			BUCKET_LOCK(b);
			DLIST_REMOVE(so, so_bind_list);
			BUCKET_UNLOCK(b);
		}
	}
	if (so->so_processing) {
		return 0;
	}
	if (sock_in_txq(so)) {
		return 0;
	}
	DBG(0, "hit; fd=%d", so_get_fd(so));
	if (so->so_ipproto == SO_IPPROTO_TCP) {
		tcps.tcps_closed++;
	}
	file_free(&so->so_file);
	return -1;
}

/*
static int
so_rcvbuf_add(struct sock *so, const void *src, int cnt)
{
	int rc, len;

	len = so->so_rcvbuf.sob_len;
	rc = so->so_rcvbuf.sob_len - len;
	DBG(0, "hit; fd=%d, cnt=%d, buflen=%d",
	    so_get_fd(so), rc, so->so_rcvbuf.sob_len);
	return rc;
}
*/

static int
so_rcvbuf_add(struct sock *so, void *buf, int len/*, be32_t faddr, be16_t fport*/)
{
	int rc;

	rc = sockbuf_add(&current->p_sockbuf_pool, &so->so_rcvbuf, buf, len);
	return rc;


/*
	int rc, rem;
	struct sockbuf_msg msg;

	rem = in->in_len;
	rc = so_rcvbuf_add(so, in->in_payload, rem);
	if (rc < 0) {
		return rc;
	}*/

	// TODO: UDP
/*		ASSERT(rc >= 0);
		ASSERT(rc <= rem);
		if (so->so_ipproto == SO_IPPROTO_UDP && rc > 0) {
			msg.sobm_trunc = rc < rem;
			msg.sobm_faddr = faddr;
			msg.sobm_fport = fport;
			msg.sobm_len = rc;
			rc = sockbuf_add(&current->p_sockbuf_pool,
			                 &so->so_msgbuf, &msg, sizeof(msg), 1);
			if (rc <= 0) {
				sockbuf_drop(&so->so_rcvbuf, msg.sobm_len);
				rc = 0;
			}
		}
		rem -= rc;
	
	return in->in_len - rem;
*/
}

static int
sock_tx(struct route_if *ifp, struct dev_pkt *pkt, struct sock *so)
{
	int rc;
	uint8_t tcp_flags;

	if (so->so_state == GT_TCP_S_CLOSED && so->so_referenced == 0) { // ?????
		tcp_flags = 0;
		if (so->so_ack) {
			tcp_flags |= TCP_FLAG_ACK;
		}
		if (so->so_rst) {
			tcp_flags |= TCP_FLAG_RST;
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
	struct sock *so, uint8_t tcp_flags, u_int len)
{
	int delack, sndwinup, total_len;
	struct tcpcb tcb;
	struct eth_hdr *eh;

	ASSERT(tcp_flags);
	ips.ips_localout++;
	tcps.tcps_sndtotal++;
	delack = timer_is_running(&so->so_timer_delack);
	sndwinup = so->so_swndup;
	eh = (struct eth_hdr *)pkt->pkt_data;
	eh->eh_type = ETH_TYPE_IP4_BE;
	total_len = tcp_fill(so, eh, &tcb, tcp_flags, len);
	pkt->pkt_len = sizeof(*eh) + total_len;
	if (tcb.tcb_len) {
		tcps.tcps_sndpack++;
		tcps.tcps_sndbyte += tcb.tcb_len;
	} else if (tcb.tcb_flags == TCP_FLAG_ACK) {
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
	arp_resolve(ifp, so->so_next_hop, pkt);
}

static int
sock_sndbuf_add(struct sock *so, const void *src, int cnt)
{
	int rc;

	rc = sockbuf_add(&current->p_sockbuf_pool,
	                 &so->so_sndbuf, src, cnt);
	DBG(0, "hit; cnt=%d, buflen=%d, fd=%d",
	    cnt, so->so_sndbuf.sob_len, so_get_fd(so));
	return rc;
}

static void
sock_sndbuf_drain(struct sock *so, int cnt)
{
	sockbuf_drain(&so->so_sndbuf, cnt);
	DBG(0, "hit; cnt=%d, buflen=%d, fd=%d",
	    cnt, so->so_sndbuf.sob_len, so_get_fd(so));
}

static void
sysctl_socket(void *udata, const char *new, struct strbuf *out)
{
	struct sock *so;
	struct socb cb;

	so = container_of(udata, struct sock, so_hash_list);
	so_get_socb(so, &cb);
	strbuf_addf(out, "%d,%d,%d,%x,%hu,%x,%hu,%d,%d,%d",
		cb.socb_fd,
		cb.socb_ipproto,
		cb.socb_state,
		ntoh32(cb.socb_laddr),
		ntoh16(cb.socb_lport),
		ntoh32(cb.socb_faddr),
		ntoh16(cb.socb_fport),
		cb.socb_acceptq_len,
		cb.socb_incompleteq_len,
		cb.socb_backlog);
}

int
so_in(int ipproto, struct in_context *in, be32_t laddr, be32_t faddr,
	be16_t lport, be16_t fport)
{
	int so_ipproto, i;
	uint32_t h;
	struct htable_bucket *b;
	struct sock *so;

	switch (ipproto) {
	case IPPROTO_UDP:
		so_ipproto = SO_IPPROTO_UDP;
		break;
	case IPPROTO_TCP:
		so_ipproto = SO_IPPROTO_TCP;
		break;
	default:
		return IN_BYPASS;
	}
	h = SO_HASH(faddr, lport, fport);
	b = htable_bucket_get(&curmod->htable, h);
	BUCKET_LOCK(b);
	so = so_find(b, so_ipproto, laddr, faddr, lport, fport);
	if (so == NULL) {
		BUCKET_UNLOCK(b);
		b = NULL;
		i = hton16(lport);
		if (i >= ARRAY_SIZE(curmod->binded)) {
			return IN_BYPASS;
		}
		b = curmod->binded + i; // rcv_LISTEN
		so = so_find_binded(b, so_ipproto, laddr, faddr, lport, fport);
	} else {
		//dbg("found %d cur=%d", so->so_service_id, current->p_id);
	}
	if (so == NULL) {
		return IN_BYPASS;
	}
	if (so->so_service_id != current->p_id) {
		ASSERT(0);
		if (b != NULL) {
			BUCKET_UNLOCK(b);
			b = NULL;
		}
		return so->so_service_id;
	}
	if (so_ipproto == SO_IPPROTO_TCP) {
		tcps.tcps_rcvtotal++;
	} else {
		udps.udps_ipackets++;
	}
	DBG(0, "hit; flags=%s, len=%d, seq=%u, ack=%u, fd=%d",
	    log_add_tcp_flags(so->so_ipproto, in->in_tcp_flags),
	    in->in_len, in->in_tcp_seq, in->in_tcp_ack, so_get_fd(so));
	so->so_processing = 1;
	in->in_events = 0;
	if (in->in_len) {
		if (so->so_rshut) {
			in->in_len = 0;
		}
	}
	if (so->so_ipproto == SO_IPPROTO_TCP) {
		switch (so->so_state) {
		case GT_TCP_S_CLOSED:
			break;
		case GT_TCP_S_LISTEN:
			tcp_rcv_LISTEN(so, in, laddr, faddr, lport, fport);
			break;
		case GT_TCP_S_TIME_WAIT:
			tcp_rcv_TIME_WAIT(so);
			break;
		default:
			tcp_rcv_open(so, in);
			break;
		}
	}
	int rc, len, buflen;

	so->so_processing = 0;
	if (in->in_events) {
		buflen = so->so_rcvbuf.sob_len; 
		len = in->in_len;
		cur_zerocopy_in = in;
		so_wakeup(so, NULL, in->in_events);
		cur_zerocopy_in = NULL;
		if (in->in_len) {
			printf_rl(NANOSECONDS_SECOND, "!!!\n");
			rc = so_rcvbuf_add(so, in->in_payload, in->in_len);
			if (rc < 0) {
				tcps.tcps_rcvmemdrop++;
			} else {
				ASSERT(rc <= in->in_len);
				len -= in->in_len - rc;
			}
		}
		if (len) {
			so->so_rseq += len;
			tcp_delack(so);
		}
		if (buflen != so->so_rcvbuf.sob_len) {
			if (tcp_set_swnd(so)) {
				tcp_into_ackq(so);
			}
		}
	}
	if (b != NULL) {
		BUCKET_UNLOCK(b);
	}
	return IN_OK;
}

int
so_in_err(int ipproto, struct in_context *p, be32_t laddr, be32_t faddr,
	be16_t lport, be16_t fport)
{
#if 0
	int rc, lport;
	uint32_t h;
	int so_ipproto, lport;
	struct htable_bucket *b;
	struct sock *so;

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
	return IN_OK;
#endif
}


