// SPDX-License-Identifier: LGPL-2.1-only

// TODO:
// 1) del ack: with a stream of full-sized incoming segments,
//    ACK responses must be sent for every second segment.

#include "../inet.h"
#include "../mod.h"
#include "../service.h"
#include "../socket.h"
#include "socket.h"

#define so_file so_base.sobase_file
#define so_bind_list so_base.sobase_bind_list
#define so_connect_list so_base.sobase_connect_list
#define so_blocked so_file.fl_blocked
#define so_referenced so_file.fl_referenced
#define so_sid so_file.fl_sid
#define so_laddr so_base.sobase_laddr
#define so_faddr so_base.sobase_faddr
#define so_lport so_base.sobase_lport
#define so_fport so_base.sobase_fport

#if 0
#define TCP_DBG(fmt, ...) \
	do { \
		log_buf_init(); \
		gt_dbg(fmt, ##__VA_ARGS__); \
	} while (0)
#endif

#if 0
#define TCP_DBG(fmt, ...) LOGF(LOG_NOTICE, 0, fmt, ##__VA_ARGS__)
#endif

#ifndef TCP_DBG
#define TCP_DBG(fmt, ...)
#endif

#define TCP_FLAG_FOREACH(x) \
	x(GT_TCPF_FIN, 'F') \
	x(GT_TCPF_SYN, 'S') \
	x(GT_TCPF_RST, 'R') \
	x(GT_TCPF_PSH, 'P') \
	x(GT_TCPF_ACK, '.') \
	x(GT_TCPF_URG, 'U') 

struct sock {
	struct gt_sock so_base;
	union {
		uint64_t so_flags;
		struct {
			u_int so_state : 8;
			u_int so_err : 4;
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
			struct gt_dlist so_accept_list;
			struct gt_dlist so_tx_list;
		};
		struct {
			// Listen
			struct gt_dlist so_incompleteq;
			struct gt_dlist so_completeq;
			int so_backlog;
			int so_acceptq_len;
		};
	};
	struct sock *so_acceptor;
	struct sock_buf so_rcvbuf;
	union {
		struct sock_buf so_sndbuf; // TCP
		struct sock_buf so_msgbuf; // UDP
	};
};



enum {
	TCP_TIMER_DELACK,
	TCP_TIMER_REXMIT,
	TCP_TIMER_PERSIST,
	TCP_TIMER_FIN,
	TCP_TIMER_TIME_WAIT,
};

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

struct tcp_fill_info {
	uint16_t tcb_win;
	uint16_t tcb_len;
	uint8_t tcb_flags;
	uint32_t tcb_seq;
	uint32_t tcb_ack;
	struct tcp_opts tcb_opts;
};

struct sockbuf_msg {
	uint16_t sobm_trunc;
	uint16_t sobm_len;
	be16_t sobm_fport;
	be32_t sobm_faddr;
};

#define curmod ((struct gt_module_socket *)gt_module_get(GT_MODULE_SOCKET))

// subr
static const char *tcp_flags_str(struct strbuf *sb, int proto,
	uint8_t tcp_flags);

static const char *gt_log_add_sock(struct sock *so)
	__attribute__((unused));

// tcp
static int tcp_set_swnd(struct sock *so);

static int tcp_set_state(struct sock *, struct in_context *, int);

static int tcp_rcvbuf_recv(struct sock *, const struct iovec *, int, int);

static void gt_tcp_rcvbuf_set_max(struct sock *, int);

static void gt_tcp_open(struct sock *);

static void tcp_close(struct sock *);

static void tcp_close_not_accepted(struct gt_dlist *);

static void tcp_wshut(struct sock *, struct in_context *);

static void tcp_tx_timer_set(struct sock *);

static int tcp_wprobe_timer_set(struct sock *);

static void tcp_timer_set_tcp_fin_timeout(struct sock *);

static void tcp_rcv_SYN_SENT(struct sock *, struct in_context *);

static int tcp_is_in_order(struct sock *, struct in_context *);

static int gt_tcp_process_badack(struct sock *so, uint32_t acked);

static int tcp_enter_time_wait(struct sock *, struct in_context *);

static void tcp_rcv_time_wait(struct sock *so);

static int tcp_process_ack(struct sock *, struct in_context *);

static int tcp_process_ack_complete(struct sock *, struct in_context *);

static void tcp_into_sndq(struct sock *);

static void tcp_into_ackq(struct sock *);

static void tcp_into_rstq(struct sock *);

static int gt_tcp_send(struct sock *so, const struct iovec *iov,
	int iovcnt, int flags);


// udp
static int gt_udp_rcvbuf_recv(struct sock *so, const struct iovec *iov,
	int iovcnt, struct sockaddr *addr, socklen_t *addrlen, int peek);

int gt_udp_sendto(struct sock *, const struct iovec *, int, int,
		const struct sockaddr_in *);

// sock
static const char *sock_str(struct strbuf *sb, struct sock *so);


static int so_in_txq(struct sock *so);

static void so_add_txq(struct route_if *ifp, struct sock *so);

static void so_del_txq(struct sock *so);

static void sock_open(struct sock *so);

static struct sock *so_new(int, int);

static int so_unref(struct sock *);

//static int sock_on_rcv(struct sock *, struct in_context *, be32_t, be16_t);

static int sock_tx(struct route_entry *, struct dev_pkt *, struct sock *);

static void tcp_tx_data(struct route_entry *, struct dev_pkt *,
	struct sock *, uint8_t, u_int);

static int sock_sndbuf_add(struct sock *, const void *, int);

static void sock_sndbuf_drain(struct sock *, int);

#define GT_SOCK_ALIVE(so) ((so)->so_file.fl_mbuf.mb_freed == 0)

#define GT_TCP_FLAG_ADD(val, name) \
	if (tcp_flags & val) { \
		strbuf_add_ch(sb, name); \
	}

static int
tcps_is_connected(int state)
{
	switch (state) {
	case GT_TCPS_ESTABLISHED:
	case GT_TCPS_CLOSE_WAIT:
	case GT_TCPS_FIN_WAIT_1:
	case GT_TCPS_CLOSING:
	case GT_TCPS_LAST_ACK:
	case GT_TCPS_FIN_WAIT_2:
	case GT_TCPS_TIME_WAIT:
		return 1;
	default:
		return 0;
	}
}

static int
so_get_fd(struct sock *so)
{
	return file_get_fd((struct file *)so);
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
gt_gbtcp_so_struct_size(void)
{
	return sizeof(struct sock);
}

static int
so_route(struct gt_sock *so, struct route_entry *r)
{
	return gt_so_route(so->sobase_laddr, so->sobase_faddr, r);
}

static void
so_wakeup(struct sock *so, struct in_context *in, short revents)
{
	if (so->so_processing) {
		assert(in != NULL);
		in->in_events |= revents;
	} else {
		file_wakeup(&so->so_file, revents);
	}
}

static int
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

static int
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
gt_gbtcp_so_get_err(struct file *fp)
{
	int errnum;
	struct sock *so;

	so = (struct sock *)fp;
	errnum = so_err_unpack(so->so_err);
	return errnum;
}

static void
so_set_err(struct sock *so, struct in_context *in, int errnum)
{
	int rc;

	TCP_DBG("Set error %d on socket; fd=%d", errnum, so_get_fd(so));
	so->so_err = so_err_pack(errnum);
	rc = tcp_set_state(so, in, GT_TCPS_CLOSED);
	if (rc == 0) {
		so_wakeup(so, in, POLLERR);
	}
}

static int
so_pop_errnum(struct sock *so)
{
	int errnum;

	errnum = gt_gbtcp_so_get_err(&so->so_file);
	if (so->so_err != SO_EINPROGRESS) {
		so->so_err = 0;
	}
	return errnum;
}

#define so_nread gt_gbtcp_so_nread

short
gt_gbtcp_so_get_events(struct file *fp)
{
	short events;
	struct sock *so;

	so = (struct sock *)fp;
	if (so->so_err && so->so_err != SO_EINPROGRESS) {
		events = POLLERR;
	} else {
		events = 0;
	}
	switch (so->so_base.sobase_proto) {
	case IPPROTO_TCP:
		switch (so->so_state) {
		case GT_TCPS_CLOSED:
			break;
		case GT_TCPS_LISTEN:
			if (!gt_dlist_is_empty(&so->so_completeq)) {
				events |= POLLIN;
			}
			break;
		default:
			if (so->so_rshut || so->so_rfin || so_nread(fp)) {
				events |= POLLIN;
			}
			if (tcps_is_connected(so->so_state) && !sockbuf_full(&so->so_sndbuf)) {
				events |= POLLOUT;
			}
			break;
		}
		break;
	case IPPROTO_UDP:
		if (so->so_faddr != 0) {
			events |= POLLOUT;
		}
		if (so_nread(fp)) {
			events |= POLLIN;
		}
		break;
	default:
		assert(0);
	}	
	return events;
}

int
gt_gbtcp_so_nread(struct file *fp)
{
	struct sock *so;

	so = (struct sock *)fp;
	return so->so_rcvbuf.sob_len;
}

int
gt_gbtcp_so_socket(struct file **fpp, int fd, int domain, int type, int proto)
{
	struct sock *so;

	so = so_new(fd, proto);
	if (so == NULL) {
		return -ENOMEM;
	}
	*fpp = &so->so_file;
	return 0;
}

int
gt_gbtcp_so_connect(struct file *fp, const struct sockaddr_in *faddr_in)
{
	int rc;
	struct sock *so;

	so = (struct sock *)fp;
	if (faddr_in->sin_port == 0 || faddr_in->sin_addr.s_addr == 0) {
		return -EINVAL;
	}

	if (so->so_base.sobase_proto == IPPROTO_UDP) {
		if (so->so_faddr) {
			return -EISCONN;			
		}
	} else {
		switch (so->so_state) {
		case GT_TCPS_CLOSED:
			break;
		case GT_TCPS_LISTEN:
		case GT_TCPS_SYN_SENT:
		case GT_TCPS_SYN_RCVD:
			return -EALREADY;
		default:
			return -EISCONN;
		}
	}

	assert(!so_in_txq(so));
	rc = gt_so_bind_ephemeral(&so->so_base, faddr_in->sin_addr.s_addr, faddr_in->sin_port);
	if (rc < 0) {
		return rc;
	}

	TCP_DBG("Socket connect, %s:%hu>%s:%hu, fd:%d",
		log_add_ipaddr(AF_INET, &so->so_laddr),
		ntoh16(so->so_lport),
		log_add_ipaddr(AF_INET, &so->so_faddr),
		ntoh16(so->so_fport), so_get_fd(so));

	if (so->so_base.sobase_proto == IPPROTO_UDP) {
		return 0;
	}

	gt_tcp_open(so);
	tcp_set_swnd(so);
	tcp_set_state(so, NULL, GT_TCPS_SYN_SENT);
	tcp_into_sndq(so);

	return -EINPROGRESS;
}

int 
gt_gbtcp_so_listen(struct file *fp, int backlog)
{
	struct sock *so;

	so = (struct sock *)fp;
	if (so->so_state == GT_TCPS_LISTEN) {
		return 0;
	}
	if (so->so_base.sobase_proto != IPPROTO_TCP) {
		return -ENOTSUP;
	}
	if (so->so_state != GT_TCPS_CLOSED) {
		return -EINVAL;
	}
	if (so->so_lport == 0) {
		return -EADDRINUSE;
	}
	gt_dlist_init(&so->so_incompleteq);
	gt_dlist_init(&so->so_completeq);
	so->so_acceptq_len = 0;
	so->so_backlog = backlog > 0 ? backlog : 32;
	tcp_set_state(so, NULL, GT_TCPS_LISTEN);
	so->so_is_listen = 1;
	return 0;
}

int
gt_gbtcp_so_accept(struct file **fpp, struct file *lfp)
{
	int fd;
	struct sock *so, *lso;

	lso = (struct sock *)lfp;
	if (lso->so_state != GT_TCPS_LISTEN) {
		return -EINVAL;
	}
	if (gt_dlist_is_empty(&lso->so_completeq)) {
		return -EAGAIN;
	}
	assert(lso->so_acceptq_len);
	so = GT_DLIST_FIRST(&lso->so_completeq, struct sock, so_accept_list);
	assert(tcps_is_connected(so->so_state));
	assert(so->so_accepted == 0);
	assert(so->so_acceptor == lso);
	so->so_accepted = 1;
	so->so_acceptor = NULL;
	GT_DLIST_REMOVE(so, so_accept_list);
	lso->so_acceptq_len--;
	fd = so_get_fd(so);
	*fpp = &so->so_file;
	tcpstat.tcps_accepts++;
	return fd;
}

int
gt_gbtcp_so_close(struct file *fp)
{
	struct sock *so;

	so = (struct sock *)fp;

	// close() can be called from controller
	so->so_sid = current->p_sid;

	if (so_in_txq(so)) {
		so_del_txq(so);
		tcp_into_sndq(so);
	}
	switch (so->so_state) {
	case GT_TCPS_CLOSED:
		so_unref(so);
		break;

	case GT_TCPS_LISTEN:
		tcp_close_not_accepted(&so->so_incompleteq);
		tcp_close_not_accepted(&so->so_completeq);
		tcp_set_state(so, NULL, GT_TCPS_CLOSED);
		break;

	case GT_TCPS_SYN_SENT:
		if (so_in_txq(so)) {
			so_del_txq(so);
		}
		tcp_set_state(so, NULL, GT_TCPS_CLOSED);
		break;

	default:
		if (1) { // Gracefull
			so->so_rshut = 1;
			so->so_wshut = 1;
			if (tcps_is_connected(so->so_state)) {
				tcp_wshut(so, NULL);	
			}
		} else {
			tcp_into_rstq(so);
			tcp_set_state(so, NULL, GT_TCPS_CLOSED);
		}
		break;
	}

	return 0;
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
	if (so->so_base.sobase_proto == IPPROTO_TCP) {
		if (!tcps_is_connected(so->so_state)) {
			return -EAGAIN;
		}
	}
	return 1;
}

int
gt_gbtcp_so_recvfrom(struct file *fp, const struct iovec *iov, int iovcnt,
		int flags, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc, peek;
	struct sock *so;

	so = (struct sock *)fp;
	if (flags & ~MSG_PEEK) {
		return -ENOTSUP;
	}
	rc = so_can_recv(so);
	if (rc <= 0) {
		return rc;
	}
	peek = flags & MSG_PEEK;
	switch (so->so_base.sobase_proto) {
	case IPPROTO_UDP:
		rc = gt_udp_rcvbuf_recv(so, iov, iovcnt, addr, addrlen, peek);
		break;
	case IPPROTO_TCP:
		rc = tcp_rcvbuf_recv(so, iov, iovcnt, peek);
		if (rc == -EAGAIN) {
			if (so->so_rfin) {
				rc = 0;
			}
		}
		break;
	default:
		rc = 0;
		assert(0);
		break;
	}
	return rc;
}

static struct in_context *cur_zerocopy_in;

int
gt_gbtcp_so_aio_recvfrom(struct file *fp, struct iovec *iov, int flags,
		struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;
	struct sock *so;

	if (flags) {
		return -ENOTSUP;
	}
	so = (struct sock *)fp;
	rc = so_can_recv(so);
	if (rc <= 0) {
		return rc;
	}
	assert(so->so_base.sobase_proto == IPPROTO_TCP); // TODO:
	if (so->so_rcvbuf.sob_len == 0) {
		if (cur_zerocopy_in == NULL ||
		    cur_zerocopy_in->in_len == 0) {
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
		assert(rc);
		iov->iov_len = rc;
		return rc;
	}
}

int
gt_gbtcp_so_recvdrain(struct file *fp, int len)
{
	int rc, off;
	struct sock *so;

	so = (struct sock *)fp;
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
gt_gbtcp_so_sendto(struct file *fp, const struct iovec *iov, int iovcnt, int flags,
		const struct sockaddr_in *dest_addr)
{
	int rc;
	struct sock *so;

	so = (struct sock *)fp;
	if (flags & ~(MSG_NOSIGNAL)) {
		return -ENOTSUP;
	}
	switch (so->so_base.sobase_proto) {
	case IPPROTO_UDP:
		rc = gt_udp_sendto(so, iov, iovcnt, flags, dest_addr);
		break;
	case IPPROTO_TCP:
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
gt_gbtcp_so_ioctl(struct file *fp, unsigned long request, uintptr_t arg)
{
	return -ENOTSUP;
}
#else /* __linux */
int
gt_gbtcp_so_ioctl(struct file *fp, unsigned long request, uintptr_t arg)
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
gt_gbtcp_so_getsockopt(struct file *fp, int level, int optname, void *optval, socklen_t *optlen)
{
	struct tcp_info *tcpi;
	struct sock *so;

	so = (struct sock *)fp;
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

		case TCP_INFO:
			if (*optlen < sizeof(*tcpi)) {
				return -EINVAL;
			}
			tcpi = optval;
			tcpi->tcpi_state = so->so_state;
			// TODO: Fill all fields
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

		case SO_PROTOCOL:
			if (*optlen < sizeof(int)) {
				return -EINVAL;
			}
			*optlen = sizeof(int);
			*((int *)optval) = so->so_base.sobase_proto;
			return 0; 
		}
	}

	return -ENOPROTOOPT;
}

int
gt_gbtcp_so_setsockopt(struct file *fp, int level, int optname,
		const void *optval, socklen_t optlen)
{
	int optint;
	struct sock *so;

	so = (struct sock *)fp;
	switch (level) {
	case IPPROTO_TCP:
		if (so->so_base.sobase_proto != IPPROTO_TCP) {
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
gt_gbtcp_so_getpeername(struct file *fp, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;
	struct sock *so;

	so = (struct sock *)fp;
	if (so->so_faddr == 0) {
		return -ENOTCONN;
	}
	if (so->so_base.sobase_proto == IPPROTO_TCP) {
		if (!tcps_is_connected(so->so_state)) {
			return -ENOTCONN;
		}
	}
	rc = gt_set_sockaddr(addr, addrlen, so->so_faddr, so->so_fport);
	return rc;
}

static const char *
tcp_flags_str(struct strbuf *sb, int proto, uint8_t tcp_flags)
{
	const char *s;

	if (proto == IPPROTO_UDP) {
		return "UDP";
	}
	TCP_FLAG_FOREACH(GT_TCP_FLAG_ADD);
	s = strbuf_cstr(sb);
	return s;
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

	assert(so->so_rmss);
	assert(so->so_lmss);
	emss = MIN(so->so_lmss, so->so_rmss);
	assert(emss >= IP4_MTU_MIN - 40);
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

	tcpstat.tcps_connects++;
	if (so->so_err == SO_EINPROGRESS) {
		so->so_err = 0;
	}
	if (so->so_wshut) {
		tcp_wshut(so, in);
	}
	if (so->so_passive_open && so->so_acceptor != NULL) {
		lso = so->so_acceptor;
		assert(lso->so_acceptq_len);
		GT_DLIST_REMOVE(so, so_accept_list);
		GT_DLIST_INSERT_HEAD(&lso->so_completeq, so, so_accept_list);
		so_wakeup(lso, in, POLLIN);
	} else {
		so_wakeup(so, in, POLLOUT);
	}
}

static int
tcp_set_state(struct sock *so, struct in_context *in, int state)
{
	int rc;

	assert(GT_SOCK_ALIVE(so));
	assert(state < GT_TCPS_MAX_STATES);
	assert(state != so->so_state);	
	TCP_DBG("Socket state transition %s->%s, fd=%d",
		tcp_state_str(so->so_state), tcp_state_str(state), so_get_fd(so));
	if (state != GT_TCPS_CLOSED) {
		tcpstat.tcps_states[state]++;
	}
	if (so->so_state != GT_TCPS_CLOSED) {
		tcpstat.tcps_states[so->so_state]--;
	}
	so->so_state = state;
	switch (so->so_state) {
	case GT_TCPS_ESTABLISHED:
		tcp_set_state_ESTABLISHED(so, in);
		break;

	case GT_TCPS_CLOSED:
		tcp_close(so);
		rc = so_unref(so);
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
	TCP_DBG("Receive from socket, fd=%d, peek=%d, cnt=%d, buflen=%d",
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
tcp_close(struct sock *so)
{
	so->so_ssnt = 0;
	timer_cancel(&so->so_timer);
	timer_cancel(&so->so_timer_delack);
	sockbuf_free(&so->so_rcvbuf);
	sockbuf_free(&so->so_sndbuf);
	if (so->so_passive_open) {
		if (so->so_accepted == 0) { 
			assert(so->so_acceptor != NULL);
			so->so_acceptor->so_acceptq_len--;
			GT_DLIST_REMOVE(so, so_accept_list);
			so->so_acceptor = NULL;
		}
	}
}

static void
tcp_close_not_accepted(struct gt_dlist *q)
{
	struct sock *so, *tmp_so;

	GT_DLIST_FOREACH_SAFE(so, q, so_accept_list, tmp_so) {
		assert(so->so_referenced == 0);
		gt_gbtcp_so_close(&so->so_file);
	}
}

static void
tcp_reset(struct sock *so, struct in_context *in)
{
	so->so_ssnt = 0;
	so->so_sack = in->in_tcp_ack;
	so->so_rseq = in->in_tcp_seq;
	tcp_into_rstq(so);
	so_unref(so);
}

static void
tcp_wshut(struct sock *so, struct in_context *in)
{
	assert(tcps_is_connected(so->so_state));
	if (so->so_sfin) {
		return;
	}
	switch (so->so_state) {
	case GT_TCPS_ESTABLISHED:
		tcp_set_state(so, in, GT_TCPS_FIN_WAIT_1);
		break;
	case GT_TCPS_CLOSE_WAIT:
		tcp_set_state(so, in, GT_TCPS_LAST_ACK);
		break;
	default:
		assert(0);
		break;
	}
	so->so_sfin = 1;
	tcp_into_sndq(so);
}

static void
tcp_delack(struct sock *so)
{
	if (timer_is_running(&so->so_timer_delack)) {
		timer_cancel(&so->so_timer_delack);
		tcp_into_ackq(so);
	}
	timer_set(&so->so_timer_delack, 200 * NSEC_MSEC, GT_MODULE_SOCKET, TCP_TIMER_DELACK);
}

static void
tcp_tx_timer_set(struct sock *so)
{
	uint64_t expires;

	assert(so->so_sfin_acked == 0);
	if (so->so_retx == 0) {
		so->so_retx = 1;
		so->so_wprobe = 0;
		so->so_ntries = 0;
	}
	if (!tcps_is_connected(so->so_state)) {
		expires = NSEC_SEC;
	} else {
		expires = 500 * NSEC_MSEC;
	}
	expires <<= so->so_ntries;
	timer_set(&so->so_timer, expires, GT_MODULE_SOCKET, TCP_TIMER_REXMIT);
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
	expires = 10 * NSEC_SEC;
	timer_set(&so->so_timer, expires, GT_MODULE_SOCKET, TCP_TIMER_PERSIST);
	return 1;
}

static void
tcp_timer_set_tcp_fin_timeout(struct sock *so)
{
	assert(so->so_retx == 0);
	assert(so->so_wprobe == 0);
	assert(!timer_is_running(&so->so_timer));
	timer_set(&so->so_timer, curmod->tcp_fin_timeout, GT_MODULE_SOCKET, TCP_TIMER_FIN);
}

int
gt_gbtcp_so_timer(struct timer *timer, u_char fn_id)
{
	struct sock *so;

	switch (fn_id) {
	case TCP_TIMER_DELACK:
		so = container_of(timer, struct sock, so_timer_delack);
		tcp_into_ackq(so);
		break;

	case TCP_TIMER_REXMIT:
		so = container_of(timer, struct sock, so_timer);
		assert(GT_SOCK_ALIVE(so));
		assert(so->so_sfin_acked == 0);
		assert(so->so_retx);
		so->so_ssnt = 0;
		so->so_sfin_sent = 0;
		tcpstat.tcps_rexmttimeo++;
		TCP_DBG("Retransmit timeout, fd=%d, state=%s",
		    so_get_fd(so), tcp_state_str(so->so_state));
		if (so->so_ntries++ > 6) {
			tcpstat.tcps_timeoutdrop++;
			so_set_err(so, NULL, ETIMEDOUT);
			return 0;
		}
		// TODO: 
	//	if (so->so_state == TCPS_SYN_RCVD) {
	//		cnt_tcp_timedout_syn_rcvd++;
	//		so_set_err(so, NULL, ETIMEDOUT);
	//		return;
	//	}
		so->so_tx_timo = 1;
		tcp_into_sndq(so);
		break;

	case TCP_TIMER_PERSIST:
		so = container_of(timer, struct sock, so_timer);
		assert(GT_SOCK_ALIVE(so));
		assert(so->so_sfin_acked == 0);
		assert(so->so_retx == 0);
		assert(so->so_wprobe);
		tcpstat.tcps_persisttimeo++;
		tcpstat.tcps_sndprobe++;
		tcp_into_ackq(so);
		tcp_wprobe_timer_set(so);
		break;

	case TCP_TIMER_FIN:
		so = container_of(timer, struct sock, so_timer);
		tcp_enter_time_wait(so, NULL);
		break;

	case TCP_TIMER_TIME_WAIT:
		so = container_of(timer, struct sock, so_timer);
		tcp_set_state(so, NULL, GT_TCPS_CLOSED);
		break;

	default:
		BUG("bad timer");
		break;
	}

	return 0;
}


static void
tcp_rcv_SYN_SENT(struct sock *so, struct in_context *in)
{
	switch (in->in_tcp_flags) {
	case GT_TCPF_SYN|GT_TCPF_ACK:
		tcp_set_state(so, in, GT_TCPS_ESTABLISHED);
		so->so_ack = 1;
		break;
	case GT_TCPF_SYN:
		tcp_set_state(so, in, GT_TCPS_SYN_RCVD);
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
		be32_t laddr, be32_t faddr, be16_t lport, be16_t fport)
{
	uint32_t h;
	struct sock *so;

	//assert(lso->so_acceptq_len <= lso->so_backlog);
	if (0 && lso->so_acceptq_len == lso->so_backlog) {
		tcpstat.tcps_listendrop++;
		return;
	}
	so = so_new(0, IPPROTO_TCP);
	if (so == NULL) {
		tcpstat.tcps_rcvmemdrop++;
		return;
	}
	so->so_laddr = laddr;
	so->so_faddr = faddr;
	so->so_lport = lport;
	so->so_fport = fport;
	gt_tcp_open(so);
	if (in->in_tcp_flags != GT_TCPF_SYN) {
		TCP_DBG("First connection packet not a SYN [%s]; %s:%hu>%s:%hu, seq=%u, lfd=%d, fd=%d",
			log_add_tcp_flags(so->so_base.sobase_proto, in->in_tcp_flags),
			log_add_ipaddr(AF_INET, &so->so_laddr),
			ntoh16(so->so_lport),
			log_add_ipaddr(AF_INET, &so->so_faddr),
			ntoh16(so->so_fport),
			in->in_tcp_seq,
			so_get_fd(lso), so_get_fd(so));
		/*dbg("theend [%s] fport=%u, seq=%u, ack=%u, tos=%u",
			log_add_tcp_flags(so->so_base.sobase_proto, in->in_tcp_flags),
			ntoh16(so->so_fport), in->in_tcp_seq, in->in_tcp_ack,
			in->in_ih->ih_tos);
		abort();*/
		tcpstat.tcps_badsyn++;
		tcp_reset(so, in);
		return;
	} else {
		TCP_DBG("New incoming connection %s:%hu>%s:%hu, lfd=%d, fd=%d",
			log_add_ipaddr(AF_INET, &so->so_laddr),
			ntoh16(so->so_lport),
			log_add_ipaddr(AF_INET, &so->so_faddr),
			ntoh16(so->so_fport),
			so_get_fd(lso), so_get_fd(so));
	}
	GT_DLIST_INSERT_HEAD(&lso->so_incompleteq, so, so_accept_list);
	lso->so_acceptq_len++;
	so->so_passive_open = 1;
	so->so_acceptor = lso;
	if (lso->so_lmss) {
		so->so_lmss = lso->so_lmss;
	}
	tcp_set_risn(so, in->in_tcp_seq);
	tcp_set_rmss(so, &in->in_tcp_opts);
	sockbuf_set_max(&so->so_sndbuf, lso->so_sndbuf.sob_max);
	gt_tcp_rcvbuf_set_max(so, lso->so_rcvbuf.sob_max);
	tcp_set_swnd(so);
	tcp_set_state(so, in, GT_TCPS_SYN_RCVD);
	tcp_into_sndq(so);

	gt_so_addto_connected(&so->so_base, &h);
}

static void
tcp_rcv_data(struct sock *so, struct in_context *in)
{
	int space;
	uint32_t off;

	off = tcp_diff_seq(in->in_tcp_seq, so->so_rseq);
	if (off == 0) {
		tcpstat.tcps_rcvpack++;
		tcpstat.tcps_rcvbyte += in->in_len;
	} else if (off == in->in_len) {
		in->in_len = 0;
		tcpstat.tcps_rcvduppack++;
		tcpstat.tcps_rcvdupbyte += in->in_len;
		return;
	} else if (off > in->in_len) {
		in->in_len = 0;
		tcpstat.tcps_pawsdrop++;
		return;
	} else {
		in->in_len -= off;
		in->in_payload += off;
		tcpstat.tcps_rcvpartduppack++;
		tcpstat.tcps_rcvpartdupbyte += off;
	}
	space = sockbuf_space(&so->so_rcvbuf);
	if (space < in->in_len) {
		tcpstat.tcps_rcvpackafterwin++;
		tcpstat.tcps_rcvbyteafterwin += in->in_len - space;
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

	assert(tcps_is_connected(so->so_state));
	if (so->so_rfin) {
		if (in->in_len || (in->in_tcp_flags & GT_TCPF_FIN)) {
			tcp_into_ackq(so);
		}
		return;
	}
	if (in->in_len) {
		tcp_rcv_data(so, in);
	}
	if (in->in_tcp_flags & GT_TCPF_SYN) {
		tcp_into_ackq(so);
	}
	if (in->in_tcp_flags & GT_TCPF_FIN) {
		so->so_rfin = 1;
		so->so_rseq++;
		so_wakeup(so, in, POLLIN|GT_POLLRDHUP);
		tcp_into_ackq(so);
		switch (so->so_state) {
		case GT_TCPS_ESTABLISHED:
			tcp_set_state(so, in, GT_TCPS_CLOSE_WAIT);
			break;
		case GT_TCPS_FIN_WAIT_1:
			tcp_set_state(so, in, GT_TCPS_CLOSING);
			break;
		case GT_TCPS_FIN_WAIT_2:
			timer_cancel(&so->so_timer); // tcp_fin_timeout
			rc = tcp_enter_time_wait(so, in);
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

	if (in->in_tcp_flags & GT_TCPF_RST) {
		// TODO: check seq
		tcpstat.tcps_drops++;
		if (!tcps_is_connected(so->so_state)) {
			tcpstat.tcps_conndrops++;
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
	if (in->in_tcp_flags & GT_TCPF_ACK) {
		rc = tcp_process_ack(so, in);
		if (rc) {
			return;
		}
		so->so_rwnd = in->in_tcp_win;
		so->so_rwnd_max = MAX(so->so_rwnd_max, so->so_rwnd);
	}
	switch (so->so_state) {
	case GT_TCPS_SYN_SENT:
		tcp_rcv_SYN_SENT(so, in);
		return;
	case GT_TCPS_CLOSED:
		tcpstat.tcps_rcvafterclose++;
		return;
	case GT_TCPS_SYN_RCVD:
		break;
	default:
		assert(so->so_rsyn);
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
	if (in->in_tcp_flags & (GT_TCPF_SYN|GT_TCPF_FIN)) {
		len++;
	}
	off = tcp_diff_seq(in->in_tcp_seq, so->so_rseq);
	if (off > len) {
		TCP_DBG("Receive out of order packet [%s], seq=%u, len=%u, %s",
			log_add_tcp_flags(so->so_base.sobase_proto, in->in_tcp_flags),
			in->in_tcp_seq, len, gt_log_add_sock(so));
		tcpstat.tcps_rcvoopack++;
		tcpstat.tcps_rcvoobyte += in->in_len;
		return 0;
	} else {
		return 1;
	}
}

static int
gt_tcp_process_badack(struct sock *so, uint32_t acked)
{
	if (tcps_is_connected(so->so_state)) {
		so->so_ssnt = 0;
	} else {
		// TODO
		//gt_tcp_out_rst(so, in);
	}
	if (acked > UINT32_MAX / 2) {
		tcpstat.tcps_rcvdupack++;
	} else {
		tcpstat.tcps_rcvacktoomuch++;
	}
	return -1;
}

static int
tcp_enter_time_wait(struct sock *so, struct in_context *in)
{
	int rc;
	uint64_t to;

	to = curmod->tcp_time_wait_timeout;
	if (to == 0) {
		rc = tcp_set_state(so, in, GT_TCPS_CLOSED);
		return rc;
	} else {
		tcp_set_state(so, NULL, GT_TCPS_TIME_WAIT);
		timer_set(&so->so_timer, to, GT_MODULE_SOCKET, TCP_TIMER_TIME_WAIT);
		return 0;
	}
}

static void
tcp_rcv_time_wait(struct sock *so)
{
}

static int
tcp_process_ack(struct sock *so, struct in_context *in)
{
	int rc, sfin_acked;
	uint32_t acked;

	acked = tcp_diff_seq(so->so_sack, in->in_tcp_ack);
	if (acked == 0) {
		return 0;
	}
	if (so->so_ssyn && so->so_ssyn_acked == 0) {
		acked--;
	}
	sfin_acked = 0;
	if (acked > so->so_ssnt) {
		if (so->so_sfin) {
			sfin_acked = 1;
			acked--;
		}
		if (acked > so->so_ssnt) {
			TCP_DBG("Received bad ACK packet [%s], ack=%u, %s",
				log_add_tcp_flags(so->so_base.sobase_proto,
					in->in_tcp_flags),
				in->in_tcp_ack, gt_log_add_sock(so));
			rc = gt_tcp_process_badack(so, acked);
			return rc;
		}
	}
	if (so->so_state == GT_TCPS_SYN_RCVD) {
		tcp_set_state(so, in, GT_TCPS_ESTABLISHED);
	}
	if (so->so_ssyn && so->so_ssyn_acked == 0) {
		so->so_ssyn_acked = 1;
		so->so_sack++;
	}
	if (acked) {
		so->so_sack += acked;
		so->so_ssnt -= acked;
		sock_sndbuf_drain(so, acked);
		tcpstat.tcps_rcvackpack++;
		tcpstat.tcps_rcvackbyte += acked;
	}
	if (so->so_ssnt == 0 && (so->so_sfin == 0 || sfin_acked)) {
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
	timer_cancel(&so->so_timer);
	so->so_nagle_acked = 1;
	if (so->so_sfin && so->so_sfin_acked == 0) {
		assert(so->so_sndbuf.sob_len == 0);
		so->so_sfin_acked = 1;
		switch (so->so_state) {
		case GT_TCPS_FIN_WAIT_1:
			tcp_timer_set_tcp_fin_timeout(so);
			tcp_set_state(so, in, GT_TCPS_FIN_WAIT_2);
			break;
		case GT_TCPS_CLOSING:
			rc = tcp_enter_time_wait(so, in);
			if (rc) {
				return rc;
			}
			break;
		case GT_TCPS_LAST_ACK:
			tcp_set_state(so, in, GT_TCPS_CLOSED);
			return -1;
		default:
			assert(0);
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

	assert(GT_SOCK_ALIVE(so));
	if (!so_in_txq(so)) {
		rc = so_route(&so->so_base, &r);
		if (rc != 0) {
			assert(0); // TODO: v 0.x.2
			return;
		}
		so_add_txq(r.rt_ifp, so);
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
	if (so->so_state == GT_TCPS_SYN_SENT || so->so_state == GT_TCPS_SYN_RCVD) {
		return -EAGAIN;
	} else if (!tcps_is_connected(so->so_state)) {
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

	assert(cnt);
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
tcp_tx_established(struct route_entry *r, struct dev_pkt *pkt, struct sock *so)
{
	int cnt, snt;
	uint8_t tcp_flags;

	if (!tcps_is_connected(so->so_state)) {
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
			tcp_flags = GT_TCPF_ACK;
		} else {
			if (tcp_wprobe_timer_set(so)) {
				so->so_wprobe = 1;
			}
			return 0;
		}
	}
	if (snt == cnt && so->so_sfin) {
		switch (so->so_state) {
		case GT_TCPS_ESTABLISHED:
			tcp_set_state(so, NULL, GT_TCPS_FIN_WAIT_1);
			break;
		case GT_TCPS_CLOSE_WAIT:
			tcp_set_state(so, NULL, GT_TCPS_LAST_ACK);
			break;
		}
		so->so_sfin_sent = 1;
		tcp_flags |= GT_TCPF_FIN;
	}
	if (tcp_flags) {
		tcp_tx_data(r, pkt, so, tcp_flags, snt);
		return 1;
	} else {
		return 0;
	}
}

//  0 - can send more
//  1 - sent all
static int
tcp_tx(struct route_entry *r, struct dev_pkt *pkt, struct sock *so)
{
	int rc;

	switch (so->so_state) {
	case GT_TCPS_CLOSED:
	case GT_TCPS_LISTEN:
		return 1;
	case GT_TCPS_SYN_SENT:
		tcp_tx_data(r, pkt, so, GT_TCPF_SYN, 0);
		return 1;
	case GT_TCPS_SYN_RCVD:
		tcp_tx_data(r, pkt, so, GT_TCPF_SYN|GT_TCPF_ACK, 0);
		return 1;
	default:
		rc = tcp_tx_established(r, pkt, so);
		if (rc == 0) {
			if (so->so_ack) {
				so->so_ack = 0;
				tcp_tx_data(r, pkt, so, GT_TCPF_ACK, 0);
			}
			return 1;
		} else {
			so->so_ack = 0;
			return 0;
		}
	}
}

static int
tcp_fill(struct sock *so, struct eth_hdr *eh, struct tcp_fill_info *tcb,
		uint8_t tcp_flags, u_int len)
{
	int cnt, emss, tcp_opts_len, th_len, total_len;
	void *payload;
	struct ip4_hdr *ih;
	struct tcp_hdr *th;

	assert(so->so_ssnt + len <= so->so_sndbuf.sob_len);
	ih = (struct ip4_hdr *)(eh + 1);
	th = (struct tcp_hdr *)(ih + 1);
	tcb->tcb_opts.tcp_opt_flags = 0;
	if (tcp_flags & GT_TCPF_SYN) {
		tcb->tcb_opts.tcp_opt_flags |= (1 << TCP_OPT_MSS);
		tcb->tcb_opts.tcp_opt_mss = so->so_lmss;
	}
	cnt = so->so_sndbuf.sob_len - so->so_ssnt;
	if (tcps_is_connected(so->so_state) && (tcp_flags & GT_TCPF_RST) == 0) {
		tcp_flags |= GT_TCPF_ACK;
		if (len == 0 && cnt && so->so_rwnd > so->so_ssnt) {
			len = MIN(cnt, so->so_rwnd - so->so_ssnt);
		}
	}
	if (len) {
		assert(len <= cnt);
		assert(len <= so->so_rwnd - so->so_ssnt);
		if (so->so_ssnt + len == so->so_sndbuf.sob_len ||
		    (so->so_rwnd - so->so_ssnt) - len <= tcp_emss(so)) {
			tcp_flags |= GT_TCPF_PSH;
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
		assert(tcp_opts_len <= emss);
		if (tcb->tcb_len + tcp_opts_len > emss) {
			tcb->tcb_len = emss - tcp_opts_len;
		}
		payload = (u_char *)(th + 1) + tcp_opts_len;
		sockbuf_copy(&so->so_sndbuf, so->so_ssnt, payload, tcb->tcb_len);
	}
	th_len = sizeof(*th) + tcp_opts_len;
	total_len = sizeof(*ih) + th_len + tcb->tcb_len;
	ih->ih_ver_ihl = IP4_VER_IHL;
	ih->ih_tos = 0;
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
	if (tcp_flags & GT_TCPF_SYN) {
		so->so_ssyn = 1;
		assert(so->so_ssyn_acked == 0);
	}
	if (tcb->tcb_len || (tcp_flags & (GT_TCPF_SYN|GT_TCPF_FIN))) {
		if (so->so_tx_timo) {
			so->so_tx_timo = 0;
			tcpstat.tcps_sndrexmitpack++;
			tcpstat.tcps_sndrexmitbyte += tcb->tcb_len;
		}
		tcp_tx_timer_set(so);
	}
	timer_cancel(&so->so_timer_delack);
	return total_len;
}

int
gt_gbtcp_so_tx_flush(void)
{
	int rc;
	struct dev_pkt pkt;
	struct route_entry r;
	struct sock *so;
	struct gt_dlist *tx_head;

	tx_head = &current->p_tx_head;
	while (!gt_dlist_is_empty(tx_head)) {
		so = GT_DLIST_FIRST(tx_head, struct sock, so_tx_list);
		rc = so_route(&so->so_base, &r);
		assert(rc == 0);
		do {
			rc = route_get_tx_packet(r.rt_ifp, &pkt, TX_CAN_REDIRECT);
			if (rc) {
				return -EAGAIN;
			}
			rc = sock_tx(&r, &pkt, so);
			dev_put_tx_packet(&pkt);
		} while (rc == 0);
		so_del_txq(so);
		so_unref(so);
	}

	return 0;
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
		assert(so->so_rcvbuf.sob_len == 0);
		return 0;
	}
	assert(rc == sizeof(msg));
	assert(msg.sobm_len);
	assert(so->so_rcvbuf.sob_len >= msg.sobm_len);
	gt_set_sockaddr(addr, addrlen, msg.sobm_faddr, msg.sobm_fport);
	cnt = sockbuf_readv(&so->so_rcvbuf, iov, iovcnt,
		msg.sobm_len, peek);
	TCP_DBG("Receive from UDP socket, peek=%d, cnt=%d, buflen=%d, fd=%d",
		peek, rc, so->so_rcvbuf.sob_len, so_get_fd(so));
	if (peek == 0) {
		if (msg.sobm_len > cnt) {
			msg.sobm_len -= cnt;
			rc = sockbuf_rewrite(&so->so_msgbuf,
			                     &msg, sizeof(msg));
			assert(rc == sizeof(msg));
		} else {
			sockbuf_drain(&so->so_msgbuf, sizeof(msg));
		}
	}
	return cnt;
}

int
gt_udp_sendto(struct sock *so, const struct iovec *iov, int iovcnt, int flags,
		const struct sockaddr_in *dest_addr)
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
	rc = so_route(so, &dev);
	if (rc) {
		return rc;
	}
	txr = not_empty_txr(dev);
	if (txr == NULL) {
		return -ENOBUFS;
	}
	assert(so->so_lmss == 1460);
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
		assert(cnt > off);
		txr_slot(&pkt, txr);
		hdr = (struct msg_hdr *)pkt.data;
		assert(hdr != NULL);
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

	is_tcp = so->so_base.sobase_proto == IPPROTO_TCP;
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
		so_in_txq(so),
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
			if (so->so_acceptor != NULL) {
				strbuf_addf(sb, ", listen_fd=%d",
				            so_get_fd(so->so_acceptor));
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

static int
so_in_txq(struct sock *so)
{
	return so->so_tx_list.dls_next != NULL;
}

static void
so_add_txq(struct route_if *ifp, struct sock *so)
{
	GT_DLIST_INSERT_TAIL(&current->p_tx_head, so, so_tx_list);
}

static void
so_del_txq(struct sock *so)
{
	assert(so_in_txq(so));
	GT_DLIST_REMOVE(so, so_tx_list);
	so->so_tx_list.dls_next = NULL;
}

static void
sock_open(struct sock *so)
{
	assert(so->so_state == GT_TCPS_CLOSED);
	so->so_dont_frag = 1;
	so->so_rmss = 0;
	so->so_lmss = 1460; // TODO:!!!!
}

static struct sock *
so_new(int fd, int proto)
{
	int rc;
	struct file *fp;
	struct sock *so;

	rc = file_alloc3(&fp, fd, FILE_SOCK);
	if (rc) {
		return NULL;
	}
	so = container_of(fp, struct sock, so_base.sobase_file);
	gt_so_base_init(&so->so_base);
	TCP_DBG("New socket, fd=%d", so_get_fd(so));
	so->so_flags = 0;
	so->so_state = GT_TCPS_CLOSED;
	so->so_sid = current->p_sid;
	so->so_base.sobase_proto = proto;
	so->so_laddr = 0;
	so->so_lport = 0;
	so->so_faddr = 0;
	so->so_fport = 0;
	so->so_acceptor = NULL;
	so->so_tx_list.dls_next = NULL;
	timer_init(&so->so_timer);
	timer_init(&so->so_timer_delack);
	switch (proto) {
	case IPPROTO_UDP:
		sockbuf_init(&so->so_msgbuf, 16384);
		sock_open(so);
		break;
	case IPPROTO_TCP:
		sockbuf_init(&so->so_sndbuf, 16384);
		break;
	default:
		BUG("bad proto");
		break;
	}
	sockbuf_init(&so->so_rcvbuf, 16384);
	return so;
}

void
gt_so_del_connected(struct gt_sock *so)
{

}

static int
so_unref(struct sock *so)
{
	assert(GT_SOCK_ALIVE(so));
	if (so->so_state != GT_TCPS_CLOSED || so->so_referenced) {
		return 0;
	}

	if (so->so_processing) {
		return 0;
	}

	if (so_in_txq(so)) {
		return 0;
	}

	gt_so_rmfrom_connected(&so->so_base);
	gt_so_rmfrom_binded(&so->so_base);

	TCP_DBG("Close socket, fd=%d", so_get_fd(so));
	if (so->so_base.sobase_proto == IPPROTO_TCP) {
		tcpstat.tcps_closed++;
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
	return rc;
}
*/

static int
so_rcvbuf_add(struct sock *so, void *buf, int len/*, be32_t faddr, be16_t fport*/)
{
	int rc;

	rc = sockbuf_add(current->p_sockbuf_pool, &so->so_rcvbuf, buf, len);
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
/*		assert(rc >= 0);
		assert(rc <= rem);
		if (so->so_base.sobase_proto == IPPROTO_UDP && rc > 0) {
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
sock_tx(struct route_entry *r, struct dev_pkt *pkt, struct sock *so)
{
	int rc;
	uint8_t tcp_flags;

	if (so->so_state == GT_TCPS_CLOSED && so->so_referenced == 0) { // ?????
		tcp_flags = 0;
		if (so->so_ack) {
			tcp_flags |= GT_TCPF_ACK;
		}
		if (so->so_rst) {
			tcp_flags |= GT_TCPF_RST;
		}
		if (tcp_flags) { // TODO: ????
			tcp_tx_data(r, pkt, so, tcp_flags, 0);
		}
		return 1;
	} else {
		rc = tcp_tx(r, pkt, so);
		return rc;
	}
}

static void
tcp_tx_data(struct route_entry *r, struct dev_pkt *pkt, struct sock *so,
		uint8_t tcp_flags, u_int len)
{
	int delack, sndwinup, total_len;
	struct tcp_fill_info tcb;
	struct eth_hdr *eh;

	assert(tcp_flags);
	ipstat.ips_localout++;
	tcpstat.tcps_sndtotal++;
	delack = timer_is_running(&so->so_timer_delack);
	sndwinup = so->so_swndup;
	eh = (struct eth_hdr *)pkt->pkt_data;
	eh->eh_type = ETH_TYPE_IP4_BE;
	total_len = tcp_fill(so, eh, &tcb, tcp_flags, len);
	pkt->pkt_len = sizeof(*eh) + total_len;
	if (tcb.tcb_len) {
		tcpstat.tcps_sndpack++;
		tcpstat.tcps_sndbyte += tcb.tcb_len;
	} else if (tcb.tcb_flags == GT_TCPF_ACK) {
		tcpstat.tcps_sndacks++;
		if (delack) {
			tcpstat.tcps_delack++;
		} else if (sndwinup) {
			tcpstat.tcps_sndwinup++;
		}
	}
	TCP_DBG("Transmit packet [%s] via %s, len=%d, seq=%u, ack=%u, fd=%d",
		log_add_tcp_flags(so->so_base.sobase_proto, tcb.tcb_flags),
		r->rt_ifp->rif_name,
		tcb.tcb_len, tcb.tcb_seq, tcb.tcb_ack, so_get_fd(so));
	service_account_opkt();
	arp_resolve(r, pkt);
}

static int
sock_sndbuf_add(struct sock *so, const void *src, int cnt)
{
	int rc;

	rc = sockbuf_add(current->p_sockbuf_pool,
	                 &so->so_sndbuf, src, cnt);
	TCP_DBG("Add %d bytes to send-buffer, buflen=%d, fd=%d",
		cnt, so->so_sndbuf.sob_len, so_get_fd(so));
	return rc;
}

static void
sock_sndbuf_drain(struct sock *so, int cnt)
{
	sockbuf_drain(&so->so_sndbuf, cnt);
	TCP_DBG("Remove %d bytes from send-buffer, buflen=%d, fd=%d",
		cnt, so->so_sndbuf.sob_len, so_get_fd(so));
}

static int
so_input(int proto, struct in_context *in, be32_t laddr, be32_t faddr,
		be16_t lport, be16_t fport)
{
	int rc;
	struct sock *so;

	rc = gt_so_lookup((struct gt_sock **)&so, proto, laddr, faddr, lport, fport); 
	if (rc != IN_OK) {
		return rc;
	}
	if (proto == IPPROTO_TCP) {
		tcpstat.tcps_rcvtotal++;
	} else {
		udpstat.udps_ipackets++;
	}
	TCP_DBG("Receive packet [%s], len=%d, seq=%u, ack=%u, fd=%d",
		log_add_tcp_flags(proto, in->in_tcp_flags),
		in->in_len, in->in_tcp_seq, in->in_tcp_ack, so_get_fd(so));
	so->so_processing = 1;
	in->in_events = 0;
	if (in->in_len) {
		if (so->so_rshut) {
			in->in_len = 0;
		}
	}
	if (so->so_base.sobase_proto == IPPROTO_TCP) {
		switch (so->so_state) {
		case GT_TCPS_CLOSED:
			break;
		case GT_TCPS_LISTEN:
			tcp_rcv_LISTEN(so, in, laddr, faddr, lport, fport);
			break;
		case GT_TCPS_TIME_WAIT:
			tcp_rcv_time_wait(so);
			break;
		default:
			tcp_rcv_open(so, in);
			break;
		}
	}
	int len, buflen;

	so->so_processing = 0;
	if (in->in_events) {
		buflen = so->so_rcvbuf.sob_len; 
		len = in->in_len;
		cur_zerocopy_in = in;
		so_wakeup(so, NULL, in->in_events);
		cur_zerocopy_in = NULL;
		if (in->in_len) {
			rc = so_rcvbuf_add(so, in->in_payload, in->in_len);
			if (rc < 0) {
				tcpstat.tcps_rcvmemdrop++;
			} else {
				assert(rc <= in->in_len);
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
	so_unref(so);
	return IN_OK;
}

int
so_input_err(int proto, struct in_context *p, be32_t laddr, be32_t faddr,
		be16_t lport, be16_t fport)
{
#if 0
	int rc, lport;
	uint32_t h;
	int lport;
	struct htable_bucket *b;
	struct sock *so;

	h = so_tuple_hash(so_tuple);
	b = htable_bucket_get(&curmod->htable, h);
	HTABLE_BUCKET_LOCK(b);
	so = so_find(b, proto, so_tuple);
	if (so != NULL) {
		so_set_err(so, errnum); 
	}
	HTABLE_BUCKET_UNLOCK(b);
	if (so != NULL) {
		return IP_OK;
	}
	if (proto == IPPROTO_TCP) {
		return IP_BYPASS;
	}
	lport = ntoh16(so_tuple->sot_lport);
	if (lport >= ARRAY_SIZE(curmod->binded)) {
		return IP_BYPASS;
	}
	b = curmod->binded + lport;
	HTABLE_BUCKET_LOCK(b);
	rc = IP_BYPASS;
	GT_DLIST_FOREACH(so, b, so_bind_list) {
		if (so->so_base.sobase_proto == IPPROTO_UDP &&
		    (so->so_tuple.sot_laddr == 0 ||
		     so->so_tuple.sot_laddr == so_tuple->sot_laddr)) {
			so_set_err(so, errnum);
			rc = IP_OK;
		}
	}
	HTABLE_BUCKET_UNLOCK(b);
	return rc;
#else
	return IN_OK;
#endif
}

int
gt_gbtcp_so_rx(struct route_if *ifp, void *data, int len)
{
	int rc, proto;
	struct in_context *p, in;

	in_context_init(&in, data, len);
	p = &in;

	rc = eth_input(ifp, p);
	assert(rc < 0);
	if (rc != IN_OK) {
		return rc;
	}
	proto = p->in_ipproto;
	if (proto == IPPROTO_UDP || proto == IPPROTO_TCP) {
		rc = so_input(proto, p,
			p->in_ih->ih_daddr, p->in_ih->ih_saddr,
			p->in_uh->uh_dport, p->in_uh->uh_sport);
	} else if (proto == IPPROTO_ICMP && p->in_errnum &&
	           (p->in_emb_ipproto == IPPROTO_UDP ||
	            p->in_emb_ipproto == IPPROTO_TCP)) {
		rc = so_input_err(p->in_emb_ipproto, p,
			p->in_ih->ih_daddr, p->in_ih->ih_saddr,
			p->in_uh->uh_dport, p->in_uh->uh_sport);
	} else {
		rc = IN_BYPASS;
	}
	return rc;
}
