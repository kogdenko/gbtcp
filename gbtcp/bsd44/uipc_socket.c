// SPDX-License-Identifier: BSD-4-Clause

#include "../list.h"
#include "../shm.h"
#include "socket.h"
#include "tcp_var.h"
#include "udp_var.h"

#define so_proto so_base.sobase_proto

// do we have to send all at once on a socket?
#define	sosendallatonce(so) ((so)->so_proto == IPPROTO_UDP)

uint32_t tcp_now = 1;

static struct socket *
gt_fptoso(struct file *fp)
{
	struct socket *so;

	so = container_of(fp, struct socket, so_base.sobase_file);

	return so;
}

static struct file *
gt_sotofp(struct socket *so)
{
	return &so->so_base.sobase_file;
}

static struct socket *
somalloc(int fd)
{
	int rc;
	struct file *fp;
	struct socket *so;

	rc = file_alloc3(&fp, fd, FILE_SOCK);
	if (rc) {
		return NULL;
	}

	so = gt_fptoso(fp);

	gt_so_base_init(&so->so_base);

	so->so_head = NULL;
	so->so_state = 0;
	gt_dlist_init(so->so_q + 0);
	gt_dlist_init(so->so_q + 1);
	so->so_events = 0;
	so->so_error = 0;
	so->inp_laddr = 0;
	so->inp_faddr = 0;
	so->inp_lport = 0;
	so->inp_fport = 0;
	sbinit(&so->so_snd, 8 * 1024);
	sbinit(&so->so_rcv, 8 * 1024);

	return so;
}

static void
somfree(struct socket *so)
{
	assert(!(so->so_state & SS_ISATTACHED));
	file_free(&so->so_base.sobase_file);
}

/*
 * Socket operation routines.
 * These routines are called by the routines in
 * sys_socket.c or from a system process, and
 * implement the semantics of socket operations by
 * switching out to the protocol specific routines.
 */
int
gt_bsd44_so_socket(struct file **fpp, int fd, int domain, int type, int proto)
{
	struct socket *so;

	so = somalloc(fd);
	if (so == NULL) {
		return -ENOMEM;
	}
	so->so_proto = proto;
	so->so_options = 0;
	so->so_linger = 0;
	so->so_state = 0;
	if (so->so_proto == IPPROTO_TCP) {
		tcp_attach(so);
	}
	*fpp = gt_sotofp(so);
	return 0;
}

int
gt_bsd44_so_listen(struct file *fp, int backlog)
{
	int error;
	struct socket *so;

	so = gt_fptoso(fp);

	if (so->so_proto == IPPROTO_TCP) {
		error = tcp_listen(so);
		if (error) {
			return -error;
		}
	} else {
		return -ENOTSUP;
	}
	so->so_options |= SO_OPTION(SO_ACCEPTCONN);
	return 0;
}

#define prss(x) \
	if (so->so_state & x) { \
		printf("%s%s", cp, #x); \
		cp = "|"; \
	}

void
sofree(struct socket *so)
{
	int q;
	struct socket *lso;

/*	const char *cp = "ss=";

	printf("sofree: %p, ", so);
	prss(SS_NOFDREF);
	prss(SS_ISCONNECTED);
	prss(SS_ISCONNECTING);
	prss(SS_ISDISCONNECTING);
	prss(SS_CANTSENDMORE);
	prss(SS_CANTRCVMORE);
	prss(SS_ISTXPENDING);
	prss(SS_ISPROCESSING);
	prss(SS_ISATTACHED);
	printf("\n");*/

	if ((so->so_state & SS_NOFDREF) == 0) {
		// Don't free if referenced
		return;
	}

	if (so->so_state & SS_ISTXPENDING) {
		return;
	}
	if (so->so_state & SS_ISPROCESSING) {
		return;
	}
	if (so->so_state & SS_ISCONNECTING) {
		return;
	}
	if (so->so_state & SS_ISCONNECTED) {
		return;
	}
	if (so->so_state & SS_ISDISCONNECTING) {
		return;
	}
	if (so->so_state & SS_ISATTACHED) {
		return;
	}

	if (so->so_options & SO_OPTION(SO_ACCEPTCONN)) {
		for (q = 0; q < ARRAY_SIZE(so->so_q); ++q) {
			if (!gt_dlist_is_empty(so->so_q + q)) {
				return;
			}
		}
	} else if (so->so_head != NULL) {
		lso = so->so_head;
		soqremque(so, 0);
		soqremque(so, 1);
		sofree(lso);
	}

	sbrelease(&so->so_snd);
	sorflush(so);
	sowakeup(so, POLLNVAL);
	tcp_canceltimers(&so->inp_ppcb);
	somfree(so);
}

/*
 * Close a socket on last file table reference removal.
 * Initiate disconnect if connected.
 * Free socket when disconnect complete.
 */
int
gt_bsd44_so_close(struct file *fp)
{
	int q, rc;
	struct gt_dlist *head;
	struct socket *so, *aso, *tmp;

	so = gt_fptoso(fp);

	if (so->so_state & SS_NOFDREF) {
		return -EINVAL;
	}

	if (so->so_options & SO_OPTION(SO_ACCEPTCONN)) {
		for (q = 0; q < ARRAY_SIZE(so->so_q); ++q) {
			head = so->so_q + q;
			GT_DLIST_FOREACH_SAFE(aso, head, so_q[q], tmp) {
				soabort(aso);
			}
		}
	}

	if (so->so_proto == IPPROTO_TCP) {
		rc = tcp_disconnect(so);
	} else {
		rc = -ENOTSUP;//udp_disconnect(so);
	}

	so->so_state |= SS_NOFDREF;
	sofree(so);

	return rc;
}

void
soabort(struct socket *so)
{
	if (so->so_proto == IPPROTO_TCP) {
		tcp_abort(so);
	} else {
		//udp_abort(so);
	}
}

int
gt_bsd44_so_connect(struct file *fp, const struct sockaddr_in *faddr_in)
{
	int rc;
	struct socket *so;

	so = (struct socket *)fp;

	if (so->so_options & SO_OPTION(SO_ACCEPTCONN)) {
		return -EOPNOTSUPP;
	}

	// If protocol is connection-based, can only connect once.
	// Otherwise, if connected, try to disconnect first.
	// This allows user to disconnect by connecting to, e.g.,
	// a null address.
	if (so->so_state & SS_ISCONNECTING) {
		rc = -EALREADY;
	} else if (so->so_state & SS_ISCONNECTED) {
		rc = -EISCONN;
	} else {
		if (so->so_proto == IPPROTO_TCP) {
			rc = tcp_connect(so, faddr_in);
		} else {
			//rc = udp_connect(so);
			rc = -ENOTSUP;
		}
	}
	return rc;
}

// Send on a socket.
// If send must go all at once and message is larger than
// send buffering, then hard error.
// Lock against other senders.
// If must go all at once and not enough room now, then
// inform user that this would block and do nothing.
// Otherwise, if nonblocking, send as much as possible.
// The data to be sent is described by "uio" if nonzero,
// otherwise by the mbuf chain "top" (which must be null
// if uio is not).  Data provided in mbuf chain must be small
// enough to send all at once.
//
// Returns nonzero on error, timeout or signal; callers
// must check for short counts if EINTR/ERESTART are returned.
// Data and control buffers are freed on return.
int
sosend(struct socket *so, const struct iovec *iov, int iovcnt,
		const struct sockaddr_in *dest_addr)
{
	int i, rc, atomic, space, datlen;

	atomic = sosendallatonce(so);
	
	if (so->so_state & SS_CANTSENDMORE) {
		return -EPIPE;
	}
	if (so->so_error) {
		return -so->so_error;
	}
	if ((so->so_state & SS_ISCONNECTED) == 0) {
		if (so->so_proto == IPPROTO_TCP) {
			return -ENOTCONN;
		} else if (dest_addr == NULL) {
			return -EDESTADDRREQ;
		}
	}
	if (atomic) {
		space = sbspace(&so->so_snd);

		datlen = 0;
		for (i = 0; i < iovcnt; ++i) {
			datlen += iov[i].iov_len;			
		}

		if (datlen > so->so_snd.sb_hiwat) {
			return -EMSGSIZE;
		}

		if (space < datlen) {
			return -EWOULDBLOCK;
		}
	}
	if (so->so_proto == IPPROTO_TCP) {
		rc = tcp_send(so, iov, iovcnt);
	} else {
		//rc = udp_send(so, dat, datlen, addr);
		rc = -ENOTSUP;
	}
	return rc;
}

/*
int
bsd_shutdown(struct socket *so, int how)
{
	if (how & SHUT_RD) {
		sorflush(so);
	}
	if (how & SHUT_WR) {
		if (so->so_proto == IPPROTO_TCP) {
			tcp_shutdown(so);
		} else {
			udp_shutdown(so);
		}
	}
	return 0;
}*/

void
sorflush(struct socket *so)
{
	socantrcvmore(so);
}

int
gt_bsd44_so_setsockopt(struct file *fp, int level, int optname,
		const void *optval, socklen_t optlen)
{
	int rc;
	const struct linger *linger;
	struct socket *so;

	so = gt_fptoso(fp);
	
	if (level != SOL_SOCKET) {
		if (so->so_proto == IPPROTO_TCP) {
			rc = tcp_ctloutput(PRCO_SETOPT, so, level, optname, optval, &optlen);
		} else {
			rc = -ENOPROTOOPT;	
		}
		return rc;
	}
	if (optlen < sizeof(int)) {
		return -EINVAL;
	}

	switch (optname) {
	case SO_LINGER:
		if (optlen < sizeof(struct linger)) {
			return -EINVAL;
		}
		linger = optval;
		so->so_linger = linger->l_linger;
		somodopt(so, optname, linger->l_onoff);
		break;

	case SO_REUSEADDR:
	case SO_REUSEPORT:
		break;

	case SO_DEBUG:
	case SO_KEEPALIVE:
		somodopt(so, optname, *((const int *)optval));
		break;

	case SO_SNDBUF:
		sbreserve(&so->so_snd, *(const int *)optval);
		break;

	case SO_RCVBUF:
		so->so_rcv.sb_hiwat = *((const int *)optval);
		break;

	case SO_SNDLOWAT:
		so->so_snd.sb_lowat = *((const int *)optval);
		break;

	case SO_RCVLOWAT:
		break;

	default:
		return -ENOPROTOOPT;
	}

	return 0;
}

int
gt_bsd44_so_getsockopt(struct file *fp, int level, int optname, void *optval, socklen_t *optlen)
{
	int rc;
	struct linger *linger;
	struct socket *so;

	so = gt_fptoso(fp);

	if (level != SOL_SOCKET) {
		if (so->so_proto == IPPROTO_TCP) {
			rc = tcp_ctloutput(PRCO_GETOPT, so, level, optname, optval, optlen);
		} else {
			rc = -ENOPROTOOPT;
		}
		return rc;
	}

	if (*optlen < sizeof(int)) {
		return -EINVAL;
	}
	*optlen = sizeof(int);

	switch (optname) {
	case SO_LINGER:
		if (*optlen < sizeof(struct linger)) {
			return -EINVAL;
		}
		*optlen = sizeof(struct linger);
		linger = (struct linger *)optval;
		linger->l_onoff = soisopt(so, SO_LINGER);
		linger->l_linger = so->so_linger;
		break;

	case SO_DEBUG:
	case SO_KEEPALIVE:
		*((int *)optval) = soisopt(so, optname);
		break;

	case SO_TYPE:
		*((int *)optval) = so->so_proto ? SOCK_STREAM : SOCK_DGRAM;
		break;

	case SO_PROTOCOL:
		*((int *)optval) = so->so_proto;
		break;

	case SO_ERROR:
		*((int *)optval) = so->so_error;
		so->so_error = 0;
		break;

	case SO_SNDBUF:
		*((int *)optval) = so->so_snd.sb_hiwat;
		break;

	case SO_RCVBUF:
		*((int *)optval) = so->so_rcv.sb_hiwat;
		break;

	case SO_SNDLOWAT:
		*((int *)optval) = so->so_snd.sb_lowat;
		break;

	case SO_RCVLOWAT:
		*((int *)optval) = 0;
		break;

	default:
		return -ENOPROTOOPT;
	}
	return 0;
}

/*
 * Primitive routines for operating on sockets and socket buffers
 */

//u_long	sb_max = SB_MAX;		/* patchable */

/*
 * Procedures to manipulate state flags of socket
 * and do appropriate wakeups.  Normal sequence from the
 * active (originating) side is that soisconnecting() is
 * called during processing of connect() call,
 * resulting in an eventual call to soisconnected() if/when the
 * connection is established.  When the connection is torn down
 * soisdisconnecting() is called during processing of disconnect() call,
 * and soisdisconnected() is called when the connection to the peer
 * is totally severed.  The semantics of these routines are such that
 * connectionless protocols can call soisconnected() and soisdisconnected()
 * only, bypassing the in-progress calls when setting up a ``connection''
 * takes no time.
 *
 * From the passive side, a socket is created with
 * two queues of sockets: so_q0 for connections in progress
 * and so_q for connections already made and awaiting user acceptance.
 * As a protocol is preparing incoming connections, it creates a socket
 * structure queued on so_q0 by calling sonewconn().  When the connection
 * is established, soisconnected() is called, and transfers the
 * socket structure to so_q, making it available to accept().
 * 
 * If a socket is closed with sockets on either
 * so_q0 or so_q, these sockets are dropped.
 */

void
soisconnecting(struct socket *so)
{
	so->so_state &= ~(SS_ISCONNECTED|SS_ISDISCONNECTING);
	so->so_state |= SS_ISCONNECTING;
}

void
soisconnected(struct socket *so)
{
	struct socket *head;

	so->so_state &= ~(SS_ISCONNECTING|SS_ISDISCONNECTING);
	so->so_state |= SS_ISCONNECTED;
	head = so->so_head;
	if (head != NULL) {
		soqremque(so, 0);
		soqinsque(head, so, 1);
		sowakeup(head, POLLIN);
	} else {
		sowakeup(so, POLLOUT);
	}
}

void
soisdisconnecting(struct socket *so)
{
	short events;

	//events = POLLIN|POLLOUT;
	events = soevents(so);
	if (events != 0) {
		sowakeup(so, events);
	}
	so->so_state &= ~SS_ISCONNECTING;
	so->so_state |= (SS_ISDISCONNECTING|SS_CANTRCVMORE|SS_CANTSENDMORE);
}

void
soisdisconnected(struct socket *so)
{
	short events;

	//events = POLLIN|POLLOUT;
	events = soevents(so);
	sowakeup(so, events);
	so->so_state &= ~(SS_ISCONNECTING|SS_ISCONNECTED|SS_ISDISCONNECTING);
	so->so_state |= (SS_CANTRCVMORE|SS_CANTSENDMORE);
}

int
soreadable(struct socket *so)
{
	if (so->so_rcv.sb_cc || (so->so_state & SS_CANTRCVMORE)) {
		return 1;
	}

	if (so->so_options & SO_OPTION(SO_ACCEPTCONN)) {
		if (!gt_dlist_is_empty(so->so_q + 1)) {
			return 1;
		}
	}

	return 0;
}

int
sowriteable(struct socket *so)
{
	return ((sbspace(&so->so_snd) >= so->so_snd.sb_lowat &&
		((so->so_state & SS_ISCONNECTED) ||
		(so->so_proto == IPPROTO_UDP)))) ||
		(so->so_state & SS_CANTSENDMORE);
}

short
soevents(struct socket *so)
{
	short events;

	events = 0;
	if (soreadable(so)) {
		events |= POLLIN;
	}
	if (sowriteable(so)) {
		events |= POLLOUT;
	}
	if (so->so_error) {
		events |= POLLERR;
	}

	return events;
}

void
sowakeup(struct socket *so, short events)
{
	assert(events);

	so->so_events |= events;

	if ((so->so_state & SS_ISPROCESSING) == 0) {
		file_wakeup(&so->so_base.sobase_file, so->so_events);
		so->so_events = 0;
	}
}

void
somodopt(struct socket *so, int optname, int optval)
{
	if (optval) {
		sosetopt(so, optname);
	} else {
		soclropt(so, optname);
	}
}

struct socket *
sonewconn(struct socket *head)
{
	struct socket *so;

	so = somalloc(0);
	if (so == NULL) {
		return NULL;
	}
	so->so_proto = head->so_proto;
	so->so_options = head->so_options;
	soclropt(so, SO_ACCEPTCONN);
	so->so_linger = head->so_linger;
	so->so_state = head->so_state | SS_NOFDREF | SS_ISCONNECTING;
	assert(so->so_proto == IPPROTO_TCP);
	tcp_attach(so);
	soqinsque(head, so, 0);
	return so;
}

void
soqinsque(struct socket *head, struct socket *so, int q)
{
	assert(so->so_head == NULL);
	so->so_head = head;

	GT_DLIST_INSERT_HEAD(head->so_q + q, so, so_q[q]);
}

int
soqremque(struct socket *so, int q)
{
	if (so->so_head == NULL) {
		return 0;
	}

	if (gt_dlist_is_empty(so->so_q + q)) {
		assert(!gt_dlist_is_empty(so->so_q + (1 - q)));
		return 0;
	}

	GT_DLIST_REMOVE(so, so_q[q]);
	so->so_head = NULL;
	gt_dlist_init(so->so_q + q);
	return 1;
}

/*
 * Socantsendmore indicates that no more data will be sent on the
 * socket; it would normally be applied to a socket when the user
 * informs the system that no more data is to be sent, by the protocol
 * code (in case PRU_SHUTDOWN).  Socantrcvmore indicates that no more data
 * will be received, and will normally be applied to the socket by a
 * protocol when it detects that the peer will send no more data.
 * Data queued for reading in the socket may yet be read.
 */

void
socantsendmore(struct socket *so)
{
	sowakeup(so, POLLOUT);
	so->so_state |= SS_CANTSENDMORE;
}

void
socantrcvmore(struct socket *so)
{
	sowakeup(so, POLLIN);
	so->so_state |= SS_CANTRCVMORE;
}

/*
 * Socket buffer (struct sockbuf) utility routines.
 */
#define SBCHUNK_DATASIZE (SOCKBUF_CHUNK_SIZE - sizeof(struct sockbuf_chunk))

struct sockbuf_chunk {
	struct mbuf sbc_mbuf;
	struct gt_dlist sbc_list;
	int sbc_len;
	int sbc_off;
};

#define sbchdata(ch) (u_char *)(ch + 1)
#define sbchspace(ch) \
	(SBCHUNK_DATASIZE - ((ch)->sbc_len + (ch)->sbc_off))

static void
sbchfree(struct sockbuf_chunk *ch)
{
	mbuf_free(&ch->sbc_mbuf);
}

static struct sockbuf_chunk *
sbchalloc(struct sockbuf *sb)
{
	struct sockbuf_chunk *ch;

	mbuf_alloc(current->p_sockbuf_pool, (struct mbuf **)&ch);

	ch->sbc_len = 0;
	ch->sbc_off = 0;
	GT_DLIST_INSERT_TAIL(&sb->sb_head, ch, sbc_list);
	return ch;
}

void
sbinit(struct sockbuf *sb, u_long cc)
{
	sb->sb_cc = 0;
	sb->sb_hiwat = cc;
	sb->sb_lowat  = 0;
	gt_dlist_init(&sb->sb_head);
}

void
sbreserve(struct sockbuf *sb, u_long cc)
{
	sb->sb_hiwat = cc;
	if (sb->sb_lowat > sb->sb_hiwat) {
		sb->sb_lowat = sb->sb_hiwat;
	}
}

static void
sbfree_n(struct sockbuf *sb, int n)
{
	int i;
	struct sockbuf_chunk *ch;

	for (i = 0; i < n; ++i) {
		assert(!gt_dlist_is_empty(&sb->sb_head));
		ch = GT_DLIST_LAST(&sb->sb_head, struct sockbuf_chunk, sbc_list);
		GT_DLIST_REMOVE(ch, sbc_list);
		sbchfree(ch);
	}
}

void
sbrelease(struct sockbuf *sb)
{
	struct sockbuf_chunk *ch;

	while (!gt_dlist_is_empty(&sb->sb_head)) {
		ch = GT_DLIST_FIRST(&sb->sb_head, struct sockbuf_chunk, sbc_list);
		GT_DLIST_REMOVE(ch, sbc_list);
		sbchfree(ch);		
	}
	sb->sb_cc = 0;
}

static void
sbwrite(struct sockbuf *sb, struct sockbuf_chunk *pos, const void *src, int cnt)
{
	int n, rem, space;
	u_char *data;
	const u_char *ptr;

	ptr = src;
	rem = cnt;
	GT_DLIST_FOREACH_CONTINUE(pos, &sb->sb_head, sbc_list) {
		assert(rem > 0);
		space = sbchspace(pos);
		n = MIN(rem, space);
		data = sbchdata(pos);
		memcpy(data + pos->sbc_off + pos->sbc_len, ptr, n);
		sb->sb_cc += n;
		pos->sbc_len += n;
		ptr += n;
		rem -= n;
	}
	assert(rem == 0);
}

int
sbappend(struct sockbuf *sb, const u_char *buf, int len)
{
	int n, rem, space, appended;
	struct sockbuf_chunk *ch, *pos;

	assert(len >= 0);
	space = sbspace(sb);
	appended = MIN(len, space);
	if (appended == 0) {
		return 0;
	}
	n = 0;
	if (gt_dlist_is_empty(&sb->sb_head)) {
		ch = sbchalloc(sb);
		if (ch == NULL) {
			return -ENOMEM;
		}
		n++;
	} else {
		ch = GT_DLIST_LAST(&sb->sb_head, struct sockbuf_chunk, sbc_list);
	}
	pos = ch;
	rem = appended;
	while (1) {
		rem -= sbchspace(ch);
		if (rem <= 0) {
			break;
		}
		ch = sbchalloc(sb);
		if (ch == NULL) {
			sbfree_n(sb, n);
			return -ENOMEM;
		}
		n++;
	}
	sbwrite(sb, pos, buf, appended);
	return appended;


}

/*
 * Drop data from (the front of) a sockbuf.
 */
void
sbdrop(struct sockbuf *sb, int len)
{
	int n, off;
	struct sockbuf_chunk *pos, *tmp;

	off = 0;
	GT_DLIST_FOREACH_SAFE(pos, &sb->sb_head, sbc_list, tmp) {
		assert(pos->sbc_len);
		assert(sb->sb_cc >= pos->sbc_len);
		n = pos->sbc_len;
		if (n > len - off) {
			n = len - off;
		}
		sb->sb_cc -= n;
		pos->sbc_off += n;
		pos->sbc_len -= n;
		if (pos->sbc_len == 0) {
			GT_DLIST_REMOVE(pos, sbc_list);
			sbchfree(pos);
		}
		off += n;
		if (off == len) {
			break;
		}
	}
}

void
sbcopy(struct sockbuf *sb, int off, int len, u_char *dst)
{
	u_char *data;
	int n;
	struct sockbuf_chunk *ch;

	assert(sb->sb_cc >= off + len);
	GT_DLIST_FOREACH(ch, &sb->sb_head, sbc_list) {
		assert(ch->sbc_len);
		if (off < ch->sbc_len) {
			break;
		}
		off -= ch->sbc_len;
	}
	for (; len != 0; ch = GT_DLIST_NEXT(ch, sbc_list)) {
		assert(&ch->sbc_list != &sb->sb_head);
		assert(off < ch->sbc_len);
		n = MIN(len, ch->sbc_len - off);
		data = sbchdata(ch);
		memcpy(dst, data + ch->sbc_off + off, n);
		off = 0;
		len -= n;
		dst += n;
	}
}

int
gt_bsd44_so_accept(struct file **fpp, struct file *lfp)
{
	int error;
	struct socket *lso, *aso;

	lso = gt_fptoso(lfp);

	if ((lso->so_options & SO_OPTION(SO_ACCEPTCONN)) == 0) {
		return -EINVAL;
	}

	if (gt_dlist_is_empty(lso->so_q + 1)) {
		return -EWOULDBLOCK;
	}

	if (lso->so_error) {
		error = lso->so_error;
		lso->so_error = 0;
		return -error;
	}

	aso = GT_DLIST_FIRST(lso->so_q + 1, struct socket, so_q[1]);
	assert(aso->so_head != NULL);
	soqremque(aso, 1);

	assert(aso->so_state & SS_NOFDREF);
	aso->so_state &= ~SS_NOFDREF;
	assert(aso->so_proto == IPPROTO_TCP);
	tcp_accept(aso);

	*fpp = gt_sotofp(aso);

	return 0;
}

int
gt_bsd44_so_sendto(struct file *fp, const struct iovec *iov, int iovcnt, int flags,
		const struct sockaddr_in *dest_addr)
{
	int rc;
	struct socket *so;

	so = gt_fptoso(fp);

	rc = sosend(so, iov, iovcnt, dest_addr);

	return rc;
}

int
gt_bsd44_so_timer(struct timer *timer, u_char fn_id)
{
	switch (fn_id) {
	case TCPT_REXMT:
		tcp_REXMT_timo(timer);
		break;

	case TCPT_PERSIST:
		tcp_PERSIST_timo(timer);
		break;

	case TCPT_KEEP:
		tcp_KEEP_timo(timer);
		break;

	case TCPT_2MSL:
		tcp_2MSL_timo(timer);
		break;

	case TCPT_DELACK:
		tcp_DELACK_timo(timer);
		break;

	default:
		assert(0);
		break;
	}

	return 0;
}

int
gt_bsd44_so_get_err(struct file *fp)
{
	struct socket *so;

	so = gt_fptoso(fp);
	return so->so_error;
}

int
gt_bsd44_so_getpeername(struct file *fp, struct sockaddr *addr, socklen_t * addrlen)
{
	int rc;
	struct socket *so;

	so = gt_fptoso(fp);

	if ((so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) == 0) {
		return -ENOTCONN;
	}

	rc = gt_set_sockaddr(addr, addrlen, so->so_base.sobase_faddr, so->so_base.sobase_fport);

	return rc;
}

int
gt_bsd44_so_tx_flush(void)
{
	int rc;
	struct dev_pkt pkt;
	struct route_entry r;
	struct socket *so;
	struct gt_dlist *tx_head;

	// TODO: optimize - without division
	tcp_now = 1 + shared_ns() / (NSEC_SEC/PR_SLOWHZ);

	tx_head = &current->p_tx_head;
	while (!gt_dlist_is_empty(tx_head)) {
		so = GT_DLIST_FIRST(tx_head, struct socket, so_txlist);
		rc = gt_so_route(so->so_base.sobase_laddr, so->so_base.sobase_faddr, &r);
		assert(rc == 0);
		for (;;) {
			rc = route_get_tx_packet(r.rt_ifp, &pkt, TX_CAN_REDIRECT);
			if (rc) {
				return 0;
			}

			rc = tcp_output_real(&r, &pkt, so);
			dev_put_tx_packet(&pkt);

			if (rc <= 0) {
				GT_DLIST_REMOVE(so, so_txlist);
				so->so_state &= ~SS_ISTXPENDING;
				sofree(so);
				break;
			}
		}
	}

	return 0;
}

short
gt_bsd44_so_get_events(struct file *fp)
{
	struct socket *so;

	so = gt_fptoso(fp);
	return soevents(so);
}

int
gt_bsd44_so_nread(struct file *fp)
{
	struct socket *so;

	so = gt_fptoso(fp);

	return so->so_rcv.sb_cc;
}

int
gt_bsd44_so_recvfrom(struct file *fp, const struct iovec *iov, int iovcnt,
		int flags, struct sockaddr *addr, socklen_t *addrlen)
{
	int i, len, rc;
	struct sockbuf *sb;
	struct socket *so;

	so = gt_fptoso(fp);

	if (so->so_error) {
		rc = -so->so_error;
		so->so_error = 0;
		return rc;
	}

	if ((so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) == 0) {
		return -ENOTCONN;
	}

	sb = &so->so_rcv;

	rc = 0;
	for (i = 0; i < iovcnt; ++i) {
		if (!sb->sb_cc) {
			break;
		}

		len = MIN(sb->sb_cc, iov[i].iov_len);

		sbcopy(sb, 0, len, iov[i].iov_base);
		sbdrop(sb, len);

		rc += len;
	}

	if (rc == 0) {
		return -EAGAIN;
	} else {
		return rc;
	}
}

int
gt_bsd44_so_aio_recvfrom(struct file *fp, struct iovec *iov, int flags,
		struct sockaddr *addr, socklen_t *addrlen)
{
	return -ENOTSUP;
}

int
gt_bsd44_so_recvdrain(struct file *fp, int len)
{
	int cc;
	struct socket *so;

	so = gt_fptoso(fp);

	if (so->so_error) {
		return -so->so_error;
	}

	if ((so->so_state & SS_ISCONNECTED) == 0) {
		return -ENOTCONN;
	}

	cc = so->so_rcv.sb_cc;
	sbdrop(&so->so_rcv, len);

	return cc - so->so_rcv.sb_cc;
}

int
gt_bsd44_so_ioctl(struct file *fp, unsigned long request, uintptr_t arg)
{
	return -ENOTSUP;
}

int
gt_bsd44_so_struct_size(void)
{
	return sizeof(struct socket);
}

