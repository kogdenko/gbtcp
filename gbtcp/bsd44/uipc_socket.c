/*
 * Copyright (c) 1982, 1986, 1988, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "../list.h"
#include "socket.h"
#include "tcp_var.h"
#include "udp_var.h"

static struct socket *
somalloc(void)
{
	int rc;
	struct file *fp;
	struct socket *so;

	rc = file_alloc3(&fp, 0, FILE_SOCK);
	if (rc) {
		return NULL;
	}
	so = (struct socket *)fp;

	so->so_head = 0;
	gt_dlist_init(so->so_q + 0);
	gt_dlist_init(so->so_q + 1);
	so->so_events = 0;
	so->so_error = 0;
	so->inp_laddr = 0;
	so->inp_faddr = 0;
	so->inp_lport = 0;
	so->inp_fport = 0;
	sbinit(&so->so_snd, 8 * 1024);
	so->so_rcv_hiwat = 8 * 1024;
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
bsd_socket(int proto, struct socket **aso)
{
	struct socket *so;

	so = somalloc();
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
	*aso = so;
	return 0;
}

int
bsd_bind(struct socket *so, be16_t port)
{
	int error;

	error = in_pcbbind(so, port);
	return -error;
}

int
bsd_listen(struct socket *so)
{
	int error;

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
/*	const char *cp = "ss=";

	printf("%p: sofree: %s, ", so, f);
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
	if ((so->so_state & (SS_ISTXPENDING|
	                     SS_ISPROCESSING|
	                     SS_ISCONNECTING|
	                     SS_ISCONNECTED|
	                     SS_ISDISCONNECTING|
	                     SS_ISATTACHED))) {
		return;
	}
	if (so->so_head) {
		soqremque(so);
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
bsd_close(struct socket *so)
{
	int i, error;
	struct gt_dlist *head;
	struct socket *aso;

	if (so->so_state & SS_NOFDREF) {
		return -EINVAL;
	}
	so->so_state |= SS_NOFDREF;
	error = 0;
	if (so->so_options & SO_OPTION(SO_ACCEPTCONN)) {
		for (i = 0; i < ARRAY_SIZE(so->so_q); ++i) {
			head = so->so_q + i;
			while (!gt_dlist_is_empty(head)) {
				aso = GT_DLIST_FIRST(head, struct socket, so_ql);
				soabort(aso);
			}
		}
	}
	if (so->so_proto == IPPROTO_TCP) {
		error = tcp_disconnect(so);
	} else {
		error = udp_disconnect(so);
	}
	sofree(so);
	return -error;
}

void
soabort(struct socket *so)
{
	if (so->so_proto == IPPROTO_TCP) {
		tcp_abort(so);
	} else {
		udp_abort(so);
	}
}

void
soaccept(struct socket *so)
{
	assert(so->so_head != NULL);
	soqremque(so);
	assert(so->so_state & SS_NOFDREF);
	so->so_state &= ~SS_NOFDREF;
	assert(so->so_proto == IPPROTO_TCP);
	tcp_accept(so);
}

int
bsd_connect(struct socket *so)
{
	int rc;

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
			rc = tcp_connect(so);
		} else {
			rc = udp_connect(so);
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
sosend(struct socket *so, const void *dat, int datlen, const struct sockaddr_in *addr, int flags)
{
	int rc, atomic, space;

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
		} else if (addr == NULL) {
			return -EDESTADDRREQ;
		}
	}
	space = sbspace(&so->so_snd);
	if (atomic && (datlen > so->so_snd.sb_hiwat)) {
		return -EMSGSIZE;
	}
	if (atomic && space < datlen) {
		return -EWOULDBLOCK;
	}
	if (so->so_proto == IPPROTO_TCP) {
		rc = tcp_send(so, dat, datlen);
	} else {
		rc = udp_send(so, dat, datlen, addr);
	}
	return rc;
}

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
}

void
sorflush(struct socket *so)
{
	socantrcvmore(so);
}

int
bsd_setsockopt(struct socket *so, int level, int optname,
	void *optval, int optlen)
{
	int rc;
	struct linger *linger;

	if (level != SOL_SOCKET) {
		if (so->so_proto == IPPROTO_TCP) {
			rc = tcp_ctloutput(PRCO_SETOPT, so, level, optname,
			                   optval, &optlen);
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
		linger = (struct linger *)optval;
		so->so_linger = linger->l_linger;
		somodopt(so, optname, linger->l_onoff);
		break;

	case SO_DEBUG:
	case SO_KEEPALIVE:
		somodopt(so, optname, *((int *)optval));
		break;

	case SO_SNDBUF:
		sbreserve(&so->so_snd, *(int *)optval);
		break;

	case SO_RCVBUF:
		so->so_rcv_hiwat = *((int *)optval);
		break;

	case SO_SNDLOWAT:
		so->so_snd.sb_lowat = *((int *)optval);
		break;

	case SO_RCVLOWAT:
		break;

	default:
		return -ENOPROTOOPT;
	}
	return 0;
}

int
bsd_getsockopt(struct socket *so, int level, int optname,
	void *optval, int *optlen)
{
	int rc;
	struct linger *linger;

	if (level != SOL_SOCKET) {
		if (so->so_proto == IPPROTO_TCP) {
			rc = tcp_ctloutput(PRCO_GETOPT, so, level, optname,
			                   optval, optlen);
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

	case SO_ERROR:
		*((int *)optval) = so->so_error;
		so->so_error = 0;
		break;

	case SO_SNDBUF:
		*((int *)optval) = so->so_snd.sb_hiwat;
		break;

	case SO_RCVBUF:
		*((int *)optval) = so->so_rcv_hiwat;
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
		soqremque(so);
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
	sowakeup(so, events);
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
	return (so->so_state & SS_CANTRCVMORE) || !gt_dlist_is_empty(so->so_q + 1);
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

	if (so->so_state & SS_ISPROCESSING) {
		so->so_events |= events;
	} else {
		file_wakeup(&so->so_base.sobase_file, so->so_events);
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

	so = somalloc();
	if (so == NULL) {
		return NULL;
	}
	so->so_proto = head->so_proto;
	so->so_options = head->so_options;
	soclropt(so, SO_ACCEPTCONN);
	so->so_linger = head->so_linger;
	so->so_state = head->so_state | SS_NOFDREF | SS_ISCONNECTING;
	if (so->so_proto == IPPROTO_TCP) {
		tcp_attach(so);
	}
	soqinsque(head, so, 0);
	return so;
}

void
soqinsque(struct socket *head, struct socket *so, int q)
{
	assert(so->so_head == NULL);
	so->so_head = head;
	GT_DLIST_INSERT_HEAD(head->so_q + q, so, so_ql);
}

void
soqremque(struct socket *so)
{
	assert(so->so_head != NULL);
	GT_DLIST_REMOVE(so, so_ql);
	so->so_head = NULL;
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
		assert(!dlist_is_empty(&sb->sb_head));
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
sbwrite(struct sockbuf *sb, struct sockbuf_chunk *pos,
        const void *src, int cnt)
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
//	return off;
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
bsd_accept(struct socket *so, struct socket **paso)
{
	int error;
	struct socket *aso;

	if ((so->so_options & SO_OPTION(SO_ACCEPTCONN)) == 0) {
		return -EINVAL;
	}
	if (gt_dlist_is_empty(so->so_q + 1)) {
		return -EWOULDBLOCK;
	}
	if (so->so_error) {
		error = so->so_error;
		so->so_error = 0;
		return -error;
	}
	aso = GT_DLIST_FIRST(so->so_q + 1, struct socket, so_ql);
	soaccept(aso);
	*paso = aso;
	return 0;
}

int
bsd_sendto(struct socket *so, const void *buf, int len, int flags, const struct sockaddr_in *nam)
{
	int rc;

	rc = sosend(so, buf, len, nam, flags);
	if (rc < 0) {
		if (rc == -EPIPE) {
			if ((flags & MSG_NOSIGNAL) == 0) {
				raise(SIGPIPE);
			}
		}
	}
	return rc;
}
