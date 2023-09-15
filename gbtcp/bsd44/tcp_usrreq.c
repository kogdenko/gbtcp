/*
 * Copyright (c) 1982, 1986, 1988, 1993
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

#include "socket.h"
#include "ip.h"
#include "in_pcb.h"
#include "ip_var.h"
#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_var.h"

// Initiate connection to peer.
// Enter SYN_SENT state, and mark socket as connecting.
// Start keep-alive timer, and seed output sequence space.
// Send initial segment on connection.
int
tcp_connect(struct socket *so)
{
	struct tcpcb *tp;
	uint32_t h;
	int rc, ostate;

	tp = sototcpcb(so);
	ostate = tp->t_state;

	rc = in_pcbconnect(so, &h);
	if (rc) {
		goto out;
	}
	/* Compute window scaling to request.  */
	while (tp->request_r_scale < TCP_MAX_WINSHIFT &&
	    (TCP_MAXWIN << tp->request_r_scale) < so->so_rcv_hiwat) {
		tp->request_r_scale++;
	}
	soisconnecting(so);
	tcpstat.tcps_connattempt++;
	tp->t_state = GT_TCPS_SYN_SENT;
	tcp_setslowtimer(tp, TCPT_KEEP, TCPTV_KEEP_INIT);
	tcp_sendseqinit(tp, h);
	tcp_output(tp);
out:
	if ((so->so_options & SO_OPTION(SO_DEBUG))) {
		tcp_trace(TA_USER, ostate, tp, NULL, NULL, PRU_CONNECT);
	}
	return rc;
}

/*
 * Initiate disconnect from peer.
 * If connection never passed embryonic stage, just drop;
 * else if don't need to let data drain, then can just drop anyways,
 * else have to begin TCP shutdown process: mark socket disconnecting,
 * drain unread data, state switch to reflect user close, and
 * send segment (e.g. FIN) to peer.  Socket will be really disconnected
 * when peer sends FIN and acks ours.
 */
int
tcp_disconnect(struct socket *so)
{
	struct tcpcb *tp;
	int ostate;

	tp = sototcpcb(so);
	ostate = tp->t_state;
	if (tp->t_state < GT_TCPS_ESTABLISHED) {
		tp = tcp_close(tp);
	} else if ((so->so_options & SO_OPTION(SO_LINGER)) &&
	           so->so_linger == 0) {
		tp = tcp_drop(tp, 0);
	} else {
		soisdisconnecting(so);
		tp = tcp_usrclosed(tp);
		if (tp) {
			tcp_output(tp);
		}
	}
	if (tp != NULL && (so->so_options & SO_OPTION(SO_DEBUG))) {
		tcp_trace(TA_USER, ostate, tp, NULL, NULL, PRU_DISCONNECT);
	}
	return 0;
}

/*
 * Prepare to accept connections.
 */
int
tcp_listen(struct socket *so)
{
	struct tcpcb *tp;
	int ostate, error;

	tp = sototcpcb(so);
	ostate = tp->t_state;
	error = 0;
	if (so->inp_lport == 0) {
		error = EADDRINUSE;
		goto out;
	}
	if (tp->t_state == GT_TCPS_LISTEN) {
		goto out;
	}
	if (tp->t_state != GT_TCPS_CLOSED) {
		error = EINVAL;
	} else {
		tp->t_state = GT_TCPS_LISTEN;
	}
out:
	if (so->so_options & SO_OPTION(SO_DEBUG)) {
		tcp_trace(TA_USER, ostate, tp, NULL, NULL, PRU_LISTEN);
	}
	return error;
}

void
tcp_accept(struct socket *so)
{
	struct tcpcb *tp;

	tp = sototcpcb(so);
	if (so->so_options & SO_OPTION(SO_DEBUG)) {
		tcp_trace(TA_USER, tp->t_state, tp, NULL, NULL, PRU_ACCEPT);
	}
}


/*
 * Do a send by putting data in output queue.
 * Possibly send more data.
 */
int
tcp_send(struct socket *so, const void *dat, int datalen)
{
	int rc, ostate;
	struct tcpcb *tp;

	tp = sototcpcb(so);
	ostate = tp->t_state;

	rc = sbappend(&so->so_snd, dat, datalen);
	if (rc > 0) {
		tcp_output(tp);
	}
	if ((so->so_options & SO_OPTION(SO_DEBUG))) {
		tcp_trace(TA_USER, ostate, tp, NULL, NULL, PRU_SEND);
	}
	return rc;
}


/*
 * Mark the connection as being incapable of further output.
 */
void
tcp_shutdown(struct socket *so)
{
	int ostate;
	struct tcpcb *tp;

	tp = sototcpcb(so);
	ostate = tp->t_state;

	socantsendmore(so);
	tp = tcp_usrclosed(tp);
	if (tp) {
		tcp_output(tp);
	}

	if ((so->so_options & SO_OPTION(SO_DEBUG))) {
		tcp_trace(TA_USER, ostate, tp, NULL, NULL, PRU_SHUTDOWN);
	}
}

void
tcp_abort(struct socket *so)
{
	struct tcpcb *tp;
	tp = sototcpcb(so);
	tcp_drop(tp, ECONNABORTED);
}

int
tcp_ctloutput(int op, struct socket *so, int level, int optname,
	void *optval, int *optlen)
{
	struct tcpcb *tp;
	int i;

	tp = sototcpcb(so);
	if (level != IPPROTO_TCP) {
		return -ENOTSUP;
	}
	switch (op) {
	case PRCO_SETOPT:
		switch (optname) {
		case TCP_NODELAY:
			if (*optlen < sizeof(int)) {
				return -EINVAL;
			}
			if (*((int *)optval)) {
				tp->t_flags |= TF_NODELAY;
			} else {
				tp->t_flags &= ~TF_NODELAY;
			}
			break;

		case TCP_MAXSEG:
			if (*optlen < sizeof(int)) {
				return -EINVAL;
			}
			i = *((int *)optval);
			if (i > 0 && i <= tp->t_maxseg) {
				tp->t_maxseg = i;
			} else {
				return -EINVAL;
			}
			break;

		default:
			return -ENOPROTOOPT;	
		}
		break;

	case PRCO_GETOPT:
		if (*optlen < sizeof(int)) {
			return -EINVAL;
		}
		*optlen = sizeof(int);
		switch (optname) {
		case TCP_NODELAY:
			*((int *)optval) = tp->t_flags & TF_NODELAY;
			break;
		case TCP_MAXSEG:
			*((int *)optval) = tp->t_maxseg;
			break;
		default:
			return -ENOPROTOOPT;
		}
		break;
	}
	return 0;
}

/*
 * User issued close, and wish to trail through shutdown states:
 * if never received SYN, just forget it.  If got a SYN from peer,
 * but haven't sent FIN, then go to FIN_WAIT_1 state to send peer a FIN.
 * If already got a FIN from peer, then almost done; go to LAST_ACK
 * state.  In all other cases, have already sent FIN to peer (e.g.
 * after PRU_SHUTDOWN), and just have to play tedious game waiting
 * for peer to send FIN or not respond to keep-alives, etc.
 * We can let the user exit from the close as soon as the FIN is acked.
 */
struct tcpcb *
tcp_usrclosed(struct tcpcb *tp)
{
	struct socket *so;

	switch (tp->t_state) {
	case GT_TCPS_CLOSED:
	case GT_TCPS_LISTEN:
	case GT_TCPS_SYN_SENT:
		tp->t_state = GT_TCPS_CLOSED;
		tp = tcp_close(tp);
		break;

	case GT_TCPS_SYN_RCVD:
	case GT_TCPS_ESTABLISHED:
		tp->t_state = GT_TCPS_FIN_WAIT_1;
		break;

	case GT_TCPS_CLOSE_WAIT:
		tp->t_state = GT_TCPS_LAST_ACK;
		break;
	}
	if (tp && tp->t_state >= GT_TCPS_FIN_WAIT_2) {
		so = tcpcbtoso(tp);
		soisdisconnected(so);
	}
	return (tp);
}

void
tcp_rcvseqinit(struct tcpcb *tp, uint32_t irs)
{
	tp->rcv_adv = tp->rcv_nxt = irs + 1;
}

void
tcp_sendseqinit(struct tcpcb *tp, uint32_t h)
{
	uint32_t iss;

	/* Must not overlap in 2 minutes (MSL)
	 * Increment 1 seq at 16 ns (like in Linux) */
	iss = h + (uint32_t)(nanoseconds >> 6);
	tp->snd_una = tp->snd_nxt = tp->snd_max = tp->snd_wl2 = iss;
}

void
tcp_setslowtimer(struct tcpcb *tp, int timer, u_short timo)
{
	uint64_t expire;

	expire = timo * NSEC_SEC / PR_SLOWHZ;
	tcp_settimer(tp, timer, expire);
}

void
tcp_settimer(struct tcpcb *tp, int timer, uint64_t timo)
{
	if (tp->t_state == GT_TCPS_CLOSED) {
		return;
	}

	timer_set(tp->t_timer + timer, timo, GT_MODULE_SOCKET, timer);
}
