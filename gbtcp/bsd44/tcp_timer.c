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

#include "socket.h"
#include "ip.h"
#include "in_pcb.h"
#include "ip_var.h"
#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_var.h"

int tcp_maxidle = TCPTV_KEEPCNT * TCPTV_KEEPINTVL;
/*
 * Fast timeout routine for processing delayed acks
 */
void
tcp_DELACK_timo(struct timer *timer)
{
	struct tcpcb *tp;

	tp = container_of(timer, struct tcpcb, t_timer_delack);
	if (tp->t_flags & TF_DELACK) {
		tp->t_flags &= ~TF_DELACK;
		tp->t_flags |= TF_ACKNOW;
		tcpstat.tcps_delack++;
		tcp_output(tp);
	}
}

void
tcp_setdelacktimer(struct tcpcb *tp)
{
	tp->t_flags |= TF_DELACK;
	timer_set(&tp->t_timer_delack, 200 * NSEC_MSEC, GT_MODULE_SOCKET, TCPT_DELACK);
}

/*
 * Cancel all timers for TCP tp.
 */
void
tcp_canceltimers(struct tcpcb *tp)
{
	int i;

	for (i = 0; i < TCPT_NTIMERS; i++) {
		timer_cancel(tp->t_timer + i);
	}
	timer_cancel(&tp->t_timer_delack);
}

int tcp_backoff[TCP_MAXRXTSHIFT + 1] =
    { 1, 2, 4, 8, 16, 32, 64, 64, 64, 64, 64, 64, 64 };


/*
 * Persistance timer into zero window.
 * Force a byte to be output, if possible.
 */
void
tcp_PERSIST_timo(struct timer *timer)
{
	struct tcpcb *tp;

	tp = container_of(timer, struct tcpcb, t_timer[TCPT_PERSIST]);

	tcpstat.tcps_persisttimeo++;
	tcp_setpersist(tp);
	tp->t_force = 1;
	tcp_output(tp);
}

/*
 * Retransmission timer went off.  Message has not
 * been acked within retransmit interval.  Back off
 * to a longer retransmit interval and retransmit one segment.
 */
void
tcp_REXMT_timo(struct timer *timer)
{
	u_int win, rexmt;
	struct tcpcb *tp;

	tp = container_of(timer, struct tcpcb, t_timer[TCPT_REXMT]);

	if (++tp->t_rxtshift > TCP_MAXRXTSHIFT) {
		tp->t_rxtshift = TCP_MAXRXTSHIFT;
		tcpstat.tcps_timeoutdrop++;
		tp = tcp_drop(tp, tp->t_softerror ? tp->t_softerror : ETIMEDOUT);
		return;
	}
	tcpstat.tcps_rexmttimeo++;
	rexmt = TCP_REXMTVAL(tp) * tcp_backoff[tp->t_rxtshift];
	TCPT_RANGESET(tp->t_rxtcur, rexmt, TCPTV_MIN, TCPTV_REXMTMAX);
	tcp_setslowtimer(tp, TCPT_REXMT, tp->t_rxtcur);
	/*
	 * If losing, let the lower level know and try for
	 * a better route.  Also, if we backed off this far,
	 * our srtt estimate is probably bogus.  Clobber it
	 * so we'll take the next rtt measurement as our srtt;
	 * move the current srtt into rttvar to keep the current
	 * retransmit times until then.
	 */
	if (tp->t_rxtshift > TCP_MAXRXTSHIFT / 4) {
		tp->t_rttvar += (tp->t_srtt >> TCP_RTT_SHIFT);
		tp->t_srtt = 0;
	}
	tp->snd_nxt = tp->snd_una;
	/*
	 * If timing a segment in this window, stop the timer.
	 */
	tp->t_rtt = 0;
	/*
	 * Close the congestion window down to one segment
	 * (we'll open it by one segment for each ack we get).
	 * Since we probably have a window's worth of unacked
	 * data accumulated, this "slow start" keeps us from
	 * dumping all that data as back-to-back packets (which
	 * might overwhelm an intermediate gateway).
	 *
	 * There are two phases to the opening: Initially we
	 * open by one mss on each ack.  This makes the window
	 * size increase exponentially with time.  If the
	 * window is larger than the path can handle, this
	 * exponential growth results in dropped packet(s)
	 * almost immediately.  To get more time between 
	 * drops but still "push" the network to take advantage
	 * of improving conditions, we switch from exponential
	 * to linear window opening at some threshhold size.
	 * For a threshhold, we use half the current window
	 * size, truncated to a multiple of the mss.
	 *
	 * (the minimum cwnd that will give us exponential
	 * growth is 2 mss.  We don't allow the threshhold
	 * to go below this.)
	 */
	win = MIN(tp->snd_wnd, tp->snd_cwnd) / 2 / tp->t_maxseg;
	if (win < 2) {
		win = 2;
	}
	tp->snd_cwnd = tp->t_maxseg;
	tp->snd_ssthresh = win * tp->t_maxseg;
	tp->t_dupacks = 0;
	tcp_output(tp);
}

/*
 * Keep-alive timer went off; send something
 * or drop connection if idle for too long.
 */
void
tcp_KEEP_timo(struct timer *timer)
{
	struct socket *so;
	struct tcpcb *tp;

	tp = container_of(timer, struct tcpcb, t_timer[TCPT_KEEP]);

	tcpstat.tcps_keeptimeo++;
	if (tp->t_state < GT_TCPS_ESTABLISHED) {
		goto dropit;
	}
	so = tcpcbtoso(tp);
	if (so->so_options & SO_OPTION(SO_KEEPALIVE) && tp->t_state <= GT_TCPS_CLOSE_WAIT) {
		uint16_t idle;
		idle = tcp_now - tp->t_idle;
		if (idle >= TCPTV_KEEP_IDLE + tcp_maxidle) {
			goto dropit;
		}
		/*
		 * Send a packet designed to force a response
		 * if the peer is up and reachable:
		 * either an ACK if the connection is still alive,
		 * or an RST if the peer has closed the connection
		 * due to timeout or reboot.
		 * Using sequence number tp->snd_una-1
		 * causes the transmitted zero-length segment
		 * to lie outside the receive window;
		 * by the protocol spec, this requires the
		 * correspondent TCP to respond.
		 */
		tcpstat.tcps_keepprobe++;
		tcp_respond(tp, NULL, NULL, tp->rcv_nxt, tp->snd_una - 1, 0);
		tcp_setslowtimer(tp, TCPT_KEEP, TCPTV_KEEPINTVL);
	} else {
		tcp_setslowtimer(tp, TCPT_KEEP, TCPTV_KEEP_IDLE);
	}
	return;
dropit:
	tcpstat.tcps_keepdrops++;
	tp = tcp_drop(tp, ETIMEDOUT);
}

/*
 * 2 MSL timeout in shutdown went off.
 * Delete connection control block.
 */
void
tcp_2MSL_timo(struct timer *timer)
{
	struct tcpcb *tp;

	tp = container_of(timer, struct tcpcb, t_timer[TCPT_2MSL]);
	tcp_close(tp);
}
