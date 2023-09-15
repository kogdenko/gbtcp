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
//#include "if_ether.h"
#include "in_pcb.h"
#include "ip_var.h"
#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_var.h"

#define MAX_TCPOPTLEN	32	/* max # bytes that go in options */

/*
 * Flags used when sending segments in tcp_output.
 * Basic flags (TH_RST,TH_ACK,TH_SYN,BSD_TH_FIN) are totally
 * determined by state, with the proviso that BSD_TH_FIN is sent only
 * if all data queued for output is included in the segment.
 */
u_char tcp_outflags[TCP_NSTATES] = {
	[TCPS_CLOSED] = TH_RST|TH_ACK,
	[TCPS_LISTEN] = 0,
	[TCPS_SYN_SENT] = TH_SYN,
	[TCPS_SYN_RECEIVED] = TH_SYN|TH_ACK,
	[TCPS_ESTABLISHED] = TH_ACK,
	[TCPS_CLOSE_WAIT] = TH_ACK,
	[TCPS_FIN_WAIT_1] = BSD_TH_FIN|TH_ACK,
	[TCPS_CLOSING] = BSD_TH_FIN|TH_ACK,
	[TCPS_LAST_ACK] = BSD_TH_FIN|TH_ACK,
	[TCPS_FIN_WAIT_2] = TH_ACK,
	[TCPS_TIME_WAIT] = TH_ACK,
};

/*
 * Tcp output routine: figure out what should be sent and send it.
 */
void
tcp_output(struct tcpcb *tp)
{
	struct socket *so;

	so = tcpcbtoso(tp);
	if (so->so_state & SS_ISTXPENDING) {
		return;
	}
	so->so_state |= SS_ISTXPENDING;
	DLIST_INSERT_TAIL(&current->t_so_txq, so, so_txlist);
}

int
tcp_output_real(struct tcpcb *tp)
{
	struct socket *so;
	int off, len, win, flags, error;
	u_char opt[MAX_TCPOPTLEN];
	unsigned optlen, hdrlen;
	int idle, sendalot, t_force;
	struct ip *ip;
	struct bsd_tcp_hdr *th;
	struct packet pkt;

	so = tcpcbtoso(tp);
	t_force = tp->t_force;
	tp->t_force = 0;

	/*
	 * Determine length of data that should be transmitted,
	 * and flags that will be used.
	 * If there is some data or critical controls (SYN, RST)
	 * to send, then transmit; otherwise, investigate further.
	 */
	idle = (tp->snd_max == tp->snd_una);
	if (idle && current->t_tcp_now - tp->t_idle >= tp->t_rxtcur) {
		/*
		 * We have been idle for "a while" and no acks are
		 * expected to clock out any data we send --
		 * slow start to get ack "clock" running again.
		 */
		tp->snd_cwnd = tp->t_maxseg;
	}
	sendalot = 0;
	off = tp->snd_nxt - tp->snd_una;
	win = MIN(tp->snd_wnd, tp->snd_cwnd);

	flags = tcp_outflags[tp->t_state];
	/*
	 * If in persist timeout with window of 0, send 1 byte.
	 * Otherwise, if window is small but nonzero
	 * and timer expired, we will send what we can
	 * and go to transmit state.
	 */
	if (t_force) {
		if (win == 0) {
			/*
			 * If we still have some data to send, then
			 * clear the FIN bit.  Usually this would
			 * happen below when it realizes that we
			 * aren't sending all the data.  However,
			 * if we have exactly 1 byte of unset data,
			 * then it won't clear the FIN bit below,
			 * and if we are in persist state, we wind
			 * up sending the packet without recording
			 * that we sent the FIN bit.
			 *
			 * We can't just blindly clear the FIN bit,
			 * because if we don't have any more data
			 * to send then the probe will be the FIN
			 * itself.
			 */
			if (off < so->so_snd.sb_cc) {
				flags &= ~BSD_TH_FIN;
			}
			win = 1;
		} else {
			timer_cancel(tp->t_timer + TCPT_PERSIST);
			tp->t_rxtshift = 0;
		}
	}

	len = MIN(so->so_snd.sb_cc, win) - off;

	if (len < 0) {
		/*
		 * If FIN has been sent but not acked,
		 * but we haven't been called to retransmit,
		 * len will be -1.  Otherwise, window shrank
		 * after we sent into it.  If window shrank to 0,
		 * cancel pending retransmit and pull snd_nxt
		 * back to (closed) window.  We will enter persist
		 * state below.  If the window didn't close completely,
		 * just wait for an ACK.
		 */
		len = 0;
		if (win == 0) {
			timer_cancel(tp->t_timer + TCPT_REXMT);
			tp->snd_nxt = tp->snd_una;
		}
	}
	if (len > tp->t_maxseg) {
		len = tp->t_maxseg;
		sendalot = 1;
	}
	if (SEQ_LT(tp->snd_nxt + len, tp->snd_una + so->so_snd.sb_cc)) {
		flags &= ~BSD_TH_FIN;
	}
	win = so->so_rcv_hiwat;

	/*
	 * Sender silly window avoidance.  If connection is idle
	 * and can send all data, a maximum segment,
	 * at least a maximum default-size segment do it,
	 * or are forced, do it; otherwise don't bother.
	 * If peer's buffer is tiny, then send
	 * when window is at least half open.
	 * If retransmitting (possibly after persist timer forced us
	 * to send into a small window), then must resend.
	 */
	if (len) {
		if (len == tp->t_maxseg)
			goto send;
		if ((idle || tp->t_flags & TF_NODELAY) &&
		    len + off >= so->so_snd.sb_cc)
			goto send;
		if (t_force)
			goto send;
		if (len >= tp->max_sndwnd / 2)
			goto send;
		if (SEQ_LT(tp->snd_nxt, tp->snd_max))
			goto send;
	}

	/*
	 * Compare available window to amount of window
	 * known to peer (as advertised window less
	 * next expected input).  If the difference is at least two
	 * max size segments, or at least 50% of the maximum possible
	 * window, then want to send a window update to peer.
	 */
	if (win > 0) {
		/* 
		 * "adv" is the amount we can increase the window,
		 * taking into account that we are limited by
		 * TCP_MAXWIN << tp->rcv_scale.
		 */
		long adv = MIN(win, (long)TCP_MAXWIN << tp->rcv_scale) -
			(tp->rcv_adv - tp->rcv_nxt);

		if (adv >= (long) (2 * tp->t_maxseg))
			goto send;
		if (2 * adv >= (long) so->so_rcv_hiwat)
			goto send;
	}

	/*
	 * Send if we owe peer an ACK.
	 */
	if (tp->t_flags & TF_ACKNOW)
		goto send;
	if (flags & (TH_SYN|TH_RST))
		goto send;
	/*
	 * If our state indicates that FIN should be sent
	 * and we have not yet done so, or we're retransmitting the FIN,
	 * then we need to send.
	 */
	if ((flags & BSD_TH_FIN) &&
	    ((tp->t_flags & TF_SENTFIN) == 0 || tp->snd_nxt == tp->snd_una))
		goto send;

	/*
	 * TCP window updates are not reliable, rather a polling protocol
	 * using ``persist'' packets is used to insure receipt of window
	 * updates.  The three ``states'' for the output side are:
	 *	idle			not doing retransmits or persists
	 *	persisting		to move a small or zero window
	 *	(re)transmitting	and thereby not persisting
	 *
	 * tp->t_timer[TCPT_PERSIST]
	 *	is set when we are in persist state.
	 * tp->t_force
	 *	is set when we are called to send a persist packet.
	 * tp->t_timer[TCPT_REXMT]
	 *	is set when we are retransmitting
	 * The output side is idle when both timers are zero.
	 *
	 * If send window is too small, there is data to transmit, and no
	 * retransmit or persist is pending, then go to persist state.
	 * If nothing happens soon, send when timer expires:
	 * if window is nonzero, transmit what we can,
	 * otherwise force out a byte.
	 */
	if (so->so_snd.sb_cc &&
	    !timer_is_running(tp->t_timer + TCPT_REXMT) &&
	    !timer_is_running(tp->t_timer + TCPT_PERSIST)) {
		tp->t_rxtshift = 0;
		tcp_setpersist(tp);
	}

	/*
	 * No reason to send a segment, just return.
	 */
	return 0;

send:
	/*
	 * Before ESTABLISHED, force sending of initial options
	 * unless TCP set not to do any options.
	 * NOTE: we assume that the IP/TCP header plus TCP options
	 * always fit in a single mbuf, leaving room for a maximum
	 * link header, i.e.
	 *	max_linkhdr + sizeof (struct tcpiphdr) + optlen <= MHLEN
	 */
	optlen = 0;
	hdrlen = sizeof(struct ip) + sizeof(struct bsd_tcp_hdr);
	if (flags & TH_SYN) {
		tp->snd_nxt = tp->snd_una;
		if ((tp->t_flags & TF_NOOPT) == 0) {
			u_short mss;

			opt[0] = TCPOPT_MAXSEG;
			opt[1] = 4;
			mss = htons((u_short) tcp_mss(tp, 0));
			memcpy((opt + 2), &mss, sizeof(mss));
			optlen = 4;
	 
			if ((tp->t_flags & TF_REQ_SCALE) &&
			    ((flags & TH_ACK) == 0 ||
			    (tp->t_flags & TF_RCVD_SCALE))) {
				*((u_long *) (opt + optlen)) = htonl(
					TCPOPT_NOP << 24 |
					TCPOPT_WINDOW << 16 |
					TCPOLEN_WINDOW << 8 |
					tp->request_r_scale);
				optlen += 4;
			}
		}
 	}
 
 	/*
	 * Send a timestamp and echo-reply if this is a SYN and our side 
	 * wants to use timestamps (TF_REQ_TSTMP is set) or both our side
	 * and our peer have sent timestamps in our SYN's.
 	 */
 	if ((tp->t_flags & (TF_REQ_TSTMP|TF_NOOPT)) == TF_REQ_TSTMP &&
			(flags & TH_RST) == 0 &&
			((flags & (TH_SYN|TH_ACK)) == TH_SYN ||
			(tp->t_flags & TF_RCVD_TSTMP))) {
		u_char *optp = opt + optlen;
		be32_t ts_val, ts_ecr;

 		ts_val = htonl(current->t_tcp_now);
		ts_ecr = htonl(tp->ts_recent);

 		/* Form timestamp option as shown in appendix A of RFC 1323. */
		*(optp + 0) = TCPOPT_NOP;
		*(optp + 1) = TCPOPT_NOP;
		*(optp + 2) = TCPOPT_TIMESTAMP;
		*(optp + 3) = TCPOLEN_TIMESTAMP;
		memcpy(optp + 4, &ts_val, 4);
		memcpy(optp + 8, &ts_ecr, 4);
 		optlen += 12;
 	}

 	hdrlen += optlen;
 
	/*
	 * Adjust data length if insertion of options will
	 * bump the packet length beyond the t_maxseg length.
	 */
	if (len > tp->t_maxseg - optlen) {
		len = tp->t_maxseg - optlen;
		sendalot = 1;
	}

	/*
	 * Grab a header mbuf, attaching a copy of data to
	 * be transmitted, and initialize the header from
	 * the template for sends on this connection.
	 */
	if (len) {
		if (t_force && len == 1)
			counter64_inc(&tcpstat.tcps_sndprobe);
		else if (SEQ_LT(tp->snd_nxt, tp->snd_max)) {
			counter64_inc(&tcpstat.tcps_sndrexmitpack);
			counter64_add(&tcpstat.tcps_sndrexmitbyte, len);
		} else {
			counter64_inc(&tcpstat.tcps_sndpack);
			counter64_add(&tcpstat.tcps_sndbyte, len);
		}
		io_init_tx_packet(&pkt);
		//if (pkt == NULL) {
		//	error = ENOBUFS;
		//	goto err;
		//}
		sbcopy(&so->so_snd, off, len, pkt.pkt.buf + sizeof(struct ether_header) + hdrlen);
		/*
		 * If we're sending everything we've got, set PUSH.
		 * (This will keep happy those implementations which only
		 * give data to the user when a buffer fills or
		 * a PUSH comes in.)
		 */
		if (off + len == so->so_snd.sb_cc) {
			flags |= TH_PUSH;
		}
	} else {
		if (tp->t_flags & TF_ACKNOW) {
			counter64_inc(&tcpstat.tcps_sndacks);
		} else if (flags & (TH_SYN|BSD_TH_FIN|TH_RST)) {
			counter64_inc(&tcpstat.tcps_sndctrl);
		} else {
			counter64_inc(&tcpstat.tcps_sndwinup);
		}
		io_init_tx_packet(&pkt);
		//if (pkt == NULL) {
		//	error = ENOBUFS;
		//	goto err;
		//}
	}
	ip = (struct ip *)(pkt.pkt.buf + sizeof(struct ether_header));
	th = (struct bsd_tcp_hdr *)(ip + 1);
	tcp_template(tp, ip, th);
	/*
	 * Fill in fields, remembering maximum advertised
	 * window for use in delaying messages about window sizes.
	 * If resending a FIN, be sure not to use a new sequence number.
	 */
	if (flags & BSD_TH_FIN && tp->t_flags & TF_SENTFIN && 
	    tp->snd_nxt == tp->snd_max) {
		tp->snd_nxt--;
	}
	/*
	 * If we are doing retransmissions, then snd_nxt will
	 * not reflect the first unsent octet.  For ACK only
	 * packets, we do not want the sequence number of the
	 * retransmitted packet, we want the sequence number
	 * of the next unsent octet.  So, if there is no data
	 * (and no SYN or FIN), use snd_max instead of snd_nxt
	 * when filling in ti_seq.  But if we are in persist
	 * state, snd_max might reflect one byte beyond the
	 * right edge of the window, so use snd_nxt in that
	 * case, since we know we aren't doing a retransmission.
	 * (retransmit and persist are mutually exclusive...)
	 */
	if (len || (flags & (TH_SYN|BSD_TH_FIN)) ||
			timer_is_running(tp->t_timer + TCPT_PERSIST)) {
		th->th_seq = htonl(tp->snd_nxt);
	} else {
		th->th_seq = htonl(tp->snd_max);
	}
	th->th_ack = htonl(tp->rcv_nxt);
	if (optlen) {
		memcpy((th + 1), opt, optlen);
		th->th_off = (sizeof(struct bsd_tcp_hdr) + optlen) >> 2;
	}
	th->th_flags = flags;
	/*
	 * Calculate receive window.  Don't shrink window,
	 * but avoid silly window syndrome.
	 */
	if (win < (long)(so->so_rcv_hiwat / 4) && win < (long)tp->t_maxseg) {
		win = 0;
	}
	if (win > (long)TCP_MAXWIN << tp->rcv_scale) {
		win = (long)TCP_MAXWIN << tp->rcv_scale;
	}
	if (win < (long)(tp->rcv_adv - tp->rcv_nxt)) {
		win = (long)(tp->rcv_adv - tp->rcv_nxt);
	}
	th->th_win = htons((u_short) (win >> tp->rcv_scale));
	/*
	 * If no urgent pointer to send, then we pull
	 * the urgent pointer to the left edge of the send window
	 * so that it doesn't drift into the send window on sequence
	 * number wraparound.
	 */
	if (current->t_tcp_do_outcksum) {
		th->th_sum = tcp_cksum(ip, sizeof(*th) + optlen + len);
	}
	/*
	 * In transmit state, time the transmission and arrange for
	 * the retransmit.  In persist state, just set snd_max.
	 */
	if (t_force == 0 ||
	    !timer_is_running(tp->t_timer + TCPT_PERSIST)) {
		tcp_seq startseq = tp->snd_nxt;
		/*
		 * Advance snd_nxt over sequence space of this segment.
		 */
		if (flags & (TH_SYN|BSD_TH_FIN)) {
			if (flags & TH_SYN) {
				tp->snd_nxt++;
			}
			if (flags & BSD_TH_FIN) {
				tp->snd_nxt++;
				tp->t_flags |= TF_SENTFIN;
			}
		}
		tp->snd_nxt += len;
		if (SEQ_GT(tp->snd_nxt, tp->snd_max)) {
			tp->snd_max = tp->snd_nxt;
			/*
			 * Time this transmission if not a retransmission and
			 * not currently timing anything.
			 */
			if (tp->t_rtt == 0) {
				tp->t_rtt = current->t_tcp_now;
				tp->t_rtseq = startseq;
				counter64_inc(&tcpstat.tcps_segstimed);
			}
		}
		/*
		 * Set retransmit timer if not currently set,
		 * and not doing an ack or a keep-alive probe.
		 * Initial value for retransmit timer is smoothed
		 * round-trip time + 2 * round-trip time variance.
		 * Initialize shift counter which is used for backoff
		 * of retransmit time.
		 */
		if (!timer_is_running(tp->t_timer + TCPT_REXMT) && tp->snd_nxt != tp->snd_una) {
			tcp_setslowtimer(tp, TCPT_REXMT, tp->t_rxtcur);
			if (timer_is_running(tp->t_timer + TCPT_PERSIST)) {
				timer_cancel(tp->t_timer + TCPT_PERSIST);
				tp->t_rxtshift = 0;
			}
		}
	} else {
		if (SEQ_GT(tp->snd_nxt + len, tp->snd_max)) {
			tp->snd_max = tp->snd_nxt + len;
		}
	}
	ip->ip_len = hdrlen + len;
	/*
	 * Trace.
	 */
	if (so->so_options & SO_OPTION(SO_DEBUG)) {
		tcp_trace(TA_OUTPUT, tp->t_state, tp, ip, th, 0);
	}
	ip_output(&pkt, ip);
	counter64_inc(&tcpstat.tcps_sndtotal);

	/*
	 * Data sent (as far as we can tell).
	 * If this advertises a larger window than any other segment,
	 * then remember the size of the advertised window.
	 * Any pending ACK has now been sent.
	 */
	if (win > 0 && SEQ_GT(tp->rcv_nxt + win, tp->rcv_adv)) {
		tp->rcv_adv = tp->rcv_nxt + win;
	}
	tp->last_ack_sent = tp->rcv_nxt;
	tp->t_flags &= ~(TF_ACKNOW|TF_DELACK);
	timer_cancel(&tp->t_timer_delack);
	return sendalot;
//err:
	if (error == ENOBUFS) {
		tcp_quench(so, 0);
		return 0;
	}
	if ((error == EHOSTUNREACH || error == ENETDOWN) &&
	    TCPS_HAVERCVDSYN(tp->t_state)) {
		tp->t_softerror = error;
		return 0;
	}
	return -error;
}

void
tcp_setpersist(struct tcpcb *tp)
{
	int t, timo;

	t = ((tp->t_srtt >> 2) + tp->t_rttvar) >> 1;

	if (timer_is_running(tp->t_timer + TCPT_REXMT)) {
		panic(0, "tcp_output REXMT");
	}
	/*
	 * Start/restart persistance timer.
	 */
	TCPT_RANGESET(timo,
	    t * tcp_backoff[tp->t_rxtshift],
	    TCPTV_PERSMIN, TCPTV_PERSMAX);
	if (tp->t_rxtshift < TCP_MAXRXTSHIFT)
		tp->t_rxtshift++;
	tcp_setslowtimer(tp, TCPT_PERSIST, timo);
}
