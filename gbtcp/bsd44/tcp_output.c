// SPDX-License-Identifier: BSD-4-Clause

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
 * Basic flags (RST,ACK,SYN,FIN) are totally
 * determined by state, with the proviso that FIN is sent only
 * if all data queued for output is included in the segment.
 */
u_char tcp_outflags[GT_TCPS_MAX_STATES] = {
	[GT_TCPS_CLOSED] = GT_TCPF_RST|GT_TCPF_ACK,
	[GT_TCPS_LISTEN] = 0,
	[GT_TCPS_SYN_SENT] = GT_TCPF_SYN,
	[GT_TCPS_SYN_RCVD] = GT_TCPF_SYN|GT_TCPF_ACK,
	[GT_TCPS_ESTABLISHED] = GT_TCPF_ACK,
	[GT_TCPS_CLOSE_WAIT] = GT_TCPF_ACK,
	[GT_TCPS_FIN_WAIT_1] = GT_TCPF_FIN|GT_TCPF_ACK,
	[GT_TCPS_CLOSING] = GT_TCPF_FIN|GT_TCPF_ACK,
	[GT_TCPS_LAST_ACK] = GT_TCPF_FIN|GT_TCPF_ACK,
	[GT_TCPS_FIN_WAIT_2] = GT_TCPF_ACK,
	[GT_TCPS_TIME_WAIT] = GT_TCPF_ACK,
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
	GT_DLIST_INSERT_TAIL(&current->p_tx_head, so, so_txlist);
}

int
tcp_output_real(struct route_entry *r, struct dev_pkt *pkt, struct socket *so)
{
	struct tcpcb *tp;
	int off, len, win, flags;
	u_char opt[MAX_TCPOPTLEN];
	unsigned optlen, hdrlen;
	int idle, sendalot, t_force;
	struct ip4_hdr *ip;
	struct tcp_hdr *th;

	tp = sototcpcb(so);
	t_force = tp->t_force;
	tp->t_force = 0;

	/*
	 * Determine length of data that should be transmitted,
	 * and flags that will be used.
	 * If there is some data or critical controls (SYN, RST)
	 * to send, then transmit; otherwise, investigate further.
	 */
	idle = (tp->snd_max == tp->snd_una);
	if (idle && tcp_now - tp->t_idle >= tp->t_rxtcur) {
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
				flags &= ~GT_TCPF_FIN;
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
		flags &= ~GT_TCPF_FIN;
	}
	win = so->so_rcv.sb_hiwat;

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
		if (2 * adv >= (long) so->so_rcv.sb_hiwat)
			goto send;
	}

	/*
	 * Send if we owe peer an ACK.
	 */
	if (tp->t_flags & TF_ACKNOW)
		goto send;
	if (flags & (GT_TCPF_SYN|GT_TCPF_RST))
		goto send;
	/*
	 * If our state indicates that FIN should be sent
	 * and we have not yet done so, or we're retransmitting the FIN,
	 * then we need to send.
	 */
	if ((flags & GT_TCPF_FIN) &&
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
	return -ENOBUFS;

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
	hdrlen = sizeof(struct ip4_hdr) + sizeof(struct tcp_hdr);
	if (flags & GT_TCPF_SYN) {
		tp->snd_nxt = tp->snd_una;
		if ((tp->t_flags & TF_NOOPT) == 0) {
			u_short mss;

			opt[0] = TCPOPT_MAXSEG;
			opt[1] = 4;
			mss = htons((u_short) tcp_mss(r->rt_ifp, tp, 0));
			memcpy((opt + 2), &mss, sizeof(mss));
			optlen = 4;
	 
			if ((tp->t_flags & TF_REQ_SCALE) &&
			    ((flags & GT_TCPF_ACK) == 0 ||
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
			(flags & GT_TCPF_RST) == 0 &&
			((flags & (GT_TCPF_SYN|GT_TCPF_ACK)) == GT_TCPF_SYN ||
			(tp->t_flags & TF_RCVD_TSTMP))) {
		u_char *optp = opt + optlen;
		be32_t ts_val, ts_ecr;

 		ts_val = htonl(tcp_now);
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
			tcpstat.tcps_sndprobe++;
		else if (SEQ_LT(tp->snd_nxt, tp->snd_max)) {
			tcpstat.tcps_sndrexmitpack++;
			tcpstat.tcps_sndrexmitbyte += len;
		} else {
			tcpstat.tcps_sndpack++;
			tcpstat.tcps_sndbyte += len;
		}
		//if (pkt == NULL) {
		//	error = ENOBUFS;
		//	goto err;
		//}
		sbcopy(&so->so_snd, off, len,
				pkt->pkt_data + sizeof(struct eth_hdr) + hdrlen);
		/*
		 * If we're sending everything we've got, set PUSH.
		 * (This will keep happy those implementations which only
		 * give data to the user when a buffer fills or
		 * a PUSH comes in.)
		 */
		if (off + len == so->so_snd.sb_cc) {
			flags |= GT_TCPF_PSH;
		}
	} else {
		if (tp->t_flags & TF_ACKNOW) {
			tcpstat.tcps_sndacks++;
		} else if (flags & (GT_TCPF_SYN|GT_TCPF_FIN|GT_TCPF_RST)) {
			tcpstat.tcps_sndctrl++;
		} else {
			tcpstat.tcps_sndwinup++;
		}
	}
	ip = (struct ip4_hdr *)(pkt->pkt_data + sizeof(struct eth_hdr));
	th = (struct tcp_hdr *)(ip + 1);
	tcp_template(so, ip, th);
	/*
	 * Fill in fields, remembering maximum advertised
	 * window for use in delaying messages about window sizes.
	 * If resending a FIN, be sure not to use a new sequence number.
	 */
	if (flags & GT_TCPF_FIN && tp->t_flags & TF_SENTFIN && 
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
	if (len || (flags & (GT_TCPF_SYN|GT_TCPF_FIN)) ||
			timer_is_running(tp->t_timer + TCPT_PERSIST)) {
		th->th_seq = htonl(tp->snd_nxt);
	} else {
		th->th_seq = htonl(tp->snd_max);
	}
	th->th_ack = htonl(tp->rcv_nxt);
	if (optlen) {
		memcpy((th + 1), opt, optlen);
		th->th_data_off = (sizeof(struct tcp_hdr) + optlen) << 2;
	}
	th->th_flags = flags;
	/*
	 * Calculate receive window.  Don't shrink window,
	 * but avoid silly window syndrome.
	 */
	if (win < (long)(so->so_rcv.sb_hiwat / 4) && win < (long)tp->t_maxseg) {
		win = 0;
	}
	if (win > (long)TCP_MAXWIN << tp->rcv_scale) {
		win = (long)TCP_MAXWIN << tp->rcv_scale;
	}
	if (win < (long)(tp->rcv_adv - tp->rcv_nxt)) {
		win = (long)(tp->rcv_adv - tp->rcv_nxt);
	}
	th->th_win_size = htons((u_short) (win >> tp->rcv_scale));

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
		if (flags & (GT_TCPF_SYN|GT_TCPF_FIN)) {
			if (flags & GT_TCPF_SYN) {
				tp->snd_nxt++;
			}
			if (flags & GT_TCPF_FIN) {
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
				tp->t_rtt = tcp_now;
				tp->t_rtseq = startseq;
				tcpstat.tcps_segstimed++;
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
	ip->ih_total_len = hdrlen + len;
	/*
	 * Trace.
	 */
	if (so->so_options & SO_OPTION(SO_DEBUG)) {
		tcp_trace(TA_OUTPUT, tp->t_state, tp, ip, th, 0);
	}
	tcpstat.tcps_sndtotal++;

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
	timer_cancel(tp->t_timer + TCPT_DELACK);
	ip_output(r, pkt, ip);
	return sendalot;
}

void
tcp_setpersist(struct tcpcb *tp)
{
	int t, timo;

	t = ((tp->t_srtt >> 2) + tp->t_rttvar) >> 1;

	if (timer_is_running(tp->t_timer + TCPT_REXMT)) {
		assert(0 && "tcp_output REXMT");
	}
	
	// Start/restart persistance timer.
	TCPT_RANGESET(timo, t * tcp_backoff[tp->t_rxtshift], TCPTV_PERSMIN, TCPTV_PERSMAX);
	if (tp->t_rxtshift < TCP_MAXRXTSHIFT)
		tp->t_rxtshift++;
	tcp_setslowtimer(tp, TCPT_PERSIST, timo);
}
