// SPDX-License-Identifier: BSD-4-Clause

#include "../socket.h"
#include "socket.h"
#include "ip.h"
#include "in_pcb.h"
#include "ip_var.h"
#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_var.h"

int tcprexmtthresh = 3;

#define TCP_PAWS_IDLE	(24 * 24 * 60 * 60 * PR_SLOWHZ)

/* for modulo comparisons of timestamps */
#define TSTMP_LT(a,b)	((int)((a)-(b)) < 0)
#define TSTMP_GEQ(a,b)	((int)((a)-(b)) >= 0)

#define curmod ((struct gt_module_socket *)gt_module_get(GT_MODULE_SOCKET))

static void
tcp_dooptions(struct route_if *ifp, struct tcpcb *tp, u_char *cp, int cnt,
		struct tcp_hdr *th, int *ts_present, uint32_t *ts_val, uint32_t *ts_ecr)
{
	u_short mss;
	int opt, optlen;

	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[0];
		if (opt == TCPOPT_EOL) {
			break;
		}
		if (opt == TCPOPT_NOP) {
			optlen = 1;
		} else {
			optlen = cp[1];
			if (optlen <= 0)
				break;
		}
		switch (opt) {
		default:
			continue;

		case TCPOPT_MAXSEG:
			if (optlen != TCPOLEN_MAXSEG)
				continue;
			if (!(th->th_flags & GT_TCPF_SYN)) {
				continue;
			}
			memcpy((char *)&mss, (char *)cp + 2, sizeof(mss));
			NTOHS(mss);
			tcp_mss(ifp, tp, mss); /* sets t_maxseg */
			break;

		case TCPOPT_WINDOW:
			if (optlen != TCPOLEN_WINDOW)
				continue;
			if (!(th->th_flags & GT_TCPF_SYN)) {
				continue;
			}
			tp->t_flags |= TF_RCVD_SCALE;
			tp->requested_s_scale = MIN(cp[2], TCP_MAX_WINSHIFT);
			break;

		case TCPOPT_TIMESTAMP:
			if (optlen != TCPOLEN_TIMESTAMP) {
				continue;
			}
			*ts_present = 1;
			memcpy((char *)ts_val, (char *)cp + 2, sizeof(*ts_val));
			NTOHL(*ts_val);
			memcpy((char *)ts_ecr, (char *)cp + 6, sizeof(*ts_ecr));
			NTOHL(*ts_ecr);

			/* 
			 * A timestamp received in a SYN makes
			 * it ok to send timestamp requests and replies.
			 */
			if (th->th_flags & GT_TCPF_SYN) {
				tp->t_flags |= TF_RCVD_TSTMP;
				tp->ts_recent = *ts_val;
				tp->ts_recent_age = tcp_now;
			}
			break;
		}
	}
}

static int
tcp_timewait(struct tcpcb *tp)
{
	struct socket *so;
	uint64_t to;

	tp->t_state = GT_TCPS_TIME_WAIT;
	to = curmod->tcp_time_wait_timeout;
	if (to == 0) {
		tcp_close(tp);
		return 0;
	} else {
		so = tcpcbtoso(tp);
		tcp_canceltimers(tp);
		tcp_settimer(tp, TCPT_2MSL, to);
		soisdisconnected(so);
		return 1;
	}
}

/*
 * Collect new round-trip time estimate
 * and update averages and current timeout.
 */
static void
tcp_xmit_timer(struct tcpcb *tp, short rtt)
{
	short delta;

	tcpstat.tcps_rttupdated++;
	if (tp->t_srtt != 0) {
		/*
		 * srtt is stored as fixed point with 3 bits after the
		 * binary point (i.e., scaled by 8).  The following magic
		 * is equivalent to the smoothing algorithm in rfc793 with
		 * an alpha of .875 (srtt = rtt/8 + srtt*7/8 in fixed
		 * point).  Adjust rtt to origin 0.
		 */
		delta = rtt - 1 - (tp->t_srtt >> TCP_RTT_SHIFT);
		if ((tp->t_srtt += delta) <= 0)
			tp->t_srtt = 1;
		/*
		 * We accumulate a smoothed rtt variance (actually, a
		 * smoothed mean difference), then set the retransmit
		 * timer to smoothed rtt + 4 times the smoothed variance.
		 * rttvar is stored as fixed point with 2 bits after the
		 * binary point (scaled by 4).  The following is
		 * equivalent to rfc793 smoothing with an alpha of .75
		 * (rttvar = rttvar*3/4 + |delta| / 4).  This replaces
		 * rfc793's wired-in beta.
		 */
		if (delta < 0) {
			delta = -delta;
		}
		delta -= (tp->t_rttvar >> TCP_RTTVAR_SHIFT);
		if ((tp->t_rttvar += delta) <= 0) {
			tp->t_rttvar = 1;
		}
	} else {
		/* 
		 * No rtt measurement yet - use the unsmoothed rtt.
		 * Set the variance to half the rtt (so our first
		 * retransmit happens at 3*rtt).
		 */
		tp->t_srtt = rtt << TCP_RTT_SHIFT;
		tp->t_rttvar = rtt << (TCP_RTTVAR_SHIFT - 1);
	}
	tp->t_rtt = 0;
	tp->t_rxtshift = 0;

	/*
	 * the retransmit should happen at rtt + 4 * rttvar.
	 * Because of the way we do the smoothing, srtt and rttvar
	 * will each average +1/2 tick of bias.  When we compute
	 * the retransmit timer, we want 1/2 tick of rounding and
	 * 1 extra tick because of +-1/2 tick uncertainty in the
	 * firing of the timer.  The bias will give us exactly the
	 * 1.5 tick we need.  But, because the bias is
	 * statistical, we have to test that we don't drop below
	 * the minimum feasible timer (which is 2 ticks).
	 */
	TCPT_RANGESET(tp->t_rxtcur, TCP_REXMTVAL(tp),
	              TCPTV_MIN, TCPTV_REXMTMAX);
	
	/*
	 * We received an ack for a packet that wasn't retransmitted;
	 * it is probably safe to discard any error indications we've
	 * received recently.  This isn't quite right, but close enough
	 * for now (a route might have failed after we sent a segment,
	 * and the return path might not be symmetrical).
	 */
	tp->t_softerror = 0;
}



/*
 * TCP input routine, follows pages 65-76 of the
 * protocol specification dated September, 1981 very closely.
 */
int
tcp_input(struct route_if *ifp, struct ip4_hdr *ip, int iphlen, int eth_flags)
{
	struct ip4_hdr save_ip;
	struct tcp_hdr *th, save_th;
	u_char *optp, *dat;
	int optlen = 0;
	int rc, win, off, acceptconn, rcv_wnd, datlen;
	struct tcpcb *tp;
	struct socket *so;
	int again, todrop, acked, ourfinisacked, needoutput = 0;
	short ostate = 0;
	uint32_t h = 0, ts_val, ts_ecr;
	int flags, ts_present, dropsocket;
	u_long tiwin;

	tcpstat.tcps_rcvtotal++;
	tp = NULL;
	so = NULL;
	ts_present = 0;
	dropsocket = 0;
	optp = NULL;
	th = (struct tcp_hdr *)((u_char *)ip + iphlen);
	if (ip->ih_total_len < sizeof(struct tcp_hdr)) {
		tcpstat.tcps_rcvshort++;
		return IN_OK;
	}

	/*
	 * Checksum extended TCP header and data.
	 */
	if (!gt_tcp_validate_cksum(ip, th, ip->ih_total_len)) {
		tcpstat.tcps_rcvbadsum++;
		goto drop;
	}

	/*
	 * Check that TCP offset makes sense,
	 * pull out TCP options and adjust length.
	 */
	off = th->th_data_off << 2;
	if (off < sizeof(struct tcp_hdr) || off > ip->ih_total_len) {
		tcpstat.tcps_rcvbadoff++;
		goto drop;
	}
	ip->ih_total_len -= off;
	dat = ((u_char *)ip) + iphlen + off;
	flags = th->th_flags;
	if (off > sizeof(struct tcp_hdr)) {
		optlen = off - sizeof(struct tcp_hdr);
		optp = (u_char *)(th + 1);
	}

	/*
	 * Convert TCP protocol specific fields to host format.
	 */
	NTOHL(th->th_seq);
	NTOHL(th->th_ack);
	NTOHS(th->th_win_size);
	NTOHS(th->th_urgent_ptr);

	/*
	 * Locate pcb for segment.
	 */
findpcb:
	again = 0;
	datlen = 0;
	rc = in_pcblookup(&so, IPPROTO_TCP,
			ip->ih_daddr, ip->ih_saddr, th->th_dport, th->th_sport);
	if (rc >= 0) {
		return rc;
	}

	/*
	 * If the state is CLOSED (i.e., TCB does not exist) then
	 * all data in the incoming segment is discarded.
	 * If the TCB exists but is in CLOSED state, it is embryonic,
	 * but should either do a listen or a connect soon.
	 */
	if (so == NULL) {
		goto dropwithreset;
	}
	so->so_state |= SS_ISPROCESSING;
	tp = sototcpcb(so);
	if (tp->t_state == GT_TCPS_CLOSED) {
		goto drop;
	}
	/* Unscale the window into a 32-bit value. */
	if ((flags & GT_TCPF_SYN) == 0) {
		tiwin = th->th_win_size << tp->snd_scale;
	} else {
		/* 
		 * RFC 1323: The Window field in a SYN
		 * (i.e., a <SYN> or <SYN,ACK>)
 		 * segment itself is never scaled.
	 	 */
		tiwin = th->th_win_size;
	}
	if (so->so_options & SO_OPTION(SO_DEBUG)) {
		ostate = tp->t_state;
		save_ip = *ip;
		save_th = *th;
	}
	acceptconn = so->so_options & SO_OPTION(SO_ACCEPTCONN);
	if (acceptconn) {
		so->so_state &= ~SS_ISPROCESSING;
		so = sonewconn(so);
		if (so == NULL) {
			tcpstat.tcps_listendrop++;
			goto drop;
		}
		so->so_state |= SS_ISPROCESSING;
		ostate = tp->t_state;
	}
	so->so_events = 0;
	if (acceptconn) {
		/*
		 * This is ugly, but ....
		 *
		 * Mark socket as temporary until we're
		 * committed to keeping it.  The code at
		 * ``drop'' and ``dropwithreset'' check the
		 * flag dropsocket to see if the temporary
		 * socket created here should be discarded.
		 * We mark the socket as discardable until
		 * we're committed to it below in TCPS_LISTEN.
		 */
		dropsocket++;
		so->inp_laddr = ip->ih_daddr;
		so->inp_lport = th->th_dport;
		so->inp_faddr = ip->ih_saddr;
		so->inp_fport = th->th_sport;
		in_pcbattach(so, &h);
		tp = sototcpcb(so);
		tp->t_state = GT_TCPS_LISTEN;

		/* Compute proper scaling value from buffer space
		 */
		while (tp->request_r_scale < TCP_MAX_WINSHIFT &&
				TCP_MAXWIN << tp->request_r_scale < so->so_rcv_hiwat) {
			tp->request_r_scale++;
		}
	}

	/*
	 * Segment received on connection.
	 * Reset idle time and keep-alive timer.
	 */
	tp->t_idle = tcp_now;
	tcp_setslowtimer(tp, TCPT_KEEP, TCPTV_KEEP_IDLE);

	/*
	 * Process options if not in LISTEN state,
	 * else do it below (after getting remote address).
	 */
	if (optp != NULL && tp->t_state != GT_TCPS_LISTEN) {
		tcp_dooptions(ifp, tp, optp, optlen, th, &ts_present, &ts_val, &ts_ecr);
	}

	/*
	 * Calculate amount of space in receive window,
	 * and then do TCP input processing.
	 * Receive window is amount of space in rcv queue,
	 * but not less than advertised window.
	 */
	rcv_wnd = MAX(so->so_rcv_hiwat, (int)(tp->rcv_adv - tp->rcv_nxt));

	switch (tp->t_state) {

	/*
	 * If the state is LISTEN then ignore segment if it contains an RST.
	 * If the segment contains an ACK then it is bad and send a RST.
	 * If it does not contain a SYN then it is not interesting; drop it.
	 * Don't bother responding if the destination was a broadcast.
	 * Otherwise initialize tp->rcv_nxt, and tp->irs, select an initial
	 * tp->iss, and send a segment:
	 *     <SEQ=ISS><ACK=RCV_NXT><CTL=SYN,ACK>
	 * Also initialize tp->snd_nxt to tp->iss+1 and tp->snd_una to tp->iss.
	 * Fill in remote peer address fields if not previously specified.
	 * Enter SYN_RECEIVED state, and process any other fields of this
	 * segment in this state.
	 */
	case GT_TCPS_LISTEN:
		if (flags & GT_TCPF_RST) {
			goto drop;
		}
		if (flags & GT_TCPF_ACK) {
			goto dropwithreset;
		}
		if ((flags & GT_TCPF_SYN) == 0) {
			goto drop;
		}
		/*
		 * RFC1122 4.2.3.10, p. 104: discard bcast/mcast SYN
		 * in_broadcast() should never return true on a received
		 * packet with M_BCAST not set.
		 */
		/*if ((eth_flags & (M_MCAST|M_BCAST)) || IN_MULTICAST(ip->ip_dst.s_addr)) {
			goto drop;
		}*/
		if (optp != NULL) {
			tcp_dooptions(ifp, tp, optp, optlen, th, &ts_present, &ts_val, &ts_ecr);
		}
		tcp_sendseqinit(tp, h);
		tcp_rcvseqinit(tp, th->th_seq);
		tp->t_flags |= TF_ACKNOW;
		tp->t_state = GT_TCPS_SYN_RCVD;
		tcp_setslowtimer(tp, TCPT_KEEP, TCPTV_KEEP_INIT);
		dropsocket = 0;		/* committed to socket */
		tcpstat.tcps_accepts++;
		goto trimthenstep6;

	/*
	 * If the state is SYN_SENT:
	 *	if seg contains an ACK, but not for our SYN, drop the input.
	 *	if seg contains a RST, then drop the connection.
	 *	if seg does not contain SYN, then drop it.
	 * Otherwise this is an acceptable SYN segment
	 *	initialize tp->rcv_nxt and tp->irs
	 *	if seg contains ack then advance tp->snd_una
	 *	if SYN has been acked change to ESTABLISHED else SYN_RCVD state
	 *	arrange for segment to be acked (eventually)
	 *	continue processing rest of data/controls, beginning with URG
	 */
	case GT_TCPS_SYN_SENT:
		if ((flags & GT_TCPF_ACK) && th->th_ack != tp->snd_nxt) {
			goto dropwithreset;
		}
		if (flags & GT_TCPF_RST) {
			if (flags & GT_TCPF_ACK) {
				tcp_drop(tp, ECONNREFUSED);
			}
			goto drop;
		}
		if ((flags & GT_TCPF_SYN) == 0) {
			goto drop;
		}
		if (flags & GT_TCPF_ACK) {
			tp->snd_una = th->th_ack;
			if (SEQ_LT(tp->snd_nxt, tp->snd_una))
				tp->snd_nxt = tp->snd_una;
		}
		timer_cancel(tp->t_timer + TCPT_REXMT);
		tcp_rcvseqinit(tp, th->th_seq);
		tp->t_flags |= TF_ACKNOW;
		if ((flags & GT_TCPF_ACK)) {
			tcpstat.tcps_connects++;
			soisconnected(so);
			tp->t_state = GT_TCPS_ESTABLISHED;
			/* Do window scaling on this connection? */
			if ((tp->t_flags & (TF_RCVD_SCALE|TF_REQ_SCALE)) ==
			                   (TF_RCVD_SCALE|TF_REQ_SCALE)) {
				tp->snd_scale = tp->requested_s_scale;
				tp->rcv_scale = tp->request_r_scale;
			}
			/*
			 * if we didn't have to retransmit the SYN,
			 * use its rtt as our initial srtt & rtt var.
			 */
			if (tp->t_rtt) {
				tcp_xmit_timer(tp, tp->t_rtt);
			}
		} else {
			tp->t_state = GT_TCPS_SYN_RCVD;
		}

trimthenstep6:
		/*
		 * Advance th->th_seq to correspond to first data byte.
		 * If data, trim to stay within window,
		 * dropping FIN if necessary.
		 */
		th->th_seq++;
		if (ip->ih_total_len > rcv_wnd) {
			todrop = ip->ih_total_len - rcv_wnd;
			ip->ih_total_len = rcv_wnd;
			flags &= ~GT_TCPF_FIN;
			tcpstat.tcps_rcvpackafterwin++;
			tcpstat.tcps_rcvbyteafterwin += todrop;
		}
		tp->snd_wl1 = th->th_seq - 1;
		goto step6;
	}

	/*
	 * States other than LISTEN or SYN_SENT.
	 * First check timestamp, if present.
	 * Then check that at least some bytes of segment are within 
	 * receive window.  If segment begins before rcv_nxt,
	 * drop leading data (and SYN); if nothing left, just ack.
	 * 
	 * RFC 1323 PAWS: If we have a timestamp reply on this segment
	 * and it's less than ts_recent, drop it.
	 */
	if (ts_present && (flags & GT_TCPF_RST) == 0 && tp->ts_recent &&
	    TSTMP_LT(ts_val, tp->ts_recent)) {

		/* Check to see if ts_recent is over 24 days old.  */
		if ((int)(tcp_now - tp->ts_recent_age) > TCP_PAWS_IDLE) {
			/*
			 * Invalidate ts_recent.  If this segment updates
			 * ts_recent, the age will be reset later and ts_recent
			 * will get a valid value.  If it does not, setting
			 * ts_recent to zero will at least satisfy the
			 * requirement that zero be placed in the timestamp
			 * echo reply when ts_recent isn't valid.  The
			 * age isn't reset until we get a valid ts_recent
			 * because we don't want out-of-order segments to be
			 * dropped when ts_recent is old.
			 */
			tp->ts_recent = 0;
		} else {
			tcpstat.tcps_rcvduppack++;
			tcpstat.tcps_rcvdupbyte += ip->ih_total_len;
			tcpstat.tcps_pawsdrop++;
			goto dropafterack;
		}
	}

	todrop = tp->rcv_nxt - th->th_seq;
	if (todrop > 0) {
		if (flags & GT_TCPF_SYN) {
			flags &= ~GT_TCPF_SYN;
			th->th_seq++;
			todrop--;
		}
		if (todrop >= ip->ih_total_len) {
			tcpstat.tcps_rcvduppack++;
			tcpstat.tcps_rcvdupbyte += ip->ih_total_len;
			/*
			 * If segment is just one to the left of the window,
			 * check two special cases:
			 * 1. Don't toss RST in response to 4.2-style keepalive.
			 * 2. If the only thing to drop is a FIN, we can drop
			 *    it, but check the ACK or we will get into FIN
			 *    wars if our FINs crossed (both CLOSING).
			 * In either case, send ACK to resynchronize,
			 * but keep on processing for RST or ACK.
			 */
			if ((flags & GT_TCPF_FIN) && todrop == ip->ih_total_len + 1) {
				todrop = ip->ih_total_len;
				flags &= ~GT_TCPF_FIN;
				tp->t_flags |= TF_ACKNOW;
			} else {
				/*
				 * Handle the case when a bound socket connects
				 * to itself. Allow packets with a SYN and
				 * an ACK to continue with the processing.
				 */
				if (todrop != 0 || (flags & GT_TCPF_ACK) == 0) {
					goto dropafterack;
				}
			}
		} else {
			tcpstat.tcps_rcvpartduppack++;
			tcpstat.tcps_rcvpartdupbyte += todrop;
		}
		dat += todrop;
		th->th_seq += todrop;
		ip->ih_total_len -= todrop;
	}

	/*
	 * If new data are received on a connection after the
	 * user processes are gone, then RST the other end.
	 */
	if ((so->so_state & SS_NOFDREF) && ip->ih_total_len &&
			(tp->t_state == GT_TCPS_FIN_WAIT_1 ||
			 tp->t_state == GT_TCPS_CLOSING ||
			 tp->t_state == GT_TCPS_LAST_ACK ||
			 tp->t_state == GT_TCPS_FIN_WAIT_2 ||
			 tp->t_state == GT_TCPS_TIME_WAIT)) {
		tcp_close(tp);
		tcpstat.tcps_rcvafterclose++;
		goto dropwithreset;
	}

	/*
	 * If segment ends after window, drop trailing data
	 * (and PUSH and FIN); if nothing left, just ACK.
	 */
	todrop = (th->th_seq + ip->ih_total_len) - (tp->rcv_nxt + rcv_wnd);
	if (todrop > 0) {
		tcpstat.tcps_rcvpackafterwin++;
		if (todrop >= ip->ih_total_len) {
			tcpstat.tcps_rcvbyteafterwin += ip->ih_total_len;
			/*
			 * If a new connection request is received
			 * while in TIME_WAIT, drop the old connection
			 * and start over if the sequence numbers
			 * are above the previous ones.
			 */
			if ((flags & GT_TCPF_SYN) &&
			    tp->t_state == GT_TCPS_TIME_WAIT &&
			    SEQ_GT(th->th_seq, tp->rcv_nxt)) {
				tcp_close(tp);
				again = 1;
				goto unref;
			}
			/*
			 * If window is closed can only take segments at
			 * window edge, and have to drop data and PUSH from
			 * incoming segments.  Continue processing, but
			 * remember to ack.  Otherwise, drop segment
			 * and ack.
			 */
			if (rcv_wnd == 0 && th->th_seq == tp->rcv_nxt) {
				tp->t_flags |= TF_ACKNOW;
				tcpstat.tcps_rcvwinprobe++;
			} else {
				goto dropafterack;
			}
		} else {
			tcpstat.tcps_rcvbyteafterwin += todrop;
		}
		ip->ih_total_len -= todrop;
		flags &= ~(GT_TCPF_PSH|GT_TCPF_FIN);
	}

	/*
	 * If last ACK falls within this segment's sequence numbers,
	 * record its timestamp.
	 */
	if (ts_present && SEQ_LEQ(th->th_seq, tp->last_ack_sent) &&
	    SEQ_LT(tp->last_ack_sent, th->th_seq + ip->ih_total_len +
		   ((flags & (GT_TCPF_SYN|GT_TCPF_FIN)) != 0))) {
		tp->ts_recent_age = tcp_now;
		tp->ts_recent = ts_val;
	}

	/*
	 * If the RST bit is set examine the state:
	 *    SYN_RECEIVED STATE:
	 *	If passive open, return to LISTEN state.
	 *	If active open, inform user that connection was refused.
	 *    ESTABLISHED, FIN_WAIT_1, FIN_WAIT2, CLOSE_WAIT STATES:
	 *	Inform user that connection was reset, and close tcb.
	 *    CLOSING, LAST_ACK, TIME_WAIT STATES
	 *	Close the tcb.
	 */
	if (flags & GT_TCPF_RST) {
		switch (tp->t_state) {
		case GT_TCPS_SYN_RCVD:
			so->so_error = ECONNREFUSED;
			goto close;

		case GT_TCPS_ESTABLISHED:
		case GT_TCPS_FIN_WAIT_1:
		case GT_TCPS_FIN_WAIT_2:
		case GT_TCPS_CLOSE_WAIT:
			so->so_error = ECONNRESET;
close:
			tp->t_state = GT_TCPS_CLOSED;
			tcpstat.tcps_drops++;
			tcp_close(tp);
			goto drop;

		case GT_TCPS_CLOSING:
		case GT_TCPS_LAST_ACK:
		case GT_TCPS_TIME_WAIT:
			tcp_close(tp);
			goto drop;
		}
	}

	/*
	 * If a SYN is in the window, then this is an
	 * error and we send an RST and drop the connection.
	 */
	if (flags & GT_TCPF_SYN) {
		tcp_drop(tp, ECONNRESET);
		goto dropwithreset;
	}

	/*
	 * If the ACK bit is off we drop the segment and return.
	 */
	if ((flags & GT_TCPF_ACK) == 0) {
		goto drop;
	}
	/*
	 * Ack processing.
	 */
	switch (tp->t_state) {

	/*
	 * In SYN_RECEIVED state if the ack ACKs our SYN then enter
	 * ESTABLISHED state and continue processing, otherwise
	 * send an RST.
	 */
	case GT_TCPS_SYN_RCVD:
		if (SEQ_GT(tp->snd_una, th->th_ack) ||
		    SEQ_GT(th->th_ack, tp->snd_max)) {
			goto dropwithreset;
		}
		tcpstat.tcps_connects++;
		soisconnected(so);
		tp->t_state = GT_TCPS_ESTABLISHED;
		/* Do window scaling? */
		if ((tp->t_flags & (TF_RCVD_SCALE|TF_REQ_SCALE)) ==
			(TF_RCVD_SCALE|TF_REQ_SCALE)) {
			tp->snd_scale = tp->requested_s_scale;
			tp->rcv_scale = tp->request_r_scale;
		}
		tp->snd_wl1 = th->th_seq - 1;
		/* fall into ... */

	/*
	 * In ESTABLISHED state: drop duplicate ACKs; ACK out of range
	 * ACKs.  If the ack is in the range
	 *	tp->snd_una < th->th_ack <= tp->snd_max
	 * then advance tp->snd_una to th->th_ack and drop
	 * data from the retransmission queue.  If this ACK reflects
	 * more up to date window information we update our window information.
	 */
	case GT_TCPS_ESTABLISHED:
	case GT_TCPS_FIN_WAIT_1:
	case GT_TCPS_FIN_WAIT_2:
	case GT_TCPS_CLOSE_WAIT:
	case GT_TCPS_CLOSING:
	case GT_TCPS_LAST_ACK:
	case GT_TCPS_TIME_WAIT:
		if (SEQ_LEQ(th->th_ack, tp->snd_una)) {
			if (ip->ih_total_len == 0 &&
			    (flags & GT_TCPF_FIN) == 0 &&
			    tiwin == tp->snd_wnd) {
				tcpstat.tcps_rcvdupack++;
				/*
				 * If we have outstanding data (other than
				 * a window probe), this is a completely
				 * duplicate ack (ie, window info didn't
				 * change), the ack is the biggest we've
				 * seen and we've seen exactly our rexmt
				 * threshhold of them, assume a packet
				 * has been dropped and retransmit it.
				 * Kludge snd_nxt & the congestion
				 * window so we send only this one
				 * packet.
				 *
				 * We know we're losing at the current
				 * window size so do congestion avoidance
				 * (set ssthresh to half the current window
				 * and pull our congestion window back to
				 * the new ssthresh).
				 *
				 * Dup acks mean that packets have left the
				 * network (they're now cached at the receiver) 
				 * so bump cwnd by the amount in the receiver
				 * to keep a constant cwnd packets in the
				 * network.
				 */
				if (!timer_is_running(tp->t_timer + TCPT_REXMT) ||
				    th->th_ack != tp->snd_una) {
					tp->t_dupacks = 0;
				} else if (++tp->t_dupacks == tcprexmtthresh) {
					win = MIN(tp->snd_wnd, tp->snd_cwnd);
					win = win / 2 / tp->t_maxseg;
					if (win < 2) {
						win = 2;
					}
					tp->snd_ssthresh = win * tp->t_maxseg;
					timer_cancel(tp->t_timer + TCPT_REXMT);
					tp->t_rtt = 0;
					tp->snd_nxt = th->th_ack;
					tp->snd_cwnd = tp->t_maxseg;
					tcp_output(tp);
					goto drop;
				} else if (tp->t_dupacks > tcprexmtthresh) {
					tp->snd_cwnd += tp->t_maxseg;
					tcp_output(tp);
					goto drop;
				}
			} else {
				tp->t_dupacks = 0;
			}
			break;
		}
		/*
		 * If the congestion window was inflated to account
		 * for the other side's cached packets, retract it.
		 */
		if (tp->t_dupacks > tcprexmtthresh &&
		    tp->snd_cwnd > tp->snd_ssthresh) {
			tp->snd_cwnd = tp->snd_ssthresh;
		}
		tp->t_dupacks = 0;
		if (SEQ_GT(th->th_ack, tp->snd_max)) {
			tcpstat.tcps_rcvacktoomuch++;
			goto dropafterack;
		}
		acked = th->th_ack - tp->snd_una;
		tcpstat.tcps_rcvackpack++;
		tcpstat.tcps_rcvackbyte += acked;

		/*
		 * If we have a timestamp reply, update smoothed
		 * round trip time.  If no timestamp is present but
		 * transmit timer is running and timed sequence
		 * number was acked, update smoothed round trip time.
		 * Since we now have an rtt measurement, cancel the
		 * timer backoff (cf., Phil Karn's retransmit alg.).
		 * Recompute the initial retransmit timer.
		 */
		if (ts_present) {
			tcp_xmit_timer(tp, tcp_now - ts_ecr + 1);
		} else if (tp->t_rtt && SEQ_GT(th->th_ack, tp->t_rtseq)) {
			tcp_xmit_timer(tp, tp->t_rtt);
		}

		/*
		 * If all outstanding data is acked, stop retransmit
		 * timer and remember to restart (more output or persist).
		 * If there is more data to be acked, restart retransmit
		 * timer, using current (possibly backed-off) value.
		 */
		if (th->th_ack == tp->snd_max) {
			timer_cancel(tp->t_timer + TCPT_REXMT);
			needoutput = 1;
		} else if (!timer_is_running(tp->t_timer + TCPT_PERSIST))
			tcp_setslowtimer(tp, TCPT_REXMT, tp->t_rxtcur);
		/*
		 * When new data is acked, open the congestion window.
		 * If the window gives us less than ssthresh packets
		 * in flight, open exponentially (maxseg per packet).
		 * Otherwise open linearly: maxseg per window
		 * (maxseg^2 / cwnd per packet), plus a constant
		 * fraction of a packet (maxseg/8) to help larger windows
		 * open quickly enough.
		 */
		{
		u_int cw = tp->snd_cwnd;
		u_int incr = tp->t_maxseg;

		if (cw > tp->snd_ssthresh) {
			incr = incr * incr / cw + incr / 8;
		}
		tp->snd_cwnd = MIN(cw + incr, TCP_MAXWIN << tp->snd_scale);
		}
		if (acked > so->so_snd.sb_cc) {
			tp->snd_wnd -= so->so_snd.sb_cc;
			sbdrop(&so->so_snd, (int)so->so_snd.sb_cc);
			ourfinisacked = 1;
		} else {
			sbdrop(&so->so_snd, acked);
			tp->snd_wnd -= acked;
			ourfinisacked = 0;
		}
		sowakeup(so, POLLOUT);
		tp->snd_una = th->th_ack;
		if (SEQ_LT(tp->snd_nxt, tp->snd_una)) {
			tp->snd_nxt = tp->snd_una;
		}
		switch (tp->t_state) {

		/*
		 * In FIN_WAIT_1 STATE in addition to the processing
		 * for the ESTABLISHED state if our FIN is now acknowledged
		 * then enter FIN_WAIT_2.
		 */
		case GT_TCPS_FIN_WAIT_1:
			if (ourfinisacked) {
				/*
				 * If we can't receive any more
				 * data, then closing user can proceed.
				 * Starting the timer is contrary to the
				 * specification, but if we don't get a FIN
				 * we'll hang forever.
				 */
				if (so->so_state & SS_CANTRCVMORE) {
					soisdisconnected(so);
					tcp_settimer(tp, TCPT_2MSL, curmod->tcp_fin_timeout);
				}
				tp->t_state = GT_TCPS_FIN_WAIT_2;
			}
			break;

	 	/*
		 * In CLOSING STATE in addition to the processing for
		 * the ESTABLISHED state if the ACK acknowledges our FIN
		 * then enter the TIME-WAIT state, otherwise ignore
		 * the segment.
		 */
		case GT_TCPS_CLOSING:
			if (ourfinisacked) {
				if (!tcp_timewait(tp)) {
					goto drop;
				}
			}
			break;

		/*
		 * In LAST_ACK, we may still be waiting for data to drain
		 * and/or to be acked, as well as for the ack of our FIN.
		 * If our FIN is now acknowledged, delete the TCB,
		 * enter the closed state and return.
		 */
		case GT_TCPS_LAST_ACK:
			if (ourfinisacked) {
				tcp_close(tp);
				goto drop;
			}
			break;

		/*
		 * In TIME_WAIT state the only thing that should arrive
		 * is a retransmission of the remote FIN.  Acknowledge
		 * it and restart the finack timer.
		 */
		case GT_TCPS_TIME_WAIT:
			tcp_settimer(tp, TCPT_2MSL, curmod->tcp_time_wait_timeout);
			goto dropafterack;
		}
	}

step6:
	/*
	 * Update window information.
	 * Don't look at window if no ACK: TAC's send garbage on first SYN.
	 */
	if ((flags & GT_TCPF_ACK) &&
	    SEQ_LEQ(tp->snd_wl1, th->th_seq) &&
	    SEQ_LEQ(tp->snd_wl2, th->th_ack) &&
	    tiwin > tp->snd_wnd) {
		/* keep track of pure window updates */
		if (ip->ih_total_len == 0 && tp->snd_wl2 == th->th_ack) {
			tcpstat.tcps_rcvwinupd++;
		}
		tp->snd_wnd = tiwin;
		tp->snd_wl1 = th->th_seq;
		tp->snd_wl2 = th->th_ack;
		if (tp->snd_wnd > tp->max_sndwnd) {
			tp->max_sndwnd = tp->snd_wnd;
		}
		needoutput = 1;
	}

	/*
	 * If a FIN has already been received on this
	 * connection then we just ignore the text.
	 */
	if ((ip->ih_total_len || (flags & GT_TCPF_FIN)) &&
	    TCPS_HAVERCVDFIN(tp->t_state) == 0) {
		if (th->th_seq == tp->rcv_nxt) {
			if (tp->t_flags & TF_DELACK) {
				tcp_setdelacktimer(tp);
			} else {
				tp->t_flags &= ~TF_DELACK;
				timer_cancel(&tp->t_timer_delack);
				tp->t_flags |= TF_ACKNOW;
			}
			tp->rcv_nxt += ip->ih_total_len;
			flags = flags & GT_TCPF_FIN;
			tcpstat.tcps_rcvpack++;
			tcpstat.tcps_rcvbyte += ip->ih_total_len;
			if (ip->ih_total_len) {
				datlen = ip->ih_total_len;
				sbappend(&so->so_rcv, dat, datlen);
				sowakeup(so, POLLIN);
			}
		} else {
			tcpstat.tcps_rcvoopack++;
			tcpstat.tcps_rcvoobyte += ip->ih_total_len;
			tp->t_flags |= TF_ACKNOW;
		}
	} else {
		flags &= ~GT_TCPF_FIN;
	}

	/*
	 * If FIN is received ACK the FIN and let the user know
	 * that the connection is closing.
	 */
	if (flags & GT_TCPF_FIN) {
		if (TCPS_HAVERCVDFIN(tp->t_state) == 0) {
			socantrcvmore(so);
			tp->t_flags |= TF_ACKNOW;
			tp->rcv_nxt++;
		}
		switch (tp->t_state) {

	 	/*
		 * In SYN_RECEIVED and ESTABLISHED STATES
		 * enter the CLOSE_WAIT state.
		 */
		case GT_TCPS_SYN_RCVD:
		case GT_TCPS_ESTABLISHED:
			tp->t_state = GT_TCPS_CLOSE_WAIT;
			break;

	 	/*
		 * If still in FIN_WAIT_1 STATE FIN has not been acked so
		 * enter the CLOSING state.
		 */
		case GT_TCPS_FIN_WAIT_1:
			tp->t_state = GT_TCPS_CLOSING;
			break;

	 	/*
		 * In FIN_WAIT_2 state enter the TIME_WAIT state,
		 * starting the time-wait timer, turning off the other 
		 * standard timers.
		 */
		case GT_TCPS_FIN_WAIT_2:
			tcp_timewait(tp);
			break;

		/*
		 * In TIME_WAIT state restart the 2 MSL time_wait timer.
		 */
		case GT_TCPS_TIME_WAIT:
			tcp_settimer(tp, TCPT_2MSL, curmod->tcp_time_wait_timeout);
			break;
		}
	}
	/*
	 * Return any desired output.
	 */
	if (needoutput || (tp->t_flags & TF_ACKNOW)) {
		tcp_output(tp);
	}
	goto unref;

dropafterack:
	/*
	 * Generate an ACK dropping incoming segment if it occupies
	 * sequence space, where the ACK reflects our state.
	 */
	if (flags & GT_TCPF_RST) {
		goto drop;
	}
	tp->t_flags |= TF_ACKNOW;
	tcp_output(tp);
	goto unref;

dropwithreset:
	/*
	 * Generate a RST, dropping incoming segment.
	 * Make ACK acceptable to originator of segment.
	 * Don't bother to respond if destination was broadcast/multicast.
	 */
	/*if ((flags & GT_TCPF_RST) || (eth_flags & (M_MCAST|M_BCAST)) ||
	    IN_MULTICAST(ip->ip_dst.s_addr)) {
		goto drop;
	}*/
	if (flags & GT_TCPF_ACK) {
		tcp_respond(NULL, ip, th, 0, th->th_ack, GT_TCPF_RST);
	} else {
		if (flags & GT_TCPF_SYN) {
			ip->ih_total_len++;
		}
		tcp_respond(NULL, ip, th, th->th_seq + ip->ih_total_len, 0,
				GT_TCPF_RST|GT_TCPF_ACK);
	}

drop:
	/* destroy temporarily created socket */
	if (dropsocket) {
		tcpstat.tcps_badsyn++;
		tcp_drop(tp, ECONNABORTED);
		tcpstat.tcps_closed++; /* socket was temporary */
	}

unref:
	if (so != NULL) {
		if (so->so_options & SO_OPTION(SO_DEBUG)) {
			tcp_trace(TA_INPUT, ostate, tp, &save_ip, &save_th, 0);
		}
		if (so->so_events) {
			file_wakeup(&so->so_base.sobase_file, so->so_events);
			so->so_events = 0;
		}
		so->so_state &= ~SS_ISPROCESSING;
		sofree(so);
		if (again) {
			goto findpcb;
		}
	}

	return IN_OK;
}

/*
 * Determine a reasonable value for maxseg size.
 * We also initialize the congestion/slow start
 * window to be a single segment if the destination isn't local.
 * While looking at the routing entry, we also initialize other path-dependent
 * parameters from pre-set or cached values in the routing entry.
 */
int
tcp_mss(struct route_if *ifp, struct tcpcb *tp, u_int offer)
{
	int mss, mtu;
	u_long bufsize;
	struct socket *so;

	so = tcpcbtoso(tp);

	mtu = READ_ONCE(ifp->rif_mtu);
	mss = mtu - (sizeof(struct ip) + sizeof(struct tcp_hdr));
	/*
	 * The current mss, t_maxseg, is initialized to the default value.
	 * If we compute a smaller value, reduce the current mss.
	 * If we compute a larger value, return it for use in sending
	 * a max seg size option, but don't store it for use
	 * unless we received an offer at least that large from peer.
	 * However, do not accept offers under 32 bytes.
	 */
	if (offer)
		mss = MIN(mss, offer);
	mss = MAX(mss, 32);		/* sanity */
	if (mss < tp->t_maxseg || offer != 0) {
		/*
		 * If there's a pipesize, change the socket buffer
		 * to that size.  Make the socket buffers an integral
		 * number of mss units; if the mss is larger than
		 * the socket buffer, decrease the mss.
		 */
		bufsize = so->so_snd.sb_hiwat;
		if (bufsize < mss)
			mss = bufsize;
		else {
			bufsize = ROUND_UP(bufsize, mss);
			if (bufsize > SB_MAX)
				bufsize = SB_MAX;
			sbreserve(&so->so_snd, bufsize);
		}
		tp->t_maxseg = mss;
	}
	tp->snd_cwnd = mss;

	return mss;
}
