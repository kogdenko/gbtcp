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

#include "types.h"
#include "socket.h"
#include "ip.h"
#include "in_pcb.h"
#include "ip_var.h"
#include "ip_icmp.h"
#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_var.h"
#include "if_ether.h"

/*
 * Create template to be used to send tcp packets on a connection.
 * Call after host entry created, allocates an mbuf and fills
 * in a skeletal tcp/ip header, minimizing the amount of work
 * necessary when the connection is used.
 */
void
tcp_template(struct tcpcb *tp, struct ip *ip, struct bsd_tcp_hdr *th)
{
	struct socket *so;

	ip->ip_hl = sizeof(struct ip) >> 2;
	ip->ip_v = 4;
	ip->ip_len = htons(sizeof(struct bsd_tcp_hdr));
	ip->ip_id = 0;
	ip->ip_off = 0;
	ip->ip_p = IPPROTO_TCP;
	ip->ip_sum = 0;
	if (tp != NULL) {
		so = tcpcbtoso(tp);
		ip->ip_src.s_addr = so->inp_laddr;
		ip->ip_dst.s_addr = so->inp_faddr;
		th->th_sport = so->inp_lport;
		th->th_dport = so->inp_fport;
	}
	th->th_seq = 0;
	th->th_ack = 0;
	th->th_x2 = 0;
	th->th_off = 5;
	th->th_flags = 0;
	th->th_win = 0;
	th->th_sum = 0;
	th->th_urp = 0;
}

/*
 * Send a single message to the TCP at address specified by
 * the given TCP/IP header.  If m == 0, then we make a copy
 * of the tcpiphdr at ti and send directly to the addressed host.
 * This is used to force keep alive messages out using the TCP
 * template for a connection tp->t_template.  If flags are given
 * then we send a message back to the TCP which originated the
 * segment ti, and discard the mbuf containing it and any other
 * attached mbufs.
 *
 * In any case the ack and sequence number of the transmitted
 * segment are as specified by the parameters.
 */
void
tcp_respond(struct tcpcb *tp, struct ip *ip_rcv, struct bsd_tcp_hdr *th_rcv,
		tcp_seq ack, tcp_seq seq, int flags)
{
	int win;
	struct ip *ip;
	struct bsd_tcp_hdr *th;
	struct packet pkt;

	io_init_tx_packet(&pkt);
	ip = (struct ip *)(pkt.pkt.buf + sizeof(struct ether_header));
	th = (struct bsd_tcp_hdr *)(ip + 1);
	tcp_template(tp, ip, th);
	if (tp == NULL) {
		assert(ip_rcv != NULL && th_rcv != NULL);
		ip->ip_src = ip_rcv->ip_dst;
		ip->ip_dst = ip_rcv->ip_src;
		th->th_sport = th_rcv->th_dport;
		th->th_dport = th_rcv->th_sport;
	}
	th->th_seq = htonl(seq);
	th->th_ack = htonl(ack);
	th->th_flags = flags ? flags : TH_ACK;
	if (tp == NULL) {
		th->th_win = 0;
	} else {
		win = tcpcbtoso(tp)->so_rcv_hiwat;
		th->th_win = htons((u_short)(win >> tp->rcv_scale));
	}
	ip->ip_len = sizeof(*ip) + sizeof(*th);
	th->th_sum = tcp_cksum(ip, sizeof(*th));
	ip_output(&pkt, ip);
}

/*
 * Create a new TCP control block, making an
 * empty reassembly queue and hooking it to the argument
 * protocol control block.
 */
void
tcp_attach(struct socket *so)
{
	struct tcpcb *tp;

	tp = sototcpcb(so);
	memset(tp, 0, sizeof(*tp));
	tp->t_maxseg = TCP_MSS;
	tp->t_flags = 0;
	if (current->t_tcp_do_wscale) {
		tp->t_flags |= TF_REQ_SCALE;
	}
	if (current->t_tcp_do_timestamps) {
		tp->t_flags |= TF_REQ_TSTMP;
	}
	/*
	 * Init srtt to TCPTV_SRTTBASE (0), so we can tell that we have no
	 * rtt estimate.  Set rttvar so that srtt + 2 * rttvar gives
	 * reasonable initial retransmit time.
	 */
	tp->t_srtt = TCPTV_SRTTBASE;
	tp->t_rttvar = current->t_tcp_rttdflt * PR_SLOWHZ << 2;
	TCPT_RANGESET(tp->t_rxtcur, 
	    ((TCPTV_SRTTBASE >> 2) + (TCPTV_SRTTDFLT << 2)) >> 1,
	    TCPTV_MIN, TCPTV_REXMTMAX);
	tp->snd_cwnd = TCP_MAXWIN << TCP_MAX_WINSHIFT;
	tp->snd_ssthresh = TCP_MAXWIN << TCP_MAX_WINSHIFT;
	tp->t_state = TCPS_CLOSED;
}

/*
 * Drop a TCP connection, reporting
 * the specified error.  If connection is synchronized,
 * then send a RST to peer.
 */
struct tcpcb *
tcp_drop(struct tcpcb *tp, int e)
{
	struct socket *so;

	so = tcpcbtoso(tp);
	if (TCPS_HAVERCVDSYN(tp->t_state)) {
		tp->t_state = TCPS_CLOSED;
		tcp_output(tp);
		counter64_inc(&tcpstat.tcps_drops);
	} else {
		counter64_inc(&tcpstat.tcps_conndrops);
	}
	if (e == ETIMEDOUT && tp->t_softerror) {
		e = tp->t_softerror;
	}
	so->so_error = e;
	return tcp_close(tp);
}

/*
 * Close a TCP control block:
 *	discard all space held by the tcp
 *	discard internet protocol block
 *	wake up any sleepers
 */
struct tcpcb *
tcp_close(struct tcpcb *tp)
{
	struct socket *so;

	so = tcpcbtoso(tp);
	tp->t_state = TCPS_CLOSED;
	tcp_canceltimers(tp);
	soisdisconnected(so);
	/* clobber input pcb cache if we're closing the cached connection */
	in_pcbdetach(so);
	counter64_inc(&tcpstat.tcps_closed);
	return NULL;
}

/*
 * Notify a tcp user of an asynchronous error;
 * store error as soft error, but wake up user
 * (for now, won't do anything until can select for soft error).
 */
void
tcp_notify(struct socket *so, int error)
{
	struct tcpcb *tp;

	tp = sototcpcb(so);

	/*
	 * Ignore some errors if we are hooked up.
	 * If connection hasn't completed, has retransmitted several times,
	 * and receives a second error, give up now.  This is better
	 * than waiting a long time to establish a connection that
	 * can never complete.
	 */
	if (tp->t_state == TCPS_ESTABLISHED &&
			(error == EHOSTUNREACH ||
			error == ENETUNREACH ||
			error == EHOSTDOWN)) {
		return;
	} else if (tp->t_state < TCPS_ESTABLISHED) {
		so->so_error = error;
	} else {
		tp->t_softerror = error;
	}
	sowakeup(so, POLLERR, NULL, NULL, 0);
}

void
tcp_ctlinput(int err, int quench, be32_t dst, struct ip *ip)
{
	struct bsd_tcp_hdr *th;
	void (*notify)(struct socket *, int);

	notify = tcp_notify;
	if (quench) {
		notify = tcp_quench;
	} else if (err == 0) {
		return;
	}
	th = (struct bsd_tcp_hdr *)((u_char *)ip + (ip->ip_hl << 2));
	in_pcbnotify(IPPROTO_TCP, ip->ip_src.s_addr, th->th_sport,
		dst, th->th_dport, err, notify);
}

/*
 * When a source quench is received, close congestion window
 * to one segment.  We will gradually open it again as we proceed.
 */
void
tcp_quench(struct socket *so, int e)
{
	struct tcpcb *tp;

	tp = sototcpcb(so);
	tp->snd_cwnd = tp->t_maxseg;
}
