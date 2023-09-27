
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
tcp_template(struct socket *so, struct ip4_hdr *ip, struct tcp_hdr *th)
{
	ip->ih_ver_ihl = IP4_VER_IHL;
	ip->ih_total_len = htons(sizeof(struct tcp_hdr));
	ip->ih_id = 0;
	ip->ih_frag_off = 0;
	ip->ih_proto = IPPROTO_TCP;
	ip->ih_cksum = 0;
	if (so != NULL) {	
		ip->ih_saddr = so->so_base.sobase_laddr;
		ip->ih_daddr = so->so_base.sobase_faddr;
		th->th_sport = so->so_base.sobase_lport;
		th->th_dport = so->so_base.sobase_fport;
	}
	th->th_seq = 0;
	th->th_ack = 0;
	th->th_data_off = 5;
	th->th_flags = 0;
	th->th_win_size = 0;
	th->th_cksum = 0;
	th->th_urgent_ptr = 0;
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
tcp_respond(struct socket *so, struct ip4_hdr *ip_rcv, struct tcp_hdr *th_rcv,
		tcp_seq ack, tcp_seq seq, int flags)
{
	int rc, win;
	be32_t laddr, faddr;
	struct ip4_hdr *ip;
	struct tcp_hdr *th;
	struct tcpcb *tp;
	struct dev_pkt pkt;
	struct route_entry r;

	if (so == NULL) {
		laddr = ip_rcv->ih_daddr;
		faddr = ip_rcv->ih_saddr;
	} else {
		laddr = so->so_base.sobase_laddr;
		faddr = so->so_base.sobase_faddr;
	}

	rc = gt_so_route(laddr, faddr, &r);
	if (rc) {
		return;
	}
	rc = route_get_tx_packet(r.rt_ifp, &pkt, TX_CAN_REDIRECT);
	if (rc) {
		return;
	}

	ip = (struct ip4_hdr *)(pkt.pkt_data + sizeof(struct ether_header));
	th = (struct tcp_hdr *)(ip + 1);
	tcp_template(so, ip, th);
	if (so == NULL) {
		assert(ip_rcv != NULL && th_rcv != NULL);
		ip->ih_saddr = ip_rcv->ih_daddr;
		ip->ih_daddr = ip_rcv->ih_saddr;
		th->th_sport = th_rcv->th_dport;
		th->th_dport = th_rcv->th_sport;
	}
	th->th_seq = htonl(seq);
	th->th_ack = htonl(ack);
	th->th_flags = flags ? flags : GT_TCPF_ACK;
	if (so == NULL) {
		th->th_win_size = 0;
	} else {
		tp = sototcpcb(so);
		win = so->so_rcv_hiwat;
		th->th_win_size = htons((u_short)(win >> tp->rcv_scale));
	}
	ip->ih_total_len = sizeof(*ip) + sizeof(*th);
	th->th_cksum = 0;
	ip_output(&r, &pkt, ip);
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
	if (1) {//(current->t_tcp_do_wscale) {
		tp->t_flags |= TF_REQ_SCALE;
	}
	if (1) { //(current->t_tcp_do_timestamps) {
		tp->t_flags |= TF_REQ_TSTMP;
	}
	/*
	 * Init srtt to TCPTV_SRTTBASE (0), so we can tell that we have no
	 * rtt estimate.  Set rttvar so that srtt + 2 * rttvar gives
	 * reasonable initial retransmit time.
	 */
	tp->t_srtt = TCPTV_SRTTBASE;
	tp->t_rttvar = TCPTV_SRTTDFLT / PR_SLOWHZ * PR_SLOWHZ << 2;
	TCPT_RANGESET(tp->t_rxtcur, 
	    ((TCPTV_SRTTBASE >> 2) + (TCPTV_SRTTDFLT << 2)) >> 1,
	    TCPTV_MIN, TCPTV_REXMTMAX);
	tp->snd_cwnd = TCP_MAXWIN << TCP_MAX_WINSHIFT;
	tp->snd_ssthresh = TCP_MAXWIN << TCP_MAX_WINSHIFT;
	tp->t_state = GT_TCPS_CLOSED;
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
		tp->t_state = GT_TCPS_CLOSED;
		tcp_output(tp);
		tcpstat.tcps_drops++;
	} else {
		tcpstat.tcps_conndrops++;
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
	tp->t_state = GT_TCPS_CLOSED;
	tcp_canceltimers(tp);
	soisdisconnected(so);
	/* clobber input pcb cache if we're closing the cached connection */
	in_pcbdetach(so);
	tcpstat.tcps_closed++;
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
	if (tp->t_state == GT_TCPS_ESTABLISHED &&
			(error == EHOSTUNREACH ||
			error == ENETUNREACH ||
			error == EHOSTDOWN)) {
		return;
	} else if (tp->t_state == GT_TCPS_CLOSED ||
	           tp->t_state == GT_TCPS_SYN_SENT ||
	           tp->t_state == GT_TCPS_SYN_RCVD) {
		so->so_error = error;
	} else {
		tp->t_softerror = error;
	}
	sowakeup(so, POLLERR);
}

void
tcp_ctlinput(int err, int quench, be32_t dst, struct ip4_hdr *ip)
{
	struct tcp_hdr *th;
	void (*notify)(struct socket *, int);

	notify = tcp_notify;
	if (quench) {
		notify = tcp_quench;
	} else if (err == 0) {
		return;
	}
	th = (struct tcp_hdr *)((u_char *)ip + IP4_HDR_LEN(ip->ih_ver_ihl));
	in_pcbnotify(IPPROTO_TCP, ip->ih_saddr, th->th_sport, dst, th->th_dport, err, notify);
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
