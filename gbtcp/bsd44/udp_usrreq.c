// SPDX-License-Identifier: LGPL-2.1-only

#include "socket.h"
#include "ip.h"
#include "in_pcb.h"
#include "ip_var.h"
#include "ip_icmp.h"
#include "udp_var.h"

// UDP protocol implementation.
// Per RFC 768, August, 1980.
int udpcksum = 1;

static	void udp_notify(struct socket *, int);

int
udp_input(struct ip4_hdr *ip, int iphlen, int eth_flags)
{
	struct udp_hdr *uh;
	struct socket *so;
	int len, uh_sum;
	struct	sockaddr_in udp_in;
	struct ip4_hdr save_ip;

	udpstat.udps_ipackets++;

	// Get IP and UDP header together in first mbuf.
	if (ip->ih_total_len < sizeof(struct udp_hdr)) {
		udpstat.udps_hdrops++;
		return IN_OK;
	}
	uh = (struct udp_hdr *)((u_char *)ip + iphlen);

	// Make mbuf data length reflect UDP length.
	// If not enough data to reflect UDP length, drop.
	len = ntohs((u_short)uh->uh_len);
	if (ip->ih_total_len != len) {
		if (len > ip->ih_total_len) {
			udpstat.udps_badlen++;
			return IN_OK;
		}
	}

	// Save a copy of the IP header in case we want restore it
	// for sending an ICMP error message in response.
	save_ip = *ip;

	// Checksum extended UDP header and data.
	if (!gt_udp_validate_cksum(ip, uh, ip->ih_total_len)) {
		udpstat.udps_badsum++;
		return IN_OK;
	}

	// Locate pcb for datagram.
	rc = in_pcblookup(&so, IPPROTO_UDP,
		ip->ih_daddr, ip->ih_saddr, uh->uh_dport, uh->uh_sport);
	if (rc >= 0) {
		return rc;
	}
	if (so == NULL) {
		udpstat.udps_noport++;
		if (eth_flags & (M_BCAST|M_MCAST)) {
			udpstat.udps_noportbcast++;
		} else {
			*ip = save_ip;
			ip->ih_total_len += iphlen;
			icmp_error(ip, ICMP_UNREACH, ICMP_UNREACH_PORT, 0);
		}
		return IN_OK;
	}

	sbappend(&so->so_rcv, uh + 1, ip->ih_total_len - sizeof(*uh));
	sowakeup(so, POLLIN);
}

// Notify a udp user of an asynchronous error;
// just wake up so that he can collect error status.
static void
udp_notify(struct socket *so, int e)
{
	so->so_error = e;
	sowakeup2(so, POLLERR);
}

void
udp_ctlinput(int err, be32_t dst, struct ip *ip)
{
	struct bsd_udp_hdr *uh;

	if (err == 0) {
		return;
	}
	uh = (struct bsd_udp_hdr *)((u_char *)ip + (ip->ip_hl << 2));
	in_pcbnotify(IPPROTO_UDP, ip->ip_src.s_addr, uh->uh_sport,
			dst, uh->uh_dport, err, udp_notify);
}

int
udp_output(struct socket *so, const void *dat, int len,	const struct sockaddr_in *addr)
{
	int rc;
	struct ip *ip;
	struct bsd_udp_hdr *uh;
	struct packet pkt;

	if (sizeof(*ip) + sizeof(*uh) + len > current->t_mtu) {
		return -EMSGSIZE;
	}

//	if (addr != NULL) {
//		rc = in_pcbconnect(so, addr, &h);
//		if (rc) {
//			return rc;	
//		}
//	} else {
	if (so->inp_faddr == INADDR_ANY) {
		rc = in_pcbconnect(so, NULL);
		if (rc) {
			return rc;
		}
	}
//	}
	io_init_tx_packet(&pkt);
	//if (pkt == NULL) {
	//	return -ENOBUFS;
	//}
	ip = (struct ip *)(pkt.pkt.buf + sizeof(struct ether_header));
	uh = (struct bsd_udp_hdr *)(ip + 1);

	ip->ip_len = sizeof(*ip) + sizeof(*uh) + len;
	ip->ip_p = IPPROTO_UDP;
	ip->ip_hl = sizeof(*ip) >> 2;
	ip->ip_src.s_addr = so->inp_laddr;
	ip->ip_dst.s_addr = so->inp_faddr;

	uh->uh_sport = so->inp_lport;
	uh->uh_dport = so->inp_fport;
	uh->uh_ulen = htons(sizeof(*uh) + len);

	memcpy(uh + 1, dat, len);

	// Stuff checksum and output datagram.
	uh->uh_sum = 0;
	if (udpcksum) {
		uh->uh_sum = udp_cksum(ip, sizeof(*uh) + len);
	}
	udpstat.udps_opackets++;
	ip_output(&pkt, ip);
//	if (addr) {
//		in_pcbdisconnect(so);
//	}
	return 0; // ?????
}

int
udp_connect(struct socket *so)
{
	int rc;

	rc = in_pcbconnect(so, NULL);
	if (rc == 0) {
		soisconnected(so);
	}
	return rc;
}

int
udp_send(struct socket *so, const void *dat, int datlen, const struct sockaddr_in *addr)
{
	return udp_output(so, dat, datlen, addr);
}

int
udp_disconnect(struct socket *so)
{
	if (so->inp_faddr == INADDR_ANY) {
		return ENOTCONN;
	}
	soisdisconnected(so);
	udp_detach(so);
	return 0;
}

void
udp_shutdown(struct socket *so)
{
	socantsendmore(so);
}

void
udp_detach(struct socket *so)
{
	in_pcbdetach(so);
}

void
udp_abort(struct socket *so)
{
	soisdisconnected(so);
	udp_detach(so);
}
