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
#include "ip_var.h"
#include "ip_icmp.h"
#include "tcp_var.h"
#include "udp_var.h"
#include "icmp_var.h"
#include "if_ether.h"

/*
 * ICMP routines: error generation, receive packet processing, and
 * routines to turnaround packets back to the originator, and
 * host table maintenance routines.
 */

int icmpprintfs = 0;

static be32_t
icmp_reflectsrc(be32_t dst)
{
	uint32_t ia;

	for (ia = current->t_ip_laddr_min;
	     ia <= current->t_ip_laddr_max; ++ia) {
		if (dst == htonl(ia)) {
			return dst;
		}
	}
	return htonl(current->t_ip_laddr_min);
}

// Send an icmp packet back to the ip level,
// after supplying a checksum.
void
icmp_send(struct packet *pkt, struct ip *ip)
{
	struct icmp *icp;

	if (icmpprintfs) {
		printf("icmp_send dst %x src %x\n", ip->ip_dst.s_addr, ip->ip_src.s_addr);
	}
	icp = (struct icmp *)(ip + 1);
	icp->icmp_cksum = 0;
	icp->icmp_cksum = in_cksum(icp, ip->ip_len - sizeof(*ip));

	ip_output(pkt, ip);
}

// Generate an error packet of type error
// in response to bad packet ip.
void
icmp_error(struct ip *oip, int type, int code, be32_t dest)
{
	struct ip *eip, *nip;
	unsigned oiplen;
	struct icmp *icp;
	unsigned icmplen;
	be32_t t;
	struct packet pkt;

	oiplen = oip->ip_hl << 2;

	if (icmpprintfs) {
		printf("icmp_error(%d, %d)\n", type, code);
	}

	if (type != ICMP_REDIRECT) {
		counter64_inc(&icmpstat.icps_error);
	}
	/*
	 * Don't send error if not the first fragment of message.
	 * Don't error if the old packet protocol was ICMP
	 * error message, only known informational types.
	 */
	if (oip->ip_off &~ (IP_MF|IP_DF)) {
		return;
	}
	/*
	 * First, formulate icmp message
	 */
	io_init_tx_packet(&pkt);
	nip = (struct ip *)(pkt.pkt.buf + sizeof(struct ether_header));
	icmplen = oiplen + MIN(8, oip->ip_len);
	icp = (struct icmp *)(nip + 1);
	if ((u_int)type > ICMP_MAXTYPE) {
		panic(0, "icmp_error");
	}
	counter64_inc(icmpstat.icps_outhist + type);
	icp->icmp_type = type;
	if (type == ICMP_REDIRECT) {
		icp->icmp_gwaddr.s_addr = dest;
	} else {
		icp->icmp_void = 0;
		// The following assignments assume an overlay with the
		// zeroed icmp_void field.
		if (type == ICMP_PARAMPROB) {
			icp->icmp_pptr = code;
			code = 0;
		} else if (type == ICMP_UNREACH &&
			code == ICMP_UNREACH_NEEDFRAG) {
			icp->icmp_nextmtu = htons(current->t_mtu);
		}
	}

	icp->icmp_code = code;
	eip = &icp->icmp_ip;
	memcpy(eip, oip, icmplen);
	eip->ip_len = htons((u_short)(eip->ip_len + oiplen));

	// Now, copy old ip header (without options)
	// in front of icmp message.
	memcpy(nip, oip, sizeof(struct ip));
	t = nip->ip_dst.s_addr;
	nip->ip_dst = nip->ip_src;
	nip->ip_src.s_addr = icmp_reflectsrc(t);
	nip->ip_len = sizeof(*nip) + icmplen + ICMP_MINLEN;
	nip->ip_hl = sizeof(struct ip) >> 2;
	nip->ip_p = IPPROTO_ICMP;
	nip->ip_tos = 0;
	nip->ip_ttl = MAXTTL;
	icmp_send(&pkt, nip);
}

/*
 * Process a received ICMP message.
 */
void
icmp_input(struct ip *ip, int hlen)
{
	struct icmp *icp;
	be32_t icmpsrc;
	int icmplen, icmp_cksum;
	int i, code, err, quench;

	err = 0;
	quench = 0;
	icmplen = ip->ip_len;

	if (icmpprintfs) {
		printf("icmp_input from %x to %x, len %d\n",
			ntohl(ip->ip_src.s_addr), ntohl(ip->ip_dst.s_addr),
			icmplen);
	}
	if (icmplen < ICMP_MINLEN) {
		counter64_inc(&icmpstat.icps_tooshort);
		return;
	}
	i = MIN(icmplen, ICMP_ADVLENMIN);
	if (ip->ip_len < i)  {
		counter64_inc(&icmpstat.icps_tooshort);
		return;
	}
	icp = (struct icmp *)((u_char *)ip + hlen);
	icmp_cksum = icp->icmp_cksum;
	icp->icmp_cksum = 0;
	icp->icmp_cksum = in_cksum(icp, icmplen);
	if (icp->icmp_cksum != icmp_cksum) {
		counter64_inc(&icmpstat.icps_checksum);
		return;
	}

	/*
	 * Message type specific processing.
	 */
	if (icmpprintfs) {
		printf("icmp_input, type %d code %d\n", icp->icmp_type,
		       icp->icmp_code);
	}
	if (icp->icmp_type > ICMP_MAXTYPE) {
		return;
	}
	counter64_inc(icmpstat.icps_inhist + icp->icmp_type);
	code = icp->icmp_code;
	switch (icp->icmp_type) {

	case ICMP_UNREACH:
		switch (code) {
			case ICMP_UNREACH_NET:
			case ICMP_UNREACH_HOST:
			case ICMP_UNREACH_PROTOCOL:
			case ICMP_UNREACH_PORT:
			case ICMP_UNREACH_SRCFAIL:
			case ICMP_UNREACH_NET_UNKNOWN:
			case ICMP_UNREACH_NET_PROHIB:
			case ICMP_UNREACH_TOSNET:
			case ICMP_UNREACH_HOST_UNKNOWN:
			case ICMP_UNREACH_ISOLATED:
			case ICMP_UNREACH_HOST_PROHIB:
			case ICMP_UNREACH_TOSHOST:
				err = EHOSTUNREACH;
				break;
			case ICMP_UNREACH_NEEDFRAG:
				err = EMSGSIZE;
				break;
			default:
				goto badcode;
		}
		goto deliver;

	case ICMP_TIMXCEED:
		if (code > 1) {
			goto badcode;
		}
		goto deliver;

	case ICMP_PARAMPROB:
		if (code > 1) {
			goto badcode;
		}
		err = ENOPROTOOPT;
		goto deliver;

	case ICMP_SOURCEQUENCH:
		if (code) {
			goto badcode;
		}
		quench = 1;
deliver:
		/*
		 * Problem with datagram; advise higher level routines.
		 */
		if (icmplen < ICMP_ADVLENMIN || icmplen < ICMP_ADVLEN(icp) ||
		    icp->icmp_ip.ip_hl < (sizeof(struct ip) >> 2)) {
			counter64_inc(&icmpstat.icps_badlen);
			return;
		}
		NTOHS(icp->icmp_ip.ip_len);
		if (icmpprintfs) {
			printf("deliver to protocol %d, err=%d\n",
			       icp->icmp_ip.ip_p, err);
		}
		icmpsrc = icp->icmp_ip.ip_dst.s_addr;
		switch (icp->icmp_ip.ip_p) {
		case IPPROTO_TCP:
			tcp_ctlinput(err, quench, icmpsrc, &icp->icmp_ip);
			break;
		case IPPROTO_UDP:
			udp_ctlinput(err, icmpsrc, &icp->icmp_ip);
			break;
		default:
			break;
		}
		break;

	badcode:
		counter64_inc(&icmpstat.icps_badcode);
		break;

	case ICMP_ECHO:
		icp->icmp_type = ICMP_ECHOREPLY;
		ip->ip_len += hlen;     /* since ip_input deducts this */
		counter64_inc(&icmpstat.icps_reflect);
		counter64_inc(icmpstat.icps_outhist + icp->icmp_type);
		icmp_reflect(ip);
		return;

	case ICMP_REDIRECT:
		if (code > 3) {
			goto badcode;
		}
		if (icmplen < ICMP_ADVLENMIN || icmplen < ICMP_ADVLEN(icp) ||
		    icp->icmp_ip.ip_hl < (sizeof(struct ip) >> 2)) {
			counter64_inc(&icmpstat.icps_badlen);
			break;
		}
		/*
		 * Short circuit routing redirects to force
		 * immediate change in the kernel's routing
		 * tables.  The message is also handed to anyone
		 * listening on a raw socket (e.g. the routing
		 * daemon for use in updating its tables).
		 */
		if (icmpprintfs) {
			printf("redirect dst %x to %x\n", icp->icmp_ip.ip_dst.s_addr,
				icp->icmp_gwaddr.s_addr);
		}
		break;

	/*
	 * No kernel processing for the following;
	 * just fall through to send to raw listener.
	 */
	case ICMP_ECHOREPLY:
	case ICMP_ROUTERADVERT:
	case ICMP_ROUTERSOLICIT:
	case ICMP_TSTAMPREPLY:
	case ICMP_IREQREPLY:
	case ICMP_MASKREPLY:
	default:
		break;
	}
}

/*
 * Reflect the ip packet back to the source
 */
void
icmp_reflect(struct ip *ip)
{
	be32_t t;
	int optlen, hlen;
	struct ip *nip;
	struct packet pkt;

	io_init_tx_packet(&pkt);
	hlen = (ip->ip_hl << 2);
	optlen = hlen - sizeof(*ip);
	nip = (struct ip *)(pkt.pkt.buf + sizeof(struct ether_header));
	memcpy(nip, ip, sizeof(*ip));
	memcpy(nip + 1, ((u_char *)ip) + hlen, ip->ip_len - hlen);

	t = nip->ip_dst.s_addr;
	nip->ip_dst = ip->ip_src;
	nip->ip_src.s_addr = icmp_reflectsrc(t);
	nip->ip_hl = sizeof(*nip) >> 2;
	nip->ip_ttl = MAXTTL;
	nip->ip_len -= optlen;

	icmp_send(&pkt, nip);
}
