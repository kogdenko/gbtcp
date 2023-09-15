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

/*
 * Ethernet address resolution protocol.
 */

#include "socket.h"
#include "ip.h"
#include "ip_var.h"
#include "if_ether.h"

u_char	etherbroadcastaddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/*
 * ARP trailer negotiation.  Trailer protocol is not IP specific,
 * but ARP request/response use IP addresses.
 */
#define ETHERTYPE_IPTRAILERS ETHERTYPE_TRAIL

/*
 * ARP for Internet protocols on 10 Mb/s Ethernet.
 * Algorithm is that given in RFC 826.
 * In addition, a sanity check is performed on the sender
 * protocol address, to catch impersonators.
 * We no longer handle negotiations for use of trailer protocol:
 * Formerly, ARP replied for protocol type ETHERTYPE_TRAIL sent
 * along with IP replies if we wanted trailers sent to us,
 * and also sent them in response to IP replies.
 * This allowed either end to announce the desire to receive
 * trailer packets.
 * We no longer reply to requests for ETHERTYPE_TRAIL protocol either,
 * but formerly didn't normally send requests.
 */
void
arp_input(struct arphdr *ar, int len)
{
	uint32_t ia;
	be32_t ian;
	struct ether_arp *ea;
	struct ether_header *eh;
	struct in_addr isaddr, itaddr, myaddr;
	int op;
	struct packet pkt;

	if (len >= sizeof(struct arphdr) &&
	    ntohs(ar->ar_hrd) == ARPHRD_ETHER &&
	    len >= sizeof(*ar) + 2 * ar->ar_hln + 2 * ar->ar_pln) {
		switch (ntohs(ar->ar_pro)) {
		case ETHERTYPE_IP:
		case ETHERTYPE_IPTRAILERS:
			goto in;
		default:
			break;
		}
	}
	return;
in:
	myaddr.s_addr = 0;
	ea = (struct ether_arp *)(ar);
	op = ntohs(ea->arp_op);
	memcpy(&isaddr, ea->arp_spa, sizeof(isaddr));
	memcpy(&itaddr, ea->arp_tpa, sizeof(itaddr));
	if (1) {
		myaddr = itaddr;
		goto reply; 	// Reply to all requetsts
	}
	for (ia = current->t_ip_laddr_min;
	     ia <= current->t_ip_laddr_max; ++ia) {
		ian = htonl(ia);
		if ((itaddr.s_addr == ian) || (isaddr.s_addr == ian)) {
			myaddr.s_addr = ian;
			break;
		}
	}
	if (myaddr.s_addr == 0) {
		goto out;
	}
	if (!memcmp(ea->arp_sha, current->t_eth_laddr, sizeof(ea->arp_sha))) {
		goto out;	/* it's from me, ignore it. */
	}
	if (!memcmp(ea->arp_sha, etherbroadcastaddr, sizeof(ea->arp_sha))) {
		printf(
		    "arp: ether address is broadcast for IP address %x!\n",
		    ntohl(isaddr.s_addr));
		goto out;
	}
	if (isaddr.s_addr == myaddr.s_addr) {
		printf(
		   "duplicate IP address %x!! sent from ethernet address: %s\n",
		   ntohl(isaddr.s_addr), ether_sprintf(ea->arp_sha));
		itaddr = myaddr;
		goto reply;
	}
reply:
	if (op != ARPOP_REQUEST) {
out:
		return;
	}
	if (itaddr.s_addr == myaddr.s_addr) {
		/* I am the target */
		memcpy(ea->arp_tha, ea->arp_sha, sizeof(ea->arp_sha));
		memcpy(ea->arp_sha, current->t_eth_laddr, sizeof(ea->arp_sha));
	} else {
		goto out;
	}
	memcpy(ea->arp_tpa, ea->arp_spa, sizeof(ea->arp_spa));
	memcpy(ea->arp_spa, &itaddr, sizeof(ea->arp_spa));
	ea->arp_op = htons(ARPOP_REPLY);
	ea->arp_pro = htons(ETHERTYPE_IP); /* let's be sure! */
	io_init_tx_packet(&pkt);
	pkt.pkt.len = sizeof(*eh) +  sizeof(*ea);
	eh = (struct ether_header *)pkt.pkt.buf;
	memcpy(eh + 1, ea, sizeof(*ea));
	memcpy(eh->ether_shost, current->t_eth_laddr, sizeof(eh->ether_shost));
	memcpy(eh->ether_dhost, ea->arp_tha, sizeof(eh->ether_dhost));
	eh->ether_type = htons(ETHERTYPE_ARP);
	io_tx_packet(&pkt);
}

/* Process a received Ethernet packet; */
void
gt_bsd_rx(struct route_if *ifp, void *data, int len)
{
	int eth_flags;
	struct ether_header *eh;

	eh = data;
	eth_flags = 0;
	len -= sizeof(*eh);
	if (memcmp(etherbroadcastaddr, eh->ether_dhost, sizeof(etherbroadcastaddr)) == 0) {
		eth_flags |= M_BCAST;
	} else if (eh->ether_dhost[0] & 1) {
		eth_flags |= M_MCAST;
	}
	NTOHS(eh->ether_type);
	switch (eh->ether_type) {
	case ETHERTYPE_IP:
		ip_input((struct ip *)(eh + 1), len, eth_flags);
		break;
	case ETHERTYPE_ARP:
		arp_input((struct arphdr *)(eh + 1), len);
		break;
	default:
		break;
	}		
}

/*
 * Convert Ethernet address to printable (loggable) representation.
 */
static char digits[] = "0123456789abcdef";
char *
ether_sprintf(u_char *ap)
{
	int i;
	static char etherbuf[18];
	char *cp = etherbuf;

	for (i = 0; i < 6; i++) {
		*cp++ = digits[*ap >> 4];
		*cp++ = digits[*ap++ & 0xf];
		*cp++ = ':';
	}
	*--cp = 0;
	return (etherbuf);
}

int
ether_scanf(u_char *ap, const char *s)
{
	int rc;

	rc = sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	            ap + 0, ap + 1, ap + 2, ap + 3, ap + 4, ap + 5);
	return rc == 6 ? 0 : -EINVAL;
}
