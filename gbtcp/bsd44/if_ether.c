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
		ip_input(ifp, (struct ip *)(eh + 1), len, eth_flags);
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
