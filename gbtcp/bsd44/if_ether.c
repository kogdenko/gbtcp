// SPDX-License-Identifier: BSD-4-Clause

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
		gt_arp_input((struct arphdr *)(eh + 1), len);
		break;
	default:
		break;
	}		
}
