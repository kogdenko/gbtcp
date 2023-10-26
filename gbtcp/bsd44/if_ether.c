// SPDX-License-Identifier: BSD-4-Clause

#include "socket.h"
#include "ip.h"
#include "ip_var.h"

// Process a received Ethernet packet
int
gt_bsd44_so_rx(struct route_if *ifp, void *data, int len)
{
	int rc;
	int eth_flags;
	struct eth_hdr *eh;

	eh = data;
	eth_flags = 0;

	len -= sizeof(*eh);
	if (eth_addr_is_bcast(eh->eh_daddr.ea_bytes)) {
		eth_flags |= M_BCAST;
	} else if (eth_addr_is_mcast(eh->eh_daddr.ea_bytes)) {
		eth_flags |= M_MCAST;
	}

	NTOHS(eh->eh_type);
	switch (eh->eh_type) {
	case ETH_TYPE_IP4:
		rc = ip_input(ifp, (struct ip4_hdr *)(eh + 1), len, eth_flags);
		break;

	case ETH_TYPE_ARP:
		rc = gt_arp_input(ifp, (eh + 1), len);
		break;

	default:
		rc = IN_BYPASS;
	}

	return rc;	
}
