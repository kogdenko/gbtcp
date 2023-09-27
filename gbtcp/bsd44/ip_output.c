// SPDX-License-Identifier: BSD-4-Clause

#include "socket.h"
#include "ip.h"
#include "in_pcb.h"
#include "ip_var.h"
//#include "if_ether.h"

static uint16_t ip_id;				/* ip packet ctr, for ids */

int
ip_output(struct route_entry *r, struct dev_pkt *pkt, struct ip4_hdr *ip)
{
	pkt->pkt_len = sizeof(struct eth_hdr) + ip->ih_total_len;
	
	// Fill in IP header.
	ip->ih_ver_ihl = IP4_VER_IHL;
	ip->ih_frag_off = IP_DF;
	ip->ih_id = htons(ip_id++);
	ip->ih_ttl = IPDEFTTL;
	ip->ih_tos = 0;
	ipstat.ips_localout++;
	assert((u_short)ip->ih_total_len <= r->rt_ifp->rif_mtu);
	ip->ih_total_len = htons((u_short)ip->ih_total_len);
	ip->ih_frag_off = htons((u_short)ip->ih_frag_off);
	ip->ih_cksum = 0;

	ip4_set_cksum(ip, ip + 1);

	arp_resolve(r, pkt);
	return 0;
}
