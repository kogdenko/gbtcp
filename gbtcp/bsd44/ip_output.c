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

#include "socket.h"
#include "ip.h"
#include "in_pcb.h"
#include "ip_var.h"
//#include "if_ether.h"

static uint16_t ip_id;				/* ip packet ctr, for ids */

int
ip_output(struct packet *pkt, struct ip *ip)
{
	int rc;
	struct ether_header *eh;

	pkt->pkt.len = sizeof(struct ether_header) + ip->ip_len;
	
	// Fill in IP header.
	ip->ip_v = IPVERSION;
	ip->ip_off = IP_DF;
	ip->ip_id = htons(ip_id++);
	ip->ip_ttl = IPDEFTTL;
	ip->ip_tos = 0;
	ip->ip_hl = sizeof(*ip) >> 2;
	counter64_inc(&ipstat.ips_localout);
	assert((u_short)ip->ip_len <= current->t_mtu);
	ip->ip_len = htons((u_short)ip->ip_len);
	ip->ip_off = htons((u_short)ip->ip_off);
	ip->ip_sum = 0;
	if (current->t_ip_do_outcksum) {
		ip->ip_sum = ip_cksum(ip);
	}
	eh = ((struct ether_header *)ip) - 1;
	eh->ether_type = htons(ETHERTYPE_IP);
 	memcpy(eh->ether_shost, current->t_eth_laddr, sizeof(eh->ether_shost));
 	memcpy(eh->ether_dhost, current->t_eth_faddr, sizeof(eh->ether_dhost));

	rc = io_tx_packet(pkt);

	return rc;
}
