// SPDX-License-Identifier: BSD-4-Clause

#include "socket.h"
#include "ip.h"
#include "in_pcb.h"
#include "ip_var.h"
#include "tcp_var.h"
#include "udp_var.h"
#include "ip_icmp.h"

/*
 * IP initialization: fill in IP protocol switch table.
 * All protocols not implemented in kernel go to raw IP protocol handler.
 */

/*
 * Ip input routine.  Checksum and byte swap header.  If fragmented
 * try to reassemble.  Process options.  Pass to next level.
 */
int
ip_input(struct route_if *ifp, struct ip4_hdr *ip, int len, int eth_flags)
{
	int hlen;

	ipstat.ips_total++;
	if (len < sizeof(*ip)) {
		ipstat.ips_toosmall++;
		return IN_OK;
	}
	if (IP4_HDR_VER(ip->ih_ver_ihl) != IPVERSION) {
		ipstat.ips_badvers++;
		return IN_OK;
	}
	hlen = IP4_HDR_LEN(ip->ih_ver_ihl);
	if (hlen < sizeof(*ip)) {	/* minimum header length */
		ipstat.ips_badhlen++;
		return IN_OK;
	}
	if (hlen > len) {
		ipstat.ips_badhlen++;
		return IN_OK;
	}
	if (!gt_ip4_validate_cksum(ip)) {
		ipstat.ips_badsum++;
		return IN_OK;
	}

	/*
	 * Convert fields to host representation.
	 */
	NTOHS(ip->ih_total_len);
	if (ip->ih_total_len < hlen) {
		ipstat.ips_badlen++;
		return IN_OK;
	}
	NTOHS(ip->ih_id);
	NTOHS(ip->ih_frag_off);

	/*
	 * Check that the amount of data in the buffers
	 * is as at least much as the IP header would have us expect.
	 * Drop packet if shorter than we expect.
	 */
	if (len < ip->ih_total_len) {
		ipstat.ips_tooshort++;
		return IN_OK;
	}

	if (ip->ih_frag_off &~ IP_DF) {
		ipstat.ips_fragments++;
		return IN_BYPASS;
	}
	ip->ih_total_len -= hlen;
	ipstat.ips_delivered++;
	switch (ip->ih_proto) {
	case IPPROTO_TCP:
		return tcp_input(ifp, ip, hlen, eth_flags);
	case IPPROTO_UDP:
		return udp_input(ip, hlen, eth_flags);
	case IPPROTO_ICMP:
		return icmp_input(ip, hlen);
	default:
		return IN_BYPASS;
	}
}
