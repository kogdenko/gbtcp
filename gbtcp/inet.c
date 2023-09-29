// SPDX-License-Identifier: LGPL-2.1-only

#include "arp.h"
#include "inet.h"
#include "log.h"
//#include "service.h"
#include "shm.h"

struct gt_module_inet {
	struct log_scope log_scope;
	int inet_cksum_offload_rx;
	int inet_cksum_offload_tx;
};

struct ip4_pseudo_hdr {
	be32_t ihp_saddr;
	be32_t ihp_daddr;
	uint8_t ihp_pad;
	uint8_t ihp_proto;
	be16_t ihp_len;
} __attribute__((packed));

struct tcp_opt_info {
	int toi_kind;
	int toi_len;
};

struct tcp_opt_info tcp_opt_info[TCP_OPT_MAX] = {
	{ TCP_OPT_MSS, 4 },
	{ TCP_OPT_WSCALE, 3 },
	{ TCP_OPT_SACK_PERMITED, 2 },
	{ TCP_OPT_TIMESTAMPS, 10 }
};

#define IP4_L4_LEN(ih) (ntoh16((ih)->ih_total_len) - IP4_HDR_LEN((ih)->ih_ver_ihl))

#define curmod ((struct gt_module_inet *)gt_module_get(GT_MODULE_INET))

static int
sysctl_inet_stat(struct sysctl_conn *cp, void *udata, const char *new, struct strbuf *old)
{
	int zero;
	uintptr_t off;
	uint64_t *ptr, accum;
	struct service *s;

	off = (uintptr_t)udata;
	if (new == NULL) {
		zero = 0;
	} else {
		if (strcmp(new, "0")) {
			return -EINVAL;
		} else {
			zero = 1;
		}
	}
	accum = 0;
	SERVICE_FOREACH(s) {
		ptr = (uint64_t *)((u_char *)s + off);
		accum += *ptr;
		if (zero) {
			*ptr = 0;
		}
	}
	strbuf_addf(old, "%"PRIu64, accum);
	return 0;
}

static void
sysctl_add_inet_stat(const char *proto, const char *name, uintptr_t off)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "inet.stat.%s.%s", proto, name);
	sysctl_add(path, SYSCTL_WR, (void *)off, NULL, sysctl_inet_stat);
}

static void
sysctl_add_inet_stat_tcp(void)
{
	int i, off;
	char name[64];

#define SYSCTL_ADD_TCP_STAT(x) \
	sysctl_add_inet_stat("tcp", #x, field_off(struct service, p_tcpstat.tcps_##x));
	GT_X_TCP_STAT(SYSCTL_ADD_TCP_STAT)
#undef SYSCTL_ADD_TCP_STAT
	for (i = 0; i < GT_TCPS_MAX_STATES; ++i) {
		snprintf(name, sizeof(name), "states.%d", i);
		off = field_off(struct service, p_tcpstat.tcps_states[i]);
		sysctl_add_inet_stat("tcp", name, off);
	}
}

static void
sysctl_add_inet_stat_udp(void)
{
#define SYSCTL_ADD_UDP_STAT(x) \
	sysctl_add_inet_stat("udp", #x, field_off(struct service, p_udpstat.udps_##x));
	GT_X_UDP_STAT(SYSCTL_ADD_UDP_STAT)
#undef SYSCTL_ADD_UDP_STAT
}

static void
sysctl_add_inet_stat_ip(void)
{
#define SYSCTL_ADD_IP_STAT(x) \
	sysctl_add_inet_stat("ip", #x, field_off(struct service, p_ipstat.ips_##x));
	GT_X_IP_STAT(SYSCTL_ADD_IP_STAT)
#undef SYSCTL_ADD_IP_STAT
}

static void
sysctl_add_inet_stat_arp(void)
{
#define SYSCTL_ADD_ARP_STAT(x) \
	sysctl_add_inet_stat("arp", #x, field_off(struct service, p_arpstat.arps_##x));
	GT_X_ARP_STAT(SYSCTL_ADD_ARP_STAT)
#undef SYSCTL_ADD_ARP_STAT
}

int
inet_mod_init(void)
{
	int rc;

	rc = gt_module_init(GT_MODULE_INET, sizeof(struct gt_module_inet));
	if (rc) {
		return rc;
	}
	sysctl_add_inet_stat_tcp();
	sysctl_add_inet_stat_udp();
	sysctl_add_inet_stat_ip();
	sysctl_add_inet_stat_arp();
	sysctl_add_int(GT_SYSCTL_INET_CKSUM_OFFLOAD_RX, SYSCTL_WR,
			&curmod->inet_cksum_offload_rx, 0, 1);
	sysctl_add_int(GT_SYSCTL_INET_CKSUM_OFFLOAD_TX, SYSCTL_WR,
			&curmod->inet_cksum_offload_tx, 0, 1);
	curmod->inet_cksum_offload_rx = 0;
	curmod->inet_cksum_offload_tx = 0;
	return 0;
}

void
in_context_init(struct in_context *in, void *data, int len)
{
	in->in_cur = data;
	in->in_rem = len;
	in->in_errnum = 0;
	in->in_ipproto = 0;
	in->in_emb_ipproto = 0;
}

static uint8_t *
tcp_opt_fill_16(u_char *buf, be16_t v)
{
	*((be16_t *)buf) = v;
	return buf + sizeof(v);
}

static uint8_t *
tcp_opt_fill_32(u_char *buf, be32_t v)
{
	*((be32_t *)buf) = v;
	return buf + sizeof(v);
}

static int
tcp_opt_fill(struct tcp_opts *opts, u_char *buf, int kind)
{
	uint32_t val;
	u_char *ptr, *len;

	ptr = buf;
	*ptr++ = kind;
	len = ptr++;
	switch (kind) {
	case TCP_OPT_MSS:
		ptr = tcp_opt_fill_16(ptr, hton16(opts->tcp_opt_mss));
		break;
	case TCP_OPT_WSCALE:
		*ptr++ = opts->tcp_opt_wscale;
		break;
	case TCP_OPT_TIMESTAMPS:
		val = hton32(opts->tcp_opt_ts.tcp_ts_val);
		ptr = tcp_opt_fill_32(ptr, val);
		val = hton32(opts->tcp_opt_ts.tcp_ts_ecr);
		ptr = tcp_opt_fill_32(ptr, val);
		break;
	}
	*len = ptr - buf;
	return ptr - buf;
}

int
tcp_opts_fill(struct tcp_opts *opts, void *buf)
{
	u_char *ptr;
	int i, kind;

	for (i = 0, ptr = buf; i < ARRAY_SIZE(tcp_opt_info); ++i) {
		kind = tcp_opt_info[i].toi_kind;
		if (opts->tcp_opt_flags & (1 << kind)) {
			ptr += tcp_opt_fill(opts, ptr, kind);
		}
	}
	while ((ptr - (uint8_t *)buf) & 0x3) {
		*ptr++ = TCP_OPT_NOP;
	}
	return ptr - (u_char *)buf;
}

int
tcp_opts_len(struct tcp_opts *opts)
{
	int i, len;

	for (i = 0, len = 0; i < ARRAY_SIZE(tcp_opt_info); ++i) {
		if (opts->tcp_opt_flags & (1 << tcp_opt_info[i].toi_kind)) {
			len += tcp_opt_info[i].toi_len;
		}
	}
	len = ROUND_UP(len, 4);	
	return len;
}

static uint64_t
cksum_add(uint64_t sum, uint64_t x)
{
	sum += x;
	if (sum < x) {
		++sum;
	}
	return sum;
}

static uint64_t
cksum_raw(const u_char *b, size_t size)
{
	uint64_t sum;

	sum = 0;
	while (size >= sizeof(uint64_t)) {
		sum = cksum_add(sum, *((uint64_t *)b));
		size -= sizeof(uint64_t);
		b += sizeof(uint64_t);
	}
	if (size >= 4) {
		sum = cksum_add(sum, *((uint32_t *)b));
		size -= sizeof(uint32_t);
		b += sizeof(uint32_t);
	}
	if (size >= 2) {
		sum = cksum_add(sum, *((uint16_t *)b));
		size -= sizeof(uint16_t);
		b += sizeof(uint16_t);
	}
	if (size) {
		assert(size == 1);
		sum = cksum_add(sum, *b);
	}
	return sum;
}

static uint16_t
cksum_reduce(uint64_t sum)
{
	uint64_t mask;
	uint16_t reduced;

	mask = 0xffffffff00000000lu;
	while (sum & mask) {
		sum = cksum_add(sum & ~mask, (sum >> 32) & ~mask);
	}
	mask = 0xffffffffffff0000lu;
	while (sum & mask) {
		sum = cksum_add(sum & ~mask, (sum >> 16) & ~mask);
	}
	reduced = ~((uint16_t)sum);
	if (reduced == 0) {
		reduced = 0xffff;
	}
	return reduced;
}

static uint64_t
ip4_pseudo_calc_cksum(struct ip4_hdr *ih, uint16_t l4_len)
{	
	uint64_t sum;
	struct ip4_pseudo_hdr ih_pseudo;

	memset(&ih_pseudo, 0, sizeof(ih_pseudo));
	ih_pseudo.ihp_saddr = ih->ih_saddr;
	ih_pseudo.ihp_daddr = ih->ih_daddr;
	ih_pseudo.ihp_pad = 0;
	ih_pseudo.ihp_proto = ih->ih_proto;
	ih_pseudo.ihp_len = hton16(l4_len);
	sum = cksum_raw((void *)&ih_pseudo, sizeof(ih_pseudo));
	return sum;
}

static uint16_t
ip4_udp_calc_cksum(struct ip4_hdr *ih, void *uh, int l4_len)
{
	uint64_t sum, pseudo_cksum;

	sum = cksum_raw(uh, l4_len);
	pseudo_cksum = ip4_pseudo_calc_cksum(ih, l4_len);
	sum = cksum_add(sum, pseudo_cksum);
	sum = cksum_reduce(sum);
	return sum;
}

static uint16_t
ip4_calc_cksum(struct ip4_hdr *ih)
{
	int ih_len;
	uint64_t sum;
	uint16_t reduce;

	ih_len = IP4_HDR_LEN(ih->ih_ver_ihl);
	sum = cksum_raw((void *)ih, ih_len);
	reduce = cksum_reduce(sum);
	return reduce;
}

void
ip4_set_cksum(struct ip4_hdr *ih, void *l4h)
{
	uint16_t ip4_cksum, udp_cksum;
	struct udp_hdr *uh;
	struct tcp_hdr *th;

	switch (ih->ih_proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		if (curmod->inet_cksum_offload_tx) {
			ip4_cksum = 0;
			udp_cksum = 0;
		} else {
			ip4_cksum = ip4_calc_cksum(ih);
			udp_cksum = ip4_udp_calc_cksum(ih, l4h, IP4_L4_LEN(ih));
		}
		break;
	case IPPROTO_ICMP:
		assert(0);
	default:
		return;
	}

	ih->ih_cksum = ip4_cksum;

	switch (ih->ih_proto) {
	case IPPROTO_UDP:
		uh = l4h;
		uh->uh_cksum = udp_cksum;
		break;
	case IPPROTO_TCP:
		th = l4h;
		th->th_cksum = udp_cksum;
		break;
	case IPPROTO_ICMP:
		assert(0);
		break;
	}
}

int
gt_ip4_validate_cksum(struct ip4_hdr *ih)
{
	int cksum, valid;

	cksum = ih->ih_cksum;
	ih->ih_cksum = 0;
	valid = 1;
	if (curmod->inet_cksum_offload_rx == 0) {
		if (cksum != ip4_calc_cksum(ih)) {
			valid = 0;
		}
	}
	ih->ih_cksum = cksum;
	return valid;
}

int
gt_udp_validate_cksum(struct ip4_hdr *ih, struct udp_hdr *uh, int l4_len)
{
	int cksum, valid;

	cksum = uh->uh_cksum;
	uh->uh_cksum = 0;
	valid = 1;
	if (curmod->inet_cksum_offload_rx == 0) {
		if (cksum != ip4_udp_calc_cksum(ih, uh, l4_len)) {
			valid = 0;
		}
	}
	uh->uh_cksum = cksum;
	return valid;
}

int
gt_tcp_validate_cksum(struct ip4_hdr *ih, struct tcp_hdr *th, int l4_len)
{
	int cksum, valid;

	cksum = th->th_cksum;
	th->th_cksum = 0;
	valid = 1;
	if (curmod->inet_cksum_offload_rx == 0) {
		if (cksum != ip4_udp_calc_cksum(ih, th, l4_len)) {
			valid = 0;
		}
	}
	th->th_cksum = cksum;
	return valid;
}

static int
tcp_opt_len(int kind)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tcp_opt_info); ++i) {
		if (tcp_opt_info[i].toi_kind == kind) {
			return tcp_opt_info[i].toi_len;
		}
	}
	return 0;
}

static int
tcp_opts_input(struct tcp_opts *opts, u_char *opts_buf, int opts_len)
{
	int i, len, opt_len;
	u_char *data, kind;
	uint32_t val, ecr;

	opts->tcp_opt_flags = 0;
	if (opts_len & 0x3) {
		return -1;
	}
	i = 0;
	while (i < opts_len) {
		kind = opts_buf[i++];
		if (kind == TCP_OPT_EOL) {
			if (i < opts_len) {
				return -1;
			}
			break;
		} else if (kind == TCP_OPT_NOP) {
			continue;
		}
		if (i == opts_len) {
			return -1;
		}
		len = opts_buf[i++];
		if (len < 2) {
			return -1;
		}
		if (i + len - 2 > opts_len) {
			return -1;
		}
		data = opts_buf + i;
		i += len - 2;
		if (kind >= TCP_OPT_MAX) {
			continue;
		}
		opt_len = tcp_opt_len(kind);
		if (opt_len == 0) {
			continue;
		}
		if (len != opt_len) {
			return -1;
		}
		switch (kind) {
		case TCP_OPT_MSS:
			opts->tcp_opt_mss = ntoh16(*((be16_t *)data));
			break;
		case TCP_OPT_WSCALE:
			opts->tcp_opt_wscale = *data;
			break;
		case TCP_OPT_TIMESTAMPS:
			val = ntoh32(*((be32_t *)data + 0));
			ecr = ntoh32(*((be32_t *)data + 1));
			opts->tcp_opt_ts.tcp_ts_val = val;
			opts->tcp_opt_ts.tcp_ts_ecr = ecr;
			break;
		}
		opts->tcp_opt_flags |= (1 << kind);
	}
	return 0;
}

static int
tcp_input(struct in_context *in)
{
	int rc, len, win;

	if (in->in_rem < sizeof(struct tcp_hdr)) {
		tcpstat.tcps_rcvshort++;
		return IN_OK;
	}
	in->in_th = (struct tcp_hdr *)in->in_cur;
	in->in_th_len = TCP_HDR_LEN(in->in_th->th_data_off);
	if (in->in_rem < in->in_th_len) {
		tcpstat.tcps_rcvshort++;
		return IN_OK;
	}
	GT_INET_PARSER_SHIFT(in, in->in_th_len);
	win = ntoh16(in->in_th->th_win_size);
	len = in->in_ip_payload_len - in->in_th_len;
	in->in_tcp_win = win;
	in->in_len = len;
	in->in_tcp_flags = in->in_th->th_flags;
	in->in_tcp_seq = ntoh32(in->in_th->th_seq);
	in->in_tcp_ack = ntoh32(in->in_th->th_ack);
	in->in_payload = (u_char *)in->in_th + in->in_th_len;
	in->in_tcp_opts.tcp_opt_flags = 0;
	if (gt_tcp_validate_cksum(in->in_ih, in->in_th, IP4_L4_LEN(in->in_ih))) {
		tcpstat.tcps_rcvbadsum++;
		return IN_OK;
	}
	rc = tcp_opts_input(&in->in_tcp_opts, (void *)(in->in_th + 1),
			in->in_th_len - sizeof(*in->in_th));
	if (rc) {
		tcpstat.tcps_rcvbadoff++;
	}
	return IN_OK;
}

static int
icmp_input(struct in_context *in)
{
	int ih_len, type, code;

	if (in->in_rem < sizeof(struct icmp4_hdr)) {
		icmpstat.icmps_tooshort++;
		return IN_OK;
	}
	in->in_icp = (struct icmp4_hdr *)in->in_cur;
	GT_INET_PARSER_SHIFT(in, sizeof(struct icmp4_hdr));
	type = in->in_icp->icmp_type;
	code = in->in_icp->icmp_code;	
	if (type > ICMP_MAXTYPE) {
		return IN_BYPASS;
	}
	icmpstat.icmps_inhist[type]++;
	switch (type) {
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
			in->in_errnum = EHOSTUNREACH;
			break;
		case ICMP_UNREACH_NEEDFRAG:
			in->in_errnum = EMSGSIZE;
			break;
		default:
			icmpstat.icmps_badcode++;
			return IN_OK;
		}
		break;
	case ICMP_TIMXCEED:
		if (code > 1) {
			icmpstat.icmps_badcode++;
			return IN_OK;
		}
		// TODO:
		break;
	case ICMP_PARAMPROB:
		if (code > 1) {
			icmpstat.icmps_badcode++;
			return IN_OK;
		}
		in->in_errnum = ENOPROTOOPT;
		break;
	case ICMP_SOURCEQUENCH:
		if (code) {
			icmpstat.icmps_badcode++;
			return IN_OK;
		}
		// TODO:
		break;
	case ICMP_REDIRECT:
		if (code > 3) {
			icmpstat.icmps_badcode++;
			return IN_OK;
		}
		// TODO:
		return IN_BYPASS;
	default:
		return IN_BYPASS;
	}
	in->in_emb_ih = NULL;
	in->in_emb_th = NULL;
	if (in->in_rem < sizeof(*in->in_emb_ih)) {
		icmpstat.icmps_badlen++;
		return IN_OK;
	}
	in->in_emb_ih = (struct ip4_hdr *)in->in_cur;
	ih_len = IP4_HDR_LEN(in->in_emb_ih->ih_ver_ihl);
	if (ih_len < sizeof(*in->in_emb_ih)) {
		icmpstat.icmps_badlen++;
		return IN_OK;
	}
	GT_INET_PARSER_SHIFT(in, ih_len);
	in->in_emb_ipproto = in->in_emb_ih->ih_proto;
	switch (in->in_emb_ipproto) {
	case IPPROTO_UDP:
		if (in->in_rem < sizeof(*in->in_emb_uh)) {
			icmpstat.icmps_badlen++;
			return IN_OK;
		}
		in->in_emb_uh = (struct udp_hdr *)in->in_cur;
		return IN_OK;
	case IPPROTO_TCP:
		if (in->in_rem < sizeof(*in->in_emb_th)) {
			icmpstat.icmps_badlen++;
			return IN_BYPASS;
		}
		in->in_emb_th = (struct tcp_hdr *)in->in_cur;
		return IN_OK;
	case IPPROTO_ICMP:
		if (in->in_rem < sizeof(*in->in_emb_icp)) {
			icmpstat.icmps_badlen++;
			return IN_OK;
		}
		in->in_emb_icp = (struct icmp4_hdr *)in->in_cur;
		return IN_BYPASS;
	default:
		return IN_BYPASS;
	}
}

static int
ip_input(struct in_context *in)
{
	int rc, total_len;

	ipstat.ips_total++;
	if (in->in_rem < sizeof(struct ip4_hdr)) {
		ipstat.ips_toosmall++;
		return IN_OK;
	}
	in->in_ih = (struct ip4_hdr *)(in->in_eh + 1);
	if (in->in_ih->ih_ttl < 1) {
		return IN_BYPASS;
	}
	if (ipaddr4_is_mcast(in->in_ih->ih_saddr)) {
		return IN_BYPASS;
	}
	if (in->in_ih->ih_frag_off & IP4_FRAG_MASK) {
//		in->in_ips->ips_fragments++;
//		in->in_ips->ips_fragdropped++;
		return IN_BYPASS;
	}
	if (IP4_HDR_VER(in->in_ih->ih_ver_ihl) != GT_IP4_VER) {
		ipstat.ips_badvers++;
		return IN_OK;
	}
	in->in_ih_len = IP4_HDR_LEN(in->in_ih->ih_ver_ihl);
	if (in->in_ih_len < sizeof(*in->in_ih)) {
		ipstat.ips_badhlen++;
		return IN_OK;
	}
	if (in->in_rem < in->in_ih_len) {
		ipstat.ips_badhlen++;
		return IN_OK;
	}
	GT_INET_PARSER_SHIFT(in, in->in_ih_len);
	total_len = ntoh16(in->in_ih->ih_total_len);
	if (total_len > 65535) {
		ipstat.ips_toolong++;
		return IN_OK;
	}
	if (total_len < in->in_ih_len) {
		ipstat.ips_badlen++;
		return IN_OK;
	}
	in->in_ip_payload_len = total_len - in->in_ih_len;
	if (in->in_ip_payload_len > in->in_rem) {
		ipstat.ips_tooshort++;
		return IN_OK;
	}
	in->in_ipproto = in->in_ih->ih_proto;
	if (!gt_ip4_validate_cksum(in->in_ih)) {
		ipstat.ips_badsum++;
		return IN_OK;
	}
	ipstat.ips_delivered++;
	switch (in->in_ipproto) {
	case IPPROTO_UDP:
		if (in->in_rem < sizeof(struct udp_hdr)) {
			udpstat.udps_badlen++;
			return IN_OK;
		}
		in->in_uh = (struct udp_hdr *)in->in_cur;
		GT_INET_PARSER_SHIFT(in, sizeof(struct udp_hdr));
		in->in_payload = in->in_cur;
		in->in_len = in->in_rem;
		return IN_OK;
	case IPPROTO_TCP:
		rc = tcp_input(in);
		break;
	case IPPROTO_ICMP:
		rc = icmp_input(in);
		return rc;
	default:
//		in->in_ips->ips_noproto++;
		rc = IN_BYPASS;
		break;
	}
	return rc;
}

int
eth_input(struct route_if *ifp, struct in_context *in)
{
	int rc;

	in->in_eh = (struct eth_hdr *)in->in_cur;
	GT_INET_PARSER_SHIFT(in, sizeof(struct eth_hdr));
	switch (in->in_eh->eh_type) {
	case ETH_TYPE_IP4_BE:
		in->in_ipproto = IPPROTO_IP;
		rc = ip_input(in);
		break;
	case ETH_TYPE_ARP_BE:
		rc = gt_arp_input(ifp, in->in_cur, in->in_rem);
		break;
	default:
		rc = IN_BYPASS;
	}
	return rc;
}
