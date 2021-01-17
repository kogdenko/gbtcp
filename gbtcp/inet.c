// gpl2
#include "internals.h"

#define CURMOD inet

struct inet_mod {
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

#define SHIFT(in, size) \
	do { \
		in->in_cur += size; \
		in->in_rem -= size; \
	} while (0)

static int
sysctl_inet_stat(struct sysctl_conn *cp, void *udata,
	const char *new, struct strbuf *old)
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
sysctl_add_inet_stat_tcp()
{
	int i, off;
	char name[64];

#define SYSCTL_ADD_TCP_STAT(x) \
	sysctl_add_inet_stat("tcp", #x, \
		field_off(struct service, p_tcps.tcps_##x));
	GT_X_TCP_STAT(SYSCTL_ADD_TCP_STAT)
#undef SYSCTL_ADD_TCP_STAT

	for (i = 0; i < GT_TCP_NSTATES; ++i) {
		snprintf(name, sizeof(name), "states.%d", i);
		off = field_off(struct service, p_tcps.tcps_states[i]);
		sysctl_add_inet_stat("tcp", name, off);
	}
}

static void
sysctl_add_inet_stat_udp()
{
#define SYSCTL_ADD_UDP_STAT(x) \
	sysctl_add_inet_stat("udp", #x, \
		field_off(struct service, p_udps.udps_##x));
	GT_X_UDP_STAT(SYSCTL_ADD_UDP_STAT)
#undef SYSCTL_ADD_UDP_STAT
}

static void
sysctl_add_inet_stat_ip()
{
#define SYSCTL_ADD_IP_STAT(x) \
	sysctl_add_inet_stat("ip", #x, \
		field_off(struct service, p_ips.ips_##x));
	GT_X_IP_STAT(SYSCTL_ADD_IP_STAT)
#undef SYSCTL_ADD_IP_STAT
}

static void
sysctl_add_inet_stat_arp()
{
#define SYSCTL_ADD_ARP_STAT(x) \
	sysctl_add_inet_stat("arp", #x, \
	                     field_off(struct service, p_arps.arps_##x));
	GT_X_ARP_STAT(SYSCTL_ADD_ARP_STAT)
#undef SYSCTL_ADD_ARP_STAT
}

int
inet_mod_init()
{
	int rc;

	rc = curmod_init();
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
	return 0;
}

void
in_context_init(struct in_context *in, void *data, int len)
{
	in->in_ifp = NULL;
	in->in_cur = data;
	in->in_rem = len;
	in->in_errnum = 0;
	in->in_ipproto = 0;
	in->in_emb_ipproto = 0;
	in->in_cksum_offload = curmod->inet_cksum_offload_rx;
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

	mask = 0xffffffff00000000lu;
	while (sum & mask) {
		sum = cksum_add(sum & ~mask, (sum >> 32) & ~mask);
	}
	mask = 0xffffffffffff0000lu;
	while (sum & mask) {
		sum = cksum_add(sum & ~mask, (sum >> 16) & ~mask);
	}
	return ~((uint16_t)sum);
}

static uint64_t
ip4_pseudo_calc_cksum(struct ip4_hdr *ih, uint16_t len)
{	
	uint64_t sum;
	struct ip4_pseudo_hdr ih_pseudo;

	memset(&ih_pseudo, 0, sizeof(ih_pseudo));
	ih_pseudo.ihp_saddr = ih->ih_saddr;
	ih_pseudo.ihp_daddr = ih->ih_daddr;
	ih_pseudo.ihp_pad = 0;
	ih_pseudo.ihp_proto = ih->ih_proto;
	ih_pseudo.ihp_len = hton16(len);
	sum = cksum_raw((void *)&ih_pseudo, sizeof(ih_pseudo));
	return sum;
}

static uint16_t
ip4_udp_calc_cksum(struct ip4_hdr *ih)
{
	int ih_len;
	uint16_t total_len, len;
	uint64_t sum, pseudo_cksum;
	void *uh;

	total_len = ntoh16(ih->ih_total_len);
	ih_len = IP4_HDR_LEN(ih->ih_ver_ihl);
	len = total_len - ih_len;
	uh = ((u_char *)ih) + ih_len;
	sum = cksum_raw(uh, len);
	pseudo_cksum = ip4_pseudo_calc_cksum(ih, len);
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
ip4_set_cksum(struct ip4_hdr *ih, void *l4_h)
{
	uint16_t ip4_cksum, udp_cksum;
	struct udp_hdr *uh;
	struct tcp_hdr *th;

	if (curmod->inet_cksum_offload_tx) {
		ip4_cksum = 0;
		udp_cksum = 0;
	} else {
		ip4_cksum = ip4_calc_cksum(ih);
		udp_cksum = ip4_udp_calc_cksum(ih);
	}
	ih->ih_cksum = ip4_cksum;
	switch (ih->ih_proto) {
	case IPPROTO_UDP:
		uh = l4_h;
		uh->uh_cksum = udp_cksum;
		break;
	case IPPROTO_TCP:
		th = l4_h;
		th->th_cksum = udp_cksum;
		break;
	}
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
arp_input(struct in_context *in)
{
	int i, is_req;
	be32_t sip, tip;
	struct route_if_addr *ifa;
	struct arp_advert adv;

	in->in_arps->arps_received++;
	if (in->in_rem < sizeof(struct arp_hdr)) {
		in->in_arps->arps_toosmall++;
		return IN_DROP;
	}
	in->in_ah = (struct arp_hdr *)in->in_cur;
	SHIFT(in, sizeof(struct arp_hdr));
	if (in->in_ah->ah_hrd != ARP_HRD_ETH_BE) {
		in->in_arps->arps_badhrd++;
		return IN_DROP;
	}
	if (in->in_ah->ah_pro != ETH_TYPE_IP4_BE) {
		in->in_arps->arps_badpro++;
		return IN_DROP;
	}
	if (in->in_ah->ah_hlen != sizeof(struct eth_addr)) {
		in->in_arps->arps_badhlen++;
		return IN_DROP;
	}
	if (in->in_ah->ah_plen != sizeof(be32_t)) {
		in->in_arps->arps_badplen++;
		return IN_DROP;
	}
	tip = in->in_ah->ah_data.aip_tip;
	sip = in->in_ah->ah_data.aip_sip;
	if (ipaddr4_is_loopback(tip)) {
		in->in_arps->arps_badaddr++;
		return IN_DROP;
	}
	if (ipaddr4_is_bcast(tip)) {
		in->in_arps->arps_badaddr++;
		return IN_DROP;
	}
	if (ipaddr4_is_loopback(sip)) {
		in->in_arps->arps_badaddr++;
		return IN_DROP;
	}
	if (ipaddr4_is_bcast(sip)) {
		in->in_arps->arps_badaddr++;
		return IN_DROP;
	}
	ifa = route_ifaddr_get4(tip);
	if (ifa == NULL) {
		return IN_BYPASS;
	}
	assert(in->in_ifp != NULL);
	for (i = 0; i < in->in_ifp->rif_n_addrs; ++i) {
		if (ifa == in->in_ifp->rif_addrs[i]) {
			break;		
		}
	}
	if (i == in->in_ifp->rif_n_addrs) {
		in->in_arps->arps_filtered++;
		return IN_BYPASS;
	}
	if (sip == 0) {
		// IP4 duplicate address detection
		return IN_BYPASS;
	}
	switch (in->in_ah->ah_op) {
	case ARP_OP_REQUEST_BE:
		in->in_arps->arps_rxrequests++;
		is_req = 1;
		arp_reply(in->in_ifp, in->in_ah);
		break;
	case ARP_OP_REPLY_BE:
		in->in_arps->arps_rxreplies++;
		is_req = 0;
		break;
	default:
		in->in_arps->arps_badop++;
		return IN_DROP;
	}
	adv.arpa_af = AF_INET;
	adv.arpa_advert = !is_req;
	adv.arpa_solicited = !is_req;
	adv.arpa_override = !is_req;
	adv.arpa_next_hop = in->in_ah->ah_data.aip_sip;
	adv.arpa_addr = in->in_ah->ah_data.aip_sha;
	arp_update(&adv);
	if (is_req) {
		return IN_DROP;
	} else {
		return IN_BYPASS;
	}
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
	int rc, len, win, cksum;

	if (in->in_rem < sizeof(struct tcp_hdr)) {
		in->in_tcps->tcps_rcvshort++;
		return IN_DROP;
	}
	in->in_th = (struct tcp_hdr *)in->in_cur;
	in->in_th_len = TCP_HDR_LEN(in->in_th->th_data_off);
	if (in->in_rem < in->in_th_len) {
		in->in_tcps->tcps_rcvshort++;
		return IN_DROP;
	}
	SHIFT(in, in->in_th_len);
	win = ntoh16(in->in_th->th_win_size);
	len = in->in_ip_payload_len - in->in_th_len;
	in->in_tcp_win = win;
	in->in_len = len;
	in->in_tcp_flags = in->in_th->th_flags;
	in->in_tcp_seq = ntoh32(in->in_th->th_seq);
	in->in_tcp_ack = ntoh32(in->in_th->th_ack);
	in->in_payload = (u_char *)in->in_th + in->in_th_len;
	in->in_tcp_opts.tcp_opt_flags = 0;
	cksum = in->in_th->th_cksum;
	in->in_th->th_cksum = 0;
	if (in->in_cksum_offload == 0) {
		if (cksum != ip4_udp_calc_cksum(in->in_ih)) {
			in->in_tcps->tcps_rcvbadsum++;
			return IN_DROP;
		}
	}
	in->in_th->th_cksum = cksum;
	rc = tcp_opts_input(&in->in_tcp_opts,
	                    (void *)(in->in_th + 1),
	                    in->in_th_len - sizeof(*in->in_th));
	if (rc) {
		in->in_tcps->tcps_rcvbadoff++;
		return IN_DROP;
	}
	return IN_OK;
}

static int
icmp_input(struct in_context *in)
{
	int ih_len, type, code;

	dbg("x");
	if (in->in_rem < sizeof(struct icmp4_hdr)) {
		in->in_icmps->icmps_tooshort++;
		return IN_DROP;
	}
	in->in_icp = (struct icmp4_hdr *)in->in_cur;
	SHIFT(in, sizeof(struct icmp4_hdr));
	type = in->in_icp->icmp_type;
	code = in->in_icp->icmp_code;	
	if (type > ICMP_MAXTYPE) {
		return IN_BYPASS;
	}
	in->in_icmps->icmps_inhist[type]++;
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
			in->in_icmps->icmps_badcode++;
			return IN_DROP;
		}
		break;
	case ICMP_TIMXCEED:
		if (code > 1) {
			in->in_icmps->icmps_badcode++;
			return IN_DROP;
		}
		// TODO:
		break;
	case ICMP_PARAMPROB:
		if (code > 1) {
			in->in_icmps->icmps_badcode++;
			return IN_DROP;
		}
		in->in_errnum = ENOPROTOOPT;
		break;
	case ICMP_SOURCEQUENCH:
		if (code) {
			in->in_icmps->icmps_badcode++;
			return IN_DROP;
		}
		// TODO:
		break;
	case ICMP_REDIRECT:
		if (code > 3) {
			in->in_icmps->icmps_badcode++;
			return IN_DROP;
		}
		// TODO:
		return IN_BYPASS;
	default:
		return IN_BYPASS;
	}
	in->in_emb_ih = NULL;
	in->in_emb_th = NULL;
	if (in->in_rem < sizeof(*in->in_emb_ih)) {
		in->in_icmps->icmps_badlen++;
		return IN_DROP;
	}
	in->in_emb_ih = (struct ip4_hdr *)in->in_cur;
	ih_len = IP4_HDR_LEN(in->in_emb_ih->ih_ver_ihl);
	if (ih_len < sizeof(*in->in_emb_ih)) {
		in->in_icmps->icmps_badlen++;
		return IN_DROP;
	}
	SHIFT(in, ih_len);
	in->in_emb_ipproto = in->in_emb_ih->ih_proto;
	switch (in->in_emb_ipproto) {
	case IPPROTO_UDP:
		if (in->in_rem < sizeof(*in->in_emb_uh)) {
			in->in_icmps->icmps_badlen++;
			return IN_DROP;
		}
		in->in_emb_uh = (struct udp_hdr *)in->in_cur;
		return IN_OK;
	case IPPROTO_TCP:
		if (in->in_rem < sizeof(*in->in_emb_th)) {
			in->in_icmps->icmps_badlen++;
			return IN_BYPASS;
		}
		in->in_emb_th = (struct tcp_hdr *)in->in_cur;
		return IN_OK;
	case IPPROTO_ICMP:
		if (in->in_rem < sizeof(*in->in_emb_icp)) {
			in->in_icmps->icmps_badlen++;
			return IN_DROP;
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
	int rc, total_len, cksum;

	in->in_ips->ips_total++;
	if (in->in_rem < sizeof(struct ip4_hdr)) {
		in->in_ips->ips_toosmall++;
		return IN_DROP;
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
	in->in_ih_len = IP4_HDR_LEN(in->in_ih->ih_ver_ihl);
	if (in->in_ih_len < sizeof(*in->in_ih)) {
		in->in_ips->ips_badhlen++;
		return IN_DROP;
	}
	if (in->in_rem < in->in_ih_len) {
		in->in_ips->ips_badhlen++;
		return IN_DROP;
	}
	SHIFT(in, in->in_ih_len);
	total_len = ntoh16(in->in_ih->ih_total_len);
	if (total_len > 65535) {
		in->in_ips->ips_toolong++;
		return IN_DROP;
	}
	if (total_len < in->in_ih_len) {
		in->in_ips->ips_badlen++;
		return IN_DROP;
	}
	in->in_ip_payload_len = total_len - in->in_ih_len;
	if (in->in_ip_payload_len > in->in_rem) {
		in->in_ips->ips_tooshort++;
		return IN_DROP;
	}
	in->in_ipproto = in->in_ih->ih_proto;
	cksum = in->in_ih->ih_cksum;
	in->in_ih->ih_cksum = 0;
	if (in->in_cksum_offload == 0) {
		if (cksum != ip4_calc_cksum(in->in_ih)) {
			in->in_ips->ips_badsum++;
			return IN_DROP;
		}
	}
	in->in_ih->ih_cksum = cksum;
	switch (in->in_ipproto) {
	case IPPROTO_UDP:
		if (in->in_rem < sizeof(struct udp_hdr)) {
			in->in_udps->udps_badlen++;
			return IN_DROP;
		}
		in->in_uh = (struct udp_hdr *)in->in_cur;
		SHIFT(in, sizeof(struct udp_hdr));
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
eth_input(struct in_context *in)
{
	int rc;

	in->in_eh = (struct eth_hdr *)in->in_cur;
	SHIFT(in, sizeof(struct eth_hdr));
	switch (in->in_eh->eh_type) {
	case ETH_TYPE_IP4_BE:
		in->in_ipproto = IPPROTO_IP;
		rc = ip_input(in);
		break;
	case ETH_TYPE_ARP_BE:
		rc = arp_input(in);
		break;
	default:
		rc = IN_BYPASS;
	}
	return rc;
}
