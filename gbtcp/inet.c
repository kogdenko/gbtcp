#include "internals.h"

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

static struct inet_mod *curmod;

#define SHIFT(p, size) \
	do { \
		p->inp_cur += size; \
		p->inp_rem -= size; \
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
	GT_TCP_STAT(SYSCTL_ADD_TCP_STAT)
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
	GT_UDP_STAT(SYSCTL_ADD_UDP_STAT)
#undef SYSCTL_ADD_UDP_STAT
}

static void
sysctl_add_inet_stat_ip()
{
#define SYSCTL_ADD_IP_STAT(x) \
	sysctl_add_inet_stat("ip", #x, \
	                     field_off(struct service, p_ips.ips_##x));
	GT_IP_STAT(SYSCTL_ADD_IP_STAT)
#undef SYSCTL_ADD_IP_STAT
}

static void
sysctl_add_inet_stat_arp()
{
#define SYSCTL_ADD_ARP_STAT(x) \
	sysctl_add_inet_stat("arp", #x, \
	                     field_off(struct service, p_arps.arps_##x));
	GT_ARP_STAT(SYSCTL_ADD_ARP_STAT)
#undef SYSCTL_ADD_ARP_STAT
}

int
inet_mod_init(void **pp)
{
	int rc;
	struct inet_mod *mod;

	rc = shm_malloc(pp, sizeof(*mod));
	if (rc) {
		return rc;
	}
	mod = *pp;
	log_scope_init(&mod->log_scope, "inet");
	sysctl_add_inet_stat_tcp();
	sysctl_add_inet_stat_udp();
	sysctl_add_inet_stat_ip();
	sysctl_add_inet_stat_arp();
	sysctl_add_int(GT_SYSCTL_INET_CKSUM_OFFLOAD_RX, SYSCTL_WR,
	               &mod->inet_cksum_offload_rx, 0, 1);
	sysctl_add_int(GT_SYSCTL_INET_CKSUM_OFFLOAD_TX, SYSCTL_WR,
	               &mod->inet_cksum_offload_tx, 0, 1);
	return 0;
}

int
inet_mod_attach(void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

void
inet_mod_deinit(void *raw_mod)
{
	struct inet_mod *mod;

	mod = raw_mod;
	sysctl_del("inet");
	log_scope_deinit(&mod->log_scope);
	shm_free(mod);
}

void
inet_mod_detach()
{
	curmod = NULL;
}

void
inet_parser_init(struct inet_parser *p, void *data, int len)
{
	p->inp_ifp = NULL;
	p->inp_cur = data;
	p->inp_rem = len;
	p->inp_errnum = 0;
	p->inp_ipproto = 0;
	p->inp_emb_ipproto = 0;
	p->inp_cksum_offload = curmod->inet_cksum_offload_rx;
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
arp_in(struct inet_parser *p)
{
	int i, is_req;
	be32_t sip, tip;
	struct route_if_addr *ifa;
	struct arp_advert_msg msg;

	p->inp_arps->arps_received++;
	if (p->inp_rem < sizeof(struct arp_hdr)) {
		p->inp_arps->arps_toosmall++;
		return IN_DROP;
	}
	p->inp_ah = (struct arp_hdr *)p->inp_cur;
	SHIFT(p, sizeof(struct arp_hdr));
	if (p->inp_ah->ah_hrd != ARP_HRD_ETH_BE) {
		p->inp_arps->arps_badhrd++;
		return IN_DROP;
	}
	if (p->inp_ah->ah_pro != ETH_TYPE_IP4_BE) {
		p->inp_arps->arps_badpro++;
		return IN_DROP;
	}
	tip = p->inp_ah->ah_data.aip_tip;
	sip = p->inp_ah->ah_data.aip_sip;
	ifa = route_ifaddr_get4(tip);
	if (ifa == NULL) {
		p->inp_arps->arps_bypassed++;
		return IN_BYPASS;
	}
	ASSERT(p->inp_ifp != NULL);
	for (i = 0; i < p->inp_ifp->rif_naddrs; ++i) {
		if (ifa == p->inp_ifp->rif_addrs[i]) {
			break;		
		}
	}
	if (i == p->inp_ifp->rif_naddrs) {
		p->inp_arps->arps_filtered++;
		return IN_DROP;
	}
	if (p->inp_ah->ah_hlen != sizeof(struct eth_addr)) {
		p->inp_arps->arps_badhlen++;
		return IN_DROP;
	}
	if (p->inp_ah->ah_plen != sizeof(be32_t)) {
		p->inp_arps->arps_badplen++;
		return IN_DROP;
	}
	if (ipaddr4_is_loopback(tip)) {
		p->inp_arps->arps_badaddr++;
		return IN_DROP;
	}
	if (ipaddr4_is_bcast(tip)) {
		p->inp_arps->arps_badaddr++;
		return IN_DROP;
	}
	if (ipaddr4_is_loopback(sip)) {
		p->inp_arps->arps_badaddr++;
		return IN_DROP;
	}
	if (ipaddr4_is_bcast(sip)) {
		p->inp_arps->arps_badaddr++;
		return IN_DROP;
	}
	// IP4 duplicate address detection
	if (sip == 0) {
		// TODO: reply
		return IN_OK;
	}
	switch (p->inp_ah->ah_op) {
	case ARP_OP_REQUEST_BE:
		p->inp_arps->arps_rxrequests++;
		is_req = 1;
		arp_reply(p->inp_ifp, p->inp_ah);
		break;
	case ARP_OP_REPLY_BE:
		p->inp_arps->arps_rxreplies++;
		is_req = 0;
		break;
	default:
		p->inp_arps->arps_badop++;
		return IN_DROP;
	}
	msg.arpam_af = AF_INET;
	msg.arpam_advert = !is_req;
	msg.arpam_solicited = !is_req;
	msg.arpam_override = !is_req;
	msg.arpam_next_hop = p->inp_ah->ah_data.aip_sip;
	msg.arpam_addr = p->inp_ah->ah_data.aip_sha;
	arp_update(&msg);
	return IN_OK;
}

static int
tcp_opts_in(struct tcp_opts *opts, u_char *opts_buf, int opts_len)
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
tcp_in(struct inet_parser *p)
{
	int rc, len, win, cksum;

	if (p->inp_rem < sizeof(struct tcp_hdr)) {
		p->inp_tcps->tcps_rcvshort++;
		return IN_DROP;
	}
	p->inp_th = (struct tcp_hdr *)p->inp_cur;
	p->inp_th_len = TCP_HDR_LEN(p->inp_th->th_data_off);
	if (p->inp_rem < p->inp_th_len) {
		p->inp_tcps->tcps_rcvshort++;
		return IN_DROP;
	}
	SHIFT(p, p->inp_th_len);
	win = ntoh16(p->inp_th->th_win_size);
	len = p->inp_ip_payload_len - p->inp_th_len;
	p->inp_tcb.tcb_win = win;
	p->inp_tcb.tcb_len = len;
	p->inp_tcb.tcb_flags = p->inp_th->th_flags;
	p->inp_tcb.tcb_seq = ntoh32(p->inp_th->th_seq);
	p->inp_tcb.tcb_ack = ntoh32(p->inp_th->th_ack);
	p->inp_payload = (u_char *)p->inp_th + p->inp_th_len;
	p->inp_tcb.tcb_opts.tcp_opt_flags = 0;
	cksum = p->inp_th->th_cksum;
	p->inp_th->th_cksum = 0;
	if (p->inp_cksum_offload == 0) {
		if (cksum != ip4_udp_calc_cksum(p->inp_ih)) {
			p->inp_tcps->tcps_rcvbadsum++;
			return IN_DROP;
		}
	}
	p->inp_th->th_cksum = cksum;
	rc = tcp_opts_in(&p->inp_tcb.tcb_opts,
	                 (void *)(p->inp_th + 1),
	                 p->inp_th_len - sizeof(*p->inp_th));
	if (rc) {
		p->inp_tcps->tcps_rcvbadoff++;
		return IN_DROP;
	}
	return IN_OK;
}

static int
icmp4_in(struct inet_parser *p)
{
	int ih_len, type, code;

	if (p->inp_rem < sizeof(struct icmp4_hdr)) {
		p->inp_icmps->icmps_tooshort++;
		return IN_DROP;
	}
	p->inp_icp = (struct icmp4_hdr *)p->inp_cur;
	SHIFT(p, sizeof(struct icmp4_hdr));
	type = p->inp_icp->icmp_type;
	code = p->inp_icp->icmp_code;	
	if (type > ICMP_MAXTYPE) {
		return IN_DROP;
	}
	p->inp_icmps->icmps_inhist[type]++;
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
			p->inp_errnum = EHOSTUNREACH;
			break;
		case ICMP_UNREACH_NEEDFRAG:
			p->inp_errnum = EMSGSIZE;
			break;
		default:
			p->inp_icmps->icmps_badcode++;
			return IN_DROP;
		}
		break;
	case ICMP_TIMXCEED:
		if (code > 1) {
			p->inp_icmps->icmps_badcode++;
			return IN_DROP;
		}
		// TODO:
		break;
	case ICMP_PARAMPROB:
		if (code > 1) {
			p->inp_icmps->icmps_badcode++;
			return IN_DROP;
		}
		p->inp_errnum = ENOPROTOOPT;
		break;
	case ICMP_SOURCEQUENCH:
		if (code) {
			p->inp_icmps->icmps_badcode++;
			return IN_DROP;
		}
		// TODO:
		break;
	case ICMP_REDIRECT:
		if (code > 3) {
			p->inp_icmps->icmps_badcode++;
			return IN_DROP;
		}
		// TODO:
		return IN_BYPASS;
	default:
		return IN_BYPASS;
	}
	p->inp_emb_ih = NULL;
	p->inp_emb_th = NULL;
	if (p->inp_rem < sizeof(*p->inp_emb_ih)) {
		p->inp_icmps->icmps_badlen++;
		return IN_DROP;
	}
	p->inp_emb_ih = (struct ip4_hdr *)p->inp_cur;
	ih_len = IP4_HDR_LEN(p->inp_emb_ih->ih_ver_ihl);
	if (ih_len < sizeof(*p->inp_emb_ih)) {
		p->inp_icmps->icmps_badlen++;
		return IN_DROP;
	}
	SHIFT(p, ih_len);
	p->inp_emb_ipproto = p->inp_emb_ih->ih_proto;
	switch (p->inp_emb_ipproto) {
	case IPPROTO_UDP:
		if (p->inp_rem < sizeof(*p->inp_emb_uh)) {
			p->inp_icmps->icmps_badlen++;
			return IN_DROP;
		}
		p->inp_emb_uh = (struct udp_hdr *)p->inp_cur;
		return IN_OK;
	case IPPROTO_TCP:
		if (p->inp_rem < sizeof(*p->inp_emb_th)) {
			p->inp_icmps->icmps_badlen++;
			return IN_BYPASS;
		}
		p->inp_emb_th = (struct tcp_hdr *)p->inp_cur;
		return IN_OK;
	case IPPROTO_ICMP:
		if (p->inp_rem < sizeof(*p->inp_emb_icp)) {
			p->inp_icmps->icmps_badlen++;
			return IN_DROP;
		}
		p->inp_emb_icp = (struct icmp4_hdr *)p->inp_cur;
		return IN_BYPASS;
	default:
		return IN_BYPASS;
	}
}

static int
ip_in(struct inet_parser *p)
{
	int rc, total_len, cksum;

	p->inp_ips->ips_total++;
	p->inp_ips->ips_delivered++;
	if (p->inp_rem < sizeof(struct ip4_hdr)) {
		p->inp_ips->ips_toosmall++;
		return IN_DROP;
	}
	p->inp_ih = (struct ip4_hdr *)(p->inp_eh + 1);
	if (p->inp_ih->ih_ttl < 1) {
		return IN_DROP;
	}
	if (ipaddr4_is_mcast(p->inp_ih->ih_saddr)) {
		return IN_BYPASS;
	}
	if (p->inp_ih->ih_frag_off & IP4_FRAG_MASK) {
		p->inp_ips->ips_fragments++;
		p->inp_ips->ips_fragdropped++;
		return IN_BYPASS;
	}
	p->inp_ih_len = IP4_HDR_LEN(p->inp_ih->ih_ver_ihl);
	if (p->inp_ih_len < sizeof(*p->inp_ih)) {
		p->inp_ips->ips_badhlen++;
		return IN_DROP;
	}
	if (p->inp_rem < p->inp_ih_len) {
		p->inp_ips->ips_badhlen++;
		return IN_DROP;
	}
	SHIFT(p, p->inp_ih_len);
	total_len = ntoh16(p->inp_ih->ih_total_len);
	if (total_len > 65535) {
		p->inp_ips->ips_toolong++;
		return IN_DROP;
	}
	if (total_len < p->inp_ih_len) {
		p->inp_ips->ips_badlen++;
		return IN_DROP;
	}
	p->inp_ip_payload_len = total_len - p->inp_ih_len;
	if (p->inp_ip_payload_len > p->inp_rem) {
		p->inp_ips->ips_tooshort++;
		return IN_DROP;
	}
	p->inp_ipproto = p->inp_ih->ih_proto;
	cksum = p->inp_ih->ih_cksum;
	p->inp_ih->ih_cksum = 0;
	if (p->inp_cksum_offload == 0) {
		if (cksum != ip4_calc_cksum(p->inp_ih)) {
			p->inp_ips->ips_badsum++;
			return IN_DROP;
		}
	}
	p->inp_ih->ih_cksum = cksum;
	switch (p->inp_ipproto) {
	case IPPROTO_UDP:
		if (p->inp_rem < sizeof(struct udp_hdr)) {
			p->inp_udps->udps_badlen++;
			return IN_DROP;
		}
		p->inp_uh = (struct udp_hdr *)p->inp_cur;
		SHIFT(p, sizeof(struct udp_hdr));
		return IN_OK;
	case IPPROTO_TCP:
		rc = tcp_in(p);
		break;
	case IPPROTO_ICMP:
		rc = icmp4_in(p);
		return rc;
	default:
		p->inp_ips->ips_noproto++;
		rc = IN_BYPASS;
		break;
	}
	return rc;
}

int
eth_in(struct inet_parser *p)
{
	int rc;

	p->inp_eh = (struct eth_hdr *)p->inp_cur;
	SHIFT(p, sizeof(struct eth_hdr));
	switch (p->inp_eh->eh_type) {
	case ETH_TYPE_IP4_BE:
		p->inp_ipproto = IPPROTO_IP;
		rc = ip_in(p);
		break;
	case ETH_TYPE_ARP_BE:
		rc = arp_in(p);
		break;
	default:
		rc = IN_BYPASS;
	}
	return rc;
}
