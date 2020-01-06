#include "log.h"
#include "inet.h"
#include "arp.h"
#include "ctl.h"

#define GT_INET_LOG_NODE_FOREACH(x) \
	x(mod_init) \
	x(mod_deinit)

struct gt_ip4_pseudo_hdr {
	gt_be32_t ip4ph_saddr;
	gt_be32_t ip4ph_daddr;
	uint8_t ip4ph_pad;
	uint8_t ip4ph_proto;
	gt_be16_t ip4ph_len;
} __attribute__((packed));

struct gt_inet_tcp_opt {
	int tcpopt_kind;
	int tcpopt_len;
};

struct gt_inet_tcp_opt gt_inet_tcp_opts[GT_TCP_OPT_MAX] = {
	{ GT_TCP_OPT_MSS, 4 },
	{ GT_TCP_OPT_WSCALE, 3 },
	{ GT_TCP_OPT_SACK_PERMITED, 2 },
	{ GT_TCP_OPT_TIMESTAMPS, 10 }
};

struct gt_tcp_stat gt_tcps;
struct gt_udp_stat gt_udps;
struct gt_ip_stat gt_ips;
struct gt_icmp_stat gt_icmps;
struct gt_arp_stat gt_arps;

static int gt_inet_rx_cksum_offload = 0;
static int gt_inet_tx_cksum_offload = 0;
static struct gt_log_scope this_log;
GT_INET_LOG_NODE_FOREACH(GT_LOG_NODE_STATIC);

static uint8_t *gt_inet_fill_16(uint8_t *buf, gt_be16_t v);

static uint8_t * gt_inet_fill_32(uint8_t *buf, gt_be32_t v);

static uint64_t gt_inet_cksum_add(uint64_t sum, uint64_t x);

static uint64_t gt_inet_cksum_raw(const uint8_t *b, size_t size);

static uint16_t gt_inet_cksum_reduce(uint64_t sum);

static uint16_t gt_inet_ip4_calc_cksum(struct gt_ip4_hdr *ip4_h);

static uint64_t gt_inet_ip4_pseudo_calc_cksum(struct gt_ip4_hdr *ip4_h,
	uint16_t len);

static uint16_t gt_inet_ip4_udp_calc_cksum(struct gt_ip4_hdr *ip4_h);

static int gt_tcp_opt_len(int kind);

static int gt_inet_arp_in(struct gt_inet_context *ctx);

static int gt_inet_ip_in(struct gt_inet_context *ctx);

static int gt_inet_tcp_in(struct gt_inet_context *ctx);

static int gt_inet_tcp_opts_in(struct gt_tcp_opts *opts, uint8_t *opts_buf,
	int opts_len);

static int gt_inet_icmp4_in(struct gt_inet_context *ctx);

static int gt_tcp_opt_fill(uint8_t *buf, struct gt_tcp_opts *opts, int kind);

static void gt_inet_ctl_add_stat_var(struct gt_log *log, const char *proto,
	uint64_t *val, const char *name);

static void gt_inet_ctl_add_ip_stat(struct gt_log *log);

static void gt_inet_ctl_add_arp_stat(struct gt_log *log);

static void gt_inet_ctl_add_udp_stat(struct gt_log *log);

static void gt_inet_ctl_add_tcp_stat(struct gt_log *log);

#define GT_INET_SHIFT(ctx, size) \
	do { \
		ctx->inp_cur += size; \
		ctx->inp_rem -= size; \
	} while (0)

int
gt_inet_mod_init()
{
	struct gt_log *log;

	gt_log_scope_init(&this_log, "inet");
	GT_INET_LOG_NODE_FOREACH(GT_LOG_NODE_INIT);
	log = GT_LOG_TRACE1(mod_init);
	gt_inet_ctl_add_tcp_stat(log);
	gt_inet_ctl_add_udp_stat(log);
	gt_inet_ctl_add_ip_stat(log);
	gt_inet_ctl_add_arp_stat(log);
	gt_ctl_add_int(log, GT_CTL_INET_RX_CKSUM_OFFLOAD, GT_CTL_WR,
	               &gt_inet_rx_cksum_offload, 0, 1);
	gt_ctl_add_int(log, GT_CTL_INET_TX_CKSUM_OFFLOAD, GT_CTL_WR,
	               &gt_inet_tx_cksum_offload, 0, 1);
	return 0;
}

void
gt_inet_mod_deinit(struct gt_log *log)
{
	log = GT_LOG_TRACE(log, mod_deinit);
	gt_ctl_del(log, "inet.stat");
	gt_ctl_del(log, GT_CTL_INET_RX_CKSUM_OFFLOAD);
	gt_ctl_del(log, GT_CTL_INET_TX_CKSUM_OFFLOAD);
	gt_log_scope_deinit(log, &this_log);
}

int
gt_inet_eth_in(struct gt_inet_context *ctx, struct gt_route_if *ifp, void *buf,
	int cnt)
{
	int rc;

	ctx->inp_ifp = ifp;
	ctx->inp_cur = buf;
	ctx->inp_rem = cnt;
	ctx->inp_eno = 0;
	ctx->inp_ipproto = 0;
	ctx->inp_emb_ipproto = 0;
	ctx->inp_eth_h = (struct gt_eth_hdr *)ctx->inp_cur;
	GT_INET_SHIFT(ctx, sizeof(struct gt_eth_hdr));
	switch (ctx->inp_eth_h->ethh_type) {
	case GT_ETH_TYPE_IP4_BE:
		ctx->inp_ipproto = IPPROTO_IP;
		rc = gt_inet_ip_in(ctx);
		break;
	case GT_ETH_TYPE_ARP_BE:
		rc = gt_inet_arp_in(ctx);
		break;
	default:
		rc = GT_INET_BYPASS;
	}
	return rc;
}

void
gt_inet_ip4_set_cksum(struct gt_ip4_hdr *ip4_h, void *l4_h)
{
	uint16_t ip4_cksum, udp_cksum;
	struct gt_udp_hdr *udp_h;
	struct gt_tcp_hdr *tcp_h;

	if (gt_inet_tx_cksum_offload) {
		ip4_cksum = 0;
		udp_cksum = 0;
	} else {
		ip4_cksum = gt_inet_ip4_calc_cksum(ip4_h);
		udp_cksum = gt_inet_ip4_udp_calc_cksum(ip4_h);
	}
	ip4_h->ip4h_cksum = ip4_cksum;
	switch (ip4_h->ip4h_proto) {
	case IPPROTO_UDP:
		udp_h = l4_h;
		udp_h->udph_cksum = udp_cksum;
		break;
	case IPPROTO_TCP:
		tcp_h = l4_h;
		tcp_h->tcph_cksum = udp_cksum;
		break;
	}
}

int
gt_tcp_opts_fill(struct gt_tcp_opts *opts, void *buf)
{
	uint8_t *ptr;
	int i, kind;

	for (i = 0, ptr = buf; i < GT_ARRAY_SIZE(gt_inet_tcp_opts); ++i) {
		kind = gt_inet_tcp_opts[i].tcpopt_kind;
		if (opts->tcpo_flags & (1 << kind)) {
			ptr += gt_tcp_opt_fill(ptr, opts, kind);
		}
	}
	while ((ptr - (uint8_t *)buf) & 0x3) {
		*ptr++ = GT_TCP_OPT_NOP;
	}
	return ptr - (uint8_t *)buf;
}

int
gt_tcp_opts_len(struct gt_tcp_opts *opts)
{
	int i, len;
	struct gt_inet_tcp_opt *opt;

	for (i = 0, len = 0; i < GT_ARRAY_SIZE(gt_inet_tcp_opts); ++i) {
		opt = gt_inet_tcp_opts + i;
		if (opts->tcpo_flags & (1 << opt->tcpopt_kind)) {
			len += opt->tcpopt_len;
		}
	}
	len = GT_ROUND_UP(len, 4);	
	return len;
}

// static
static uint8_t *
gt_inet_fill_16(uint8_t *buf, gt_be16_t v)
{
	*((gt_be16_t *)buf) = v;
	return buf + sizeof(v);
}

static uint8_t *
gt_inet_fill_32(uint8_t *buf, gt_be32_t v)
{
	*((gt_be32_t *)buf) = v;
	return buf + sizeof(v);
}

static uint64_t
gt_inet_cksum_add(uint64_t sum, uint64_t x)
{
	sum += x;
	if (sum < x) {
		++sum;
	}
	return sum;
}

static uint64_t
gt_inet_cksum_raw(const uint8_t *b, size_t size)
{
	uint64_t sum;

	sum = 0;
	while (size >= sizeof(uint64_t)) {
		sum = gt_inet_cksum_add(sum, *((uint64_t *)b));
		size -= sizeof(uint64_t);
		b += sizeof(uint64_t);
	}
	if (size >= 4) {
		sum = gt_inet_cksum_add(sum, *((uint32_t *)b));
		size -= sizeof(uint32_t);
		b += sizeof(uint32_t);
	}
	if (size >= 2) {
		sum = gt_inet_cksum_add(sum, *((uint16_t *)b));
		size -= sizeof(uint16_t);
		b += sizeof(uint16_t);
	}
	if (size) {
		assert(size == 1);
		sum = gt_inet_cksum_add(sum, *b);
	}
	return sum;
}

static uint16_t
gt_inet_cksum_reduce(uint64_t sum)
{
	uint64_t mask;

	mask = 0xffffffff00000000lu;
	while (sum & mask) {
		sum = gt_inet_cksum_add(sum & ~mask, (sum >> 32) & ~mask);
	}
	mask = 0xffffffffffff0000lu;
	while (sum & mask) {
		sum = gt_inet_cksum_add(sum & ~mask, (sum >> 16) & ~mask);
	}
	return ~((uint16_t)sum);
}

static uint16_t
gt_inet_ip4_calc_cksum(struct gt_ip4_hdr *ip4_h)
{
	int ip4_h_len;
	uint64_t sum;
	uint16_t reduce;

	ip4_h_len = GT_IP4_HDR_LEN(ip4_h->ip4h_ver_ihl);
	sum = gt_inet_cksum_raw((void *)ip4_h, ip4_h_len);
	reduce = gt_inet_cksum_reduce(sum);
	return reduce;
}

static uint64_t
gt_inet_ip4_pseudo_calc_cksum(struct gt_ip4_hdr *ip4_h, uint16_t len)
{	
	uint64_t sum;
	struct gt_ip4_pseudo_hdr ip4_pseudo_h;

	memset(&ip4_pseudo_h, 0, sizeof(ip4_pseudo_h));
	ip4_pseudo_h.ip4ph_saddr = ip4_h->ip4h_saddr;
	ip4_pseudo_h.ip4ph_daddr = ip4_h->ip4h_daddr;
	ip4_pseudo_h.ip4ph_pad = 0;
	ip4_pseudo_h.ip4ph_proto = ip4_h->ip4h_proto;
	ip4_pseudo_h.ip4ph_len = GT_HTON16(len);
	sum = gt_inet_cksum_raw((void *)&ip4_pseudo_h, sizeof(ip4_pseudo_h));
	return sum;
}

static uint16_t
gt_inet_ip4_udp_calc_cksum(struct gt_ip4_hdr *ip4_h)
{
	int ip4_h_len;
	uint16_t total_len, len;
	uint64_t sum, pseudo_cksum;
	void *udp_h;

	total_len = GT_NTOH16(ip4_h->ip4h_total_len);
	ip4_h_len = GT_IP4_HDR_LEN(ip4_h->ip4h_ver_ihl);
	len = total_len - ip4_h_len;
	udp_h = ((uint8_t *)ip4_h) + ip4_h_len;
	sum = gt_inet_cksum_raw(udp_h, len);
	pseudo_cksum = gt_inet_ip4_pseudo_calc_cksum(ip4_h, len);
	sum = gt_inet_cksum_add(sum, pseudo_cksum);
	sum = gt_inet_cksum_reduce(sum);
	return sum;
}

//static gt_be16_t
//gt_ip4_hdr_frag_off(uint16_t off, uint8_t flags)
//{
//	gt_be16_t x;
//
//	x = GT_HTON16(off);
//	*((uint8_t *)(&x)) |= flags;
//	return x;
//}

static int
gt_tcp_opt_len(int kind)
{
	int i;

	for (i = 0; i < GT_ARRAY_SIZE(gt_inet_tcp_opts); ++i) {
		if (gt_inet_tcp_opts[i].tcpopt_kind == kind) {
			return gt_inet_tcp_opts[i].tcpopt_len;
		}
	}
	return 0;
}

static int
gt_inet_arp_in(struct gt_inet_context *ctx)
{
	int i, rc, is_req;
	gt_be32_t sip, tip;
	struct gt_route_if_addr *ifa;
	struct gt_arp_advert_msg advert_msg;

	gt_arps.arps_received++;
	if (ctx->inp_rem < sizeof(struct gt_arp_hdr)) {
		gt_arps.arps_toosmall++;
		return GT_INET_DROP;
	}
	ctx->inp_arp_h = (struct gt_arp_hdr *)ctx->inp_cur;
	GT_INET_SHIFT(ctx, sizeof(struct gt_arp_hdr));
	if (ctx->inp_arp_h->arph_hrd != GT_ARP_HRD_ETH_BE) {
		gt_arps.arps_badhrd++;
		return GT_INET_DROP;
	}
	if (ctx->inp_arp_h->arph_pro != GT_ETH_TYPE_IP4_BE) {
		gt_arps.arps_badpro++;
		return GT_INET_DROP;
	}
	tip = ctx->inp_arp_h->arph_data.arpip_tip;
	sip = ctx->inp_arp_h->arph_data.arpip_sip;
	ifa = gt_route_if_addr_get4(tip);
	if (ifa == NULL) {
		gt_arps.arps_bypassed++;
		return GT_INET_BYPASS;
	}
	for (i = 0; i < ctx->inp_ifp->rif_nr_addrs; ++i) {
		if (ifa == ctx->inp_ifp->rif_addrs[i]) {
			break;		
		}
	}
	if (i == ctx->inp_ifp->rif_nr_addrs) {
		gt_arps.arps_filtered++;
		return GT_INET_DROP;
	}
	if (ctx->inp_arp_h->arph_hlen != sizeof(struct gt_eth_addr)) {
		gt_arps.arps_badhlen++;
		return GT_INET_DROP;
	}
	if (ctx->inp_arp_h->arph_plen != sizeof(gt_be32_t)) {
		gt_arps.arps_badplen++;
		return GT_INET_DROP;
	}
	if (gt_ip_addr4_is_loopback(tip)) {
		gt_arps.arps_badaddr++;
		return GT_INET_DROP;
	}
	if (gt_ip_addr4_is_bcast(tip)) {
		gt_arps.arps_badaddr++;
		return GT_INET_DROP;
	}
	if (gt_ip_addr4_is_loopback(sip)) {
		gt_arps.arps_badaddr++;
		return GT_INET_DROP;
	}
	if (gt_ip_addr4_is_bcast(sip)) {
		gt_arps.arps_badaddr++;
		return GT_INET_DROP;
	}
	// IP4 duplicate address detection
	if (sip == 0) {
		// TODO: reply
		return GT_INET_OK;
	}
	rc = GT_INET_OK;
	switch (ctx->inp_arp_h->arph_op) {
	case GT_ARP_OP_REQUEST_BE:
		gt_arps.arps_rxrequests++;
		is_req = 1;
		gt_arp_reply(ctx->inp_ifp, ctx->inp_arp_h);
		break;
	case GT_ARP_OP_REPLY_BE:
		gt_arps.arps_rxreplies++;
		rc = GT_INET_BCAST;
		is_req = 0;
		break;
	default:
		gt_arps.arps_badop++;
		return GT_INET_OK;
	}
	advert_msg.arpam_af = AF_INET;
	advert_msg.arpam_advert = !is_req;
	advert_msg.arpam_solicited = !is_req;
	advert_msg.arpam_override = !is_req;
	advert_msg.arpam_next_hop = ctx->inp_arp_h->arph_data.arpip_sip;
	advert_msg.arpam_addr = ctx->inp_arp_h->arph_data.arpip_sha;
	gt_arp_update(&advert_msg);
	return rc;
}

static int
gt_inet_ip_in(struct gt_inet_context *ctx)
{
	int rc, total_len, cksum;

	gt_ips.ips_total++;
	gt_ips.ips_delivered++;
	if (ctx->inp_rem < sizeof(struct gt_ip4_hdr)) {
		gt_ips.ips_toosmall++;
		return GT_INET_DROP;
	}
	ctx->inp_ip4_h = (struct gt_ip4_hdr *)(ctx->inp_eth_h + 1);
	if (ctx->inp_ip4_h->ip4h_ttl < 1) {
		return GT_INET_DROP;
	}
	if (gt_ip_addr4_is_mcast(ctx->inp_ip4_h->ip4h_saddr)) {
		return GT_INET_BYPASS;
	}
	if (ctx->inp_ip4_h->ip4h_frag_off & GT_IP4H_FRAG_MASK) {
		gt_ips.ips_fragments++;
		gt_ips.ips_fragdropped++;
		return GT_INET_BYPASS;
	}
	ctx->inp_ip_h_len = GT_IP4_HDR_LEN(ctx->inp_ip4_h->ip4h_ver_ihl);
	if (ctx->inp_ip_h_len < sizeof(*ctx->inp_ip4_h)) {
		gt_ips.ips_badhlen++;
		return GT_INET_DROP;
	}
	if (ctx->inp_rem < ctx->inp_ip_h_len) {
		gt_ips.ips_badhlen++;
		return GT_INET_DROP;
	}
	GT_INET_SHIFT(ctx, ctx->inp_ip_h_len);
	total_len = GT_NTOH16(ctx->inp_ip4_h->ip4h_total_len);
	if (total_len > 65535) {
		gt_ips.ips_toolong++;
		return GT_INET_DROP;
	}
	if (total_len < ctx->inp_ip_h_len) {
		gt_ips.ips_badlen++;
		return GT_INET_DROP;
	}
	ctx->inp_ip_payload_len = total_len - ctx->inp_ip_h_len;
	if (ctx->inp_ip_payload_len > ctx->inp_rem) {
		gt_ips.ips_tooshort++;
		return GT_INET_DROP;
	}
	ctx->inp_ipproto = ctx->inp_ip4_h->ip4h_proto;
	cksum = ctx->inp_ip4_h->ip4h_cksum;
	ctx->inp_ip4_h->ip4h_cksum = 0;
	if (gt_inet_rx_cksum_offload == 0) {
		if (cksum != gt_inet_ip4_calc_cksum(ctx->inp_ip4_h)) {
			gt_ips.ips_badsum++;
			return GT_INET_DROP;
		}
	}
	ctx->inp_ip4_h->ip4h_cksum = cksum;
	switch (ctx->inp_ipproto) {
	case IPPROTO_UDP:
		if (ctx->inp_rem < sizeof(struct gt_udp_hdr)) {
			gt_udps.udps_badlen++;
			return GT_INET_DROP;
		}
		ctx->inp_udp_h = (struct gt_udp_hdr *)ctx->inp_cur;
		GT_INET_SHIFT(ctx, sizeof(struct gt_udp_hdr));
		return GT_INET_OK;
	case IPPROTO_TCP:
		rc = gt_inet_tcp_in(ctx);
		break;
	case IPPROTO_ICMP:
		rc = gt_inet_icmp4_in(ctx);
		return rc;
	default:
		gt_ips.ips_noproto++;
		rc = GT_INET_BYPASS;
		break;
	}
	return rc;
}

static int
gt_inet_tcp_in(struct gt_inet_context *ctx)
{
	int rc, len, win, cksum;

	if (ctx->inp_rem < sizeof(struct gt_tcp_hdr)) {
		gt_tcps.tcps_rcvshort++;
		return GT_INET_DROP;
	}
	ctx->inp_tcp_h = (struct gt_tcp_hdr *)ctx->inp_cur;
	ctx->inp_tcp_h_len = GT_TCP_HDR_LEN(ctx->inp_tcp_h->tcph_data_off);
	if (ctx->inp_rem < ctx->inp_tcp_h_len) {
		gt_tcps.tcps_rcvshort++;
		return GT_INET_DROP;
	}
	GT_INET_SHIFT(ctx, ctx->inp_tcp_h_len);
	win = GT_NTOH16(ctx->inp_tcp_h->tcph_win_size);
	len = ctx->inp_ip_payload_len - ctx->inp_tcp_h_len;
	ctx->inp_tcb.tcb_win = win;
	ctx->inp_tcb.tcb_len = len;
	ctx->inp_tcb.tcb_flags = ctx->inp_tcp_h->tcph_flags;
	ctx->inp_tcb.tcb_seq = GT_NTOH32(ctx->inp_tcp_h->tcph_seq);
	ctx->inp_tcb.tcb_ack = GT_NTOH32(ctx->inp_tcp_h->tcph_ack);
	ctx->inp_payload = (uint8_t *)ctx->inp_tcp_h + ctx->inp_tcp_h_len;
	ctx->inp_tcb.tcb_opts.tcpo_flags = 0;
	cksum = ctx->inp_tcp_h->tcph_cksum;
	ctx->inp_tcp_h->tcph_cksum = 0;
	if (gt_inet_rx_cksum_offload == 0) {
		if (cksum != gt_inet_ip4_udp_calc_cksum(ctx->inp_ip4_h)) {
			gt_tcps.tcps_rcvbadsum++;
			return GT_INET_DROP;
		}
	}
	ctx->inp_tcp_h->tcph_cksum = cksum;
	rc = gt_inet_tcp_opts_in(&ctx->inp_tcb.tcb_opts,
	                         (void *)(ctx->inp_tcp_h + 1),
	                         ctx->inp_tcp_h_len - sizeof(*ctx->inp_tcp_h));
	if (rc) {
		gt_tcps.tcps_rcvbadoff++;
		return GT_INET_DROP;
	}
	return GT_INET_OK;
}

static int
gt_inet_tcp_opts_in(struct gt_tcp_opts *opts, uint8_t *opts_buf, int opts_len)
{
	int i, len, opt_len;
	uint8_t *data, kind;
	uint32_t val, ecr;

	opts->tcpo_flags = 0;
	if (opts_len & 0x3) {
		return -1;
	}
	i = 0;
	while (i < opts_len) {
		kind = opts_buf[i++];
		if (kind == GT_TCP_OPT_EOL) {
			if (i < opts_len) {
				return -1;
			}
			break;
		} else if (kind == GT_TCP_OPT_NOP) {
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
		if (kind >= GT_TCP_OPT_MAX) {
			continue;
		}
		opt_len = gt_tcp_opt_len(kind);
		if (opt_len == 0) {
			continue;
		}
		if (len != opt_len) {
			return -1;
		}
		switch (kind) {
		case GT_TCP_OPT_MSS:
			opts->tcpo_mss = GT_NTOH16(*((gt_be16_t *)data));
			break;
		case GT_TCP_OPT_WSCALE:
			opts->tcpo_wscale = *data;
			break;
		case GT_TCP_OPT_TIMESTAMPS:
			val = GT_NTOH32(*((gt_be32_t *)data + 0));
			ecr = GT_NTOH32(*((gt_be32_t *)data + 1));
			opts->tcpo_ts.tcpots_val = val;
			opts->tcpo_ts.tcpots_ecr = ecr;
			break;
		}
		opts->tcpo_flags |= (1 << kind);
	}
	return 0;
}

static int
gt_inet_icmp4_in(struct gt_inet_context *ctx)
{
	int ip4_h_len, type, code;

	if (ctx->inp_rem < sizeof(struct gt_icmp4_hdr)) {
		gt_icmps.icmps_tooshort++;
		return GT_INET_DROP;
	}
	ctx->inp_icmp4_h = (struct gt_icmp4_hdr *)ctx->inp_cur;
	GT_INET_SHIFT(ctx, sizeof(struct gt_icmp4_hdr));
	type = ctx->inp_icmp4_h->icmp4h_type;
	code = ctx->inp_icmp4_h->icmp4h_code;	
	if (type > ICMP_MAXTYPE) {
		return GT_INET_DROP;
	}
	gt_icmps.icmps_inhist[type]++;
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
			ctx->inp_eno = EHOSTUNREACH;
			break;
		case ICMP_UNREACH_NEEDFRAG:
			ctx->inp_eno = EMSGSIZE;
			break;
		default:
			gt_icmps.icmps_badcode++;
			return GT_INET_DROP;
		}
		break;
	case ICMP_TIMXCEED:
		if (code > 1) {
			gt_icmps.icmps_badcode++;
			return GT_INET_DROP;
		}
		// TODO:
		break;
	case ICMP_PARAMPROB:
		if (code > 1) {
			gt_icmps.icmps_badcode++;
			return GT_INET_DROP;
		}
		ctx->inp_eno = ENOPROTOOPT;
		break;
	case ICMP_SOURCEQUENCH:
		if (code) {
			gt_icmps.icmps_badcode++;
			return GT_INET_DROP;
		}
		// TODO:
		break;
	case ICMP_REDIRECT:
		if (code > 3) {
			gt_icmps.icmps_badcode++;
			return GT_INET_DROP;
		}
		// TODO:
		return GT_INET_BCAST;
	default:
		return GT_INET_BYPASS;
	}
	ctx->inp_emb_ip4_h = NULL;
	ctx->inp_emb_tcp_h = NULL;
	if (ctx->inp_rem < sizeof(*ctx->inp_emb_ip4_h)) {
		gt_icmps.icmps_badlen++;
		return GT_INET_DROP;
	}
	ctx->inp_emb_ip4_h = (struct gt_ip4_hdr *)ctx->inp_cur;
	ip4_h_len = GT_IP4_HDR_LEN(ctx->inp_emb_ip4_h->ip4h_ver_ihl);
	if (ip4_h_len < sizeof(*ctx->inp_emb_ip4_h)) {
		gt_icmps.icmps_badlen++;
		return GT_INET_DROP;
	}
	GT_INET_SHIFT(ctx, ip4_h_len);
	ctx->inp_emb_ipproto = ctx->inp_emb_ip4_h->ip4h_proto;
	switch (ctx->inp_emb_ipproto) {
	case IPPROTO_UDP:
		if (ctx->inp_rem < sizeof(*ctx->inp_emb_udp_h)) {
			gt_icmps.icmps_badlen++;
			return GT_INET_DROP;
		}
		ctx->inp_emb_udp_h = (struct gt_udp_hdr *)ctx->inp_cur;
		return GT_INET_BCAST;
	case IPPROTO_TCP:
		if (ctx->inp_rem < sizeof(*ctx->inp_emb_tcp_h)) {
			gt_icmps.icmps_badlen++;
			return GT_INET_BYPASS;
		}
		ctx->inp_emb_tcp_h = (struct gt_tcp_hdr *)ctx->inp_cur;
		return GT_INET_BCAST;
	case IPPROTO_ICMP:
		if (ctx->inp_rem < sizeof(*ctx->inp_emb_icmp4_h)) {
			gt_icmps.icmps_badlen++;
			return GT_INET_DROP;
		}
		ctx->inp_emb_icmp4_h = (struct gt_icmp4_hdr *)ctx->inp_cur;
		return GT_INET_BYPASS;
	default:
		return GT_INET_BYPASS;
	}
}

static int
gt_tcp_opt_fill(uint8_t *buf, struct gt_tcp_opts *opts, int kind)
{
	uint32_t val;
	uint8_t *ptr, *len;

	ptr = buf;
	*ptr++ = kind;
	len = ptr++;
	switch (kind) {
	case GT_TCP_OPT_MSS:
		ptr = gt_inet_fill_16(ptr, GT_HTON16(opts->tcpo_mss));
		break;
	case GT_TCP_OPT_WSCALE:
		*ptr++ = opts->tcpo_wscale;
		break;
	case GT_TCP_OPT_TIMESTAMPS:
		val = GT_HTON32(opts->tcpo_ts.tcpots_val);
		ptr = gt_inet_fill_32(ptr, val);
		val = GT_HTON32(opts->tcpo_ts.tcpots_ecr);
		ptr = gt_inet_fill_32(ptr, val);
		break;
	}
	*len = ptr - buf;
	return ptr - buf;
}

static void
gt_inet_ctl_add_stat_var(struct gt_log *log,
	const char *proto, uint64_t *val, const char *name)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "inet.stat.%s.%s", proto, name);
	gt_ctl_add_uint64(log, path, GT_CTL_RD, val, 0, 0);
}

static void
gt_inet_ctl_add_ip_stat(struct gt_log *log)
{
#define GT_X(x) gt_inet_ctl_add_stat_var(log, "ip", &gt_ips.ips_##x, #x);
	GT_IP_STAT(GT_X)
#undef GT_X
}

static void
gt_inet_ctl_add_arp_stat(struct gt_log *log)
{
#define GT_X(x) gt_inet_ctl_add_stat_var(log, "arp", &gt_arps.arps_##x, #x);
	GT_ARP_STAT(GT_X)
#undef GT_X
}

static void
gt_inet_ctl_add_udp_stat(struct gt_log *log)
{
#define GT_X(x) gt_inet_ctl_add_stat_var(log, "udp", &gt_udps.udps_##x, #x);
	GT_UDP_STAT(GT_X)
#undef GT_X
}

static void
gt_inet_ctl_add_tcp_stat(struct gt_log *log)
{
	int i;
	char name[64];

#define GT_X(x) gt_inet_ctl_add_stat_var(log, "tcp", &gt_tcps.tcps_##x, #x);
	GT_TCP_STAT(GT_X)
#undef GT_X
	for (i = 0; i < GT_ARRAY_SIZE(gt_tcps.tcps_states); ++i) {
		snprintf(name, sizeof(name), "states.%d", i);
		gt_inet_ctl_add_stat_var(log, "tcp",
		                         gt_tcps.tcps_states + i, name);
	}
}
