#include "ip.h"

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

struct nm_desc *nmd_main;
struct nm_desc *nmd_host;

static struct timeval up_tv;

static struct tcp_opt_field tcp_opt_fields[TCP_OPT_MAX] = {
	[TCP_OPT_MSS] = {
		.kind = TCP_OPT_MSS,
		.len = 4,
		.name = "mss"
	},
	[TCP_OPT_WSCALE] = {
		.kind = TCP_OPT_WSCALE,
		.len = 3,
		.name = "wscale",
	},
	[TCP_OPT_SACK_PERMITED] = {
		.kind = TCP_OPT_SACK_PERMITED,
		.len = 2,
		.name = "sackOK",
	},
	[TCP_OPT_TIMESTAMPS] = {
		.kind = TCP_OPT_TIMESTAMPS,
		.len = 10,
		.name = "TS"
	},
};

static void
dev_open(const char *ifname)
{
	struct nmreq nmr;
	//char buf[IFNAMSIZ + 16];

	memset(&nmr, 0, sizeof(nmr));
//	nmr.nr_rx_rings = 1;
//	nmr.nr_tx_rings = 1;
	nmd_main = nm_open(ifname, &nmr, 0, NULL);
	if (nmd_main == NULL) {
		die(errno, "nm_open('%s') failed", ifname);
	}
/*	memset(&nmr, 0, sizeof(nmr));
	nmr.nr_rx_rings = 1;
	nmr.nr_tx_rings = 1;
	snprintf(buf, sizeof(buf), "%s^", ifname);
	nmd_host = nm_open(buf, &nmr, 0, NULL);
	if (nmd_host == NULL) {
		dbg("nm_open('%s') failed (%d:%s)", buf, errno, strerror(errno));
	}*/
}

void
zc_fwd(struct netmap_ring *txr,
       struct netmap_ring *rxr, struct netmap_slot *src)
{
	uint32_t tmp;
	struct netmap_slot *dst;

	assert(!nm_ring_empty(txr));
	dst = txr->slot + txr->cur;
	tmp = dst->buf_idx;
	dst->buf_idx = src->buf_idx;
	dst->len = src->len;
	dst->flags = NS_BUF_CHANGED;
	src->buf_idx = tmp;
	src->flags = NS_BUF_CHANGED;
	txr->head = txr->cur = nm_ring_next(txr, txr->cur);
}

struct netmap_ring *
not_empty_txr(struct nm_desc *nmd)
{
	int i;
	struct netmap_ring *txr;

	while (1) {
		for (i = nmd->first_tx_ring; i <= nmd->last_tx_ring; ++i) {
			txr = NETMAP_TXRING(nmd->nifp, i);
			if (!nm_ring_empty(txr))
				return txr;
		}
		ioctl(nmd->fd, NIOCTXSYNC, NULL);
	}
}

/*static int
is_tcp_rst(const void *data, size_t len)
{
	int rem, ipv4_h_len;
	const struct eth_hdr *eth_h;
	const struct ipv4_hdr *ipv4_h;
	const struct tcp_hdr *tcp_h;

	rem = len;

	if (rem < sizeof(*eth_h))
		return 0;
	eth_h = data;
	if (eth_h->type != ETH_TYPE_IPV4)
		return 0;
	rem -= sizeof(*eth_h);

	if (rem < sizeof(*ipv4_h))
		return 0;
	ipv4_h = (struct ipv4_hdr *)(eth_h + 1);
	ipv4_h_len = ipv4_hdr_len(ipv4_h->ver_ihl);
	if (ipv4_h_len < sizeof(*ipv4_h))
		return 0;

	if (rem < ipv4_h_len + sizeof(*tcp_h))
		return 0;
	tcp_h = (struct tcp_hdr *)((const uint8_t *)ipv4_h + ipv4_h_len);

	return tcp_h->flags & TCP_FLAG_RST;
}*/

static int
get_first_slot(struct nm_desc *nmd, const uint8_t **data)
{
	int i;
	struct netmap_ring *rxr;
	struct netmap_slot *slot;

	for (i = nmd->first_rx_ring; i <= nmd->last_rx_ring; ++i) {
		rxr = NETMAP_RXRING(nmd->nifp, i);
		if (!nm_ring_empty(rxr)) {
			slot = rxr->slot + rxr->cur;
			*data = (const uint8_t *)NETMAP_BUF(rxr, slot->buf_idx);
			rxr->head = rxr->cur = nm_ring_next(rxr, rxr->cur);
			return slot->len;
		}
	}
	return 0;
}

static void
fwd(struct nm_desc *dst, struct nm_desc *src)
{
	int i;
	struct netmap_ring *rxr, *txr;
	struct netmap_slot *slot;

	for (i = src->first_rx_ring; i <= src->last_rx_ring; ++i) {
		rxr = NETMAP_RXRING(src->nifp, i);
		while (!nm_ring_empty(rxr)) {
			slot = rxr->slot + rxr->cur;
			// Drop tcp packets with RST flag
			//if (!is_tcp_rst(NETMAP_BUF(rxr, slot->buf_idx), slot->len)) {
				txr = not_empty_txr(dst);
				zc_fwd(txr, rxr, slot);
			//}
			rxr->head = rxr->cur = nm_ring_next(rxr, rxr->cur);
		}
	}
}

static int
recv_slot(const uint8_t **data)
{
	int rc, len, nr_pfds;
	struct pollfd pfds[2];

	pfds[0].fd = nmd_main->fd;
	pfds[0].events = POLLIN;
	if (nmd_host == NULL) {
		nr_pfds = 1;
	} else {
		pfds[1].fd = nmd_host->fd;
		pfds[1].events = POLLIN;
		pfds[1].revents = 0;
		nr_pfds = 2;
	}
	while (1) {
		rc = poll(pfds, nr_pfds, 1);
		if (rc == -1) {
			if (errno != EINTR) {
				die(errno, "poll() failed");
			}
		} else if (rc == 0) {
			return 0;
		} else {
			if (pfds[1].revents) {
				assert(nmd_host != NULL);
				fwd(nmd_main, nmd_host);
			}
			if (pfds[0].revents) {
				len = get_first_slot(nmd_main, data);
				if (len != 0) {
					return len;
				}
			}
		}
	}
	return 0;
}

static void
transmit(struct nm_desc *nmd, const void *data, size_t count)
{
	struct netmap_ring *txr;
	struct netmap_slot *slot;

	txr = not_empty_txr(nmd);
	slot = txr->slot + txr->cur;
	slot->len = count;
	memcpy(NETMAP_BUF(txr, slot->buf_idx), data, count);
	txr->head = txr->cur = nm_ring_next(txr, txr->cur);
}

size_t
ipv4_hdr_len(uint8_t ver_ihl)
{
	return (ver_ihl & 0x0f) << 2;
}

size_t
tcp_hdr_len(uint8_t data_off)
{
	return (data_off & 0xf0) >> 2;
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
ipv4_cksum_raw64(const uint8_t *b, size_t size)
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
ipv4_cksum_reduce64(uint64_t sum)
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

static uint16_t
ipv4_cksum(struct ipv4_hdr *ipv4_h)
{
	int ipv4_h_len;
	uint64_t sum;

	ipv4_h_len = ipv4_hdr_len(ipv4_h->ver_ihl);
	sum = ipv4_cksum_raw64((void *)ipv4_h, ipv4_h_len);
	return ipv4_cksum_reduce64(sum);
}

static uint64_t
ipv4_pseudo_cksum(struct ipv4_hdr *ipv4_h, uint16_t len)
{
	struct ipv4_pseudo_hdr ipv4_pseudo_h;

	memset(&ipv4_pseudo_h, 0, sizeof(ipv4_pseudo_h));
	ipv4_pseudo_h.saddr = ipv4_h->saddr;
	ipv4_pseudo_h.daddr = ipv4_h->daddr;
	ipv4_pseudo_h.pad = 0;
	ipv4_pseudo_h.proto = ipv4_h->proto;
	ipv4_pseudo_h.len = CPU_TO_BE16(len);
	return ipv4_cksum_raw64((void *)&ipv4_pseudo_h, sizeof(ipv4_pseudo_h));
}

static uint16_t
ipv4_tcp_cksum(struct ipv4_hdr *ipv4_h)
{
	int ipv4_h_len;
	uint16_t total_len, len;
	uint64_t sum;
	void *tcp_h;

	total_len = BE16_TO_CPU(ipv4_h->total_len);
	ipv4_h_len = ipv4_hdr_len(ipv4_h->ver_ihl);
	len = total_len - ipv4_h_len;
	tcp_h = ((uint8_t *)ipv4_h) + ipv4_h_len;
	sum = ipv4_cksum_raw64(tcp_h, len);
	sum = cksum_add(sum, ipv4_pseudo_cksum(ipv4_h, len));
	return ipv4_cksum_reduce64(sum);
}

static uint16_t
icmpv4_cksum(struct ipv4_hdr *ipv4_h)
{
	int ipv4_h_len;
	uint16_t total_len, len;
	uint64_t sum;
	void *icmpv4_h;

	total_len = BE16_TO_CPU(ipv4_h->total_len);
	ipv4_h_len = ipv4_hdr_len(ipv4_h->ver_ihl);
	len = total_len - ipv4_h_len;
	icmpv4_h = ((uint8_t *)ipv4_h) + ipv4_h_len;
	sum = ipv4_cksum_raw64(icmpv4_h, len);
	return ipv4_cksum_reduce64(sum);
}

unsigned int
get_mseconds()
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (tv.tv_sec - up_tv.tv_sec) * 1000 +
		(tv.tv_usec - up_tv.tv_usec) / 1000;
}

void
dev_init(struct if_dev *dev, const char *ifname)
{
	int ifname_len;

	ifname_len = strlen(ifname);
	if (ifname_len >= sizeof(dev->ifname)) {
		die(0, "too long ifname '%s'", ifname);
	}
	strcpy(dev->ifname, ifname);
	dev_open(ifname);
	gettimeofday(&up_tv, NULL);
}

int
dev_recv(struct if_dev *dev, const uint8_t **data, unsigned int *to)
{
	char daddr_buf[ETH_ADDRSTRLEN];
	char hwaddr_buf[ETH_ADDRSTRLEN];
	int len;
	unsigned int start, now, dur;
	struct eth_hdr *eth_h;

	start = get_mseconds();
	while (1) {
		len = recv_slot(data);
		now = get_mseconds();
		dur = now - start;
		if (len == 0) {
			if (to != NULL) {
				if (*to < dur) {
					*to = 0;
					return 0;
				}
			}
			continue;
		}
		if (len < sizeof(*eth_h)) {
			dbg("packet too small: len=%u", len);
			continue;
		}
		eth_h = (struct eth_hdr *)*data;
		if (eth_is_bcast(&eth_h->daddr) == 0 &&
		    memcmp(&eth_h->daddr, &dev->s_hwaddr, sizeof(dev->s_hwaddr))) {
			dbg("skip packet: daddr=%s, hwaddr=%s",
			    eth_ntoa(&eth_h->daddr, daddr_buf),
			    eth_ntoa(&dev->s_hwaddr, hwaddr_buf));
			continue;
		}
		if (to != NULL) {
			*to = *to < dur ? 0 : *to - dur;
		}
		return len;
	}
}

void
dev_send(struct if_dev *dev, const struct sockaddr_in *addr,
         const void *buf, size_t count)
{
	transmit(nmd_main, buf, count);
}

void
dev_put(const void *buf, size_t count)
{
	if (nmd_host != NULL) {
		transmit(nmd_host, buf, count);
	}
}

static uint8_t *
fill_be16(uint8_t *ptr, be16_t x)
{
	*((be16_t *)ptr) = x;
	return ptr + sizeof(x);
}

static uint8_t *
fill_be32(uint8_t *ptr, be32_t x)
{
	*((be32_t *)ptr) = x;
	return ptr + sizeof(x);
}

static int
fill_tcp_opt_field(uint8_t *buf, struct tcp_opt *tcp_opt, int kind)
{
	uint8_t *ptr;
	const struct tcp_opt_field *field;

	field = tcp_opt_fields + kind;
	if (field->kind == 0) {
		return 0;
	}
	ptr = buf;
	*ptr++ = field->kind;
	*ptr++ = field->len;
	switch (kind) {
	case TCP_OPT_MSS:
		ptr = fill_be16(ptr, CPU_TO_BE16(tcp_opt->mss));
		break;
	case TCP_OPT_WSCALE:
		*ptr++ = tcp_opt->wscale;
		break;
	case TCP_OPT_SACK_PERMITED:
		break;
	case TCP_OPT_TIMESTAMPS:
		ptr = fill_be32(ptr, CPU_TO_BE32(tcp_opt->ts.val));
		ptr = fill_be32(ptr, CPU_TO_BE32(tcp_opt->ts.ecr));
		break;
	}
	assert(ptr - buf == field->len);
	while ((ptr - buf) & 0x3) {
		*ptr++ = TCP_OPT_NOP;
	}
	return ptr - buf;
}

static int
fill_tcp_opt(uint8_t *buf, struct tcp_opt *tcp_opt)
{
	int kind, len;

	len = 0;
	for (kind = 0; kind < TCP_OPT_MAX; ++kind) {
		if (test_bit(tcp_opt->flags, kind)) {
			 len += fill_tcp_opt_field(buf + len, tcp_opt, kind);
		}
	}
	return len;
}

static int
fill_eth_hdr(struct if_dev *dev, void *buf, struct proto_cb *pcb)
{
	struct eth_hdr *eth_h;

	eth_h = buf;
	eth_h->type = CPU_TO_BE16(pcb->eth_type);
	eth_h->saddr = pcb->eth_saddr;
	eth_h->daddr = pcb->eth_daddr;
	return sizeof(*eth_h);
}

static int
get_eth_hdr(struct if_dev *dev, struct proto_cb *pcb, const uint8_t *buf)
{
	const struct eth_hdr *eth_h;

	eth_h = (const struct eth_hdr *)buf;
	pcb->eth_type = BE16_TO_CPU(eth_h->type);
	pcb->eth_saddr = eth_h->saddr;
	pcb->eth_daddr = eth_h->daddr;
	return sizeof(*eth_h);
}

int
fill_pkt(struct if_dev *dev, void *buf, struct proto_cb *pcb, const uint8_t *data)
{
	int len, l2_len, tcp_opts_len, off, h_len;
	void *l3;
	uint8_t *frag_off_flags, *ip_data_ptr, *data_ptr;
	struct arp_hdr *arp_h;
	struct ipv4_hdr *ipv4_h;
	struct tcp_hdr *tcp_h;
	struct icmpv4_hdr *icmpv4_h;

	ipv4_h = NULL;
	tcp_h = NULL;
	icmpv4_h = NULL;
	l2_len = fill_eth_hdr(dev, buf, pcb);
	l3 = (uint8_t *)buf+ l2_len;
	switch (pcb->eth_type) {
	case ETH_TYPE_ARP:
		arp_h = l3;
		arp_h->hrd = ARP_HRD_ETH_BE;
		arp_h->pro = ETH_TYPE_IPV4_BE;
		arp_h->hlen = ETH_ADDR_LEN;
		arp_h->plen = 4;
		arp_h->op = CPU_TO_BE16(pcb->arp.op);
		arp_h->data = pcb->arp.ipv4;
		return l2_len + sizeof(*arp_h);
	case ETH_TYPE_IPV4:
		ipv4_h = l3;
		break;
	default:
		assert(!"not implemented");
		break;
	}
	h_len = 0;
	ip_data_ptr = (void *)(ipv4_h + 1);
	switch (pcb->ip.proto) {
	case IPPROTO_TCP:
		tcp_h = (struct tcp_hdr *)ip_data_ptr;
		tcp_opts_len = fill_tcp_opt((uint8_t *)(tcp_h + 1), &pcb->tcp.opt);
		h_len = sizeof(*tcp_h) + tcp_opts_len;
		assert(h_len % 4 == 0);
		assert(h_len <= TCP_HDR_LEN_MAX);
		tcp_h->sport = pcb->tcp.sport;
		tcp_h->dport = pcb->tcp.dport;
		tcp_h->seq = CPU_TO_BE32(pcb->tcp.seq);
		tcp_h->ack = CPU_TO_BE32(pcb->tcp.ack);
		tcp_h->data_off = h_len << 2;
		tcp_h->flags = pcb->tcp.flags;
		tcp_h->win_size = CPU_TO_BE16(pcb->tcp.win);
		tcp_h->cksum = 0;
		tcp_h->urgent_ptr = 0;
		break;
	case IPPROTO_ICMP:
		icmpv4_h = (struct icmpv4_hdr *)ip_data_ptr;
		memset(icmpv4_h, 0, sizeof(*icmpv4_h));
		icmpv4_h->type = pcb->icmpv4.type;
		icmpv4_h->code = pcb->icmpv4.code;
		switch (icmpv4_h->type) {
		case ICMPV4_TYPE_ECHO:
		case ICMPV4_TYPE_ECHO_REPLY:
			icmpv4_h->echo.id = CPU_TO_BE16(pcb->icmpv4.echo.id);
			icmpv4_h->echo.seq = CPU_TO_BE16(pcb->icmpv4.echo.seq);
			break;
		case ICMPV4_TYPE_DEST_UNREACHABLE:
			switch (icmpv4_h->code) {
			case ICMPV4_CODE_FRAG_NEEDED_AND_DF_WAS_SET:
				icmpv4_h->ptb.mtu = CPU_TO_BE16(pcb->icmpv4.ptb.mtu);
				break;
			default:
				assert(!"not implemented");
				break;	
			}
			break; 
		default:
			assert(!"not implemented");
			break;
		}
		h_len = sizeof(*icmpv4_h);
		break;
	default:
		assert(!"not implemented");
		break;
	}
	assert(h_len);
	len = sizeof(*ipv4_h) + h_len + pcb->ip.len;
	if (len > UINT16_MAX) {
		return -EINVAL;
	}
	data_ptr = (uint8_t *)(ipv4_h + 1) + h_len;
	if (data != NULL) {
		memcpy(data_ptr, data, pcb->ip.len);
	} else {
		memset(data_ptr, 0, pcb->ip.len);
	}
	off = pcb->ip.v4.frag_off << 3;
	if (off > len) {
		off = 0;
	}
	if (off == 0) {
		 pcb->ip.v4.len = len;
	}
	if (pcb->ip.v4.len == 0 || pcb->ip.v4.len > len - off) {
		pcb->ip.v4.len = len - off;
	}
	ipv4_h->ver_ihl = IPV4_VER_IHL;
	ipv4_h->type_of_svc = 0;
	ipv4_h->total_len = CPU_TO_BE16(pcb->ip.v4.len);
	ipv4_h->id = CPU_TO_BE16(pcb->ip.v4.id);
	ipv4_h->frag_off = CPU_TO_BE16(pcb->ip.v4.frag_off);
	frag_off_flags = (uint8_t *)&ipv4_h->frag_off;
	(*frag_off_flags) |= pcb->ip.v4.flags;
	ipv4_h->ttl = 64;
	ipv4_h->proto = pcb->ip.proto;
	ipv4_h->cksum = 0;
	ipv4_h->saddr = pcb->ip.saddr.ipv4;
	ipv4_h->daddr = pcb->ip.daddr.ipv4;
	switch (pcb->ip.proto) {
	case IPPROTO_TCP:
		tcp_h->cksum = ipv4_tcp_cksum(ipv4_h);
		break;
	case IPPROTO_ICMP:
		icmpv4_h->cksum = icmpv4_cksum(ipv4_h); 
		break;
	default:
		assert(!"not implemented");
		break;
	}
	if (pcb->ip.v4.frag_off) {
		memmove(ip_data_ptr, ip_data_ptr + off, pcb->ip.v4.len - off);
	}
	ipv4_h->cksum = ipv4_cksum(ipv4_h);
	return l2_len + pcb->ip.v4.len;
}

static int
tcp_opt_in(struct tcp_opt *tcp_opt, const struct tcp_hdr *tcp_h, size_t tcp_h_len)
{
	size_t i, len, opts_len;
	uint8_t *opts, *data, kind;
	const struct tcp_opt_field *field;

	assert(sizeof(*tcp_h) <= tcp_h_len);
	tcp_opt->flags = 0;
	opts = (uint8_t *)(tcp_h + 1);
	opts_len = tcp_h_len - sizeof(*tcp_h);
	if (opts_len % sizeof(uint32_t)) {
		return -EINVAL;
	}
	i = 0;
	while (i < opts_len) {
		kind = opts[i++];
		if (kind == TCP_OPT_EOL) {
			if (i != opts_len) {
				return -EINVAL;
			}
			break;
		} else if (kind == TCP_OPT_NOP) {
			continue;
		}
		if (i == opts_len) {
			return -EINVAL;
		}
		len = opts[i++];
		if (len < 2) {
			return -EINVAL;
		}
		if (i + len - 2 > opts_len) {
			return -EINVAL;
		}
		data = opts + i;
		i += len - 2;
		if (kind >= TCP_OPT_MAX) {
			continue;
		}
		field = tcp_opt_fields + kind;
		if (field->kind == 0) {
			continue;
		}
		if (len != field->len) {
			return -EINVAL;
		}
		switch (kind) {
		case TCP_OPT_MSS:
			tcp_opt->mss = BE16_TO_CPU(*((uint16_t *)data));
			break;
		case TCP_OPT_WSCALE:
			tcp_opt->wscale = *data;
			break;
		case TCP_OPT_SACK_PERMITED:
			tcp_opt->sack_permited = 1;
			break;
		case TCP_OPT_TIMESTAMPS:
			tcp_opt->ts.val = BE32_TO_CPU(*((uint32_t *)data + 0));
			tcp_opt->ts.ecr = BE32_TO_CPU(*((uint32_t *)data + 1));
			break;
		}
		set_bit(&tcp_opt->flags, kind);
	}
	return 0;
}

const void *
tcp_input(struct if_dev *dev, struct proto_cb *pcb, const uint8_t *buf, size_t n)
{
	int ipv4_h_len, tcp_h_len, len, rem, total_len;
	uint8_t *frag_off_flags;
	be16_t frag_off;
	const struct arp_hdr *arp_h;
	const struct ipv4_hdr *ipv4_h;
	const struct tcp_hdr *tcp_h;
	const struct icmpv4_hdr *icmpv4_h;

	rem = n;
	pcb->l2_len = get_eth_hdr(dev, pcb, buf);
	if (rem < pcb->l2_len) {
		dbg("no space for ethernet header");
		return NULL;
	}
	rem -= pcb->l2_len;
	switch (pcb->eth_type) {
	case ETH_TYPE_ARP:
		if (rem < sizeof(*arp_h)) { 
			dbg("no space for ARP header");
			return NULL;
		}
		arp_h = (struct arp_hdr *)(buf + pcb->l2_len);
		if (arp_h->hrd != ARP_HRD_ETH_BE) {
			dbg("bad arp hrd %hu", BE16_TO_CPU(arp_h->hrd));
			return NULL;
		}
		if (arp_h->pro != ETH_TYPE_IPV4_BE) {
			dbg("bad arp pro %hu", BE16_TO_CPU(arp_h->pro));
			return NULL;
		}
		if (arp_h->hlen != ETH_ADDR_LEN) {
			dbg("bad arp hlen %hhu", arp_h->hlen);
			return NULL;
		}
		if (arp_h->plen != 4) {
			dbg("bad arp plen %hhu", arp_h->plen);
			return NULL;
		}
		pcb->arp.op = BE16_TO_CPU(arp_h->op);
		pcb->arp.ipv4 = arp_h->data;
		return arp_h + 1;
	case ETH_TYPE_IPV4:
		break;
	default:
		dbg("bad ethernet type: 0x%hx", pcb->eth_type);
		return NULL;
	}
	if (rem < sizeof(*ipv4_h)) {
		dbg("no space for IP header");
		return NULL;
	}
	ipv4_h = (const struct ipv4_hdr *)(buf + pcb->l2_len);
	frag_off = ipv4_h->frag_off;
	frag_off_flags = (uint8_t *)&frag_off;
	pcb->ip.v4.flags = (*frag_off_flags) & 0xE0;
	(*frag_off_flags) &= 0x3F;
	pcb->ip.v4.frag_off = BE16_TO_CPU(frag_off);
	pcb->ip.proto = ipv4_h->proto;
	pcb->ip.v4.id = BE16_TO_CPU(ipv4_h->id);
	ipv4_h_len = ipv4_hdr_len(ipv4_h->ver_ihl);
	total_len = BE16_TO_CPU(ipv4_h->total_len);
	pcb->ip.v4.len = total_len;
	if (rem < ipv4_h_len) {
		dbg("no space for IP options");
		return NULL;
	}
	rem -= ipv4_h_len;
	pcb->ip.daddr.ipv4 = ipv4_h->daddr;
	pcb->ip.saddr.ipv4 = ipv4_h->saddr;
	switch (ipv4_h->proto) {
	case IPPROTO_TCP:
		if (rem < sizeof(*tcp_h)) {
			dbg("no space for TCP hdr");
			return NULL;
		}
		tcp_h = (const struct tcp_hdr *)(((uint8_t *)ipv4_h) + ipv4_h_len);
		tcp_h_len = tcp_hdr_len(tcp_h->data_off);
		if (rem < tcp_h_len) {
			dbg("no space for TCP options");
			return NULL;
		}
		rem -= tcp_h_len;
		if (total_len < ipv4_h_len + tcp_h_len) {
			dbg("too small IP total length");
			return NULL;
		}
		len = total_len - ipv4_h_len - tcp_h_len;
		if (rem < len) {
			dbg("no space for IP total length");
			return NULL;
		}
		if (tcp_opt_in(&pcb->tcp.opt, tcp_h, tcp_h_len)) {
			dbg("bad TCP options");
			return NULL;
		}
		pcb->tcp.dport = tcp_h->dport;
		pcb->tcp.sport = tcp_h->sport;
		pcb->tcp.flags = tcp_h->flags;
		pcb->tcp.seq = BE32_TO_CPU(tcp_h->seq);
		pcb->tcp.ack = BE32_TO_CPU(tcp_h->ack);
		pcb->tcp.win = BE16_TO_CPU(tcp_h->win_size);
		pcb->ip.len = len;
		return (uint8_t *)tcp_h + tcp_h_len;
	case IPPROTO_ICMP:
		if (rem < sizeof(*icmpv4_h)) {
			dbg("no space for ICMP header");
			return NULL;
		}
		icmpv4_h = (const struct icmpv4_hdr *)(((uint8_t *)ipv4_h) + ipv4_h_len);
		rem -= sizeof(*icmpv4_h);
		if (total_len < ipv4_h_len + sizeof(*icmpv4_h)) {
			dbg("too small IP total length");
			return NULL;
		}
		len = total_len - ipv4_h_len - sizeof(*icmpv4_h);
		if (rem < len) {
			dbg("no space for IP total length");
			return NULL;
		}
		pcb->icmpv4.type = icmpv4_h->type;
		pcb->icmpv4.code = icmpv4_h->code;
		switch (icmpv4_h->type) {
		case ICMPV4_TYPE_ECHO:
		case ICMPV4_TYPE_ECHO_REPLY:
			pcb->icmpv4.echo.id = BE16_TO_CPU(icmpv4_h->echo.id);
			pcb->icmpv4.echo.seq = BE16_TO_CPU(icmpv4_h->echo.seq);
			break;
		case ICMPV4_TYPE_DEST_UNREACHABLE:
			pcb->icmpv4.ppm.ptr = icmpv4_h->ppm.ptr;
			break;
		case ICMPV4_TYPE_PARAM_PROBLEM:
			pcb->icmpv4.ptb.mtu = BE16_TO_CPU(icmpv4_h->ptb.mtu);
			break;
		}
		return (uint8_t *)(icmpv4_h + 1);
	default:
		dbg("unsupported IP proto: %u", ipv4_h->proto);
		return NULL;
	}
}
