#include <gbtcp/gbtcp_lib.h>

#define ETH_ADDR_LEN 6
#define ETH_TYPE_IP4 0x0800

typedef uint16_t be16_t;
typedef uint32_t be32_t;

struct eth_addr {
	uint8_t bytes[ETH_ADDR_LEN];
} __attribute__((packed));

struct eth_hdr {
	struct eth_addr daddr;
	struct eth_addr saddr;
	be16_t type;
};

struct ip4_hdr {
	uint8_t ver_ihl;
	uint8_t type_of_svc;
	be16_t total_len;
	be16_t id;
	be16_t frag_off;
	uint8_t ttl;
	uint8_t proto;
	uint16_t cksum;
	be32_t saddr;
	be32_t daddr;
} __attribute__((packed));

struct ip4_pseudo_hdr {
	be32_t saddr;
	be32_t daddr;
	uint8_t pad;
	uint8_t proto;
	be16_t len;
} __attribute__((packed));

struct udp_hdr {                                                                                                       
	be16_t sport;                                                                                                  
	be16_t dport;                                                                                                  
	be16_t len;                                                                                                    
	uint16_t cksum;                                                                                                
} __attribute__((packed));

struct dev {
	struct nm_desc *nmd;
	int tx_full;
	int cur_tx_ring_epoch;
	int cur_tx_ring;
	struct eth_addr mac;
};

struct pdu {
	struct eth_hdr *eth_h;
	struct ip4_hdr *ip4_h;
	struct udp_hdr *udp_h;
};

static int burst_size;
static int epoch;
static int rx_cksum;
static int tx_cksum;
static int zero_copy;
static int echo;
static unsigned long long cnt_not_an_UDP;
static unsigned long long cnt_bad_cksum;

static void die(int errnum, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

#ifndef dbg
#define dbg(fmt, ...) do { \
	printf("%-20s %-5d %-20s: ", __FILE__, __LINE__, __func__); \
	printf(fmt, ##__VA_ARGS__); \
	printf("\n"); \
} while (0)
#endif /* dbg */

static void
die(int errnum, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	if (errnum) {
		printf(" (%d:%s)\n", errnum, strerror(errnum));
	} else {
		printf("\n");
	}
	abort();
}

static void
print_usage()
{
	printf("nm_echo [options] {if0} [if1]\n");
}

#ifdef __linux__
#define gt_cpu_set_t cpu_set_t
#else /* __linux__ */
#define gt_cpu_set_t cpuset_t
#endif /* __linux__ */

#define PEER(i) ((n - 1) - i)

#define UNIQV_CAT3(x, res) res
#define UNIQV_CAT2(x, y, z) UNIQV_CAT3(~, x##y##z)
#define UNIQV_CAT(x, y, z) UNIQV_CAT2(x, y, z)
#define UNIQV(n) UNIQV_CAT(n, _uniqv_, __LINE__)

#define DEV_FOREACH_RXRING(rxr, dev) \
	for (int UNIQV(i) = (dev)->nmd->first_rx_ring; \
		UNIQV(i) <= (dev)->nmd->last_rx_ring && \
		((rxr = NETMAP_RXRING((dev)->nmd->nifp, UNIQV(i))), 1); \
		++UNIQV(i))

#define DEV_FOREACH_TXRING_CONTINUE(i, txr, dev) \
	for (; i <= (dev)->nmd->last_tx_ring && \
		((txr = NETMAP_TXRING((dev)->nmd->nifp, i)), 1); \
		++i)

static int
eth_aton(struct eth_addr *a, const char *s)
{
	int rc;
	struct eth_addr x;

	rc = sscanf(s, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
	            x.bytes + 0, x.bytes + 1, x.bytes + 2,
	            x.bytes + 3, x.bytes + 4, x.bytes + 5);
	if (rc == 6) {
		*a = x;
		return 0;
	} else {
		return -EINVAL;
	}
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
ip4_cksum_raw64(const uint8_t *b, size_t size)
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
ip4_cksum_reduce64(uint64_t sum)
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

static inline int
ip4_hdr_len(uint8_t ver_ihl)
{
	return (ver_ihl & 0x0f) << 2;
}

static uint16_t
ip4_cksum(struct ip4_hdr *ip4_h)
{
	int ip4_h_len;
	uint64_t sum;
	uint16_t reduce;

	ip4_h_len = ip4_hdr_len(ip4_h->ver_ihl);
	sum = ip4_cksum_raw64((void *)ip4_h, ip4_h_len);
	reduce = ip4_cksum_reduce64(sum);
	return reduce;
}

static uint64_t
ip4_pseudo_cksum(struct ip4_hdr *ip4_h, uint16_t len)
{	
	uint64_t sum;
	struct ip4_pseudo_hdr ip4_pseudo_h;

	memset(&ip4_pseudo_h, 0, sizeof(ip4_pseudo_h));
	ip4_pseudo_h.saddr = ip4_h->saddr;
	ip4_pseudo_h.daddr = ip4_h->daddr;
	ip4_pseudo_h.pad = 0;
	ip4_pseudo_h.proto = ip4_h->proto;
	ip4_pseudo_h.len = htons(len);
	sum = ip4_cksum_raw64((void *)&ip4_pseudo_h, sizeof(ip4_pseudo_h));
	return sum;
}

static uint16_t
ip4_udp_cksum(struct ip4_hdr *ip4_h)
{
	int ip4_h_len;
	uint16_t total_len, len;
	uint64_t sum;
	void *udp_h;

	total_len = ntohs(ip4_h->total_len);
	ip4_h_len = ip4_hdr_len(ip4_h->ver_ihl);
	len = total_len - ip4_h_len;
	udp_h = ((uint8_t *)ip4_h) + ip4_h_len;
	sum = ip4_cksum_raw64(udp_h, len);
	sum = cksum_add(sum, ip4_pseudo_cksum(ip4_h, len));
	sum = ip4_cksum_reduce64(sum);
	return sum;
}


static int
parse(void *data, unsigned int len, struct pdu *pdu)
{
	static int ip4_h_len, total_len;

	if (len < sizeof(*pdu->eth_h) + sizeof(*pdu->ip4_h)) {
		return -EINVAL;
	}
	pdu->eth_h = (struct eth_hdr *)data;
	if (ntohs(pdu->eth_h->type) != ETH_TYPE_IP4) {
		return -EINVAL;
	}
	pdu->ip4_h = (struct ip4_hdr *)(pdu->eth_h + 1);
	if (pdu->ip4_h->proto != IPPROTO_UDP) {
		return -EINVAL;
	}
	ip4_h_len = ip4_hdr_len(pdu->ip4_h->ver_ihl);
	if (ip4_h_len < sizeof(*pdu->ip4_h)) {
		return -EINVAL;
	}
	total_len = ntohs(pdu->ip4_h->total_len);
	if (total_len + sizeof(*pdu->eth_h) > len) {
		return -EINVAL;
	}
	if (total_len < ip4_h_len + sizeof(*pdu->udp_h)) {
		return -EINVAL;
	}
	pdu->udp_h = (struct udp_hdr *)(((uint8_t *)pdu->ip4_h) + ip4_h_len);
	return 0;
}

static struct netmap_ring *
not_empty_txr(struct dev *dev)
{
	struct netmap_ring *txr;

	if (dev->tx_full) {
		return NULL;
	}
	if (dev->cur_tx_ring_epoch != epoch) {
		dev->cur_tx_ring_epoch = epoch;
		dev->cur_tx_ring = dev->nmd->first_tx_ring;
	}
	DEV_FOREACH_TXRING_CONTINUE(dev->cur_tx_ring, txr, dev) {
		if (!nm_ring_empty(txr)) {
			return txr;
		}
	}
	dev->tx_full = 1;
	return NULL;
}

static int
fwd(struct dev *src, struct dev *dst)
{
	int i, n, rc, more;
	uint32_t tmp;
	struct netmap_slot *rx_slot, *tx_slot;
	struct netmap_ring *rxr, *txr;
	struct pdu pdu;

	more = 0;
	DEV_FOREACH_RXRING(rxr, src) {
		n = nm_ring_space(rxr);
		if (n > burst_size) {
			more = 1;
			n = burst_size;
		}
		for (i = 0; i < n; ++i) {
			rx_slot = rxr->slot + rxr->cur;
			if (rx_cksum || zero_copy == 0) { 
				rc = parse(NETMAP_BUF(rxr, rx_slot->buf_idx),
				           rx_slot->len, &pdu);
				if (rc) {
					cnt_not_an_UDP++;
					goto next;
				}
			}
			if (rx_cksum) {
				tmp = pdu.ip4_h->cksum;
				pdu.ip4_h->cksum = 0;
				pdu.ip4_h->cksum = ip4_cksum(pdu.ip4_h);
				if (tmp != pdu.ip4_h->cksum) {
					cnt_bad_cksum++;
					goto next;
				}
				tmp = pdu.udp_h->cksum;
				pdu.udp_h->cksum = 0;
				pdu.udp_h->cksum = ip4_udp_cksum(pdu.ip4_h);
				if (tmp != 0 && tmp != pdu.udp_h->cksum) {
					cnt_bad_cksum++;
					goto next;
				}
			}
			if (zero_copy) {
				txr = not_empty_txr(dst);
				if (txr == NULL) {
					return 0;
				}
				tx_slot = txr->slot + txr->cur;
				tmp = tx_slot->buf_idx;
				tx_slot->buf_idx = rx_slot->buf_idx;
				tx_slot->len = rx_slot->len;
				tx_slot->flags = NS_BUF_CHANGED;
				rx_slot->buf_idx = tmp;
				rx_slot->flags = NS_BUF_CHANGED;
				txr->head = txr->cur = nm_ring_next(txr, txr->cur);
				goto next;
			}
			pdu.eth_h->daddr = pdu.eth_h->saddr;
			pdu.eth_h->saddr = dst->mac;
			if (echo) {
				tmp = pdu.ip4_h->saddr;
				pdu.ip4_h->saddr = pdu.ip4_h->daddr;
				pdu.ip4_h->daddr = tmp;
				tmp = pdu.udp_h->sport;
				pdu.udp_h->sport = pdu.udp_h->dport;
				pdu.udp_h->dport = tmp;
				if (tx_cksum) {
					pdu.ip4_h->cksum = ip4_cksum(pdu.ip4_h);
					pdu.udp_h->cksum = ip4_udp_cksum(pdu.ip4_h);
				}
			}
			txr = not_empty_txr(dst);
			if (txr == NULL) {
				return 0;
			}
			tx_slot = txr->slot + txr->cur;
			memcpy(NETMAP_BUF(txr, tx_slot->buf_idx),
			       NETMAP_BUF(rxr, rx_slot->buf_idx),
			       rx_slot->len);
			tx_slot->len = rx_slot->len;
			txr->head = txr->cur = nm_ring_next(txr, txr->cur);
next:
			rxr->head = rxr->cur = nm_ring_next(rxr, rxr->cur);
		}
	}
	return more;
}

static int
set_affinity(int i)
{
	int rc;
	gt_cpu_set_t m;

	if (i < 0 || i > 32) {
		return -EINVAL;
	}
	CPU_ZERO(&m);
	CPU_SET(i, &m);
	rc = pthread_setaffinity_np(pthread_self(), sizeof(m), &m);
	return -rc;
}

static void
invalid_arg(int opt, const char *val)
{
	die(0, "invalid argument '-%c': %s", opt, val);
}

int
main(int argc, char **argv)
{
	int opt, i, n, rc, cpu, more;
	char ifname[IFNAMSIZ + 16];
	struct dev devs[2];
	struct pollfd pfds[2];
	struct eth_addr mac;

	burst_size = 512;
	n = 0;
	memset(devs, 0, sizeof(devs));
	eth_aton(&mac, "ff:ff:ff:ff:f:ff");
	while ((opt = getopt(argc, argv, "hi:M:rtzea:b:")) != -1) {
		switch (opt) {
		case 'h':
			print_usage();
			break;
		case 'i':
			if (n == 2) {
				print_usage();
				return 1;
			}
			snprintf(ifname, sizeof(ifname), "netmap:%s", optarg);
			devs[n].nmd = nm_open(ifname, NULL, 0, NULL);
			if (devs[n].nmd == NULL) {
				die(errno, "nm_open('%s') failed", ifname);
			}
			devs[n].cur_tx_ring = devs[n].nmd->first_tx_ring;
			devs[n].mac = mac;
			pfds[n].fd = devs[n].nmd->fd;
			n++;
			break;
		case 'M':
			rc = eth_aton(&mac, optarg);
			if (rc) {
				invalid_arg(opt, optarg);
			}
			break;
		case 'r':
			rx_cksum = 1;
			break;
		case 't':
			tx_cksum = 1;
			break;
		case 'z':
			zero_copy = 1;
			break;
		case 'e':
			echo = 1;
			break;
		case 'a':
			cpu = strtoul(optarg, NULL, 10);
			rc = set_affinity(cpu);
			if (rc) {
				die(-rc, "set_affinity(%d) failed", cpu);
			}
			break;
		case 'b':
			burst_size = strtoul(optarg, NULL, 10);
			break;
		}
	}
	if (!n) {
		print_usage();
		return 1;
	}
	if (burst_size < 1 || burst_size > 4096) {
		die(0, "invalid burst size: %d\n", burst_size);
	}
	while (1) {
		for (i = 0; i < n; ++i) {
			pfds[i].events = 0;
			pfds[i].revents = 0;
			if (devs[i].tx_full) {
				pfds[i].events |= POLLOUT;
			}
			if (i == 0 && devs[PEER(i)].tx_full == 0) {
				pfds[i].events |= POLLIN;
			}
		}
		poll(pfds, n, -1);
		epoch++;
		for (i = 0; i < n; ++i) {
			if (pfds[i].revents & POLLOUT) {
				devs[i].tx_full = 0;
			}
			if (i == 0 && (pfds[i].revents & POLLIN)) {
				do {
					more = fwd(devs + i, devs + PEER(i));
				} while (more);
			}
		}
	}
	printf("not_an_UDP  %llu\n", cnt_not_an_UDP);
	printf("bad_cksum   %llu\n", cnt_bad_cksum);
	return 0;
}
