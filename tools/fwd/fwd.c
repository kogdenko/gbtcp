#include <gbtcp/internals.h>

#define ETH_ADDR_LEN 6
#define ETH_TYPE_IP4 0x0800

typedef uint16_t be16_t;
typedef uint32_t be32_t;

struct eth_hdr {
	struct ethaddr daddr;
	struct ethaddr saddr;
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

struct fwd_dev {
	struct nm_desc *nmd;
	int tx_full;
	int cur_tx_ring_epoch;
	int cur_tx_ring;
};

struct pdu {
	struct eth_hdr *eth_h;
	struct ip4_hdr *ip4_h;
	struct udp_hdr *udp_h;
	void *payload;
	int len;
};

static struct ethaddr eth_saddr;
static struct ethaddr eth_daddr;
static int Tflag;
static int Mflag;
static int burst_size;
static int epoch;
static int rx_cksum;
static int tx_cksum;
static int zero_copy;
static int echo;
static int sock_hash_size;
static int sock_hash_mask;
static struct dlist txq;
static int nr_socks;
static int nr_socks_max;
static struct mbuf_pool sock_pool;
static struct dlist free_socks;
static struct dlist used_socks;
static struct dlist *sock_hash;
static unsigned long long cnt_not_an_UDP;
static unsigned long long cnt_bad_cksum;

static void
print_usage()
{
	printf("fwd [options] {if0} [if1]\n");
}

#ifdef __linux__
#define gt_cpu_set_t cpu_set_t
#else /* __linux__ */
#define gt_cpu_set_t cpuset_t
#endif /* __linux__ */

#define PEER(i) ((nr_devs - 1) - i)

#define UNIQV_CAT3(x, res) res
#define UNIQV_CAT2(x, y, z) UNIQV_CAT3(~, x##y##z)
#define UNIQV_CAT(x, y, z) UNIQV_CAT2(x, y, z)
#define UNIQV(n) UNIQV_CAT(n, _uniqv_, __LINE__)

#define FWD_DEV_FOREACH_RXRING(rxr, dev) \
	for (int UNIQV(i) = (dev)->nmd->first_rx_ring; \
		UNIQV(i) <= (dev)->nmd->last_rx_ring && \
		((rxr = NETMAP_RXRING((dev)->nmd->nifp, UNIQV(i))), 1); \
		++UNIQV(i))

#define FWD_DEV_FOREACH_TXRING_CONTINUE(i, txr, dev) \
	for (; i <= (dev)->nmd->last_tx_ring && \
		((txr = NETMAP_TXRING((dev)->nmd->nifp, i)), 1); \
		++i)

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
	int ip4_h_len, total_len, udp_len;

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
	pdu->payload = pdu->udp_h + 1;
	pdu->len = total_len - (ip4_h_len + sizeof(*pdu->udp_h));
//	gt_dbg("rem=%d, udp_len=%d, udp_h_len=%d",
//	       total_len - (ip4_h_len + (int)sizeof(*pdu->udp_h)),
//	       GT_NTOH16(pdu->udp_h->len), (int)sizeof(*pdu->udp_h));
	udp_len = ntoh16(pdu->udp_h->len);
	if (udp_len < sizeof(*pdu->udp_h)) {
		return -EINVAL;
	}
	if (udp_len - sizeof(*pdu->udp_h) != pdu->len) {
		return -EINVAL;
	}
	return 0;
}

static struct netmap_ring *
fwd_not_empty_txr(struct fwd_dev *dev)
{
	struct netmap_ring *txr;

	if (dev->tx_full) {
		return NULL;
	}
	if (dev->cur_tx_ring_epoch != epoch) {
		dev->cur_tx_ring_epoch = epoch;
		dev->cur_tx_ring = dev->nmd->first_tx_ring;
	}
	FWD_DEV_FOREACH_TXRING_CONTINUE(dev->cur_tx_ring, txr, dev) {
		if (!nm_ring_empty(txr)) {
			return txr;
		}
	}
	dev->tx_full = 1;
	return NULL;
}

static void
so_del(struct gt_sock *so)
{
	DLIST_REMOVE(so, so_list);
	DLIST_REMOVE(so, so_bindl);
	if (Mflag) {
		mbuf_free(&so->so_file.fl_mbuf);
	} else {
		DLIST_INSERT_HEAD(&free_socks, so, so_bindl);
	}
	nr_socks--;
}

static struct gt_sock *
so_alloc(struct dlist *bucket)
{
	struct gt_sock *so;

	if (nr_socks == nr_socks_max) {
		so = DLIST_LAST(&used_socks, struct gt_sock, so_bindl);
		so_del(so);
	}
	if (Mflag) {
		mbuf_alloc(NULL, &sock_pool, (struct mbuf **)&so);
	} else {
		assert(dlist_is_empty(&free_socks));
		so = DLIST_LAST(&free_socks, struct gt_sock, so_bindl);
		DLIST_REMOVE(so, so_bindl);
	}
	DLIST_INSERT_HEAD(&used_socks, so, so_bindl);
	DLIST_INSERT_HEAD(bucket, so, so_list);
	so->so_flags = 0;
	so->so_ssnt = 0;
	nr_socks++;
	return so;
}

static int
so_process(struct gt_sock *so)
{
	so->so_flags++;
	if (so->so_flags == 4) {
		so_del(so);
		return 0;
	} else {
		return 1;
	}
}

static int
so_fill(struct gt_sock *so, void *buf, int pay_len)
{
	int len;
	struct eth_hdr *eth_h;
	struct ip4_hdr *ip4_h;
	struct udp_hdr *udp_h;

	eth_h = buf;
	ip4_h = (struct ip4_hdr *)(eth_h + 1);
	udp_h = (struct udp_hdr *)(ip4_h + 1);
	len = sizeof(*ip4_h) + sizeof(*udp_h) + pay_len;
	eth_h->type = htons(ETH_TYPE_IP4);
	eth_h->saddr = eth_saddr;
	eth_h->daddr = eth_daddr;
	ip4_h->ver_ihl = GT_IP4H_VER_IHL;
	ip4_h->type_of_svc = 0;
	ip4_h->total_len = htons(len);
	ip4_h->id = 0;
	ip4_h->frag_off =  0;
	ip4_h->ttl = 64;
	ip4_h->proto = IPPROTO_UDP;
	ip4_h->cksum = 0;
	ip4_h->saddr = so->so_tuple.sot_laddr;
	ip4_h->daddr = so->so_tuple.sot_faddr;
	udp_h->sport = so->so_tuple.sot_lport;
	udp_h->dport = so->so_tuple.sot_fport;
	udp_h->len = htons(sizeof(*udp_h) + pay_len);
	udp_h->cksum = 0;
	memset(udp_h + 1, '.', pay_len);
	if (tx_cksum) {
		ip4_h->cksum = ip4_cksum(ip4_h);
		udp_h->cksum = ip4_udp_cksum(ip4_h);
	}
	return sizeof(*eth_h) + len;
}

static int
fwd(struct fwd_dev *src, struct fwd_dev *dst)
{
	int i, n, rc, more, found;
	uint32_t tmp, hash;
	struct netmap_slot *rx_slot, *tx_slot;
	struct netmap_ring *rxr, *txr;
	struct dlist *bucket;
	struct sock_tuple tuple;
	struct gt_sock *so;
	struct pdu pdu;

	more = 0;
	FWD_DEV_FOREACH_RXRING(rxr, src) {
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
				txr = fwd_not_empty_txr(dst);
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
			so = NULL;
			if (sock_hash_size) {
				tuple.sot_laddr = pdu.ip4_h->saddr;
				tuple.sot_faddr = pdu.ip4_h->daddr;
				tuple.sot_lport = pdu.udp_h->sport;
				tuple.sot_fport = pdu.udp_h->dport;
				hash = custom_hash(&tuple, sizeof(tuple), 0);
				bucket = sock_hash + (hash & sock_hash_mask);
				found = 0;
				DLIST_FOREACH(so, bucket, so_list) {
					if (!memcmp(&so->so_tuple, &tuple, sizeof(tuple))) {
						found = so_process(so);
						break;
					}
				}
				if (found == 0) {
					so = so_alloc(bucket);
					so->so_tuple = tuple;
				}
				if (Tflag) {
					if (so->so_ssnt == 0) {
						DLIST_INSERT_HEAD(&txq, so, so_txl);
					}
					so->so_ssnt++;
					so->so_lmss = pdu.len;
				}
			}
			if (Tflag) {
				goto next;
			}
			txr = fwd_not_empty_txr(dst);
			if (txr == NULL) {
				return 0;
			}
			tx_slot = txr->slot + txr->cur;
			if (sock_hash_size) {
				tx_slot->len = so_fill(so, NETMAP_BUF(txr, tx_slot->buf_idx), pdu.len);
			} else {
				if (echo) {
					pdu.eth_h->daddr = eth_daddr;
					pdu.eth_h->saddr = eth_saddr;
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
				memcpy(NETMAP_BUF(txr, tx_slot->buf_idx),
				       NETMAP_BUF(rxr, rx_slot->buf_idx),
				       rx_slot->len);
				tx_slot->len = rx_slot->len;
			}
			txr->head = txr->cur = nm_ring_next(txr, txr->cur);
next:
			rxr->head = rxr->cur = nm_ring_next(rxr, rxr->cur);
		}
	}
	if (Tflag) {
		while (!dlist_is_empty(&txq)) {
			so = DLIST_FIRST(&txq, struct gt_sock, so_txl);
			assert(so->so_ssnt);
			txr = fwd_not_empty_txr(dst);
			if (txr == NULL) {
				break;
			}
			so->so_ssnt--;
			if (so->so_ssnt == 0) {
				DLIST_REMOVE(so, so_txl);
			}
			tx_slot = txr->slot + txr->cur;
			tx_slot->len = so_fill(so, NETMAP_BUF(txr, tx_slot->buf_idx), so->so_lmss);
			txr->head = txr->cur = nm_ring_next(txr, txr->cur);
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
	die(NULL, 0, "invalid argument '-%c': %s", opt, val);
}

int
main(int argc, char **argv)
{
	int opt, i, rc, cpu, more, nr_devs;
	char ifname[IFNAMSIZ + 16];
	struct fwd_dev devs[2];
	struct pollfd pfds[2];
	struct gt_sock *so_buf;

	rc = service_init();
	if (rc) {
		fprintf(stderr, "Initialization failed\n");
		return 1;
	}
	dlist_init(&txq);
	burst_size = 512;
	nr_devs = 0;
	memset(devs, 0, sizeof(devs));
	ethaddr_aton(&eth_saddr, "ff:ff:ff:ff:f:ff");
	ethaddr_aton(&eth_daddr, "ff:ff:ff:ff:f:ff");
	while ((opt = getopt(argc, argv, "hi:S:D:TMrtzea:b:c:")) != -1) {
		switch (opt) {
		case 'h':
			print_usage();
			break;
		case 'i':
			if (nr_devs == 2) {
				print_usage();
				return 1;
			}
			snprintf(ifname, sizeof(ifname), "netmap:%s", optarg);
			devs[nr_devs].nmd = nm_open(ifname, NULL, 0, NULL);
			if (devs[nr_devs].nmd == NULL) {
				die(NULL, errno, "nm_open('%s') failed", ifname);
			}
			devs[nr_devs].cur_tx_ring = devs[nr_devs].nmd->first_tx_ring;
			pfds[nr_devs].fd = devs[nr_devs].nmd->fd;
			nr_devs++;
			break;
		case 'S':
			rc = ethaddr_aton(&eth_saddr, optarg);
			if (rc) {
				invalid_arg(opt, optarg);
			}
			break;
		case 'D':
			rc = ethaddr_aton(&eth_daddr, optarg);
			if (rc) {
				invalid_arg(opt, optarg);
			}
			break;
		case 'T':
			Tflag = 1;
			break;
		case 'M':
			Mflag = 1;
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
				die(NULL, -rc, "set_affinity(%d) failed", cpu);
			}
			break;
		case 'b':
			burst_size = strtoul(optarg, NULL, 10);
			break;
		case 'c':
			nr_socks_max = strtoul(optarg, NULL, 10);			
			break;
		}
	}
	if (!nr_devs) {
		print_usage();
		return 1;
	}
	if (nr_socks_max) {
		if (Mflag) {
			mbuf_pool_init(&sock_pool, sizeof(struct gt_sock));
		} else {
			dlist_init(&free_socks);
			so_buf = malloc(nr_socks_max * sizeof(struct gt_sock));
			for (i = 0; i < nr_socks_max; ++i) {
				DLIST_INSERT_HEAD(&free_socks, so_buf + i, so_bindl);
			}
		}
		dlist_init(&used_socks);
		sock_hash_size = upper_pow2_32(nr_socks_max * 3 / 2);
		sock_hash = malloc(sock_hash_size * sizeof(struct dlist));
		sock_hash_mask = sock_hash_size - 1;
		for (i = 0; i < sock_hash_size; ++i) {
			dlist_init(sock_hash + i);
		}
	}
	if (burst_size < 1 || burst_size > 4096) {
		die(NULL, 0, "invalid burst size: %d\n", burst_size);
	}
	while (1) {
		for (i = 0; i < nr_devs; ++i) {
			pfds[i].events = 0;
			pfds[i].revents = 0;
			if (devs[i].tx_full) {
				pfds[i].events |= POLLOUT;
			}
			if (i == 0 && devs[PEER(i)].tx_full == 0) {
				pfds[i].events |= POLLIN;
			}
		}
		poll(pfds, nr_devs, -1);
		epoch++;
		for (i = 0; i < nr_devs; ++i) {
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
