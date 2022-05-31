#include "internals.h"

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#define CURMOD dev

#define DEV_RX_BURST_SIZE 256
#define DEV_TX_BURST_SIZE 64
#define NETMAP_PFX "netmap:"
#define NETMAP_DEV_NAMSIZ (IFNAMSIZ + 32)

#define DEV_FOREACH_TXRING(txr, dev) \
	for (int UNIQV(i) = (dev)->dev_nmd->first_tx_ring; \
	     UNIQV(i) <= (dev)->dev_nmd->last_tx_ring && \
	     ((txr = NETMAP_TXRING((dev)->dev_nmd->nifp, UNIQV(i))), 1); \
	     ++UNIQV(i))

#define DEV_FOREACH_TXRING_CONTINUE(i, txr, dev) \
	for (; i <= (dev)->dev_nmd->last_tx_ring && \
	     ((txr = NETMAP_TXRING((dev)->dev_nmd->nifp, i)), 1); \
	     ++i)

#define DEV_FOREACH_RXRING(rxr, dev) \
	for (int UNIQV(i) = (dev)->dev_nmd->first_rx_ring; \
	     UNIQV(i) <= (dev)->dev_nmd->last_rx_ring && \
	     ((rxr = NETMAP_RXRING((dev)->dev_nmd->nifp, UNIQV(i))), 1); \
	     ++UNIQV(i))

#define DEV_RXR_NEXT(rxr) \
	(rxr)->head = (rxr)->cur = nm_ring_next(rxr, (rxr)->cur)

static DLIST_HEAD(dev_head);

static const char *
netmap_dev_name(struct dev *dev, char *buf)
{
	if (dev->dev_queue_id == DEV_QUEUE_NONE) {
		strzcpy(buf, dev->dev_ifname, NETMAP_DEV_NAMSIZ);
	} else if (dev->dev_queue_id == DEV_QUEUE_HOST) {
		snprintf(buf, NETMAP_DEV_NAMSIZ, "%s%s^", NETMAP_PFX, dev->dev_ifname);
	} else {
		snprintf(buf, NETMAP_DEV_NAMSIZ, "%s%s-%d",
			NETMAP_PFX, dev->dev_ifname, dev->dev_queue_id);
	}
	return buf;
}

int
netmap_dev_rx(struct dev *dev)
{
	int i, n, rc, cur;
	struct netmap_ring *rxr;
	struct netmap_slot *slot;

	rc = 0;
	DEV_FOREACH_RXRING(rxr, dev) {
		n = nm_ring_space(rxr);
		if (n > DEV_RX_BURST_SIZE) {
			n = DEV_RX_BURST_SIZE;
			rc = -EAGAIN;
		}
		cur = nm_ring_next(rxr, rxr->cur);
		MEM_PREFETCH(NETMAP_BUF(rxr, (rxr->slot + cur)->buf_idx));
		for (i = 0; i < n; ++i) {
			slot = rxr->slot + rxr->cur;
			(*dev->dev_fn)(dev, NETMAP_BUF(rxr, slot->buf_idx), slot->len);
			DEV_RXR_NEXT(rxr);
		}
	}
	return rc;
}

void *
netmap_dev_get_tx_packet(struct dev *dev, struct dev_pkt *pkt)
{
	struct netmap_ring *txr;
	struct netmap_slot *slot;

	DEV_FOREACH_TXRING(txr, dev) {
		if (!nm_ring_empty(txr)) {
			assert(txr != NULL);
			pkt->pkt_txr = txr;
			slot = txr->slot + txr->cur;
			return NETMAP_BUF(txr, slot->buf_idx);
		}
	}
	return NULL;
}

static void
netmap_dev_deinit(struct dev *dev)
{
	char dev_name[NETMAP_DEV_NAMSIZ];

	NOTICE(0, "Destroy netmap device '%s'", netmap_dev_name(dev, dev_name));
	nm_close(dev->dev_nmd);
}

int
netmap_dev_init(struct dev *dev)
{
	int rc, flags;
	char dev_name[NETMAP_DEV_NAMSIZ];
	struct nmreq nmr;

	memset(&nmr, 0, sizeof(nmr));
	flags = 0;
	netmap_dev_name(dev, dev_name);
	NOTICE(0, "Create netmap device '%s'", dev_name);
	dev->dev_nmd = nm_open(dev_name, &nmr, flags, NULL);
	if (dev->dev_nmd != NULL) {
		assert(dev->dev_nmd->nifp != NULL);
		dev->dev_fd = dev->dev_nmd->fd;
		nmr = dev->dev_nmd->req;
		NOTICE(0, "Netmap device '%s' created with %u rx slots and %u tx slots",
			dev_name, nmr.nr_rx_slots, nmr.nr_tx_slots);
		return dev->dev_nmd->fd;
	} else {
		rc = -errno;
		assert(rc);
		ERR(-rc, "Failed to create netmap device '%s'", dev_name);
		return rc;
	}
}

void
netmap_dev_transmit(struct dev_pkt *pkt)
{
	struct netmap_slot *dst;
	struct netmap_ring *txr;

	txr = pkt->pkt_txr;
	assert(txr != NULL);
	dst = txr->slot + txr->cur;
	dst->len = pkt->pkt_len;
	txr->head = txr->cur = nm_ring_next(txr, txr->cur);
}
//=========================================
#ifdef HAVE_XDP
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>


#define XDP_FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define XDP_FRAME_NUM \
	(2 * (XSK_RING_CONS__DEFAULT_NUM_DESCS + XSK_RING_PROD__DEFAULT_NUM_DESCS))
#define XDP_FRAME_INVALID UINT64_MAX

struct xdp_queue {
	struct xsk_ring_prod xq_fill;
	struct xsk_ring_cons xq_comp;
	struct xsk_ring_prod xq_tx;
	struct xsk_ring_cons xq_rx;
	int xq_tx_outstanding;
	int xq_fd;
	int xq_frame_free;
	void *xq_buf;
	struct xsk_umem *xq_umem;
	struct xsk_socket *xq_xsk;
	void *xq_tx_buf;
	uint32_t xq_tx_idx;
	uint64_t xq_frame[XDP_FRAME_NUM];
};

uint64_t
xdp_queue_alloc_frame(struct xdp_queue *q)
{
	uint64_t frame;

	if (q->xq_frame_free == 0) {
		return XDP_FRAME_INVALID;
	}
	frame = q->xq_frame[--q->xq_frame_free];
	q->xq_frame[q->xq_frame_free] = XDP_FRAME_INVALID;
	return frame;
}

void
xdp_queue_free_frame(struct xdp_queue *q, uint64_t frame)
{
	assert(q->xq_frame_free < XDP_FRAME_NUM);
	q->xq_frame[q->xq_frame_free++] = frame;
}



void
xdp_queue_deinit(struct xdp_queue *q)
{
	int size;

	xsk_socket__delete(q->xq_xsk);
	q->xq_xsk = NULL;
	xsk_umem__delete(q->xq_umem);
	q->xq_umem = NULL;
	size = XDP_FRAME_NUM * XDP_FRAME_SIZE;
	shm_free_pages(q->xq_buf, ROUND_UP(size, PAGE_SIZE));
	q->xq_buf = NULL;
}

int
xdp_queue_init(struct xdp_queue *q, const char *ifname, int queue_id)
{
	int i, rc, size;
	uint32_t idx;
	struct xsk_socket_config cfg;

	memset(q, 0, sizeof(*q));
	size = XDP_FRAME_NUM * XDP_FRAME_SIZE;
	rc = shm_alloc_pages(&q->xq_buf, PAGE_SIZE, ROUND_UP(size, PAGE_SIZE));
	if (rc < 0) {
		goto err;
	}
	for (i = 0; i < XDP_FRAME_NUM ; ++i) {
		q->xq_frame[i] = i * XDP_FRAME_SIZE;
	}
	q->xq_frame_free = XDP_FRAME_NUM;
	size = XDP_FRAME_NUM * XDP_FRAME_SIZE;
	rc = xsk_umem__create(&q->xq_umem, q->xq_buf, size, &q->xq_fill, &q->xq_comp, NULL);
	if (rc < 0) {
		ERR(-rc, "xsk_umem__create() failed");
		goto err;
	}
	memset(&cfg, 0, sizeof(cfg));
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	rc = xsk_socket__create(&q->xq_xsk, ifname, queue_id, q->xq_umem,
		&q->xq_rx, &q->xq_tx, &cfg);
	if (rc < 0) {
		ERR(-rc, "xsk_socket__create() failed");
		goto err;
	}
	idx = UINT32_MAX;
	rc = xsk_ring_prod__reserve(&q->xq_fill, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
	if (rc != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
		ERR(0, "xsk_ring_prod__reserve() failed");
		rc = -EINVAL;
		goto err;
	}
	assert(idx != UINT32_MAX);
	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++, idx++) {
		*xsk_ring_prod__fill_addr(&q->xq_fill, idx) = xdp_queue_alloc_frame(q);
	}
	xsk_ring_prod__submit(&q->xq_fill, XSK_RING_PROD__DEFAULT_NUM_DESCS);
	q->xq_fd = xsk_socket__fd(q->xq_xsk);
	return q->xq_fd;
err:
	xdp_queue_deinit(q);
	return rc;
}

int
xdp_dev_init(struct dev *dev)
{
	int rc, ifindex;
	uint32_t xdp_prog_id;

	NOTICE(0, "Create XDP device '%s-%d", dev->dev_ifname, dev->dev_queue_id);
	if (dev->dev_queue_id < 0) {
		rc = -ENOTSUP;
		goto err;
	}
	rc = sys_if_nametoindex(dev->dev_ifname);
	if (rc < 0) {
		goto err;
	}
	ifindex = rc;
	rc = bpf_get_link_xdp_id(ifindex, &xdp_prog_id, 0);
	if (rc < 0) {
		ERR(-rc, "bpf_get_link_xdp_id('%d') failed", ifindex);
		goto err;
	}
	dev->dev_xdp_queue = shm_malloc(sizeof(*dev->dev_xdp_queue));
	if (dev->dev_xdp_queue == NULL) {
		ERR(0, "No memory to allocate XDP queue");
		rc = -ENOMEM;
		goto err;
	}
	rc = xdp_queue_init(dev->dev_xdp_queue, dev->dev_ifname, dev->dev_queue_id);
	if (rc >= 0) {
		NOTICE(0, "XDP device '%s-%d' created", dev->dev_ifname, dev->dev_queue_id);
		return rc;
	}
err:
	ERR(-rc, "Failed to create XDP device '%s-%d'", dev->dev_ifname, dev->dev_queue_id);
	shm_free(dev->dev_xdp_queue);
	dev->dev_xdp_queue = NULL;
	return rc;
}

void
xdp_dev_deinit(struct dev *dev)
{
	NOTICE(0, "Destroy XDP device '%s-%d'", dev->dev_ifname, dev->dev_queue_id);
	xdp_queue_deinit(dev->dev_xdp_queue);
	shm_free(dev->dev_xdp_queue);
	dev->dev_xdp_queue = NULL;

}

void *
xdp_dev_get_tx_packet(struct dev *dev, struct dev_pkt *pkt)
{
	int rc;
	void *buf;
	uint64_t addr;
	struct xdp_queue *q;

	q = dev->dev_xdp_queue;
	if (q->xq_tx_buf != NULL) {
		buf = q->xq_tx_buf;
		q->xq_tx_buf = NULL;
		pkt->pkt_idx = q->xq_tx_idx;
		return buf;
	}
	if (q->xq_frame_free == 0) {
		return NULL;
	}
	rc = xsk_ring_prod__reserve(&q->xq_tx, 1, &pkt->pkt_idx);
	assert(rc <= 1);
	if (rc == 1) {
		addr = xdp_queue_alloc_frame(q);
		xsk_ring_prod__tx_desc(&q->xq_tx, pkt->pkt_idx)->addr = addr;
		addr = xsk_umem__add_offset_to_addr(addr);
		buf = xsk_umem__get_data(q->xq_buf, addr);
		return buf;
	} else {
		return NULL;
	}
}

void
xdp_dev_put_tx_packet(struct dev_pkt *pkt)
{
	struct xdp_queue *q;

	q = pkt->pkt_dev->dev_xdp_queue;
	assert(q->xq_tx_buf == NULL);
	q->xq_tx_buf = pkt->pkt_data;
	q->xq_tx_idx = pkt->pkt_idx;
}

void
xdp_dev_transmit(struct dev_pkt *pkt)
{
	struct xdp_queue *q;

	q = pkt->pkt_dev->dev_xdp_queue;
	xsk_ring_prod__tx_desc(&q->xq_tx, pkt->pkt_idx)->len = pkt->pkt_len;
	xsk_ring_prod__submit(&q->xq_tx, 1);
	q->xq_tx_outstanding++;
}

void
xdp_dev_tx_flush(struct dev *dev)
{
	int i, n;
	uint32_t idx;
	uint64_t addr;
	struct xdp_queue *q;

	q = dev->dev_xdp_queue;
	if (q->xq_tx_outstanding == 0) {
		return;
	}
	sys_sendto(q->xq_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
	idx = UINT32_MAX;
	n = xsk_ring_cons__peek(&q->xq_comp, XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx);
	if (n <= 0) {
		return;
	}
	assert(idx != UINT32_MAX);
	for (i = 0; i < n; ++i, ++idx) {
		addr = *xsk_ring_cons__comp_addr(&q->xq_comp, idx);
		xdp_queue_free_frame(q, addr);
	}
	xsk_ring_cons__release(&q->xq_comp, n);
	assert(n <= q->xq_tx_outstanding);
	q->xq_tx_outstanding -= n;
}

int
xdp_dev_rx(struct dev *dev)
{
	int i, n, m, rc, len;
	uint32_t idx_rx, idx_fill;
	uint64_t addr, frame;
	struct xdp_queue *q;

	q = dev->dev_xdp_queue;
	n = xsk_ring_cons__peek(&q->xq_rx, DEV_RX_BURST_SIZE, &idx_rx);
	dbg("rc %d", n);
	if (n == 0) {
		return 0;
	}
	for (i = 0; i < n; ++i, ++idx_rx) {
		addr = xsk_ring_cons__rx_desc(&q->xq_rx, idx_rx)->addr;
		frame = xsk_umem__extract_addr(addr);
		addr = xsk_umem__add_offset_to_addr(addr);
		len = xsk_ring_cons__rx_desc(&q->xq_rx, idx_rx)->len;
		dbg("call...");
		(*dev->dev_fn)(dev, xsk_umem__get_data(q->xq_buf, addr), len);
		xdp_queue_free_frame(q, frame);
	}
	xsk_ring_cons__release(&q->xq_rx, n);
	m = xsk_prod_nb_free(&q->xq_fill, q->xq_frame_free);
	if (m > 0) {
		m = MIN(m, q->xq_frame_free);
		idx_fill = UINT32_MAX;
		rc = xsk_ring_prod__reserve(&q->xq_fill, m, &idx_fill);
		assert(rc == m);
		assert(idx_fill != UINT32_MAX);
		UNUSED(rc);
		for (i = 0; i < m; ++i, ++idx_fill) {
			frame = xdp_queue_alloc_frame(q);
			*xsk_ring_prod__fill_addr(&q->xq_fill, idx_fill) = frame;
		}
		xsk_ring_prod__submit(&q->xq_fill, m);
	}
	if (xsk_cons_nb_avail(&q->xq_rx, 1) == 1) {
		return -EAGAIN;
	} else {
		return 0;
	}
}
#endif // HAVE_XDP

// =============================================
static int
dev_rxtx(void *udata, short revents)
{
	int rc;
	struct dev *dev;

	dev = udata;
	if (revents & POLLOUT) {
		dev->dev_tx_throttled = 0;
		fd_event_clear(dev->dev_event, POLLOUT);
	}
	if (revents & POLLIN) {
#ifdef HAVE_XDP
		rc = xdp_dev_rx(dev);
#else
		rc = netmap_dev_rx(dev);

#endif
	}
	return rc;
}

int
dev_init(struct dev *dev, const char *ifname, int queue_id, dev_f dev_fn)
{
	int rc, fd;

	assert(!dev_is_inited(dev));
	memset(dev, 0, sizeof(*dev));
	strzcpy(dev->dev_ifname, ifname, sizeof(dev->dev_ifname));
	dev->dev_queue_id = queue_id;
	dev->dev_fd = -1;
#ifdef HAVE_XDP
	rc = xdp_dev_init(dev);
#else
	rc = netmap_dev_init(dev);
#endif
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	sys_fcntl(fd, F_SETFD, FD_CLOEXEC);
	rc = fd_event_add(&dev->dev_event, fd, dev, dev_rxtx);
	if (rc) {
		netmap_dev_deinit(dev);
		return rc;
	}
	dev->dev_fd = fd;
	dev->dev_fn = dev_fn;
	DLIST_INSERT_TAIL(&dev_head, dev, dev_list);
	dev_rx_on(dev);
	return 0;
}

void
dev_deinit(struct dev *dev)
{
	if (dev_is_inited(dev)) {
		DLIST_REMOVE(dev, dev_list);
		fd_event_del(dev->dev_event);
		dev->dev_event = NULL;
#ifdef HAVE_XDP
		xdp_dev_deinit(dev);
#else
		netmap_dev_deinit(dev);
#endif
		dev->dev_fn = NULL;
		dev->dev_fd = -1;
	}
}

void
dev_close_fd(struct dev *dev)
{
	sys_close(dev->dev_fd);
	dev->dev_fd = -1;
}

void
dev_rx_on(struct dev *dev)
{
	if (dev->dev_event != NULL) {
		fd_event_set(dev->dev_event, POLLIN);
	}
}

void
dev_rx_off(struct dev *dev)
{
	if (dev->dev_event != NULL) {
		fd_event_clear(dev->dev_event, POLLIN);
	}
}

int
dev_get_tx_packet(struct dev *dev, struct dev_pkt *pkt)
{
	void *buf;

	pkt->pkt_data = NULL;
	if (!dev_is_inited(dev)) {
		return -ENODEV;
	}
	if (dev->dev_tx_throttled) {
		return -ENOBUFS;
	}
#ifdef HAVE_XDP
	buf = xdp_dev_get_tx_packet(dev, pkt);

#else
	buf = netmap_dev_get_tx_packet(dev, pkt);

#endif
	if (buf == NULL) {
		dev->dev_tx_throttled = 1;
		fd_event_set(dev->dev_event, POLLOUT);
		return -ENOBUFS;
	} else {
		pkt->pkt_len = 0;
		pkt->pkt_sid = current->p_sid;
		pkt->pkt_dev = dev;
		pkt->pkt_data = buf;
		return 0;
	}
}

void
dev_put_tx_packet(struct dev_pkt *pkt)
{
	if (pkt->pkt_data != NULL) {
#ifdef HAVE_XDP
		xdp_dev_put_tx_packet(pkt);
#endif
		pkt->pkt_data = NULL;
	}
}

void
dev_transmit(struct dev_pkt *pkt)
{
	assert(pkt->pkt_len != 0);
	assert(pkt->pkt_data != NULL);
#ifdef HAVE_XDP
	xdp_dev_transmit(pkt);
#else
	netmap_dev_transmit(pkt);
#endif
	pkt->pkt_data = NULL;
}

void
dev_tx_flush()
{
#ifdef HAVE_XDP
	struct dev *dev;
	DLIST_FOREACH(dev, &dev_head, dev_list) {
		xdp_dev_tx_flush(dev);
	}
#endif
}
