// GPL v2 License
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <xdp/xsk.h>
#include "../sys.h"
#include "../dev.h"

#define CURMOD dev

#define XDP_FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define XDP_FRAME_NUM \
	(2 * (XSK_RING_CONS__DEFAULT_NUM_DESCS + XSK_RING_PROD__DEFAULT_NUM_DESCS))
#define XDP_FRAME_INVALID UINT64_MAX

static void xdp_queue_deinit(struct dev *, bool);
static int xdp_dev_init(struct dev *);
static void xdp_dev_deinit(struct dev *, bool);
static int xdp_dev_rx(struct dev *);
static void *xdp_dev_get_tx_packet(struct dev *, struct dev_pkt *);
static void xdp_dev_put_tx_packet(struct dev_pkt *);
static void xdp_dev_transmit(struct dev_pkt *);
static void xdp_dev_tx_flush(struct dev *);

struct dev_ops xdp_dev_ops = {
	.dev_init_op = xdp_dev_init,
	.dev_deinit_op = xdp_dev_deinit,
	.dev_rx_op = xdp_dev_rx,
	.dev_get_tx_packet_op = xdp_dev_get_tx_packet,
	.dev_put_tx_packet_op = xdp_dev_put_tx_packet,
	.dev_transmit_op = xdp_dev_transmit,
	.dev_tx_flush_op = xdp_dev_tx_flush,
};

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
	uint32_t xq_prog_id;
};

static uint64_t
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

static void
xdp_queue_free_frame(struct xdp_queue *q, uint64_t frame)
{
	assert(q->xq_frame_free < XDP_FRAME_NUM);
	q->xq_frame[q->xq_frame_free++] = frame;
}

static int
xdp_queue_init(struct dev *dev)
{
	int i, rc, size;
	uint32_t idx;
	struct xsk_socket_config cfg;
	struct xdp_queue *q;

	q = dev->dev_xdp_queue;
	memset(q, 0, sizeof(*q));
	q->xq_prog_id = UINT32_MAX;
	rc = bpf_xdp_query_id(dev->dev_ifindex, 0, &q->xq_prog_id);
	if (rc < 0) {
		ERR(-rc, "bpf_xdp_query_id('%d') failed", dev->dev_ifindex);
		goto err;
	}

//	bpf_xdp_attach(opt_ifindex, prog_fd, opt_xdp_flags, NULL) < 0

	size = XDP_FRAME_NUM * XDP_FRAME_SIZE;
	rc = sys_posix_memalign(&q->xq_buf, PAGE_SIZE, size);
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
//	cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
	rc = xsk_socket__create(&q->xq_xsk, dev->dev_ifname, dev->dev_queue_id, q->xq_umem,
		&q->xq_rx, &q->xq_tx, &cfg);
	if (rc < 0) {
		ERR(-rc, "xsk_socket__create('%s', '%d') failed",
			dev->dev_ifname, dev->dev_queue_id);
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
	xdp_queue_deinit(dev, false);
	return rc;
}

static void
xdp_queue_deinit(struct dev *dev, bool cloexec)
{
	struct xdp_queue *q;

	q = dev->dev_xdp_queue;
	xsk_socket__delete(q->xq_xsk);
	xsk_umem__delete(q->xq_umem);
	sys_free(q->xq_buf);
	if (q->xq_prog_id != UINT32_MAX) {
		bpf_xdp_detach(dev->dev_ifindex, 0, NULL);
	}
	if (!cloexec) {
		q->xq_xsk = NULL;
		q->xq_umem = NULL;
		q->xq_buf = NULL;
		q->xq_prog_id = UINT32_MAX;
	}
}

static int
xdp_dev_init(struct dev *dev)
{
	int rc;

	NOTICE(0, "Create XDP device '%s', queue=%d", dev->dev_ifname, dev->dev_queue_id);
	if (dev->dev_queue_id < 0) {
		rc = -ENOTSUP;
		goto err;
	}
	dev->dev_xdp_queue = sys_malloc(sizeof(*dev->dev_xdp_queue));
	if (dev->dev_xdp_queue == NULL) {
		ERR(0, "No memory to allocate XDP queue");
		rc = -ENOMEM;
		goto err;
	}
	rc = xdp_queue_init(dev);
	if (rc >= 0) {
		NOTICE(0, "XDP device '%s' created, queue=%d", dev->dev_ifname, dev->dev_queue_id);
		return rc;
	}
err:
	ERR(-rc, "Failed to create XDP device '%s', queue=%d", dev->dev_ifname, dev->dev_queue_id);
	sys_free(dev->dev_xdp_queue);
	dev->dev_xdp_queue = NULL;
	return rc;
}

static void
xdp_dev_deinit(struct dev *dev, bool cloexec)
{
	NOTICE(0, "Destroy XDP device '%s', queue=%d'", dev->dev_ifname, dev->dev_queue_id);
	assert(dev->dev_xdp_queue != NULL);
	xdp_queue_deinit(dev, cloexec);
	sys_free(dev->dev_xdp_queue);
	if (!cloexec) {
		dev->dev_xdp_queue = NULL;
	}
}

static int
xdp_dev_rx(struct dev *dev)
{
	int i, n, m, rc, len;
	uint32_t idx_rx, idx_fill;
	uint64_t addr, frame;
	struct xdp_queue *q;

	q = dev->dev_xdp_queue;
	idx_rx = 0;
	n = xsk_ring_cons__peek(&q->xq_rx, DEV_RX_BURST_SIZE, &idx_rx);
	if (n == 0) {
		return 0;
	}
	for (i = 0; i < n; ++i) {
		addr = xsk_ring_cons__rx_desc(&q->xq_rx, idx_rx + i)->addr;
		frame = xsk_umem__extract_addr(addr);
		addr = xsk_umem__add_offset_to_addr(addr);
		len = xsk_ring_cons__rx_desc(&q->xq_rx, idx_rx + i)->len;
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

static void *
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

static void
xdp_dev_put_tx_packet(struct dev_pkt *pkt)
{
	struct xdp_queue *q;

	q = pkt->pkt_dev->dev_xdp_queue;
	assert(q->xq_tx_buf == NULL);
	q->xq_tx_buf = pkt->pkt_data;
	q->xq_tx_idx = pkt->pkt_idx;
}

static void
xdp_dev_transmit(struct dev_pkt *pkt)
{
	struct xdp_queue *q;

	q = pkt->pkt_dev->dev_xdp_queue;
	xsk_ring_prod__tx_desc(&q->xq_tx, pkt->pkt_idx)->len = pkt->pkt_len;
	xsk_ring_prod__submit(&q->xq_tx, 1);
	q->xq_tx_outstanding++;
}

static void
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
