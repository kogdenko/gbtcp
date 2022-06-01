#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include "dev.h"

#define CURMOD dev

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

static int netmap_dev_init(struct dev *);
static void netmap_dev_deinit(struct dev *);
static int netmap_dev_rx(struct dev *);
static void *netmap_dev_get_tx_packet(struct dev *, struct dev_pkt *);
static void netmap_dev_put_tx_packet(struct dev_pkt *) {}
static void netmap_dev_transmit(struct dev_pkt *);
static void netmap_dev_tx_flush(struct dev *) {}

struct dev_ops netmap_dev_ops = {
	.dev_init_op = netmap_dev_init,
	.dev_deinit_op = netmap_dev_deinit,
	.dev_rx_op = netmap_dev_rx,
	.dev_get_tx_packet_op = netmap_dev_get_tx_packet,
	.dev_put_tx_packet_op = netmap_dev_put_tx_packet,
	.dev_transmit_op = netmap_dev_transmit,
	.dev_tx_flush_op = netmap_dev_tx_flush,
};

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

static int
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

static void
netmap_dev_deinit(struct dev *dev)
{
	char dev_name[NETMAP_DEV_NAMSIZ];

	NOTICE(0, "Destroy netmap device '%s'", netmap_dev_name(dev, dev_name));
	nm_close(dev->dev_nmd);
}

static int
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

static void *
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
