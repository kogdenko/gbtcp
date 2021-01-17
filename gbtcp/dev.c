// GPL v2
#include "internals.h"

#define CURMOD dev

#define DEV_RX_BURST_SIZE 256 // TODO: configure
#define DEV_TX_BURST_SIZE 64

static int
dev_rxtx(void *udata, short revents)
{
	int n;
	struct dev *dev;
	struct netmap_ring *r;

	dev = udata;
	if (revents & POLLOUT) {
		dev->dev_tx_throttled = 0;
		fd_event_clear(dev->dev_event, POLLOUT);
	}
	(*dev->dev_fn)(dev, revents);
	if (revents & POLLIN) {
		DEV_FOREACH_RXRING(r, dev) {
			n = nm_ring_space(r);
			if (n) {
				return -EAGAIN;
			}
		}
	}
	return 0;
}

static void
dev_nm_close(struct dev *dev)
{
	NOTICE(0, "ok; nmd=%p", dev->dev_nmd);
	nm_close(dev->dev_nmd);
	dev->dev_nmd = NULL;
}

static int
dev_nm_open(struct dev *dev, const char *dev_name)
{
	int rc, flags;
	struct nmreq nmr;

	memset(&nmr, 0, sizeof(nmr));
	flags = 0;
	dev->dev_nmd = nm_open(dev_name, &nmr, flags, NULL);
	if (dev->dev_nmd != NULL) {
		dbg("opne %s", dev_name);
		assert(dev->dev_nmd->nifp != NULL);
		sys_fcntl(dev->dev_nmd->fd, F_SETFD, FD_CLOEXEC);
		nmr = dev->dev_nmd->req;
		NOTICE(0, "open dev; dev='%s', nmd=%p, rx=%u/%u, tx=%u/%u",
			dev_name, dev->dev_nmd,
			nmr.nr_rx_rings, nmr.nr_rx_slots,
			nmr.nr_tx_rings, nmr.nr_tx_slots);
		return 0;
	} else {
		rc = -errno;
		assert(rc);
		ERR(-rc, "nm_open() failed; dev='%s'", dev_name);
		return rc;
	}
}

int
dev_init(struct dev *dev, const char *ifname, dev_f dev_fn)
{
	int rc;
	char dev_name[NM_IFNAMSIZ];

	assert(!dev_is_inited(dev));
	memset(dev, 0, sizeof(*dev));
	snprintf(dev_name, sizeof(dev_name), "%s%s", NETMAP_PFX, ifname);
	rc = dev_nm_open(dev, dev_name);
	if (rc) {
		return rc;
	}
	dev->dev_cur_tx_ring = dev->dev_nmd->first_tx_ring;
	rc = fd_event_add(&dev->dev_event, dev->dev_nmd->fd,
	                  dev_name + NETMAP_PFX_LEN, dev, dev_rxtx);
	if (rc) {
		dev_nm_close(dev);
		return rc;
	}
	dev->dev_fn = dev_fn;
	dev_rx_on(dev);
	return 0;
}

void
dev_deinit(struct dev *dev)
{
	if (dev_is_inited(dev)) {
		fd_event_del(dev->dev_event);
		dev->dev_event = NULL;
		dev_nm_close(dev);
		dev->dev_fn = NULL;
	}
}

void
dev_close_fd(struct dev *dev)
{
	if (dev->dev_nmd != NULL) {
		sys_close(dev->dev_nmd->fd);
	}
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
dev_not_empty_txr(struct dev *dev, struct dev_pkt *pkt, int flags)
{
	void *buf;
	struct netmap_ring *txr;
	struct netmap_slot *slot;

	if (dev->dev_nmd == NULL) {
		return -ENODEV;
	}
	if (dev->dev_tx_throttled) {
		return -ENOBUFS;
	}
	if (dev->dev_cur_tx_ring_epoch != fd_poll_epoch) {
		dev->dev_cur_tx_ring_epoch = fd_poll_epoch;
		dev->dev_cur_tx_ring = dev->dev_nmd->first_tx_ring;
	}
restart:
	DEV_FOREACH_TXRING_CONTINUE(dev->dev_cur_tx_ring, txr, dev) {
		if (!nm_ring_empty(txr)) {
			assert(txr != NULL);
			pkt->pkt_len = 0;
			pkt->pkt_sid = current->p_sid;
			pkt->pkt_txr = txr;
			slot = txr->slot + txr->cur;
			buf = NETMAP_BUF(txr, slot->buf_idx);
			pkt->pkt_data = buf;
			if (dev->dev_tx_without_reclaim < DEV_TX_BURST_SIZE) {
				dev->dev_tx_without_reclaim++;
			}
			return 0;
		}
	}
	if (dev->dev_tx_without_reclaim == DEV_TX_BURST_SIZE &&
	    (flags & TX_CAN_RECLAIM)) {
		dev->dev_tx_without_reclaim = 0;
		dev->dev_cur_tx_ring = dev->dev_nmd->first_tx_ring;
		sys_ioctl(dev->dev_nmd->fd, NIOCTXSYNC, 0);
		goto restart;
	}
	dev->dev_tx_throttled = 1;
	fd_event_set(dev->dev_event, POLLOUT);
	return -ENOBUFS;
}

int
dev_rxr_space(struct dev *dev, struct netmap_ring *rxr)
{
	int n;

	n = nm_ring_space(rxr);
	if (n > DEV_RX_BURST_SIZE) {
		n = DEV_RX_BURST_SIZE;
	}
	return n;
}

void
dev_transmit(struct dev_pkt *pkt)
{
	struct netmap_slot *dst;
	struct netmap_ring *txr;

	txr = pkt->pkt_txr;
	assert(txr != NULL);
	dst = txr->slot + txr->cur;
	dst->len = pkt->pkt_len;
	txr->head = txr->cur = nm_ring_next(txr, txr->cur);
}
