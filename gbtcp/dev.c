#include "internals.h"

#define CURMOD dev

static DLIST_HEAD(dev_head);

#ifdef HAVE_NETMAP
extern struct dev_ops netmap_dev_ops;
#endif

#ifdef HAVE_XDP
extern struct dev_ops xdp_dev_ops;
#endif

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
		rc = (*dev->dev_ops->dev_rx_op)(dev);
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
	if (1) {
		dev->dev_ops = &xdp_dev_ops;
	} else {
		dev->dev_ops = &netmap_dev_ops;
	}
	rc = (*dev->dev_ops->dev_init_op)(dev);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	sys_fcntl(fd, F_SETFD, FD_CLOEXEC);
	rc = fd_event_add(&dev->dev_event, fd, dev, dev_rxtx);
	if (rc) {
		(*dev->dev_ops->dev_deinit_op)(dev);
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
		(*dev->dev_ops->dev_deinit_op)(dev);
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
	buf = (*dev->dev_ops->dev_get_tx_packet_op)(dev, pkt);
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
		(*pkt->pkt_dev->dev_ops->dev_put_tx_packet_op)(pkt);
		pkt->pkt_data = NULL;
	}
}

void
dev_transmit(struct dev_pkt *pkt)
{
	assert(pkt->pkt_len != 0);
	assert(pkt->pkt_data != NULL);
	(*pkt->pkt_dev->dev_ops->dev_transmit_op)(pkt);
	pkt->pkt_data = NULL;
}

void
dev_tx_flush()
{
	struct dev *dev;

	DLIST_FOREACH(dev, &dev_head, dev_list) {
		(*dev->dev_ops->dev_tx_flush_op)(dev);
	}
}
