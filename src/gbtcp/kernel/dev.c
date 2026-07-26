// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/kernel/cli.h>
#include <gbtcp/kernel/dev.h>
#include <gbtcp/kernel/fd_event.h>
#include <gbtcp/kernel/global.h>
#include <gbtcp/kernel/mod.h>
#include <gbtcp/kernel/worker.h>

#if GT_HAVE_NETMAP
extern struct dev_ops netmap_dev_ops;
#endif // GT_HAVE_NETMAP

#if GT_HAVE_XDP
extern struct dev_ops xdp_dev_ops;
#endif // GT_HAVE_XDP

static int
dev_rxtx(void *udata, short revents, struct gt_dlist *dh)
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
	} else {
		rc = 0;
	}
	return rc;
}

const char *
gt_dev_io_to_str(int dev_io)
{
	switch (dev_io) {
#if GT_HAVE_NETMAP
	case GT_DEV_IO_NETMAP:
		return "netmap";
#endif // GT_HAVE_NETMAP
#if GT_HAVE_XDP
	case GT_DEV_IO_XDP:
		return "xdp";
#endif // GT_HAVE_XDP
	default:
		return NULL;
	}
}

int
gt_dev_io_from_str(const char *s)
{
#if GT_HAVE_NETMAP
	if (!strcmp(s, "netmap")) {
		return GT_DEV_IO_NETMAP;
	}
#endif // GT_HAVE_NETMAP
#if GT_HAVE_XDP
	if (!strcmp(s, "xdp")) {
		return GT_DEV_IO_XDP;
	}
#endif // GT_HAVE_XDP
	return -EINVAL;
}

static void
dev_set_ops(struct dev *dev, u8 io)
{
	dev->dev_ops = NULL;
#if GT_HAVE_NETMAP
	if (io == GT_DEV_IO_NETMAP) {
		dev->dev_ops = &netmap_dev_ops;
	}
#endif // GT_HAVE_NETMAP
#if GT_HAVE_XDP
	if (io == GT_DEV_IO_XDP) {
		dev->dev_ops = &xdp_dev_ops;
	}
#endif // GT_HAVE_XDP
	assert(dev->dev_ops != NULL);
}

int
gt_dev_init(struct dev *dev, u8 io, const char *ifname, int queue_id,
	    dev_f dev_fn)
{
	int rc, fd;

	memset(dev, 0, sizeof(*dev));
	gt_strzcpy(dev->dev_ifname, ifname, sizeof(dev->dev_ifname));
	rc = sys_if_nametoindex(dev->dev_ifname);
	dev->dev_ifindex = rc; // TODO: ifindex to XDP
	dev->dev_queue_id = queue_id;
	dev->dev_fd = -1;
	dev_set_ops(dev, io);
	rc = (*dev->dev_ops->dev_init_op)(dev);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	sys_fcntl(fd, F_SETFD, FD_CLOEXEC);
	rc = fd_event_add(&dev->dev_event, fd, dev, dev_rxtx);
	if (rc) {
		(*dev->dev_ops->dev_deinit_op)(dev, false);
		return rc;
	}
	dev->dev_fd = fd;
	dev->dev_fn = dev_fn;
	GT_DLIST_INSERT_TAIL(&current->p_dev_head, dev, dev_list);
	dev_rx_on(dev);
	return 0;
}

int
gt_dev_deinit(struct dev *dev, bool cloexec)
{
	if (dev_is_inited(dev)) {
		if (!cloexec) {
			GT_DLIST_REMOVE(dev, dev_list);
			fd_event_del(dev->dev_event);
			dev->dev_event = NULL;
			dev->dev_fn = NULL;
			dev->dev_fd = -1;
		}
		(*dev->dev_ops->dev_deinit_op)(dev, cloexec);
		return 0;
	} else {
		return -EINVAL;
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
dev_tx_flush(void)
{
	struct dev *dev;

	GT_DLIST_FOREACH(dev, &current->p_dev_head, dev_list) {
		(*dev->dev_ops->dev_tx_flush_op)(dev);
	}
}
