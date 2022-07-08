// GPL v2 License
#include "internals.h"

#define CURMOD dev

#ifdef GT_HAVE_NETMAP
extern struct dev_ops netmap_dev_ops;
#endif // GT_HAVE_NETMAP

#ifdef GT_HAVE_XDP
extern struct dev_ops xdp_dev_ops;
#endif // GT_HAVE_XDP

struct dev_mod {
	struct log_scope log_scope;
	int dev_transport;
};

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
	} else {
		rc = 0;
	}
	return rc;
}

const char *
dev_transport_str(int transport)
{
	switch (transport) {
#ifdef GT_HAVE_NETMAP
	case DEV_TRANSPORT_NETMAP: return "netmap";
#endif // GT_HAVE_NETMAP
#ifdef GT_HAVE_XDP
	case DEV_TRANSPORT_XDP: return "xdp";
#endif // GT_HAVE_XDP
	default: return NULL;
	}
}

int
dev_transport_from_str(const char *s)
{
#ifdef GT_HAVE_NETMAP
	if (!strcmp(s, "netmap")) {
		return DEV_TRANSPORT_NETMAP;
	}
#endif // GT_HAVE_NETMAP
#ifdef GT_HAVE_XDP
	if (!strcmp(s, "xdp")) {
		return DEV_TRANSPORT_XDP;
	}
#endif // GT_HAVE_XDP
	return -EINVAL;
}

int
dev_transport_get(void)
{
	return curmod->dev_transport;
}

static void
dev_set_ops(struct dev *dev, int transport)
{
	dev->dev_ops = NULL;
#ifdef GT_HAVE_NETMAP
	if (transport == DEV_TRANSPORT_NETMAP) {
		dev->dev_ops = &netmap_dev_ops;
	}
#endif // GT_HAVE_NETMAP
#ifdef GT_HAVE_XDP
	if (transport == DEV_TRANSPORT_XDP) {
		dev->dev_ops = &xdp_dev_ops;
	}
#endif // GT_HAVE_XDP
	assert(dev->dev_ops != NULL);
}

static int
sysctl_dev_transport(struct sysctl_conn *cp, void *udata, const char *new, struct strbuf *out)
{
	int rc;

	strbuf_add_str(out, dev_transport_str(curmod->dev_transport));
	if (new != NULL) {
		rc = dev_transport_from_str(new);
		if (rc < 0) {
			return rc;
		}
		curmod->dev_transport = rc;
	}
	return 0;
}

int
dev_mod_init(void)
{
	int rc;

	rc = curmod_init();
	if (rc) {
		return rc;
	}
	curmod->dev_transport = DEV_TRANSPORT_DEFAULT;
	sysctl_add(GT_SYSCTL_DEV_TRANSPORT, SYSCTL_LD, NULL, NULL, sysctl_dev_transport);
	return 0;
}

int
dev_init(struct dev *dev, int transport, const char *ifname, int queue_id, dev_f dev_fn)
{
	int rc, fd;

	assert(!dev_is_inited(dev));
	memset(dev, 0, sizeof(*dev));
	strzcpy(dev->dev_ifname, ifname, sizeof(dev->dev_ifname));
	rc = sys_if_nametoindex(dev->dev_ifname);
	dev->dev_ifindex = rc; // TODO: ifindex to XDP
	dev->dev_queue_id = queue_id;
	dev->dev_fd = -1;
	dev_set_ops(dev, transport);
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
	DLIST_INSERT_TAIL(&current->p_dev_head, dev, dev_list);
	dev_rx_on(dev);
	return 0;
}

int
dev_deinit(struct dev *dev, bool cloexec)
{
	if (dev_is_inited(dev)) {
		if (!cloexec) {
			DLIST_REMOVE(dev, dev_list);
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
dev_tx_flush()
{
	struct dev *dev;

	DLIST_FOREACH(dev, &current->p_dev_head, dev_list) {
		(*dev->dev_ops->dev_tx_flush_op)(dev);
	}
}
