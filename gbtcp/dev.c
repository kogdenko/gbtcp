#include "internals.h"

#define DEV_BURST_SIZE  256

#define DEV_LOG_MSG_FOREACH(x) \
	x(mod_deinit) \
	x(nm_open) \
	x(nm_close) \
	x(init) \
	x(deinit) \

struct dev_mod {
	struct log_scope log_scope;
	DEV_LOG_MSG_FOREACH(LOG_MSG_DECLARE);
};

static struct dev_mod *current_mod;

int
dev_mod_init(struct log *log, void **pp)
{
	int rc;
	struct dev_mod *mod;
	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (!rc) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "dev");
	}
	return rc;
}
int
dev_mod_attach(struct log *log, void *raw_mod)
{
	current_mod = raw_mod;
	return 0;
}
void
dev_mod_deinit(struct log *log, void *raw_mod)
{
	struct dev_mod *mod;
	LOG_TRACE(log);
	mod = raw_mod;
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}
void
dev_mod_detach(struct log *log)
{
	current_mod = NULL;
}
static int
dev_rxtx(void *udata, short revents)
{
	int n;
	struct dev *dev;
	struct netmap_ring *r;
	dev = udata;
	if (revents & POLLOUT) {
		dev->dev_tx_full = 0;
		gt_fd_event_clear(dev->dev_event, POLLOUT);
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
dev_nm_close(struct log *log, struct dev *dev)
{
	LOG_TRACE(log);
	LOGF(log, LOG_MSG(nm_close), LOG_INFO, 0, "ok; dev='%s', nmd=%p",
	     dev->dev_name, dev->dev_nmd);
	if (dev->dev_nmd->fd != -1) {
		sys_close(log, dev->dev_nmd->fd);
		dev->dev_nmd->fd = -1;
	}
	nm_close(dev->dev_nmd);
	dev->dev_nmd = NULL;
}

static int
dev_nm_open(struct log *log, struct dev *dev)
{
	int rc, flags, epoch;
	struct nmreq nmr;
	LOG_TRACE(log);
	memset(&nmr, 0, sizeof(nmr));
	flags = 0;
	epoch = gt_global_epoch;
	GT_GLOBAL_UNLOCK;
	// nm_open called socket API ~ ioctl or something
	dev->dev_nmd = nm_open(dev->dev_name, &nmr, flags, NULL);
	GT_GLOBAL_LOCK;
	printf("dev=%p, nmd=%p\n", dev, dev->dev_nmd);
	if (epoch != gt_global_epoch) {
		if (dev->dev_nmd != NULL) {
			dev_nm_close(log, dev);
		}
		return -EFAULT;
	}
	if (dev->dev_nmd != NULL) {
		ASSERT(dev->dev_nmd->nifp != NULL);
		sys_fcntl(log, dev->dev_nmd->fd,
		          F_SETFD, FD_CLOEXEC);
		nmr = dev->dev_nmd->req;
		LOGF(log, LOG_MSG(nm_open), LOG_INFO, 0,
		     "ok; dev='%s', nmd=%p, rx=%u/%u, tx=%u/%u",
		      dev->dev_name, dev->dev_nmd,
	              nmr.nr_rx_rings, nmr.nr_rx_slots,
		      nmr.nr_tx_rings, nmr.nr_tx_slots);
		return 0;
	} else {
		rc = -errno;
		ASSERT(rc);
		LOGF(log, LOG_MSG(nm_open), LOG_ERR, -rc,
		     "failed; dev='%s'", dev->dev_name);
		return rc;
	}
}
int
dev_init(struct log *log, struct dev *dev, const char *ifname, dev_f dev_fn)
{
	int rc;
	const char *name;
	ASSERT(dev_fn != NULL);
	LOG_TRACE(log);
	memset(dev, 0, sizeof(*dev));
	snprintf(dev->dev_name, sizeof(dev->dev_name), "%s%s",
	         NETMAP_PFX, ifname);
	rc = dev_nm_open(log, dev);
	if (rc) {
		return rc;
	}
	name = dev->dev_name + NETMAP_PFX_LEN;
	dev->dev_cur_tx_ring = dev->dev_nmd->first_tx_ring;
	rc = gt_fd_event_new(log, &dev->dev_event, dev->dev_nmd->fd,
	                     name, dev_rxtx, dev);
	if (rc) {
		dev_nm_close(log, dev);
		return rc;
	}
//	fd_event_init_sysctl(dev->event);
	dev->dev_fn = dev_fn;
	dev_rx_on(dev);
	return 0;
}
void
dev_deinit(struct dev *dev)
{
	struct log *log;
	if (dev->dev_fn != NULL) {
		log = log_trace0();
		dev->dev_fn = NULL;
		gt_fd_event_del(dev->dev_event);
		dev->dev_event = NULL;
		dev_nm_close(log, dev);
		DLIST_REMOVE(dev, dev_list);
	}
}
void
dev_rx_on(struct dev *dev)
{
	if (dev->dev_event != NULL) {
		gt_fd_event_set(dev->dev_event, POLLIN);
	}
}
void
dev_rx_off(struct dev *dev)
{
	if (dev->dev_event != NULL) {
		gt_fd_event_clear(dev->dev_event, POLLIN);
	}
}
int
dev_not_empty_txr(struct dev *dev, struct dev_pkt *pkt)
{
	void *buf;
	struct netmap_ring *txr;
	struct netmap_slot *slot;
	ASSERT(dev->dev_nmd != NULL);
	if (dev->dev_tx_full) {
		return -ENOBUFS;
	}
	if (dev->dev_cur_tx_ring_epoch != gt_fd_event_epoch) {
		dev->dev_cur_tx_ring_epoch = gt_fd_event_epoch;
		dev->dev_cur_tx_ring = dev->dev_nmd->first_tx_ring;
	}
	DEV_FOREACH_TXRING_CONTINUE(dev->dev_cur_tx_ring, txr, dev) {
		if (!nm_ring_empty(txr)) {
			ASSERT(txr != NULL);
			pkt->pkt_flags = 0;
			pkt->pkt_txr = txr;
			slot = txr->slot + txr->cur;
			buf = NETMAP_BUF(txr, slot->buf_idx);
			pkt->pkt_data = buf;
			return 0;
		}
	}
	dev->dev_tx_full = 1;
	gt_fd_event_set(dev->dev_event, POLLOUT);
	return -ENOBUFS;
}
int
dev_rxr_space(struct dev *dev, struct netmap_ring *rxr)
{
	int n;
	n = nm_ring_space(rxr);
	if (n > DEV_BURST_SIZE) {
		n = DEV_BURST_SIZE;
	}
	return n;
}
void
dev_tx(struct dev_pkt *pkt)
{
	struct netmap_slot *dst;
	struct netmap_ring *txr;
	txr = pkt->pkt_txr;
	ASSERT(txr != NULL);
	dst = txr->slot + txr->cur;
	dst->len = pkt->pkt_len;
	txr->head = txr->cur = nm_ring_next(txr, txr->cur);
}
int
dev_tx3(struct dev *dev, void *data, int len)
{
	int rc;
	struct dev_pkt pkt;
	rc = dev_not_empty_txr(dev, &pkt);
	if (rc) {
		return rc;
	}
	GT_PKT_COPY(pkt.pkt_data, data, len);
	pkt.pkt_len = len;
	dev_tx(&pkt);
	return 0;
}
