// GPL2 license
#ifndef GBTCP_DEV_H
#define GBTCP_DEV_H

#include "timer.h"
#include "mbuf.h"

#define DEV_PKT_SIZE_MAX 2048

typedef void (*dev_f)(struct dev *, short);

struct dev {
	struct nm_desc *dev_nmd;
	struct gt_fd_event *dev_event;
	int dev_cur_tx_ring;
	int dev_tx_full;
	uint64_t dev_cur_tx_ring_epoch;
	dev_f dev_fn;
	struct dlist dev_list;
	struct route_if *dev_ifp;
};

struct dev_pkt {
	struct mbuf pkt_mbuf;
	union {
		struct {
			unsigned int pkt_len : 11;
			unsigned int pkt_off : 11;
			unsigned int pkt_no_dev : 1;
		};
		uint32_t pkt_flags;
	};
	struct netmap_ring *pkt_txr;
	u_char *pkt_data;
};

#define DEV_FIRST_RXRING(dev) \
	NETMAP_RXRING((dev)->dev_nmd->nifp, (dev)->dev_nmd->first_rx_ring)

#define DEV_RXRING(dev, i) \
	NETMAP_RXRING((dev)->dev_nmd->nifp, i)

#define DEV_FIRST_TXRING(dev) \
	NETMAP_TXRING((dev)->dev_nmd->nifp, (dev)->dev_nmd->first_tx_ring)

#define DEV_FOREACH_RXRING(rxr, dev) \
	for (int GT_UNIQV(i) = (dev)->dev_nmd->first_rx_ring; \
	     GT_UNIQV(i) <= (dev)->dev_nmd->last_rx_ring && \
	     ((rxr = NETMAP_RXRING((dev)->dev_nmd->nifp, GT_UNIQV(i))), 1); \
	     ++GT_UNIQV(i))

#define DEV_FOREACH_TXRING(txr, dev) \
	for (int GT_UNIQV(i) = (dev)->dev_nmd->first_tx_ring; \
	     GT_UNIQV(i) <= (dev)->dev_nmd->last_tx_ring && \
	     ((txr = NETMAP_TXRING((dev)->dev_nmd->nifp, GT_UNIQV(i))), 1); \
	     ++GT_UNIQV(i))

#define DEV_FOREACH_TXRING_CONTINUE(i, txr, dev) \
	for (; i <= (dev)->dev_nmd->last_tx_ring && \
	     ((txr = NETMAP_TXRING((dev)->dev_nmd->nifp, i)), 1); \
	     ++i)

#define DEV_RXR_NEXT(rxr) \
	(rxr)->head = (rxr)->cur = nm_ring_next(rxr, (rxr)->cur)

#define dev_is_inited(dev) ((dev)->dev_fn != NULL)

int dev_mod_init(struct log *, void **);
int dev_mod_attach(struct log *, void *);
void dev_mod_deinit(struct log *, void *);
void dev_mod_detach(struct log *);

int dev_init(struct log *, struct dev *, const char *, dev_f);
void dev_deinit(struct log *, struct dev *);
void dev_clean(struct dev *);
void dev_rx_on(struct dev *);
void dev_rx_off(struct dev *);
int dev_not_empty_txr(struct dev *, struct dev_pkt *);
int dev_rxr_space(struct dev *, struct netmap_ring *);
void dev_tx(struct dev_pkt *);
int dev_tx3(struct dev *, void *, int);

static inline void
dev_prefetch(struct netmap_ring *ring)
{
	int cur;
	cur = nm_ring_next(ring, ring->cur);
	MEM_PREFETCH(NETMAP_BUF(ring, (ring->slot + cur)->buf_idx));
}

#endif // GBTCP_DEV_H
