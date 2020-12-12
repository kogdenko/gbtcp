// gpl2
#ifndef GBTCP_DEV_H
#define GBTCP_DEV_H

#include "timer.h"
#include "mbuf.h"

#define TX_CAN_RECLAIM (1 << 0)
#define TX_CAN_REDIRECT (1 << 1)

#define DEV_PKT_SIZE_MAX 2048

typedef void (*dev_f)(struct dev *, short);

struct dev {
	struct nm_desc *dev_nmd;
	struct fd_event *dev_event;
	int dev_cur_tx_ring;
	u_char dev_tx_throttled;
	u_short dev_tx_without_reclaim;
	uint64_t dev_cur_tx_ring_epoch;
	dev_f dev_fn;
	struct dlist dev_list;
	struct route_if *dev_ifp;
};

struct dev_pkt {
	u_short pkt_len;
	u_char pkt_sid;
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
	for (int UNIQV(i) = (dev)->dev_nmd->first_rx_ring; \
	     UNIQV(i) <= (dev)->dev_nmd->last_rx_ring && \
	     ((rxr = NETMAP_RXRING((dev)->dev_nmd->nifp, UNIQV(i))), 1); \
	     ++UNIQV(i))

#define DEV_FOREACH_TXRING(txr, dev) \
	for (int UNIQV(i) = (dev)->dev_nmd->first_tx_ring; \
	     UNIQV(i) <= (dev)->dev_nmd->last_tx_ring && \
	     ((txr = NETMAP_TXRING((dev)->dev_nmd->nifp, UNIQV(i))), 1); \
	     ++UNIQV(i))

#define DEV_FOREACH_TXRING_CONTINUE(i, txr, dev) \
	for (; i <= (dev)->dev_nmd->last_tx_ring && \
	     ((txr = NETMAP_TXRING((dev)->dev_nmd->nifp, i)), 1); \
	     ++i)

#define DEV_RXR_NEXT(rxr) \
	(rxr)->head = (rxr)->cur = nm_ring_next(rxr, (rxr)->cur)

#if 1
#define DEV_PKT_COPY(d, s, len) nm_pkt_copy(s, d, len)
#else
#define DEV_PKT_COPY(d, s, len) memcpy(d, s, len)
#endif

#define dev_is_inited(dev) ((dev)->dev_fn != NULL)

int dev_init(struct dev *, const char *, dev_f);
void dev_deinit(struct dev *);
void dev_close_fd(struct dev *);
void dev_rx_on(struct dev *);
void dev_rx_off(struct dev *);
int dev_not_empty_txr(struct dev *, struct dev_pkt *, int);
int dev_rxr_space(struct dev *, struct netmap_ring *);
void dev_transmit(struct dev_pkt *);

static inline void
dev_prefetch(struct netmap_ring *ring)
{
	int cur;
	cur = nm_ring_next(ring, ring->cur);
	MEM_PREFETCH(NETMAP_BUF(ring, (ring->slot + cur)->buf_idx));
}

#endif // GBTCP_DEV_H
