#ifndef GBTCP_DEV_H
#define GBTCP_DEV_H

#include "timer.h"
#include "mbuf.h"

#define GT_DEV_PKT_SIZE 2048

struct gt_dev;

typedef void (*gt_dev_f)(struct gt_dev *, short revents);

struct gt_dev {
	struct nm_desc *dev_nmd;
	struct gt_fd_event *dev_event;
	int dev_cur_tx_ring;
	int dev_tx_full;
	uint64_t dev_cur_tx_ring_epoch;
	gt_dev_f dev_fn;
	struct dlist dev_list;
	char dev_name[NM_IFNAMSIZ];
};

struct gt_dev_pkt {
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
	uint8_t *pkt_data;
};

#define GT_DEV_FIRST_RXRING(dev) \
	NETMAP_RXRING((dev)->dev_nmd->nifp, (dev)->dev_nmd->first_rx_ring)

#define GT_DEV_RXRING(dev, i) \
	NETMAP_RXRING((dev)->dev_nmd->nifp, i)

#define GT_DEV_FIRST_TXRING(dev) \
	NETMAP_TXRING((dev)->dev_nmd->nifp, (dev)->dev_nmd->first_tx_ring)

#define GT_DEV_FOREACH_RXRING(rxr, dev) \
	for (int GT_UNIQV(i) = (dev)->dev_nmd->first_rx_ring; \
	     GT_UNIQV(i) <= (dev)->dev_nmd->last_rx_ring && \
	     ((rxr = NETMAP_RXRING((dev)->dev_nmd->nifp, GT_UNIQV(i))), 1); \
	     ++GT_UNIQV(i))

#define GT_DEV_FOREACH_TXRING(txr, dev) \
	for (int GT_UNIQV(i) = (dev)->dev_nmd->first_tx_ring; \
	     GT_UNIQV(i) <= (dev)->dev_nmd->last_tx_ring && \
	     ((txr = NETMAP_TXRING((dev)->dev_nmd->nifp, GT_UNIQV(i))), 1); \
	     ++GT_UNIQV(i))

#define GT_DEV_FOREACH_TXRING_CONTINUE(i, txr, dev) \
	for (; i <= (dev)->dev_nmd->last_tx_ring && \
	     ((txr = NETMAP_TXRING((dev)->dev_nmd->nifp, i)), 1); \
	     ++i)

#define GT_DEV_RXR_NEXT(rxr) \
	(rxr)->head = (rxr)->cur = nm_ring_next(rxr, (rxr)->cur)

int dev_mod_init(struct log *, void **);
int dev_mod_attach(struct log *, void *);
void dev_mod_deinit(struct log *, void *);
void dev_mod_detach(struct log *);

struct gt_dev *gt_dev_get(const char *if_name);

int gt_dev_init(struct log *log, struct gt_dev *dev, const char *if_name,
	gt_dev_f fn);

void gt_dev_deinit(struct gt_dev *dev);

void gt_dev_rx_on(struct gt_dev *dev);

void gt_dev_rx_off(struct gt_dev *dev);

int gt_dev_not_empty_txr(struct gt_dev *dev, struct gt_dev_pkt *pkt);

int gt_dev_rxr_space(struct gt_dev *dev, struct netmap_ring *rxr);

void gt_dev_tx(struct gt_dev_pkt *pkt);

int gt_dev_tx3(struct gt_dev *dev, void *data, int len);

static inline void
gt_dev_prefetch(struct netmap_ring *ring)
{
	int cur;

	cur = nm_ring_next(ring, ring->cur);
	GT_MEM_PREFETCH(NETMAP_BUF(ring, (ring->slot + cur)->buf_idx));
}

#endif /* GBTCP_DEV_H */
