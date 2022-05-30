// GPL v2 License
#ifndef GBTCP_DEV_H
#define GBTCP_DEV_H

#include "timer.h"
#include "mbuf.h"

#define TX_CAN_REDIRECT (1 << 0)

#define DEV_PKT_SIZE_MAX 2048
#define DEV_QUEUE_HOST (-1)
#define DEV_QUEUE_NONE (-2)

#define DEV_PKT_COPY(d, s, len) memcpy(d, s, len)

#define dev_is_inited(dev) ((dev)->dev_fn != NULL)

typedef void (*dev_f)(struct dev *, void *, int);

struct dev {
	struct nm_desc *dev_nmd;
	struct fd_event *dev_event;
	u_char dev_tx_throttled;
	dev_f dev_fn;
	struct dlist dev_list;
	struct route_if *dev_ifp;
	int dev_fd;
	int dev_queue_id;
	char dev_ifname[IFNAMSIZ];
};

struct dev_pkt {
	struct mbuf pkt_mbuf;
	u_short pkt_len;
	u_char pkt_sid;
	u_char *pkt_data;
	struct netmap_ring *pkt_txr;
};

int dev_init(struct dev *, const char *, int, dev_f);
void dev_deinit(struct dev *);
void dev_close_fd(struct dev *);
void dev_rx_on(struct dev *);
void dev_rx_off(struct dev *);
int dev_not_empty_txr(struct dev *, struct dev_pkt *);
void dev_transmit(struct dev_pkt *);

#endif // GBTCP_DEV_H
