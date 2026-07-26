// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_DEV_H
#define GBTCP_DEV_H

#include <gbtcp/config.h>
#include <gbtcp/kernel/timer.h>

#define TX_CAN_REDIRECT (1 << 0)

#define DEV_RX_BURST_SIZE 256
#define DEV_TX_BURST_SIZE 64
#define DEV_PKT_SIZE_MAX 2048
#define DEV_QUEUE_HOST (-1)
#define DEV_QUEUE_NONE (-2)

enum gt_dev_io {
#if GT_HAVE_NETMAP
	GT_DEV_IO_NETMAP,
#endif // GT_HAVE_NETMAP
#if GT_HAVE_XDP
	GT_DEV_IO_XDP,
#endif // GT_HAVE_XDP
	GT_DEV_IO_MAX
};

#if GT_HAVE_NETMAP
#define GT_DEFAULT_DEV_IO GT_DEV_IO_NETMAP
#else
#define GT_DEFAULT_DEV_IO GT_DEV_IO_XDP
#endif // GT_HAVE_NETMAP

#define dev_is_inited(dev) ((dev)->dev_fn != NULL)

struct dev;
struct dev_pkt;

typedef void (*dev_f)(struct dev *, void *, int);

struct dev_ops {
	int (*dev_init_op)(struct dev *);
	void (*dev_deinit_op)(struct dev *, bool);
	int (*dev_rx_op)(struct dev *);
	void *(*dev_get_tx_packet_op)(struct dev *, struct dev_pkt *);
	void (*dev_put_tx_packet_op)(struct dev_pkt *);
	void (*dev_transmit_op)(struct dev_pkt *);
	void (*dev_tx_flush_op)(struct dev *);
};

struct dev {
	union {
		struct nm_desc *dev_nmd;
		struct xdp_queue *dev_xdp_queue;
	};
	struct fd_event *dev_event;
	struct dev_ops *dev_ops;
	u_char dev_tx_throttled;
	dev_f dev_fn;
	struct gt_dlist dev_list;
	struct route_if *dev_ifp;
	int dev_fd;
	int dev_queue_id;
	int dev_ifindex;
	char dev_ifname[IFNAMSIZ];
};

struct dev_pkt {
	struct dev *pkt_dev;
	u_short pkt_len;
	u_char pkt_sid;
	u_char *pkt_data;
	union {
		struct netmap_ring *pkt_txr;
		uint32_t pkt_idx;
	};
};

const char *gt_dev_io_to_str(int io);
int gt_dev_io_from_str(const char *s);

int gt_dev_init(struct dev *dev, u8 io, const char *ifname, int queue_id,
		dev_f dev_fn);
int gt_dev_deinit(struct dev *, bool);

void dev_rx_on(struct dev *);
void dev_rx_off(struct dev *);
int dev_get_tx_packet(struct dev *, struct dev_pkt *);
void dev_put_tx_packet(struct dev_pkt *);
void dev_transmit(struct dev_pkt *);
void dev_tx_flush(void);

#endif // GBTCP_DEV_H
