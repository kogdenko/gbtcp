// GPL v2 License
#ifndef GBTCP_DEV_H
#define GBTCP_DEV_H

#include "timer.h"
#include "mbuf.h"

#define TX_CAN_REDIRECT (1 << 0)

#define DEV_RX_BURST_SIZE 256
#define DEV_TX_BURST_SIZE 64
#define DEV_PKT_SIZE_MAX 2048
#define DEV_QUEUE_HOST (-1)
#define DEV_QUEUE_NONE (-2)

#ifdef HAVE_NETMAP
#define DEV_TRANSPORT_NETMAP 0
#define DEV_TRANSPORT_DEFAULT DEV_TRANSPORT_NETMAP
#endif // HAVE_NETMAP

#ifdef HAVE_XDP
#define DEV_TRANSPORT_XDP 1
#ifndef DEV_TRANSPORT_DEFAULT
#define DEV_TRANSPORT_DEFAULT DEV_TRANSPORT_XDP
#endif // DEV_TRANSPORT_DEFAULT
#endif // HAVE_XDP

#define dev_is_inited(dev) ((dev)->dev_fn != NULL)

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
	struct dlist dev_list;
	struct route_if *dev_ifp;
	int dev_fd;
	int dev_queue_id;
	char dev_ifname[IFNAMSIZ];
};

struct dev_pkt {
	struct mbuf pkt_mbuf;
	struct dev *pkt_dev;
	u_short pkt_len;
	u_char pkt_sid;
	u_char *pkt_data;
	union {
		struct netmap_ring *pkt_txr;
		uint32_t pkt_idx;
	};
};

const char *dev_transport_str(int);
int dev_transport_from_str(const char *);
int dev_transport_get(void);

int dev_mod_init(void);

int dev_init(struct dev *, int, const char *, int, dev_f);
void dev_deinit(struct dev *, bool);
void dev_rx_on(struct dev *);
void dev_rx_off(struct dev *);
int dev_get_tx_packet(struct dev *, struct dev_pkt *);
void dev_put_tx_packet(struct dev_pkt *);
void dev_transmit(struct dev_pkt *);
void dev_tx_flush(void);

#endif // GBTCP_DEV_H
