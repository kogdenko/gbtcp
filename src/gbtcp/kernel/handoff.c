// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/kernel/handoff.h>
#include <gbtcp/kernel/log.h>
#include <gbtcp/kernel/mod.h>
#include <gbtcp/kernel/netlink.h>
#include <gbtcp/kernel/shm.h>
#include <gbtcp/kernel/sys.h>
#include <gbtcp/kernel/worker.h>

#define gt_debug(...) gt_debug3(&gt_main->infra_logger, ##__VA_ARGS__)
#define gt_info(...) gt_info3(&gt_main->infra_logger, ##__VA_ARGS__)
#define gt_notice(...) gt_notice3(&gt_main->infra_logger, ##__VA_ARGS__)
#define gt_warning(...) gt_warning3(&gt_main->infra_logger, ##__VA_ARGS__)
#define gt_err(...) gt_err3(&gt_main->infra_logger, ##__VA_ARGS__)

#define MSG_ETHTYPE 0x0101

struct service_msg {
	uint16_t msg_type;
	uint16_t msg_ifindex;
	be16_t msg_orig_type;
	struct gt_eth_addr msg_orig_saddr;
	struct gt_eth_addr msg_orig_daddr;
};

static int
gt_worker_rx(struct route_if *ifp, void *data, int len)
{
	int i, rc;

	// gt_main isn't valid yet during the attach handshake, and gt_main
	// alone doesn't catch a not-yet-synced sibling thread either — see the
	// same guard (and why) in gt_worker_tx() (node.c). No rx traffic
	// reaches a worker before it's synced, but stay consistent regardless.
	if (gt_main == NULL || current->n_worker_modules == 0) {
		return IN_BYPASS;
	}

	// TODO:
	for (i = 0; i < gt_main->n_rx_callbacks; ++i) {
		rc = GT_WORKER_FUNC_EXEC(&gt_main->rx_callbacks[i], rx, ifp,
					 data, len);
		if (rc != IN_BYPASS) {
			return rc;
		}
	}

	return IN_BYPASS;
}

static int
gt_do_handoff(struct route_if *ifp, int msg_type, u_char sid, const void *data,
	      int len)
{
	int rc;
	struct dev_pkt pkt;

	rc = dev_get_tx_packet(&current->wrk_handoff, &pkt);
	if (rc == 0) {
		memcpy(pkt.pkt_data, data, len);
		pkt.pkt_len = len;
		pkt.pkt_sid = sid;
		redirect_dev_transmit(ifp, msg_type, &pkt);
	}
	return rc;
}

void
service_rssq_rx(struct dev *dev, void *data, int len)
{
	int in, rc;
	u_char sid;
	struct route_if *ifp;

	ifp = dev->dev_ifp;
	in = gt_worker_rx(ifp, data, len);
	if (in == IN_BYPASS) {
		// TODO: restore bypassing to Linux
		if (current == gt_controller_service) {
			transmit_to_host(ifp, data, len);
		} else {
			rc = gt_do_handoff(ifp, SERVICE_MSG_BYPASS, 0, data,
					   len);
			if (rc) {
				// TODO: increment counter
			}
		}
	} else if (in >= 0) {
		sid = in;
		rc = gt_do_handoff(ifp, SERVICE_MSG_RX, sid, data, len);
		if (rc) {
			counter64_inc(&ifp->rif_rx_drop);
			return;
		}
	}

	counter64_inc(&ifp->rif_rx_pkts);
	counter64_add(&ifp->rif_rx_bytes, len);
}

static void
gt_worker_handoff_rx(struct dev *dev, void *data, int len)
{
	int rc, dst_sid;
	struct eth_hdr *eh;
	struct route_if *ifp;
	struct service_msg *msg;
	struct dev_pkt pkt;

	if (len < sizeof(*eh)) {
		// TODO: counter
	}
	eh = data;
	if (eh->eh_type != MSG_ETHTYPE) {
		return;
	}
	if (len < sizeof(*msg) + sizeof(*eh)) {
		// TODO: counter
		return;
	}
	dst_sid = eh->eh_daddr.eth_u8[5];
	if (dst_sid != current->p_sid) {
		// TODO: counter
		return;
	}
	msg = (struct service_msg *)((u_char *)data + len - sizeof(*msg));
	ifp = route_if_get_by_index(msg->msg_ifindex);
	if (ifp == NULL) {
		return;
	}
	eh->eh_type = msg->msg_orig_type;
	eh->eh_saddr = msg->msg_orig_saddr;
	eh->eh_daddr = msg->msg_orig_daddr;
	len -= sizeof(*msg);
	switch (msg->msg_type) {
	case SERVICE_MSG_RX:
		gt_worker_rx(NULL, data, len);
		break;
	case SERVICE_MSG_TX:
		rc = route_get_tx_packet(ifp, &pkt, 0);
		if (rc == 0) {
			memcpy(pkt.pkt_data, data, len);
			pkt.pkt_len = len;
			route_transmit(ifp, &pkt);
		} else {
			counter64_inc(&ifp->rif_tx_drop);
		}
		break;
	case SERVICE_MSG_BYPASS:
		// Only the controller's own service passes traffic to the
		// host stack (gt_controller_service is NULL in worker
		// processes).
		if (current == gt_controller_service) {
			transmit_to_host(ifp, data, len);
		}
		break;
	}
}

#if GT_HAVE_VALE
int
gt_main_handoff_init(struct service *s)
{
	return 0;
}

void
gt_main_handoff_deinit(struct service *s)
{
}

int
gt_worker_handoff_init(struct service *s)
{
	int rc;
	char ifname[IFNAMSIZ];

	snprintf(ifname, sizeof(ifname), "vale_gt:%d", s->p_sid);
	rc = gt_dev_init(&s->wrk_handoff, GT_DEFAULT_DEV_IO, ifname,
			 DEV_QUEUE_NONE, gt_worker_handoff_rx);
	return rc;
}
#else // GT_HAVE_VALE
static void
gt_handoff_switch(struct dev *dev, void *data, int len)
{
	int rc;
	u_char dst_sid, src_sid;
	struct eth_hdr *eh;
	struct dev_pkt pkt;
	struct service *s;

	if (len < sizeof(*eh)) {
		// TODO: counter
		return;
	}
	eh = data;
	if (eh->eh_type != MSG_ETHTYPE) {
		return;
	}
	s = container_of(dev, struct service, wrk_handoff_peer);
	src_sid = s->p_sid;
	dst_sid = eh->eh_daddr.eth_u8[5];
	// p_inited (not p_pid): a claimed slot whose handshake is still in
	// flight has no handoff machinery yet.
	if (dst_sid >= GT_SERVICES_MAX ||
	    !service_get_by_sid(dst_sid)->p_inited) {
		// TODO: counter
		return;
	}
	if (dst_sid == src_sid) {
		return;
	}
	if (dst_sid == current->p_sid) {
		gt_worker_handoff_rx(NULL, data, len);
		return;
	}
	s = shared->shm_services + dst_sid;
	if (!s->p_inited) {
		return;
	}
	rc = dev_get_tx_packet(&s->wrk_handoff_peer, &pkt);
	if (rc == 0) {
		memcpy(pkt.pkt_data, data, len);
		pkt.pkt_len = len;
		dev_transmit(&pkt);
	}
}

#define SERVICE_VETHF "gtv%c%d"

int
gt_main_handoff_init(struct service *s)
{
	int i, rc, added, ifindex, flags;
	char ifname[2][IFNAMSIZ];

	added = 0;
	snprintf(ifname[0], IFNAMSIZ, SERVICE_VETHF, 's', s->p_sid);
	snprintf(ifname[1], IFNAMSIZ, SERVICE_VETHF, 'c', s->p_sid);
	rc = netlink_veth_add(ifname[0], ifname[1]);
	if (rc < 0) {
		goto err;
	}
	added = 1;
	for (i = 0; i < GT_ARRAY_SIZE(ifname); ++i) {
		rc = sys_if_nametoindex(ifname[i]);
		if (rc < 0) {
			goto err;
		}
		ifindex = rc;
		rc = netlink_link_get_flags(ifindex);
		if (rc < 0) {
			goto err;
		}
		flags = rc;
		rc = netlink_link_up(ifindex, ifname[i], flags);
		if (rc < 0) {
			goto err;
		}
	}
	rc = gt_dev_init(&s->wrk_handoff_peer, GT_DEFAULT_DEV_IO, ifname[1], 0,
			 gt_handoff_switch);
	if (rc < 0) {
		goto err;
	}
	return rc;
err:
	gt_err(-rc, "Failed to create device for redirecting packets");
	if (added) {
		netlink_link_del(ifname[1]);
	}
	return rc;
}

void
gt_main_handoff_deinit(struct service *s)
{
	char peer[IFNAMSIZ];

	gt_dev_deinit(&s->wrk_handoff_peer, false);
	snprintf(peer, sizeof(peer), SERVICE_VETHF, 'c', s->p_sid);
	netlink_link_del(peer);
}

int
gt_worker_handoff_init(struct service *s)
{
	int rc;
	char ifname[IFNAMSIZ];

	snprintf(ifname, sizeof(ifname), SERVICE_VETHF, 's', s->p_sid);
	rc = gt_dev_init(&s->wrk_handoff, GT_DEFAULT_DEV_IO, ifname, 0,
			 gt_worker_handoff_rx);
	return rc;
}
#endif // GT_HAVE_VALE

void
gt_worker_handoff_deinit(void)
{
	gt_dev_deinit(&current->wrk_handoff, false);
}

int
redirect_dev_get_tx_packet(struct route_if *ifp, struct dev_pkt *pkt)
{
	int i, n, rc;
	u_char s[GT_RSS_NQ_MAX];

	// Round robin between services which can send packet
	n = 0;
	for (i = 0; i < ifp->rif_rss_queue_num; ++i) {
		s[n] = READ_ONCE(shared->shm_rss_table[i]);
		if (s[n] != SERVICE_ID_INVALID) {
			n++;
		}
	}
	if (n == 0) {
		return -ENODEV;
	}
	rc = dev_get_tx_packet(&current->wrk_handoff, pkt);
	if (rc) {
		return rc;
	}
	if (current->p_rr_redir >= n) {
		current->p_rr_redir = 0;
	}
	pkt->pkt_sid = s[current->p_rr_redir];
	current->p_rr_redir++;
	return 0;
}

void
redirect_dev_transmit(struct route_if *ifp, int msg_type, struct dev_pkt *pkt)
{
	struct eth_hdr *eh;
	struct service_msg *msg;

	msg = (struct service_msg *)((u_char *)pkt->pkt_data + pkt->pkt_len);
	eh = (struct eth_hdr *)pkt->pkt_data;
	msg->msg_orig_type = eh->eh_type;
	msg->msg_orig_saddr = eh->eh_saddr;
	msg->msg_orig_daddr = eh->eh_daddr;
	eh->eh_type = MSG_ETHTYPE;
	memset(eh->eh_saddr.eth_u8, 0, sizeof(eh->eh_saddr));
	memset(eh->eh_daddr.eth_u8, 0, sizeof(eh->eh_daddr));
	eh->eh_saddr.eth_u8[5] = current->p_sid;
	assert(pkt->pkt_sid < GT_SERVICES_MAX);
	eh->eh_daddr.eth_u8[5] = pkt->pkt_sid;
	msg->msg_type = msg_type;
	msg->msg_ifindex = ifp->rif_index;
	pkt->pkt_len += sizeof(*msg);
	dev_transmit(pkt);
}
