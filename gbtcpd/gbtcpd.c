#include <gbtcp/gbtcp_lib.h>

struct gtd_net_stat_entry {
	const char *nse_name;
	uint64_t *nse_ptr;
};

struct gtd_service {
	struct gt_list_head s_list;
	int s_pid;
	int s_qid;
	int s_status;
	int s_port_pairity;
	int s_ref_cnt;
	gt_time_t s_ctime;
	struct gt_dev s_pipe;
	struct gtd_net_stat_entry *s_req;
};

#define GTD_LOG_NODE_FOREACH(x) \
	x(service_get_net_stat) \
	x(service_get_if_stat) \
	x(service_sub_handler) \
	x(if_add) \
	x(main) \
	x(set_rss_conf) \
	x(service_add) \
	x(service_set_status) \
	x(service_del) \
	x(service_free) \
	x(service_start) \

#define GTD_TCP_STAT(n) \
	{ \
		.nse_name = "tcp."#n, \
		.nse_ptr = &gt_tcps.tcps_##n \
	},
#define GTD_TCP_STATE(i) \
	{ \
		.nse_name = "tcp.states." #i, \
		.nse_ptr = gt_tcps.tcps_states + i \
	},
#define GTD_UDP_STAT(n) \
	{ \
		.nse_name = "udp."#n, \
		.nse_ptr = &gt_udps.udps_##n \
	},
#define GTD_IP_STAT(n) \
	{ \
		.nse_name = "ip."#n, \
		.nse_ptr = &gt_ips.ips_##n \
	},
#define GTD_ARP_STAT(n) \
	{ \
		.nse_name = "arp."#n, \
		.nse_ptr = &gt_arps.arps_##n \
	},

static struct gtd_net_stat_entry gtd_net_stat_entries[] = {
	GT_TCP_STAT(GTD_TCP_STAT)
	GTD_TCP_STATE(0)
	GTD_TCP_STATE(1)
	GTD_TCP_STATE(2)
	GTD_TCP_STATE(3)
	GTD_TCP_STATE(4)
	GTD_TCP_STATE(5)
	GTD_TCP_STATE(6)
	GTD_TCP_STATE(7)
	GTD_TCP_STATE(8)
	GTD_TCP_STATE(9)
	GTD_TCP_STATE(10)
	GT_UDP_STAT(GTD_UDP_STAT)
	GT_IP_STAT(GTD_IP_STAT)
	GT_ARP_STAT(GTD_ARP_STAT)
	{ NULL, NULL }

};
#undef GTD_TCP_STATE
#undef GTD_TCP_STAT
#undef GTD_UDP_STAT
#undef GTD_IP_STAT
#undef GTD_ARP_STAT

static struct gtd_service *gtd_services[2][GT_SERVICES_MAX];
static struct gt_log_scope this_log;
GTD_LOG_NODE_FOREACH(GT_LOG_NODE_STATIC);

static void gtd_service_unref(struct gt_log *log, struct gtd_service *s);

static int gtd_service_get_net_stat_cb(struct gt_log *log, void *udata,
	int eno, char *old);

static int gtd_service_get_net_stat(struct gtd_service *s);

static void gtd_tx_to_host(struct gt_route_if *ifp, void *data, int len);

static void gtd_tx_to_net(struct gt_route_if *ifp, void *data, int len);

static void gtd_host_rxtx(struct gt_dev *dev, short revents);

static void gtd_tx_bcast(struct gtd_service *from, struct gt_route_if *ifp,
	void *data, int len);

static int gtd_pipe_in(struct gtd_service *s, uint8_t *data, int len);

static void gtd_pipe_rxtx(struct gt_dev *dev, short revents);

static int gtd_service_get_if_stat_cb(struct gt_log *log, void *udata,
	int eno, char *old);

static int gtd_service_get_if_stat(struct gtd_service *s,
	struct gt_route_if *ifp);

static void gtd_service_set_status(struct gt_log *log, struct gtd_service *s,
	int status);

static void gtd_deinit(struct gt_log *log);

static void gtd_service_start(struct gt_log *log);

static int gtd_set_rss_conf(struct gt_log *log, int rss_q_cnt,
	const uint8_t *rss_key);

static int gtd_if_add(struct gt_log *log, struct gt_route_if *ifp);

static int gtd_if_set_link_status(struct gt_log * log, struct gt_route_if *ifp,
	int add);

static struct gtd_service *gtd_service_find(int pid);

static int gtd_service_add(struct gt_log *log, int pid, struct gtd_service **ps);

static void gtd_service_sub_handler(int pid, int action);

static int gtd_ctl_service_add(struct gt_log *log, void *udata,
	const char *new, struct gt_strbuf *out);

static void gtd_service_del(struct gt_log *log, struct gtd_service *s);

static int gtd_ctl_service_del(struct gt_log *log, void *udata,
	const char *new, struct gt_strbuf *out);

static int gtd_ctl_service_list_next(void *udata, int pid);

static int gtd_ctl_service_list(void *udata, int id, const char *new,
	struct gt_strbuf *out);

#define GTD_SERVICE_FOREACH(s) \
	for (int GT_UNIQV(i) = 0; GT_UNIQV(i) < 2; ++GT_UNIQV(i)) \
		for (int GT_UNIQV(j) = 0; \
		     GT_UNIQV(j) < gt_route_rss_q_cnt; \
		     ++GT_UNIQV(j)) \
			if ((s = gtd_services[GT_UNIQV(i)][GT_UNIQV(j)]) \
				!= NULL)

static void
gtd_service_unref(struct gt_log *log, struct gtd_service *s)
{
	GT_ASSERT(s->s_ref_cnt > 0);
	s->s_ref_cnt--;
	if (s->s_ref_cnt == 0) {
		log = GT_LOG_TRACE(log, service_free);
		GT_LOGF(log, LOG_INFO, 0, "hit; pid=%d", s->s_pid);
		gt_dev_deinit(&s->s_pipe);
		gt_ctl_unsub(log, s->s_pid);
		free(s);
	}
}

static int
gtd_service_get_net_stat_cb(struct gt_log *log, void *udata, int eno,
	char *old)
{
	int rc;
	unsigned long long x;
	char *endptr;
	struct gtd_service *s;

	rc = 0;
	s = udata;
	if (eno == 0) {
		x = strtoull(old, &endptr, 10);
		if (*endptr != '\0') {
			rc = -EINVAL;
		} else {
			*s->s_req->nse_ptr += x;
			s->s_req++;
			gtd_service_get_net_stat(s);
		}
	}
	gtd_service_unref(log, s);
	return rc;
}

static int
gtd_service_get_net_stat(struct gtd_service *s)
{
	int rc;
	char path[PATH_MAX];
	struct gt_log *log;

	log = GT_LOG_TRACE1(service_get_net_stat);
	if (s->s_req->nse_name == NULL) {
		return 0;
	}
	s->s_ref_cnt++;
	snprintf(path, sizeof(path), "inet.stat.%s", s->s_req->nse_name);
	rc = gt_ctl_r(log, s->s_pid, path,
	              s, gtd_service_get_net_stat_cb, NULL);
	if (rc) {
		gtd_service_unref(log, s);
		return rc;
	}
	return 0;
}

static void
gtd_tx_to_host(struct gt_route_if *ifp, void *data, int len)
{
	len -= sizeof(struct gt_service_msg);
	gt_dev_tx3(&ifp->rif_dev, data, len);
}

static void
gtd_tx_to_net(struct gt_route_if *ifp, void *data, int len)
{
	int i, rc;
	struct gt_service_msg *msg;
	struct gt_dev_pkt pkt;
	struct gtd_service *s;

	rc = -ENOBUFS;
	for (i = 0; i < gt_route_rss_q_cnt; ++i) {
		s = gtd_services[GT_SERVICE_ACTIVE][i];
		if (s != NULL) {
			rc = gt_dev_not_empty_txr(&s->s_pipe, &pkt);
			if (rc == 0) {
				break;
			}
		}
	}
	if (rc) {
		return;
	}
	msg = (struct gt_service_msg *)(data + len);
	len += sizeof(*msg);
	msg->svcm_cmd = GT_INET_BYPASS;
	msg->svcm_if_idx = ifp->rif_idx;
	GT_PKT_COPY(pkt.pkt_data, data, len);
	pkt.pkt_len = len;
	gt_dev_tx(&pkt);
}

static void
gtd_host_rxtx(struct gt_dev *dev, short revents)
{
	int i, n, len;
	uint8_t *data;
	struct netmap_ring *rxr;
	struct netmap_slot *slot;
	struct gt_route_if *ifp;

	ifp = gt_container_of(dev, struct gt_route_if, rif_dev);
	GT_DEV_FOREACH_RXRING(rxr, dev) {
		n = gt_dev_rxr_space(dev, rxr);
		for (i = 0; i < n; ++i) {
			slot = rxr->slot + rxr->cur;
			data = (uint8_t *)NETMAP_BUF(rxr, slot->buf_idx);
			len = slot->len;
			gtd_tx_to_net(ifp, data, len);
			GT_DEV_RXR_NEXT(rxr);
		}
	}
}

static void
gtd_tx_bcast(struct gtd_service *from, struct gt_route_if *ifp, void *data,
	int len)
{
	struct gtd_service *s;

	GTD_SERVICE_FOREACH(s) {
		if (s != from) {
			gt_dev_tx3(&s->s_pipe, data, len);
		}
	}
	gtd_tx_to_host(ifp, data, len);
}

static int
gtd_pipe_in(struct gtd_service *s, uint8_t *data, int len)
{
	struct gt_service_msg *msg;
	struct gt_route_if *ifp;

	if (len < sizeof(*msg)) {
		return -EINVAL;
	}
	msg = (struct gt_service_msg *)(data + len - sizeof(*msg));
	ifp = gt_route_if_get_by_idx(msg->svcm_if_idx);
	if (ifp == NULL) {
		return -ENODEV;
	}
	switch (msg->svcm_cmd) {
	case GT_INET_OK:
		gtd_tx_to_net(ifp, data, len);
		break;
	case GT_INET_BYPASS:
		gtd_tx_to_host(ifp, data, len);
		break;
	case GT_INET_BCAST:
		gtd_tx_bcast(s, ifp, data, len);
		break;
	default:
		return -ENOMSG;
	}
	return 0;
}

static void
gtd_pipe_rxtx(struct gt_dev *dev, short revents)
{
	int i, n, len;
	void *data;
	struct netmap_ring *rxr;
	struct netmap_slot *slot;
	struct gtd_service *s;

	s = gt_container_of(dev, struct gtd_service, s_pipe);
	GT_DEV_FOREACH_RXRING(rxr, dev) {
		n = gt_dev_rxr_space(dev, rxr);
		for (i = 0; i < n; ++i) {
			slot = rxr->slot + rxr->cur;
			data = NETMAP_BUF(rxr, slot->buf_idx);
			len = slot->len;
			gtd_pipe_in(s, data, len);
			GT_DEV_RXR_NEXT(rxr);
		}
	}
}

static int
gtd_service_get_if_stat_cb(struct gt_log *log, void *udata, int eno, char *old)
{
	int rc, if_idx, tmpx;
	unsigned long long rx_pkts, rx_bytes, tx_pkts, tx_bytes, tx_drop;
	char tmp[128];
	struct gt_route_if *ifp;
	struct gtd_service *s;

	s = udata;
	gtd_service_unref(log, s);
	if (eno) {
		return 0;
	}
	rc = sscanf(old, "%128[^,],%d,%x,%32[^,],%llu,%llu,%llu,%llu,%llu",
	            tmp, &if_idx, &tmpx, tmp,
	            &rx_pkts,
	            &rx_bytes,
	            &tx_pkts,
	            &tx_bytes,
	            &tx_drop);
	if (rc != 9) {
		return -EINVAL;
	}
	ifp = gt_route_if_get_by_idx(if_idx);
	if (ifp == NULL) {
		return -ENXIO;
	}
	ifp->rif_cnt_rx_pkts += rx_pkts;
	ifp->rif_cnt_rx_bytes += rx_bytes;
	ifp->rif_cnt_tx_pkts += tx_pkts;
	ifp->rif_cnt_tx_bytes += tx_bytes;
	ifp->rif_cnt_tx_drop += tx_drop;
	return 0;
}

static int
gtd_service_get_if_stat(struct gtd_service *s, struct gt_route_if *ifp)
{
	int rc;
	char path[PATH_MAX];
	struct gt_log *log;

	log = GT_LOG_TRACE1(service_get_if_stat);
	s->s_ref_cnt++;
	snprintf(path, sizeof(path), GT_CTL_ROUTE_IF_LIST".%d", ifp->rif_idx);
	rc = gt_ctl_r(log, s->s_pid, path, s,
	              gtd_service_get_if_stat_cb, NULL);
	if (rc) {
		gtd_service_unref(log, s);
	}
	return rc;
}

static int
gtd_service_set_status_cb(struct gt_log *log, void *udata, int eno, char *old)
{
	struct gtd_service *s;

	s = udata;
	if (eno) {
		gtd_service_del(log, s);
	}
	gtd_service_unref(log, s);
	return 0;
}

static void
gtd_service_set_status(struct gt_log *log, struct gtd_service *s, int status)
{
	int rc;
	const char *new;

	log = GT_LOG_TRACE(log, service_set_status);
	if (s->s_status == status) {
		return;
	}
	new = gt_service_status_str(status);
	GT_LOGF(log, LOG_INFO, 0, "hit; pid=%d, status=%s", s->s_pid, new);
	s->s_status = status;
	rc = gt_ctl_r(log, s->s_pid, GT_CTL_SERVICE_STATUS,
	              s, gtd_service_set_status_cb, new);
	if (rc) {
		gtd_service_del(log, s);
	} else {
		s->s_ref_cnt++;
	}
}

static void
gtd_deinit(struct gt_log *log)
{
	gt_log_scope_deinit(log, &this_log);
	gt_global_deinit(log);
}

static void
gtd_service_start(struct gt_log *log)
{
	int rc;

	return;
	log = GT_LOG_TRACE(log, service_start);
	rc = gt_sys_fork(log);
	if (rc < 0) {
		return;
	} else if (rc == 0) {
		gtd_deinit(log);
		gt_global_init();
		log = GT_LOG_TRACE(log, service_start);
		gt_service_ctl_polling = 0;
		rc = gt_service_init(log);
		if (rc) {
			return;
		}
while (gt_service_pid) {
			gt_fd_event_mod_check();
		}
	}
}

static int
gtd_set_rss_conf(struct gt_log *log, int rss_q_cnt, const uint8_t *rss_key)
{
	int i;
	struct gtd_service *s;

	log = GT_LOG_TRACE(log, set_rss_conf);
	GTD_SERVICE_FOREACH(s) {
		gtd_service_del(log, s);
	}
	memset(gtd_services, 0, sizeof(gtd_services));
	gt_route_rss_q_cnt = rss_q_cnt;
	if (gt_route_rss_q_cnt > 1) {
		memcpy(gt_route_rss_key, rss_key, sizeof(gt_route_rss_key));
	}
	for (i = 0; i < gt_route_rss_q_cnt; ++i) {
		gtd_service_start(log);
	}
	GT_LOGF(log, LOG_INFO, 0, "ok; rss_q_cnt=%d", gt_route_rss_q_cnt);
	return 0;
}

static int
gtd_if_add(struct gt_log *log, struct gt_route_if *ifp)
{
	int rc, nr_rx_rings, nr_tx_rings;
	char ifname[GT_IFNAMSIZ];
	uint8_t rss_key[GT_RSS_KEY_SIZE];
	struct nmreq *req;

	log = GT_LOG_TRACE(log, if_add);
	if (ifp->rif_is_pipe == 0) {
		snprintf(ifname, sizeof(ifname), "%s^", ifp->rif_name);
		rc = gt_dev_init(log, &ifp->rif_dev, ifname, gtd_host_rxtx);
		if (rc) {
			return rc;
		}
	}
	req = &ifp->rif_dev.dev_nmd->req;
	nr_rx_rings = req->nr_rx_rings; 
	nr_tx_rings = req->nr_tx_rings;
	GT_ASSERT(nr_rx_rings > 0);
	if (nr_rx_rings > GT_SERVICES_MAX) {
		GT_LOGF(log, LOG_ERR, 0,
		        "invalid nr_rx_rings; if='%s', nr_rx_rings=%d, max=%d",
		        ifp->rif_name, nr_rx_rings, GT_SERVICES_MAX);
		return -EINVAL;
	}
	if (nr_tx_rings < nr_rx_rings) {
		GT_LOGF(log, LOG_ERR, 0,
		        "invalid nr_tx_rings; if='%s', nr_tx_rings=%d, min=%d",
		        ifp->rif_name, nr_tx_rings, nr_rx_rings);
		return -EINVAL;
	}
	if (nr_rx_rings > 1) {
		rc = gt_read_rss_key(log, ifp->rif_name, rss_key);
		if (rc) {
			return rc;
		}
	}
	if (gt_route_rss_q_cnt == 0) {
		gtd_set_rss_conf(log, nr_rx_rings, rss_key);
	} else if (nr_rx_rings != gt_route_rss_q_cnt) {
		GT_LOGF(log, LOG_ERR, 0,
		        "invalid nr_rx_rings; if='%s', nr_rx_rings=%d, rss_q_cnt=%d",
		        ifp->rif_name, nr_rx_rings, gt_route_rss_q_cnt);
		return -EINVAL;
	} else if (gt_route_rss_q_cnt > 1 &&
	           memcmp(gt_route_rss_key, rss_key, GT_RSS_KEY_SIZE)) {
		GT_LOGF(log, LOG_ERR, 0,
		        "invalid rss_key - all interfaces must have same rss_key; if=%s",
		        ifp->rif_name);
	}
	return 0;
}

static int
gtd_if_set_link_status(struct gt_log *log, struct gt_route_if *ifp, int add)
{
	int rc;

	if (add) {
		rc = gtd_if_add(log, ifp);
		if (rc) {
			gt_dev_deinit(&ifp->rif_dev);
		}
		return rc;
	} else {
		gt_dev_deinit(&ifp->rif_dev);
		if (gt_list_empty(&gt_route_if_head)) {
			gtd_set_rss_conf(log, 0, NULL);
		}
		return 0;
	}
}

static struct gtd_service *
gtd_service_find(int pid)
{
	struct gtd_service *s;
	
	GTD_SERVICE_FOREACH(s) {
		if (s->s_pid == pid) {
			return s;
		}
	}
	return NULL;
}

static int
gtd_service_add(struct gt_log *log, int pid, struct gtd_service **ps)
{
	int i, qid, rc;
	char ifname[GT_IFNAMSIZ];
	struct gtd_service *oldest_active, *s, *active, *shadow;

	log = GT_LOG_TRACE(log, service_add);
	GT_LOGF(log, LOG_INFO, 0, "hit; pid=%d", pid);
	*ps = NULL;
	s = gtd_service_find(pid);
	if (s != NULL) {
		*ps = s;
		GT_LOGF(log, LOG_ERR, 0, "already; pid=%d", pid);
		return -EEXIST;
	}
	if (gt_route_rss_q_cnt == 0) {
		GT_LOGF(log, LOG_ERR, 0, "no rss q");
		return -ENXIO;
	}
	rc = gt_sys_malloc(log, (void **)&s, sizeof(*s));
	if (rc < 0) {
		return rc;
	}
	memset(s, 0, sizeof(*s));
	snprintf(ifname, sizeof(ifname), "gbtcp.%d{0", pid);
	rc = gt_dev_init(log, &s->s_pipe, ifname, gtd_pipe_rxtx);
	if (rc) {
		free(s);
		return rc;
	}
	qid = -1;
	oldest_active = NULL;
	for (i = 0; i < gt_route_rss_q_cnt; ++i) {
		active = gtd_services[GT_SERVICE_ACTIVE][i];
		if (active == NULL) {
			qid = i;
			break;
		} else {
			if (oldest_active == NULL ||
			    oldest_active->s_ctime > active->s_ctime) {
				oldest_active = active;
				qid = i;
			}
		}
	}
	if (qid == -1) {
		return -ENXIO;
	}
	active = gtd_services[GT_SERVICE_ACTIVE][qid];
	if (active == NULL) {
		s->s_port_pairity = 0;
		goto out;
	}
	s->s_port_pairity = 1 - active->s_port_pairity;
	shadow = gtd_services[GT_SERVICE_SHADOW][qid];
	if (shadow != NULL) {
		gtd_service_del(log, shadow);
	}
	gtd_services[GT_SERVICE_SHADOW][qid] = active;
	gtd_service_set_status(log, active, GT_SERVICE_SHADOW);
out:
	gtd_services[GT_SERVICE_ACTIVE][qid] = s;
	s->s_pid = pid;
	s->s_ctime = gt_nsec;
	s->s_qid = qid;
	s->s_status = GT_SERVICE_ACTIVE;
	s->s_ref_cnt = 1;
	*ps = s;
	GT_LOGF(log, LOG_INFO, 0, "ok; pid=%d, qid=%d", pid, qid);
	return 0;
}

static void
gtd_service_sub_handler(int pid, int action)
{
	struct gt_log *log;
	struct gtd_service *s;

	s = gtd_service_find(pid);
	if (s != NULL && action == GT_CTL_UNSUB) {
		log = GT_LOG_TRACE1(service_sub_handler);
		GT_LOGF(log, LOG_ERR, 0, "unexpected unsubscribe; pid=%d",
		        pid);
		gtd_service_del(log, s);
	}
}

static int
gtd_ctl_service_add(struct gt_log *log, void *udata, const char *new,
	struct gt_strbuf *out)
{
	int rc, pid;
	struct gtd_service *s;

	if (new == NULL) {
		return 0;
	}
	rc = sscanf(new, "%d", &pid);
	if (rc != 1) {
		return -EINVAL;
	}
	rc = gtd_service_add(log, pid, &s);
	if (rc < 0) {
		return rc;
	}
	gt_strbuf_addf(out, "%d,%d,%d,",
	               s->s_qid, gt_route_rss_q_cnt, s->s_port_pairity);
	gt_strbuf_add_rss_key(out, gt_route_rss_key);
	return 0;
}

static void
gtd_service_del(struct gt_log *log, struct gtd_service *s)
{
	int rc;
	struct gt_route_if *ifp;

	GT_ASSERT(s->s_status < 2);
	log = GT_LOG_TRACE(log, service_del);
	gtd_services[s->s_status][s->s_qid] = NULL;
	GT_LOGF(log, LOG_INFO, 0, "hit; pid=%d", s->s_pid);
	GT_ROUTE_IF_FOREACH(ifp) {
		rc = gtd_service_get_if_stat(s, ifp);
		if (rc) {
			return;
		}
	}
	s->s_req = gtd_net_stat_entries;
	gtd_service_get_net_stat(s);
	gtd_service_unref(log, s);
}

static int
gtd_ctl_service_del(struct gt_log *log, void *udata, const char *new,
	struct gt_strbuf *out)
{
	int rc, pid;
	struct gtd_service *s;

	if (new == NULL) {
		return 0;
	}
	rc = sscanf(new, "%d", &pid);
	if (rc != 1) {
		return -EINVAL;
	}
	s = gtd_service_find(pid);
	if (s == NULL) {
		return -EEXIST;
	}
	gtd_service_del(log, s);
	return 0;
}

static int
gtd_ctl_service_list_next(void *udata, int pid)
{
	struct gtd_service *s, *next;

	next = NULL;
	GTD_SERVICE_FOREACH(s) {
		if (s->s_pid > pid) {
			if (next == NULL || next->s_pid > s->s_pid) {
				next = s;
			}
		}
	}
	if (next == NULL) {
		return -ENOENT;
	} else {
		return next->s_pid;
	}
}

static int
gtd_ctl_service_list(void *udata, int id, const char *new,
	struct gt_strbuf *out)
{
	struct gtd_service *s;

	s = gtd_service_find(id);
	if (s == NULL) {
		return -ENOENT;
	}
	gt_strbuf_addf(out, "%d,%s", s->s_qid,
	               gt_service_status_str(s->s_status));
	return 0;	
}

int
main(int argc, char **argv)
{
	int rc, opt;
	const char *path;
	struct gt_log *log;

	path = NULL;
	while ((opt = getopt(argc, argv, "hc:")) != -1) {
		switch (opt) {
		case 'h':
			printf("Usage: gbtcpd [-h] [-c path]\n");
		case 'c':
			path = optarg;
			break;
		}
	}
	GT_GLOBAL_LOCK;
	rc = gt_global_init();
	if (rc) {
		GT_GLOBAL_UNLOCK;
		fprintf(stderr, "Initialization failed\n");
		return 1;
	}
	gt_route_if_set_link_status_fn = gtd_if_set_link_status;
	gt_log_scope_init(&this_log, "gbtcpd");
	GTD_LOG_NODE_FOREACH(GT_LOG_NODE_INIT);
	log = GT_LOG_TRACE1(main);
	gt_ctl_read_file(log, path);
	rc = gt_ctl_bind(log, 0);
	if (rc) {
		return 1;
	}
	gt_ctl_sub_fn = gtd_service_sub_handler;
	gt_ctl_add(log, GT_CTL_SERVICE_ADD, GT_CTL_WR,
	           NULL, NULL, gtd_ctl_service_add);
	gt_ctl_add(log, GT_CTL_SERVICE_DEL, GT_CTL_WR,
	           NULL, NULL, gtd_ctl_service_del);
	gt_ctl_add_list(log, GT_CTL_SERVICE_LIST, GT_CTL_RD, NULL,
	                gtd_ctl_service_list_next,
	                gtd_ctl_service_list);
	while (1) {
		gt_fd_event_mod_wait();
	}
	gtd_deinit(log);
	GT_GLOBAL_UNLOCK;
	return 0;
}
