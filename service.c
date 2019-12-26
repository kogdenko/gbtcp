#include "log.h"
#include "sys.h"
#include "file.h"
#include "timer.h"
#include "global.h"
#include "route.h"
#include "tcp.h"
#include "inet.h"
#include "strbuf.h"
#include "ctl.h"
#include "api.h"
#include "fd_event.h"
#include "service.h"

#define GT_SERVICE_STACK_SIZE (1024 * 1024)

#ifdef __linux__
#define GT_SERVICE_WAITPID_OPTIONS __WALL
#else /* __linux__ */
#define GT_SERVICE_WAITPID_OPTIONS 0
#endif /* __linux__ */

#define GT_SERVICE_LOG_NODE_FOREACH(x) \
	x(mod_init) \
	x(mod_deinit) \
	x(if_add) \
	x(set_status) \
	x(polling) \
	x(start_polling) \
	x(stop_polling) \
	x(sub) \
	x(sync) \
	x(add) \
	x(init) \
	x(clean) \
	x(del) \
	x(unsub) \
	x(in_child) \
	x(fork) \

#ifdef __linux__
#define GT_SERVICE_LOG_NODE_FOREACH_OS(x) \
	x(clone) \

#else /* __linux__ */
#define GT_SERVICE_LOG_NODE_FOREACH_OS(x) \

#endif /* __linux__ */

struct gt_service_sock {
	struct gt_list_head ss_list;
	struct gt_sockcb ss_socb;
};

int gt_service_pid;
int gt_service_ctl_polling = 1;

static struct gt_dev gt_service_pipe;
static int gt_service_ctl_child_close_listen_socks;
static void *gt_service_polling_stack;
static int gt_service_subscribed;
static int gt_service_status = GT_SERVICE_NONE;
static int gt_service_done;
static int gt_service_epoch;
static struct gt_log_scope this_log;
GT_SERVICE_LOG_NODE_FOREACH(GT_LOG_NODE_STATIC);
GT_SERVICE_LOG_NODE_FOREACH_OS(GT_LOG_NODE_STATIC);

#ifdef __linux__
static int (*gt_service_clone_fn)(void *);
#else /* __linux__ */
#endif /* __linux__ */

static int gt_service_ctl_status(struct gt_log *log, void *udata,
	const char *new, struct gt_strbuf *out);
static int gt_service_in(struct gt_route_if *ifp, uint8_t *data, int len);

static void gt_service_if_in(struct gt_route_if *ifp, uint8_t *data, int len);

static int gt_service_pipe_in(uint8_t *data, int len);

static void service_pipe_rxtx(struct gt_dev *dev, short revents);

static void gt_service_rxtx(struct gt_dev *dev, short revents);

static int gt_service_dev_init(struct gt_log *log, struct gt_route_if *ifp);

static int gt_service_route_if_set_link_status(struct gt_log *log,
	struct gt_route_if *ifp, int add);

static int gt_service_route_if_not_empty_txr(struct gt_route_if *ifp,
	struct gt_dev_pkt *pkt);

static int gt_service_set_status(struct gt_log *log, int status);

static int gt_service_polling(void *arg);

static int gt_service_stop_polling(struct gt_log *log);

static int gt_service_sub(struct gt_log *log);

static int gt_service_sync(struct gt_log *log);

static int gt_service_add(struct gt_log *log);

static void gt_service_clean(struct gt_log *log);

static int gt_service_del_cb(struct gt_log *log, void *udata, int eno,
	char *old);

static void gt_service_del();

static void gt_service_unsub_handler();

static void gt_service_in_parent();

static void gt_service_alloc_listen_socks(struct gt_log *log,
	struct gt_list_head *head);

static void gt_service_free_listen_socks(struct gt_log *log,
	struct gt_list_head *head);

static void gt_service_open_listen_socks(struct gt_log *log,
	struct gt_list_head *head);

static void gt_service_in_child(struct gt_log *log);

static int gt_service_clone_fn_locked(void *arg);

static int
gt_service_ctl_status(struct gt_log *log, void *udata, const char *new,
	struct gt_strbuf *out)
{
	int rc, status;

	gt_strbuf_addf(out, "%s", gt_service_status_str(gt_service_status));
	if (new == NULL) {
		return 0;
	} else if (!strcmp(new, "active")) {
		status = GT_SERVICE_ACTIVE;
	} else if (!strcmp(new, "shadow")) {
		status = GT_SERVICE_SHADOW;
	} else if (!strcmp(new, "none")) {
		status = GT_SERVICE_NONE;
	} else {
		return -EINVAL;
	} 
	rc = gt_service_set_status(log, status);
	return rc;
}

int
gt_service_mod_init()
{
	struct gt_log *log;

	gt_log_scope_init(&this_log, "service");
	GT_SERVICE_LOG_NODE_FOREACH(GT_LOG_NODE_INIT);
	GT_SERVICE_LOG_NODE_FOREACH_OS(GT_LOG_NODE_INIT);
	log = GT_LOG_TRACE1(mod_init);
	gt_ctl_add_int(log, GT_CTL_SERVICE_CHILD_CLOSE_LISTEN_SOCKS, GT_CTL_LD,
	               &gt_service_ctl_child_close_listen_socks, 0, 1);
	gt_ctl_add_int(log, GT_CTL_SERVICE_POLLING, GT_CTL_LD,
	               &gt_service_ctl_polling, 0, 1);
	gt_ctl_add(log, GT_CTL_SERVICE_STATUS, GT_CTL_WR,
	           NULL, NULL, gt_service_ctl_status);	
	return 0;
}

void
gt_service_mod_deinit(struct gt_log *log)
{
	log = GT_LOG_TRACE(log, mod_deinit);
	gt_ctl_del(log, GT_CTL_SERVICE_POLLING);
	gt_ctl_del(log, GT_CTL_SERVICE_CHILD_CLOSE_LISTEN_SOCKS);
	gt_ctl_del(log, GT_CTL_SERVICE_STATUS);
	gt_log_scope_deinit(log, &this_log);
}

const char *
gt_service_status_str(int status)
{
	switch (status) {
	case GT_SERVICE_ACTIVE: return "active";
	case GT_SERVICE_SHADOW: return "shadow";
	case GT_SERVICE_NONE: return "none";
	default:
		GT_BUG;
		return "";
	}
}

static int
gt_service_in(struct gt_route_if *ifp, uint8_t *data, int len)
{
	int rc;
	struct gt_sock_tuple so_tuple;
	struct gt_inet_context ctx;

	rc = gt_inet_eth_in(&ctx, ifp, data, len);
	if (rc == GT_INET_OK &&
	    (ctx.inp_ipproto == IPPROTO_UDP ||
	     ctx.inp_ipproto == IPPROTO_TCP)) {
		so_tuple.sot_laddr = ctx.inp_ip4_h->ip4h_daddr;
		so_tuple.sot_faddr = ctx.inp_ip4_h->ip4h_saddr;
		so_tuple.sot_lport = ctx.inp_udp_h->udph_dport;
		so_tuple.sot_fport = ctx.inp_udp_h->udph_sport;
		rc = gt_sock_in(ctx.inp_ipproto, &so_tuple, &ctx.inp_tcb,
		                ctx.inp_payload);
	} else if (rc == GT_INET_BCAST && 
	           ctx.inp_ipproto == IPPROTO_ICMP && ctx.inp_eno &&
	           (ctx.inp_emb_ipproto == IPPROTO_UDP ||
	            ctx.inp_emb_ipproto == IPPROTO_TCP)) {
		so_tuple.sot_laddr = ctx.inp_emb_ip4_h->ip4h_saddr;
		so_tuple.sot_faddr = ctx.inp_emb_ip4_h->ip4h_daddr;
		so_tuple.sot_lport = ctx.inp_emb_udp_h->udph_sport;
		so_tuple.sot_fport = ctx.inp_emb_udp_h->udph_dport;
		gt_sock_in_err(ctx.inp_emb_ipproto, &so_tuple, ctx.inp_eno);
	}
	return rc;
}

static void
gt_service_if_in(struct gt_route_if *ifp, uint8_t *data, int len)
{
	int rc;
	struct gt_service_msg msg;

	rc = gt_service_in(ifp, data, len);
	switch (rc) {
	case GT_INET_OK:
		break;
	case GT_INET_BYPASS:
	case GT_INET_BCAST:
		msg.svcm_cmd = rc;
		msg.svcm_if_idx = ifp->rif_idx;
		memcpy(data + len, &msg, sizeof(msg));
		len += sizeof(msg);
		gt_dev_tx3(&gt_service_pipe, data, len);
		break;
	default:
		GT_BUG;
		break;
	}
}

static int
gt_service_pipe_in(uint8_t *data, int len)
{
	int cmd;
	struct gt_service_msg *msg;
	struct gt_route_if *ifp;

	if (len < sizeof(*msg)) {
		return -EINVAL;
	}
	msg = (struct gt_service_msg *)(data + len - sizeof(*msg));
	len -= sizeof(*msg);
	ifp = gt_route_if_get_by_idx(msg->svcm_if_idx);
	if (ifp == NULL) {
		return -EINVAL;
	}
	cmd = msg->svcm_cmd;
	switch (cmd) {
	case GT_INET_BYPASS:
		gt_dev_tx3(&ifp->rif_dev, data, len);
		return 0;
	case GT_INET_BCAST:
		gt_service_in(ifp, data, len);
		return 0;
	default:
		return -EINVAL;
	}
}

static void
service_pipe_rxtx(struct gt_dev *dev, short revents)
{
	int i, n;
	void *data;
	struct netmap_slot *slot;
	struct netmap_ring *rxr;

	GT_DEV_FOREACH_RXRING(rxr, dev) {
		n = gt_dev_rxr_space(dev, rxr);
		for (i = 0; i < n; ++i) {
			slot = rxr->slot + rxr->cur;
			data = NETMAP_BUF(rxr, slot->buf_idx);
			gt_service_pipe_in(data, slot->len);
			GT_DEV_RXR_NEXT(rxr);
		}
	}
}

static void
gt_service_rxtx(struct gt_dev *dev, short revents)
{
	int i, n, len;
	void *data;
	struct netmap_ring *rxr;
	struct netmap_slot *slot;
	struct gt_route_if *ifp;

	ifp = gt_container_of(dev, struct gt_route_if, rif_dev);
	GT_DEV_FOREACH_RXRING(rxr, dev) {
		n = gt_dev_rxr_space(dev, rxr);
		for (i = 0; i < n; ++i) {
			//DEV_RX_PREFETCH(rxr);
			slot = rxr->slot + rxr->cur;
			data = NETMAP_BUF(rxr, slot->buf_idx);
			len = slot->len;
			gt_service_if_in(ifp, data, len);
			gt_route_if_rxr_next(ifp, rxr);
		}
	}
}

static int
gt_service_dev_init(struct gt_log *log, struct gt_route_if *ifp)
{
	int rc;
	char buf[GT_IFNAMSIZ];

	snprintf(buf, sizeof(buf), "%s-%d", ifp->rif_name, gt_route_rss_q_id);
	rc = gt_dev_init(log, &ifp->rif_dev, buf, gt_service_rxtx);
	return rc;
}

static int
gt_service_route_if_set_link_status(struct gt_log *log,
	struct gt_route_if *ifp, int add)
{
	int rc;

	rc = 0;
	if (add) {
		if (gt_service_status == GT_SERVICE_ACTIVE) {
			log = GT_LOG_TRACE(log, if_add);
			rc = gt_service_dev_init(log, ifp);
		}
	} else {
		gt_dev_deinit(&ifp->rif_dev);
	}
	return rc;
}

static int
gt_service_route_if_not_empty_txr(struct gt_route_if *ifp, struct gt_dev_pkt *pkt)
{
	int rc;

	rc = gt_dev_not_empty_txr(&gt_service_pipe, pkt);
	return rc;
}

void
gt_service_route_if_tx(struct gt_route_if *ifp, struct gt_dev_pkt *pkt)
{
	struct gt_service_msg *msg;

	msg = (struct gt_service_msg *)(pkt->pkt_data + pkt->pkt_len);
	msg->svcm_cmd = GT_INET_OK;
	msg->svcm_if_idx = ifp->rif_idx;
	pkt->pkt_len += sizeof(*msg);
}

static int
gt_service_set_status(struct gt_log *log, int status)
{
	int rc, tmp_fd;
	struct gt_file *fp;
	struct gt_route_if *ifp;

	if (gt_service_status == status) {
		return 0;
	}
	log = GT_LOG_TRACE(log, set_status);
	GT_LOGF(log, LOG_INFO, 0, "hit; status=%s",
	        gt_service_status_str(status));
	if (gt_service_pid == 0) {
		return -ESRCH;
	}
	if (status != GT_SERVICE_ACTIVE && status != GT_SERVICE_SHADOW) {
		return -EINVAL;
	}
	if (status == GT_SERVICE_SHADOW) {
		GT_FILE_FOREACH_SAFE(fp, tmp_fd) {
			if (fp->fl_type == GT_FILE_SOCK) {	
				gt_file_close(fp, GT_SOCK_GRACEFULL);
			}
		}
		GT_ROUTE_IF_FOREACH(ifp) {
			gt_dev_deinit(&ifp->rif_dev);
		}
		gt_service_status = GT_SERVICE_SHADOW;
		return 0;
	} else {
		rc = 0;
		GT_ROUTE_IF_FOREACH(ifp) {
			rc = gt_service_dev_init(log, ifp);
			if (rc) {
				break;
			}
		}
		if (rc) {
			GT_ROUTE_IF_FOREACH(ifp) {
				gt_dev_deinit(&ifp->rif_dev);
			}
		} else {
			gt_service_status = GT_SERVICE_ACTIVE;
		}
		return rc;
	}
}

static int
gt_service_polling(void *arg)
{
	int rc, tmp_id;
	gt_time_t t0, t1;
	sigset_t mask;
	struct gt_log *log;
	struct gt_file *fp;

	log = GT_LOG_TRACE1(polling);
	t0 = gt_global_get_time();
	sigfillset(&mask);
	gt_sys_sigprocmask(log, SIG_SETMASK, &mask, NULL);
	while (gt_service_done == 0) {
		t1 = gt_global_get_time();
		if (t1 - t0 > 100 * GT_MSEC) {
			t0 = t1;
			rc = gt_sys_kill(NULL, gt_application_pid, 0);
			if (rc == -ESRCH) {
				break;
			}
		}
		gt_fd_event_mod_trylock_check();
	}
	GT_LOGF(log, LOG_INFO, 0, "application gone");
	GT_FILE_FOREACH_SAFE(fp, tmp_id) {
		gt_file_close(fp, GT_SOCK_GRACEFULL);
	}
	while (gt_service_done == 0) {
		gt_fd_event_mod_wait();
	}
	return 0;
}

#ifdef __linux__
int
gt_service_start_polling(struct gt_log *log)
{
	int rc, flags;

	gt_service_done = 0;
	log = GT_LOG_TRACE(log, start_polling);
	rc = gt_sys_malloc(log, &gt_service_polling_stack,
	                   GT_SERVICE_STACK_SIZE);
	if (rc < 0) {
		return rc;
	}
	flags = 0;
	flags |= CLONE_VM;
	flags |= CLONE_FILES;
	rc = gt_sys_clone(log, gt_service_polling,
	                  gt_service_polling_stack + GT_SERVICE_STACK_SIZE,
	                  flags, NULL, NULL, NULL, NULL);
	if (rc < 0) {
		free(gt_service_polling_stack);
		gt_service_polling_stack = NULL;
	}
	return rc;
}
#else /* __linux__ */
int
gt_service_start_polling(struct gt_log *log)
{
	GT_BUG;
	return -ENOTSUP;
}
#endif /* __linux__ */

static int
gt_service_stop_polling(struct gt_log *log)
{
	int rc, pid, status;

	gt_service_done = 1;
	pid = getpid();
	if (pid == gt_service_pid) {
		return 0;
	}
	log = GT_LOG_TRACE(log, stop_polling);
	rc = gt_sys_waitpid(log, gt_service_pid, &status,
	                    GT_SERVICE_WAITPID_OPTIONS);
	free(gt_service_polling_stack);
	gt_service_polling_stack = NULL;
	if (rc == 0) {
		rc = WEXITSTATUS(status);
	}
	return rc;
}

static int
gt_service_sub(struct gt_log *log)
{
	int rc;
	
	GT_ASSERT(!gt_service_subscribed);
	log = GT_LOG_TRACE(log, sub);
	rc = gt_ctl_sub(log, gt_service_unsub_handler);
	if (rc == 0) {
		gt_service_subscribed = 1;
	}
	return rc;
}

static int
gt_service_sync(struct gt_log *log)
{
	int i, rc;
	static const char *names[] = {
		GT_CTL_ROUTE_IF_LIST,
		GT_CTL_ROUTE_ROUTE_LIST,
		GT_CTL_ROUTE_ADDR_LIST,
		NULL,
	};

	log = GT_LOG_TRACE(log, sync);
	for (i = 0; names[i] != NULL; ++i) {
		rc = gt_ctl_sync(log, names[i]);
		if (rc) {
			return rc;
		}
	}
	return 0;
}

static int
gt_service_add(struct gt_log *log)
{
	int i, rc, arg, args[3];
	unsigned int rss_q_id, rss_q_cnt, port_pairity;
	char *endptr;
	struct iovec iov[3 + GT_RSS_KEY_SIZE];
	char buf[128 + 3 * GT_RSS_KEY_SIZE];

	log = GT_LOG_TRACE(log, add);
	snprintf(buf, sizeof(buf), "%d", gt_service_pid);
	rc = gt_ctl(log, 0, GT_CTL_SERVICE_ADD, buf, sizeof(buf), buf);
	if (rc < 0) {
		return rc;
	} else if (rc > 0) {
		GT_LOGF(log, LOG_ERR, rc, "err rpl");
		return -rc;
	}
	rc = gt_strsplit(buf, ",:", iov, GT_ARRAY_SIZE(iov));
	if (rc != GT_ARRAY_SIZE(iov)) {
		goto err;
	}
	for (i = 0; i < 3; ++i) {
		arg = strtoul(iov[i].iov_base, &endptr, 10);
		if (*endptr != ',') {
			goto err;
		}
		args[i] = arg;
	}
	rss_q_id = args[0];
	rss_q_cnt = args[1];
	port_pairity = args[2];
	for (i = 0; i < GT_RSS_KEY_SIZE; ++i) {
		arg = strtoul(iov[i + 3].iov_base, &endptr, 16);
		if (*endptr != ':' && *endptr != '\0') {
			goto err;
		}
		if (arg > 255) {
			goto err;
		}
		gt_route_rss_key[i] = arg;
	}
	
	if (rss_q_cnt == 0 || rss_q_cnt > GT_SERVICES_MAX ||
	    rss_q_id > rss_q_cnt ||
	    port_pairity > 1) {
		GT_LOGF(log, LOG_ERR, 0,
		        "bad rpl; rss_q_id=%d, rss_q_cnt=%d, port_pairity=%d",
		        rss_q_id, rss_q_cnt, port_pairity);
		return -EINVAL;
	}
	gt_route_rss_q_id = rss_q_id;
	gt_route_rss_q_cnt = rss_q_cnt;
	gt_route_port_pairity = port_pairity;
	return 0;
err:
	GT_LOGF(log, LOG_ERR, 0, "invalid rpl; rpl=%s", buf);
	return -EINVAL;
}

int
gt_service_init(struct gt_log *log)
{
	int rc;
	char buf[GT_IFNAMSIZ];

	if (gt_service_pid) {
		return 0;
	}
	log = GT_LOG_TRACE(log, init);
	GT_LOGF(log, LOG_INFO, 0, "hit; epoch=%d", gt_service_epoch);
	gt_route_if_set_link_status_fn = gt_service_route_if_set_link_status;
	gt_route_if_not_empty_txr_fn = gt_service_route_if_not_empty_txr;
	gt_route_if_tx_fn = gt_service_route_if_tx;
	gt_service_status = GT_SERVICE_ACTIVE;
	if (gt_service_ctl_polling == 0) {
		gt_service_pid = gt_application_pid;
	} else {
		rc = gt_service_start_polling(log);
		if (rc < 0) {
			goto err;
		}
		gt_service_pid = rc;
	}
	snprintf(buf, sizeof(buf), "gbtcp.%d}0", gt_service_pid);
	rc = gt_dev_init(log, &gt_service_pipe, buf, service_pipe_rxtx);
	if (rc) {
		goto err1;
	}
	rc = gt_ctl_bind(log, gt_service_pid);
	if (rc) {
		goto err2;
	}
	rc = gt_service_sub(log);
	if (rc) {
		goto err3;
	}
	rc = gt_service_add(log);
	if (rc) {
		goto err4;
	}
	gt_service_sync(log);
	gt_sock_no_opened_fn = gt_service_del;
	GT_LOGF(log, LOG_INFO, 0,
	        "ok; pid=%d, rss_q_id=%d, rss_q_cnt=%d, port_pairity=%d",
	        gt_service_pid, gt_route_rss_q_id,
	        gt_route_rss_q_cnt, gt_route_port_pairity);
	return 0;
err4:
	gt_ctl_unsub_me();
err3:
	gt_ctl_unbind();
err2:
	gt_dev_deinit(&gt_service_pipe);
err1:
	gt_service_stop_polling(log);
	gt_service_pid = 0;
err:
	gt_service_status = GT_SERVICE_NONE;
	gt_route_if_set_link_status_fn = NULL;
	gt_route_if_not_empty_txr_fn = NULL;
	gt_route_if_tx_fn = NULL;
	return rc;
}

static void
gt_service_clean(struct gt_log *log)
{
	log = GT_LOG_TRACE(log, clean);
	GT_LOGF(log, LOG_INFO, 0, "hit");
	gt_service_epoch++;
	gt_service_stop_polling(log);
	gt_dev_deinit(&gt_service_pipe);
	gt_ctl_unbind();
	gt_ctl_unsub_me();
	gt_route_mod_clean(log);
	gt_service_pid = 0;
	gt_service_subscribed = 0;
	gt_service_status = GT_SERVICE_NONE;
	gt_route_if_set_link_status_fn = NULL;
	gt_route_if_not_empty_txr_fn = NULL;
	gt_route_if_tx_fn = NULL;
}

static int
gt_service_del_cb(struct gt_log *log, void *udata, int eno, char *old)
{
	uintptr_t epoch;

	if (eno) {
		epoch = (uintptr_t)udata;
		if (gt_service_epoch == epoch) {
			gt_service_clean(log);
		}
	}
	return 0;
}

static void
gt_service_del()
{
	int rc, pid;
	uintptr_t udata;
	char buf[32];
	struct gt_log *log;

	log = GT_LOG_TRACE1(del);
	GT_LOGF(log, LOG_INFO, 0, "hit");
	gt_sock_no_opened_fn = NULL;
	rc = gt_ctl_binded_pid(log);
	if (rc > 0) {
		pid = rc;
		snprintf(buf, sizeof(buf), "%d", pid);
		udata = gt_service_epoch;
		rc = gt_ctl_r(log, 0, GT_CTL_SERVICE_DEL,
		              (void *)udata, gt_service_del_cb, buf);
		if (rc < 0) {
			gt_service_clean(log);
			return;
		}
	}
	if (gt_service_subscribed == 0) {
		gt_service_clean(log);
	}
}

static void
gt_service_unsub_handler()
{
	int tmp_fd;
	struct gt_file *fp;
	struct gt_log *log;

	gt_service_subscribed = 0;
	if (gt_service_status != GT_SERVICE_ACTIVE) {
		GT_FILE_FOREACH_SAFE(fp, tmp_fd) {
			if (fp->fl_type == GT_FILE_SOCK) {
				gt_file_close(fp, GT_SOCK_RESET);
			}
		}
	}
	if (gt_sock_nr_opened == 0) {
		log = GT_LOG_TRACE1(unsub);
		gt_service_clean(log);
	}
}

static void
gt_service_in_parent()
{
}

static void
gt_service_alloc_listen_socks(struct gt_log *log, struct gt_list_head *head)
{
	int rc;
	struct gt_sock *so;
	struct gt_service_sock *sso;

	GT_SOCK_FOREACH_BINDED(so) {
		if (so->so_state != GT_TCP_S_LISTEN) {
			continue;
		}
		rc = gt_sys_malloc(log, (void **)&sso, sizeof(*sso));
		if (rc) {
			break;
		}
		gt_sock_get_sockcb(so, &sso->ss_socb);
		GT_LIST_INSERT_TAIL(head, sso, ss_list);
	}
}

static void
gt_service_free_listen_socks(struct gt_log *log, struct gt_list_head *head)
{
	struct gt_service_sock *sso;

	while (!gt_list_empty(head)) {
		sso = GT_LIST_FIRST(head, struct gt_service_sock, ss_list);
		GT_LIST_REMOVE(sso, ss_list);
		free(sso);
	}
}

static void
gt_service_open_listen_socks(struct gt_log *log, struct gt_list_head *head)
{
	int rc, fd, type;
	struct sockaddr_in addr;
	struct gt_service_sock *sso;

	GT_LIST_FOREACH(sso, head, ss_list) {
		type = SOCK_STREAM;
		if (sso->ss_socb.socb_flags & O_NONBLOCK) {
			type |= SOCK_NONBLOCK;
		} 
		rc = gt_api_socket(log, sso->ss_socb.socb_fd, AF_INET, type, 0);
		if (rc < 0) {
			continue;
		}
		fd = rc;
		addr.sin_family = AF_INET;
		addr.sin_port = sso->ss_socb.socb_lport;
		addr.sin_addr.s_addr = sso->ss_socb.socb_laddr;
		rc = gt_api_bind(log, fd, (struct sockaddr *)&addr,
		                 sizeof(addr));
		if (rc) {
			gt_api_close(fd);
			continue;
		}
		rc = gt_api_listen(log, fd, sso->ss_socb.socb_backlog);
		if (rc) {
			gt_api_close(fd);
			continue;
		}
	}
}

static void
gt_service_in_child(struct gt_log *log)
{
	struct gt_list_head so_head;

	log = GT_LOG_TRACE(log, in_child);
	gt_service_epoch = 0;
	gt_list_init(&so_head);
	if (!gt_service_ctl_child_close_listen_socks) {
		gt_service_alloc_listen_socks(log, &so_head);
	}
	gt_service_clean(log);
	gt_global_deinit(log);
	gt_global_init();
	gt_ctl_read_file(log, NULL);
	log = GT_LOG_TRACE1(in_child);
	gt_service_open_listen_socks(log, &so_head);
	gt_service_free_listen_socks(log, &so_head);
}

int
gt_service_fork(struct gt_log *log)
{
	int rc, pid;

	log = GT_LOG_TRACE(log, fork);
	rc = gt_sys_fork(log);
	if (rc >= 0) {
		pid = rc;
		if (pid == 0) {
			gt_service_in_child(log);
		} else {
			gt_service_in_parent();
		}
	}
	return rc;
}

#ifdef __linux__
static int
gt_service_clone_fn_locked(void *arg)
{
	int (*fn)(void *);
	struct gt_log *log;

	log = GT_LOG_TRACE1(clone);
	gt_service_in_child(log);
	fn = gt_service_clone_fn;
	GT_GLOBAL_UNLOCK;
	return (*fn)(arg);
}

int
gt_service_clone(int (*fn)(void *), void *child_stack,
                 int flags, void *arg,
                 void *ptid, void *tls, void *ctid)
{
	int rc, clone_vm;

	clone_vm = flags & CLONE_VM;
	if (clone_vm) {
		if ((flags & CLONE_FILES) == 0 ||
		    (flags & CLONE_THREAD) == 0) {
			return -EINVAL;
		}
	} else {
		if ((flags & CLONE_FILES) != 0 ||
		    (flags & CLONE_THREAD) != 0) {
			return -EINVAL;
		}
	}
	if (clone_vm) {
		rc = (*gt_sys_clone_fn)(fn, child_stack, flags, arg,
		                        ptid, tls, ctid);
	} else {
		gt_service_clone_fn = fn;
		rc = (*gt_sys_clone_fn)(gt_service_clone_fn_locked,
		                        child_stack, flags,
		                        arg, ptid, tls, ctid);
		if (rc == -1) {
			rc = -errno;
		} else {
			gt_service_in_parent();
		}
	}
	return rc;
}
#endif /* __linux__ */
