// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/kernel/fd_event.h>
#include <gbtcp/kernel/route.h>

#include <gbtcp/nl/nl.h>

static struct fd_event *route_monitor_event;
static int route_monitor_fd = -1;

int route_open(void);
int route_read(int, route_msg_f, void *);
int route_dump(route_msg_f, void *);

static void
route_on_msg(struct route_msg *msg, void *udata)
{
	struct route_entry route;
	struct route_if *ifp;

	if (msg->rtm_type != ROUTE_MSG_LINK) {
		if (msg->rtm_af != AF_INET) {
			return;
		}
	}
	ifp = route_if_get_by_index(msg->rtm_ifindex);
	if (ifp == NULL) {
		return;
	}
	switch (msg->rtm_type) {
	case ROUTE_MSG_LINK:
		if (msg->rtm_cmd == ROUTE_MSG_ADD) {
			// TODO: Handle interface up/down
			ifp->rif_flags = msg->rtm_link.rtml_flags;
			ifp->rif_hwaddr = msg->rtm_link.rtml_hwaddr;
		}
		break;
	case ROUTE_MSG_ADDR:
		if (msg->rtm_cmd == ROUTE_MSG_ADD) {
			route_ifaddr_add(NULL, ifp, &msg->rtm_addr);
		} else {
			route_ifaddr_del(ifp, &msg->rtm_addr);
		}
		break;
	case ROUTE_MSG_ROUTE:
		route.rt_ifp = ifp;
		route.rt_af = msg->rtm_af;
		route.rt_pfx = msg->rtm_route.rtmr_pfx;
		route.rt_dst = msg->rtm_route.rtmr_dst;
		route.rt_via = msg->rtm_route.rtmr_via;
		if (msg->rtm_cmd == ROUTE_MSG_ADD) {
			route_add(&route);
		} else {
			gt_route_del(route.rt_dst.ipa_4, route.rt_pfx);
		}
		break;
	default:
		break;
	}
}

static int
route_monitor_handler(void *udata, short revent, struct gt_dlist *dh)
{
	route_read(route_monitor_fd, route_on_msg, NULL);
	return 0;
}

static void
route_monitor_stop(void)
{
	if (route_monitor_fd != -1) {
		sys_close(route_monitor_fd);
		route_monitor_fd = -1;
	}
	if (route_monitor_event != NULL) {
		fd_event_del(route_monitor_event);
		route_monitor_event = NULL;
	}
}

static int
route_monitor_start(void)
{
	int rc;

	if (route_monitor_fd != -1) {
		return -EALREADY;
	}
	rc = route_open();
	if (rc < 0) {
		return rc;
	}
	route_monitor_fd = rc;
	rc = fcntl_setfl_nonblock2(route_monitor_fd);
	if (rc < 0) {
		goto err;
	}
	rc = fd_event_add(&route_monitor_event, route_monitor_fd, NULL,
			  route_monitor_handler);
	if (rc) {
		goto err;
	}
	fd_event_set(route_monitor_event, POLLIN);
	route_dump(route_on_msg, NULL);
	return 0;
err:
	route_monitor_stop();
	return rc;
}

static void
gt_nl_on_dev(u8 is_add, struct route_if *ifp)
{
	if (is_add && route_monitor_fd != -1) {
		// TODO: Delete old routes
		route_dump(route_on_msg, NULL);
	}
}

int
gt_plugin_init(void)
{
	int rc;

	gt_add_on_dev_handler(gt_nl_on_dev);

	rc = route_monitor_start();

	return rc;
}

void
gt_plugin_deinit(void)
{
	route_monitor_stop();
}
