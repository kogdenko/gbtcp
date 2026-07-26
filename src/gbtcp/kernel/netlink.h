// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_NETLINK_H
#define GBTCP_NETLINK_H

#include <gbtcp/kernel/subr.h>

#define GT_NETLINK_MSG_SIZE_MAX 32768

struct nlm {
	u_char *nlm_buf;
	int nlm_capacity;
};

int netlink_veth_add(const char *, const char *);
int netlink_link_up(int ifindex, const char *ifname, int flags);
int netlink_link_del(const char *ifname);

#endif
