// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_NL_NL_H
#define GBTCP_NL_NL_H

#include <gbtcp/kernel/ip_addr.h>

enum route_msg_type { ROUTE_MSG_LINK, ROUTE_MSG_ADDR, ROUTE_MSG_ROUTE };

enum route_msg_cmd {
	ROUTE_MSG_ADD,
	ROUTE_MSG_DEL,
};

enum route_table {
	ROUTE_TABLE_MAIN,
	ROUTE_TABLE_LOCAL,
};

struct route_msg_link {
	u32 rtml_flags;
	struct gt_eth_addr rtml_hwaddr;
};

struct route_msg_route {
	int rtmr_pfx;
	enum route_table rtmr_table;
	struct ipaddr rtmr_dst;
	struct ipaddr rtmr_via;
};

struct route_msg {
	enum route_msg_cmd rtm_cmd;
	enum route_msg_type rtm_type;
	int rtm_af;
	int rtm_ifindex;
	union {
		struct route_msg_link rtm_link;
		struct ipaddr rtm_addr;
		struct route_msg_route rtm_route;
	};
};

typedef void (*route_msg_f)(struct route_msg *, void *);

#endif
