#include "../internals.h"


struct gt_route_dump_req {
	struct nlmsghdr rdmp_nlh;
	struct ifinfomsg rdmp_ifm;
	struct rtattr rdmp_ext_req __attribute__((aligned(NLMSG_ALIGNTO)));
	uint32_t rdmp_ext_filter_mask;
};

static struct route_mod *current_mod;

static const char *gt_route_nlmsg_type_str(int nlmsg_type)
	__attribute__ ((unused));

static uint32_t gt_route_get_attr_u32(struct rtattr *attr);

static void gt_route_get_attrs(struct rtattr *attr, int len,
	struct rtattr **attrs, int nr_attrs_max);

static int gt_route_handle_link(struct nlmsghdr *h, struct gt_route_msg *msg);

static int gt_route_handle_addr(struct nlmsghdr *h, struct gt_route_msg *msg);

static int gt_route_handle_route(struct nlmsghdr *h, struct gt_route_msg *msg);

static int gt_route_rtnl_handler(struct nlmsghdr *h, gt_route_msg_f fn);

static int gt_route_read_all(int fd, gt_route_msg_f fn);

static const char *
gt_route_nlmsg_type_str(int nlmsg_type)
{
	switch (nlmsg_type) {
	case RTM_NEWLINK: return "RTM_NEWLINK";
	case RTM_DELLINK: return "RTM_DELLINK";
	case RTM_NEWADDR: return "RTM_NEWADDR";
	case RTM_DELADDR: return "RTM_DELADDR";
	case RTM_NEWROUTE: return "RTM_NEWROUTE";
	case RTM_DELROUTE: return "RTM_DELROUTE";
	default: return NULL;
	}
}

static uint32_t
gt_route_get_attr_u32(struct rtattr *attr)
{
	return *(uint32_t *)RTA_DATA(attr);
}

int
gt_route_rtnl_open(struct log *log, unsigned int nl_groups)
{
	int rc, fd, opt;
	struct sockaddr_nl addr;

	LOG_TRACE(log);
	rc = sys_socket(log, AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	rc = fcntl_setfl_nonblock2(log, fd);
	if (rc) {
		sys_close(log, fd);
		return rc;
	}
	opt = 32768;
	rc = sys_setsockopt(log, fd, SOL_SOCKET, SO_SNDBUF,
	                    &opt, sizeof(opt));
	if (rc < 0) {
		sys_close_fn(fd);
		return rc;
	}
	opt = 1024 * 1024;
	rc = sys_setsockopt(log, fd, SOL_SOCKET, SO_RCVBUF,
	                    &opt, sizeof(opt));
	if (rc < 0) {
		sys_close(log, fd);
		return rc;
	}
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = nl_groups;
	rc = sys_bind(log, fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc) {
		sys_close(log, fd);
		return rc;
	}
	return fd;
}

static void
gt_route_get_attrs(struct rtattr *attr, int len, struct rtattr **attrs,
	int nr_attrs_max)
{
	memset(attrs, 0, sizeof(struct rtattr *) * nr_attrs_max);
	while (RTA_OK(attr, len)) {
		if (attr->rta_type < nr_attrs_max &&
			attrs[attr->rta_type] == NULL) {
			attrs[attr->rta_type] = attr;
		}
		attr = RTA_NEXT(attr, len);
	}
}

static int
gt_route_handle_link(struct nlmsghdr *h, struct gt_route_msg *msg)
{
	int len, tmp;
	struct ifinfomsg *ifi;
	struct rtattr *attrs[IFLA_MAX + 1], *attr;
	struct log *log;

	log = log_trace0();
	tmp = NLMSG_LENGTH(sizeof(*ifi));
	len = h->nlmsg_len - tmp;
	if (len < 0) {
		LOGF(log, LOG_ERR, 0, "bad nlmsg_len; len=%d, need>=%d",
		     h->nlmsg_len, tmp);
		return -EPROTO;
	}
	ifi = NLMSG_DATA(h);
	attr = IFLA_RTA(ifi);
	gt_route_get_attrs(attr, len, attrs, ARRAY_SIZE(attrs));
	msg->rtm_if_idx = ifi->ifi_index;
	msg->rtm_link.rtml_flags = ifi->ifi_flags;
	attr = attrs[IFLA_ADDRESS];
	if (attr != NULL) {
		tmp = RTA_PAYLOAD(attr);
		if (tmp != 6) {
			LOGF(log, LOG_ERR, 0,
			     "attr bad len; attr=IFLA_ADDRESS, len=%d, need=6",
			     tmp);
			return -EPROTO;
		}
		memcpy(msg->rtm_link.rtml_hwaddr.etha_bytes,
		       RTA_DATA(attr), 6);
	}
	return 1;
}

static int
gt_route_handle_addr(struct nlmsghdr *h, struct gt_route_msg *msg)
{
	int len, tmp, addr_len;
	struct ifaddrmsg *ifa;
	struct rtattr *attrs[IFA_MAX + 1], *attr;
	struct log *log;

	log = log_trace0();
	tmp = NLMSG_LENGTH(sizeof(*ifa));
	len = h->nlmsg_len - tmp;
	if (len < 0) {
		LOGF(log, LOG_ERR, 0, "bad nlmsg_len; len=%d, need>=%d",
		     h->nlmsg_len, tmp);
		return -EPROTO;
	}
	ifa = NLMSG_DATA(h);
	attr = IFA_RTA(ifa);
	if (ifa->ifa_family == AF_INET) {
		addr_len = 4;
	} else if (ifa->ifa_family == AF_INET6) {
		addr_len = 16;
	} else {
		LOGF(log, LOG_INFO, 0, "skip addr family; af=%d",
		     ifa->ifa_family);
		return 0;
	}
	msg->rtm_af = ifa->ifa_family;
	gt_route_get_attrs(attr, len, attrs, ARRAY_SIZE(attrs));
	attr = attrs[IFA_LOCAL];
	if (attr == NULL) {
		attr = attrs[IFA_ADDRESS];
	}
	if (attr == NULL) {
		LOGF(log, LOG_ERR, 0, "attr doesnt exists; attr=IFA_ADDRESS");
		return -EPROTO;
	}
	tmp = RTA_PAYLOAD(attr);
	if (tmp != addr_len) {
		LOGF(log, LOG_ERR, 0,
		     "attr bad len; attr=IFA_ADDRESS, len=%d, need=%d",
		     tmp, addr_len);
		return -EPROTO;
	}
	memcpy(msg->rtm_addr.ipa_data, RTA_DATA(attr), addr_len);
	msg->rtm_if_idx = ifa->ifa_index;
	return 1;
}

static int
gt_route_handle_route(struct nlmsghdr *h, struct gt_route_msg *msg)
{
	int len, tmp, table, addr_len;
	struct rtmsg *rtm;
	struct rtattr *attrs[RTA_MAX + 1], *attr;
	struct log *log;

	log = log_trace0();
	tmp = NLMSG_LENGTH(sizeof(*rtm));
	len = h->nlmsg_len - tmp;
	if (len < 0) {
		LOGF(log, LOG_ERR, 0, "bad nlmsg_len; len=%d, need>=%d",
		     h->nlmsg_len, tmp);
		return -EPROTO;
	}
	rtm = NLMSG_DATA(h);
	if (rtm->rtm_flags & RTM_F_CLONED) {
		LOGF(log, LOG_INFO, 0, "RTM_F_CLONED");
		return 0;
	}
	if (rtm->rtm_type != RTN_UNICAST) {
		LOGF(log, LOG_INFO, 0, "not unicast; rtm_type=%d",
		     rtm->rtm_type);
		return 0;
	}
	if (rtm->rtm_family == AF_INET) {
		addr_len = 4;
	} else if (rtm->rtm_family == AF_INET6) {
		addr_len = 16;
	} else {
		LOGF(log, LOG_INFO, 0, "skip addr family; af=%d",
		     rtm->rtm_family);
		return 0;
	}
	msg->rtm_af = rtm->rtm_family;
	attr = RTM_RTA(rtm);
	gt_route_get_attrs(attr, len, attrs, ARRAY_SIZE(attrs));
	attr = attrs[RTA_TABLE];
	if (attr != NULL) {
		tmp = RTA_PAYLOAD(attr);
		if (tmp != sizeof(uint32_t)) {
			LOGF(log, LOG_ERR, 0,
			     "attr bad len; attr=RTA_TABLE, len=%d, need=%zu",
			     tmp, sizeof(uint32_t));
			return -EPROTO;
		}
		table = gt_route_get_attr_u32(attr);
	} else {
		table = rtm->rtm_table;
	}
	switch (table) {
	case RT_TABLE_MAIN:
		msg->rtm_route.rtmr_table = GT_ROUTE_TABLE_MAIN;
		break;
	case RT_TABLE_LOCAL:
		msg->rtm_route.rtmr_table = GT_ROUTE_TABLE_LOCAL;
		break;
	default:
		return 0;
	}
	attr = attrs[RTA_DST];
	if (attr == NULL) {
		msg->rtm_route.rtmr_dst = ipaddr_zero;
	} else {
		tmp = RTA_PAYLOAD(attr);
		if (tmp != addr_len) {
			LOGF(log, LOG_ERR, 0,
			     "attr bad len; attr=RTA_DST, len=%d, need=%d",
			     tmp, addr_len);
			return -EPROTO;
		}
		memcpy(msg->rtm_route.rtmr_dst.ipa_data,
		       RTA_DATA(attr), addr_len);
	}
	if (rtm->rtm_dst_len > addr_len * 8) {
		LOGF(log, LOG_ERR, 0,
		     "attr bad len; rtm_dst_len=%d, need>%d",
		     rtm->rtm_dst_len, addr_len * 8);
		return -EPROTO;
	}	
	msg->rtm_route.rtmr_pfx = rtm->rtm_dst_len;
	attr = attrs[RTA_OIF];
	if (attr == NULL) {
		LOGF(log, LOG_ERR, 0,
		     "attr doesnt exists; attr=RTA_OIF");
		return -EPROTO;
	}
	tmp = RTA_PAYLOAD(attr);
	if (tmp != sizeof(uint32_t)) {
		LOGF(log, LOG_ERR, 0,
		     "attr bad len; attr=RTA_OIF, len=%d, need=%zu",
		     tmp, sizeof(uint32_t));
		return -EPROTO;
	}
	msg->rtm_if_idx = gt_route_get_attr_u32(attr);
	attr = attrs[RTA_GATEWAY];
	if (attr != NULL) {
		tmp = RTA_PAYLOAD(attr);
		if (tmp != addr_len) {
			LOGF(log, LOG_ERR, 0,
			     "attr bad len; attr=RTA_GATEWAY, len=%d, need=%d",
			     tmp, addr_len);
			return -EPROTO;
		}
		memcpy(msg->rtm_route.rtmr_via.ipa_data,
		       RTA_DATA(attr), addr_len);
	}
	return 1;
}

static int
gt_route_rtnl_handler(struct nlmsghdr *h, gt_route_msg_f fn)
{
	int rc;
	struct gt_route_msg msg;
	struct log *log;

	log = log_trace0();
	memset(&msg, 0, sizeof(msg));
	msg.rtm_cmd = GT_ROUTE_MSG_DEL;
	switch (h->nlmsg_type) {
	case RTM_NEWLINK:
		msg.rtm_cmd = GT_ROUTE_MSG_ADD;
	case RTM_DELLINK:
		msg.rtm_type = GT_ROUTE_MSG_LINK;
		rc = gt_route_handle_link(h, &msg);
		break;
	case RTM_NEWADDR:
		msg.rtm_cmd = GT_ROUTE_MSG_ADD;
	case RTM_DELADDR:
		msg.rtm_type = GT_ROUTE_MSG_ADDR;
		rc = gt_route_handle_addr(h, &msg);
		break;
	case RTM_NEWROUTE:
		msg.rtm_cmd = GT_ROUTE_MSG_ADD;
	case RTM_DELROUTE:
		msg.rtm_type = GT_ROUTE_MSG_ROUTE;
		rc = gt_route_handle_route(h, &msg);
		break;
	default:
		LOGF(log, LOG_INFO, 0, "unknown; nlmsg_type=%d",
		     h->nlmsg_type);
		return 0;
	}
	if (rc < 0) {
		LOGF(log, LOG_ERR, -rc, "failed; nlmsg_type=%s",
		     gt_route_nlmsg_type_str(h->nlmsg_type));
	} else {
		LOGF(log, LOG_INFO, 0, "ok; nlmsg_type=%s",
		     gt_route_nlmsg_type_str(h->nlmsg_type));
	}
	if (rc == 1 && fn != NULL) {
		(*fn)(&msg);
	}
	return rc;
}

int
gt_route_read(int fd, gt_route_msg_f fn)
{
	uint8_t buf[16384];
	int rc, len;
	struct msghdr msg;
	struct nlmsghdr *h;
	struct sockaddr_nl addr;
	struct iovec iov;
	struct log *log;

	log = log_trace0();
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1; 
	rc = sys_recvmsg(log, fd, &msg, 0);
	if (rc < 0) {
		return rc;
	}
	len = rc;
	for (h = (struct nlmsghdr *)buf;
		NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
		switch (h->nlmsg_type) {
		case NLMSG_ERROR:
			break;
		case NLMSG_DONE:
			return 0;
		default:
			rc = gt_route_rtnl_handler(h, fn);
			if (rc < 0) {
				return rc;
			}
			break;
		}
	}
	if (msg.msg_flags & MSG_TRUNC) {
		LOGF(log, LOG_ERR, 0, "truncated");
		return 0;
	}
	return 0;
}

int
route_open(struct route_mod *mod, struct log *log)
{
	int rc, g;

	current_mod = mod;
	g = 0;
	g |= RTMGRP_LINK;
	g |= RTMGRP_IPV4_IFADDR;
	g |= RTMGRP_IPV4_ROUTE;
	g |= RTMGRP_IPV6_IFADDR;
	g |= RTMGRP_IPV6_ROUTE;
	rc = gt_route_rtnl_open(log, g);
	return rc;
}

static int
gt_route_read_all(int fd, gt_route_msg_f fn)
{
	int rc;

	while (1) {
		rc = gt_route_read(fd, fn);
		if (rc < 0) {
			return rc;
		}
	}
}

int
gt_route_dump(gt_route_msg_f fn)
{
	static int types[3] = { RTM_GETLINK, RTM_GETADDR, RTM_GETROUTE };
	int i, rc, fd;
	struct log *log;
	struct gt_route_dump_req req;

	log = log_trace0();
	rc = gt_route_rtnl_open(log, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	for (i = 0; i < ARRAY_SIZE(types); ++i) {
		memset(&req, 0, sizeof(req));
		req.rdmp_nlh.nlmsg_len = sizeof(req);
		req.rdmp_nlh.nlmsg_type = types[i];
		req.rdmp_nlh.nlmsg_flags = NLM_F_DUMP|NLM_F_REQUEST;
		req.rdmp_nlh.nlmsg_pid = 0; 
		req.rdmp_nlh.nlmsg_seq = 1;
		req.rdmp_ifm.ifi_family = AF_UNSPEC;
		req.rdmp_ext_req.rta_type = IFLA_EXT_MASK;
		req.rdmp_ext_req.rta_len = RTA_LENGTH(sizeof(uint32_t));
		req.rdmp_ext_filter_mask = RTEXT_FILTER_VF;
		rc = sys_send(log, fd, &req, sizeof(req), 0);
		if (rc < 0) {
			sys_close(log, fd);
			return rc;
		}
		gt_route_read_all(fd, fn);
	}
	sys_close(log, fd);
	return 0;
}
