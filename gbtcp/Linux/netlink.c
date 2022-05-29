// gpl2
#include "../internals.h"

#define CURMOD route

#define VETH_INFO_PEER 1

#define NLM_PUT_STRING(m, attr_type, s) nlm_put_attr(m, attr_type, s, strlen(s) + 1)

struct nlm {
	u_char *nlm_buf;
	int nlm_capacity;
};

const char *
nlmsg_type_str(int nlmsg_type)
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
rtattr_get_u32(struct rtattr *attr)
{
	return *(uint32_t *)RTA_DATA(attr);
}

static void *
nla_data(struct nlattr *nla)
{
	return (u_char *)nla + NLA_HDRLEN;
}

static int
nla_padlen(int data_len)
{
	return NLA_ALIGN(NLA_HDRLEN + data_len) - (NLA_HDRLEN + data_len);
}

static struct nlmsghdr *
nlm_hdr(struct nlm *m)
{
	return (struct nlmsghdr *)m->nlm_buf;
}

static int
nlmsg_len(struct nlmsghdr *h)
{
	return h->nlmsg_len - NLMSG_HDRLEN;
}

static void
nlh_init(struct nlmsghdr *h, int type, int flags)
{
	h->nlmsg_type = type;
	h->nlmsg_flags = flags;
	h->nlmsg_pid = 0;
	h->nlmsg_seq = 1;
}

void
nlm_init(struct nlm *m, u_char *buf, int capacity)
{
	m->nlm_buf = buf;
	m->nlm_capacity = capacity;
	nlm_hdr(m)->nlmsg_len = sizeof(struct nlmsghdr);
	assert((sizeof(struct nlmsghdr) & (NLMSG_ALIGNTO - 1)) == 0);
}

static void
nlm_put(struct nlm *m, void *data, int data_len)
{
	int len;
	u_char *buf;

	len = nlm_hdr(m)->nlmsg_len + NLMSG_ALIGN(data_len);
	assert(len <= m->nlm_capacity);
	buf = m->nlm_buf + nlm_hdr(m)->nlmsg_len;
	memcpy(buf, data, data_len);
	memset(buf + data_len, 0, NLMSG_ALIGN(data_len) - data_len);
	nlm_hdr(m)->nlmsg_len = len;
}

static struct nlattr *
nlm_put_attr(struct nlm *m, int attr_type, const void *data, int data_len)
{
	int len;
	struct nlattr *nla;

	len = nlm_hdr(m)->nlmsg_len + NLA_ALIGN(NLA_HDRLEN + data_len);
	assert(len <= m->nlm_capacity);
	nla = (struct nlattr *)(m->nlm_buf + nlm_hdr(m)->nlmsg_len);
	nla->nla_type = attr_type;
	nla->nla_len = NLA_HDRLEN + data_len;
	if (data_len) {
		memcpy(nla_data(nla), data, data_len);
		memset((u_char *)nla + nla->nla_len, 0, nla_padlen(data_len));
	}
	nlm_hdr(m)->nlmsg_len = len;
	return nla;
}

static struct nlattr *
nlm_nest_start(struct nlm *m, int attr_type)
{
	return nlm_put_attr(m, NLA_F_NESTED|attr_type, NULL, 0);
}

static void
nlm_nest_end(struct nlm *m, struct nlattr *start)
{
	int len;

	len = nlm_hdr(m)->nlmsg_len - ((u_char *)start - m->nlm_buf);
	start->nla_len = len;
}

int
rtnl_open(unsigned int nl_groups)
{
	int rc, fd, opt;
	struct sockaddr_nl addr;

	fd = -1;
	rc = sys_socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (rc < 0) {
		goto err;
	}
	fd = rc;
	rc = fcntl_setfl_nonblock2(fd);
	if (rc) {
		goto err;
	}
	opt = 32768;
	rc = sys_setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt));
	if (rc < 0) {
		goto err;
	}
	opt = 1024 * 1024;
	rc = sys_setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));
	if (rc < 0) {
		goto err;
	}
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = nl_groups;
	rc = sys_bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc) {
		goto err;
	}
	return fd;
err:
	ERR(-rc, "Failed to open netlink connection");
	if (fd != -1) {
		sys_close(fd);
	}
	return rc;
}

static void
nl_get_rtattrs(struct rtattr *attr, int len, struct rtattr **attrs, int n)
{
	memset(attrs, 0, sizeof(struct rtattr *) * n);
	while (RTA_OK(attr, len)) {
		if (attr->rta_type < n && attrs[attr->rta_type] == NULL) {
			attrs[attr->rta_type] = attr;
		}
		attr = RTA_NEXT(attr, len);
	}
}

static int
route_handle_link(struct nlmsghdr *h, struct route_msg *msg)
{
	int len;
	struct ifinfomsg *ifi;
	struct rtattr *attrs[IFLA_MAX + 1], *attr;

	len = nlmsg_len(h) - sizeof(*ifi);
	if (len < 0) {
		return -EPROTO;
	}
	ifi = NLMSG_DATA(h);
	attr = IFLA_RTA(ifi);
	nl_get_rtattrs(attr, len, attrs, ARRAY_SIZE(attrs));
	msg->rtm_if_idx = ifi->ifi_index;
	msg->rtm_link.rtml_flags = ifi->ifi_flags;
	attr = attrs[IFLA_ADDRESS];
	if (attr != NULL) {
		if (RTA_PAYLOAD(attr) != 6) {
			return -EPROTO;
		}
		memcpy(msg->rtm_link.rtml_hwaddr.ea_bytes, RTA_DATA(attr), 6);
	}
	return 1;
}

static int
route_handle_addr(struct nlmsghdr *h, struct route_msg *msg)
{
	int len, addr_len;
	struct ifaddrmsg *ifa;
	struct rtattr *attrs[IFA_MAX + 1], *attr;

	len = nlmsg_len(h) - sizeof(*ifa);
	if (len < 0) {
		return -EPROTO;
	}
	ifa = NLMSG_DATA(h);
	attr = IFA_RTA(ifa);
	if (ifa->ifa_family == AF_INET) {
		addr_len = 4;
	} else if (ifa->ifa_family == AF_INET6) {
		addr_len = 16;
	} else {
		return 0;
	}
	msg->rtm_af = ifa->ifa_family;
	nl_get_rtattrs(attr, len, attrs, ARRAY_SIZE(attrs));
	attr = attrs[IFA_LOCAL];
	if (attr == NULL) {
		attr = attrs[IFA_ADDRESS];
	}
	if (attr == NULL) {
		return -EPROTO;
	}
	if (RTA_PAYLOAD(attr) != addr_len) {
		return -EPROTO;
	}
	memcpy(msg->rtm_addr.ipa_data, RTA_DATA(attr), addr_len);
	msg->rtm_if_idx = ifa->ifa_index;
	return 1;
}

static int
route_handle_route(struct nlmsghdr *h, struct route_msg *msg)
{
	int len, table, addr_len;
	struct rtmsg *rtm;
	struct rtattr *attrs[RTA_MAX + 1], *attr;

	len = nlmsg_len(h) - sizeof(*rtm);
	if (len < 0) {
		return -EPROTO;
	}
	rtm = NLMSG_DATA(h);
	if (rtm->rtm_flags & RTM_F_CLONED) {
		return 0;
	}
	if (rtm->rtm_type != RTN_UNICAST) {
		return 0;
	}
	if (rtm->rtm_family == AF_INET) {
		addr_len = 4;
	} else if (rtm->rtm_family == AF_INET6) {
		addr_len = 16;
	} else {
		return 0;
	}
	msg->rtm_af = rtm->rtm_family;
	attr = RTM_RTA(rtm);
	nl_get_rtattrs(attr, len, attrs, ARRAY_SIZE(attrs));
	attr = attrs[RTA_TABLE];
	if (attr != NULL) {
		if (RTA_PAYLOAD(attr) != sizeof(uint32_t)) {
			return -EPROTO;
		}
		table = rtattr_get_u32(attr);
	} else {
		table = rtm->rtm_table;
	}
	switch (table) {
	case RT_TABLE_MAIN:
		msg->rtm_route.rtmr_table = ROUTE_TABLE_MAIN;
		break;
	case RT_TABLE_LOCAL:
		msg->rtm_route.rtmr_table = ROUTE_TABLE_LOCAL;
		break;
	default:
		return 0;
	}
	attr = attrs[RTA_DST];
	if (attr == NULL) {
		msg->rtm_route.rtmr_dst = ipaddr_zero;
	} else {
		if (RTA_PAYLOAD(attr) != addr_len) {
			return -EPROTO;
		}
		memcpy(msg->rtm_route.rtmr_dst.ipa_data, RTA_DATA(attr), addr_len);
	}
	if (rtm->rtm_dst_len > addr_len * 8) {
		return -EPROTO;
	}	
	msg->rtm_route.rtmr_pfx = rtm->rtm_dst_len;
	attr = attrs[RTA_OIF];
	if (attr == NULL) {
		return -EPROTO;
	}
	if (RTA_PAYLOAD(attr) != sizeof(uint32_t)) {
		return -EPROTO;
	}
	msg->rtm_if_idx = rtattr_get_u32(attr);
	attr = attrs[RTA_GATEWAY];
	if (attr != NULL) {
		if (RTA_PAYLOAD(attr) != addr_len) {
			return -EPROTO;
		}
		memcpy(msg->rtm_route.rtmr_via.ipa_data, RTA_DATA(attr), addr_len);
	}
	return 1;
}

static int
route_dump_handler(struct nlmsghdr *h, void *udata)
{
	int rc;
	struct route_msg msg;
	route_msg_f fn;

	fn = udata;
	memset(&msg, 0, sizeof(msg));
	msg.rtm_cmd = ROUTE_MSG_DEL;
	switch (h->nlmsg_type) {
	case RTM_NEWLINK:
		msg.rtm_cmd = ROUTE_MSG_ADD;
	case RTM_DELLINK:
		msg.rtm_type = ROUTE_MSG_LINK;
		rc = route_handle_link(h, &msg);
		break;
	case RTM_NEWADDR:
		msg.rtm_cmd = ROUTE_MSG_ADD;
	case RTM_DELADDR:
		msg.rtm_type = ROUTE_MSG_ADDR;
		rc = route_handle_addr(h, &msg);
		break;
	case RTM_NEWROUTE:
		msg.rtm_cmd = ROUTE_MSG_ADD;
	case RTM_DELROUTE:
		msg.rtm_type = ROUTE_MSG_ROUTE;
		rc = route_handle_route(h, &msg);
		break;
	default:
		INFO(0, "Unknown netlink message type '%d'", h->nlmsg_type);
		return 0;
	}
	if (rc == 1 && fn != NULL) {
		(*fn)(&msg);
	}
	return rc;
}

int
rtnl_recvmsg(int fd, int (*handler)(struct nlmsghdr *, void *), void *udata)
{
	uint8_t buf[16384];
	int rc, len;
	struct msghdr msg;
	struct nlmsghdr *h;
	struct sockaddr_nl addr;
	struct iovec iov;
	struct nlmsgerr *err;

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1; 
	rc = sys_recvmsg(fd, &msg, 0);
	if (rc < 0) {
		if (rc != -EAGAIN) {
			ERR(-rc, "Unable to read netlink message");
		}
		return rc;
	}
	len = rc;
	for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
		switch (h->nlmsg_type) {
		case NLMSG_ERROR:
			err = NLMSG_DATA(h);
			if (nlmsg_len(h) < sizeof(*err)) {
				ERR(0, "Netlink error truncated");
				return -EPROTO;
			}
			err = NLMSG_DATA(h);
			if (err->error) {
				ERR(-err->error, "Receive netlink error");
				return -err->error;
			}
			break;
		case NLMSG_DONE:
			return 0;
		default:
			if (handler == NULL) {
				rc = 0;
			} else {
				rc = (*handler)(h, udata);
			}
			if (rc < 0) {
				ERR(-rc, "Netlink '%s' message handler failed",
					nlmsg_type_str(h->nlmsg_type));
			} else {
				DBG(0, "Netlink '%s' message processed",
					nlmsg_type_str(h->nlmsg_type));
			}
			if (rc < 0) {
				return rc;
			}
			break;
		}
	}
	if (msg.msg_flags & MSG_TRUNC) {
		ERR(0, "Receive truncated netlink message");
		return 0;
	}
	return 0;
}

int
route_open()
{
	int rc, g;

	g = 0;
	g |= RTMGRP_LINK;
	g |= RTMGRP_IPV4_IFADDR;
	g |= RTMGRP_IPV4_ROUTE;
	g |= RTMGRP_IPV6_IFADDR;
	g |= RTMGRP_IPV6_ROUTE;
	rc = rtnl_open(g);
	return rc;
}

static int
rtnl_read(int fd, int (*handler)(struct nlmsghdr *, void *), void *udata)
{
	int rc;

	while (1) {
		rc = rtnl_recvmsg(fd, handler, udata);
		if (rc < 0) {
			if (rc == -EAGAIN) {
				return 0;
			} else {
				return rc;
			}
		}
	}
}

int
route_dump(route_msg_f fn)
{
	static int types[3] = { RTM_GETLINK, RTM_GETADDR, RTM_GETROUTE };
	u_char buf[256];
	int i, rc, fd;
	uint32_t vf_mask;
	struct ifinfomsg ifm;
	struct nlm m;

	fd = rc = rtnl_open(0);
	if (rc < 0) {
		goto err;
	}
	memset(&ifm, 0, sizeof(ifm));
	ifm.ifi_family = AF_UNSPEC;
	vf_mask = RTEXT_FILTER_VF;
	for (i = 0; i < ARRAY_SIZE(types); ++i) {
		nlm_init(&m, buf, sizeof(buf));
		nlh_init(nlm_hdr(&m), types[i], NLM_F_DUMP|NLM_F_REQUEST);
		nlm_put(&m, &ifm, sizeof(ifm));
		nlm_put_attr(&m, IFLA_EXT_MASK, &vf_mask, sizeof(vf_mask));
		rc = send_record(fd, m.nlm_buf, nlm_hdr(&m)->nlmsg_len, 0);
		if (rc < 0) {
			goto err;
		}
		rc = rtnl_read(fd, route_dump_handler, fn);
		if (rc < 0) {
			goto err;
		}
	}
	sys_close(fd);
	return 0;
err:
	ERR(-rc, "Failed to dump route info");
	sys_close(fd);
	return rc;
}

int
route_read(int fd, route_msg_f fn)
{
	return rtnl_read(fd, route_dump_handler, fn);
}

int
netlink_veth_add(const char *veth, const char *peer)
{
	int fd, rc;
	u_char buf[512];
	struct ifinfomsg ifm;
	struct nlm m;
	struct nlattr *nla_a, *nla_b, *nla_c;

	fd = rc = rtnl_open(0);
	if (rc < 0) {
		goto err;
	}
	fd = rc;
	nlm_init(&m, buf, sizeof(buf));
	nlh_init(nlm_hdr(&m), RTM_NEWLINK, NLM_F_REQUEST|NLM_F_CREATE|NLM_F_ACK);
	memset(&ifm, 0, sizeof(ifm));
	ifm.ifi_family = AF_UNSPEC;
	nlm_put(&m, &ifm, sizeof(ifm));
	NLM_PUT_STRING(&m, IFLA_IFNAME, veth);
	nla_a = nlm_nest_start(&m, IFLA_LINKINFO);
	NLM_PUT_STRING(&m, IFLA_INFO_KIND, "veth");
	nla_b = nlm_nest_start(&m, IFLA_INFO_DATA);
	nla_c = nlm_nest_start(&m, VETH_INFO_PEER);
	nlm_put(&m, &ifm, sizeof(ifm));
	NLM_PUT_STRING(&m, IFLA_IFNAME, peer);
	nlm_nest_end(&m, nla_c);
	nlm_nest_end(&m, nla_b);
	nlm_nest_end(&m, nla_a);
	rc = send_record(fd, m.nlm_buf, nlm_hdr(&m)->nlmsg_len, 0);
	if (rc < 0) {
		goto err;
	}
	rc = rtnl_read(fd, NULL, NULL);
	if (rc < 0) {
		goto err;
	}
	return 0;
err:
	ERR(-rc, "Failed to add veth interface '%s' peer '%s'", veth, peer);
	sys_close(fd);
	return rc;
}

/*
static int
link_get_flags(int fd, int ifindex)
{
	int rc, flags;
	u_char buf[4096];
	struct ifinfomsg ifm;
	struct nlm m;

	nlm_init(&m, buf, sizeof(buf));
	nlm_hdr(&m)->nlmsg_type = RTM_GETLINK;
	nlm_hdr(&m)->nlmsg_flags = NLM_F_REQUEST;
	nlm_hdr(&m)->nlmsg_pid = 0;
	nlm_hdr(&m)->nlmsg_seq = 1;

	memset(&ifm, 0, sizeof(ifm));
	ifm.ifi_family = AF_UNSPEC;
	ifm.ifi_flags = 0;
	ifm.ifi_index = ifindex;
	nlm_put(&m, &ifm, sizeof(ifm));

	rc = send(fd, m.nlm_buf, nlm_hdr(&m)->nlmsg_len, 0);
	assert(rc == nlm_hdr(&m)->nlmsg_len);
	flags = 0;
	netlink_read(fd, link_get_flags_handler, &flags);
	return flags;
}

void
netlink_link_up(int ifindex)
{
	int rc, flags;
	u_char buf[4096];
	struct ifinfomsg ifm;
	struct nlm m;

	memset(&ifm, 0, sizeof(ifm));
	ifm.ifi_family = AF_UNSPEC;
	ifm.ifi_index = if_nametoindex(ifname);
	assert(ifm.ifi_index > 0);

	flags = link_get_flags(fd, ifm.ifi_index);
	if (flags & IFF_UP) {
		printf("Already UP\n");
	}
	ifm.ifi_flags = flags | IFF_UP;
	ifm.ifi_change = IFF_UP;

	// Copied
	nlm_init(&m, buf, sizeof(buf));
	nlm_hdr(&m)->nlmsg_type = RTM_NEWLINK;
	nlm_hdr(&m)->nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
	nlm_hdr(&m)->nlmsg_pid = 0;
	nlm_hdr(&m)->nlmsg_seq = 1;

	nlm_put(&m, &ifm, sizeof(ifm));

	NLM_PUT_STRING(&m, IFLA_IFNAME, ifname);

	rc = send(fd, m.nlm_buf, nlm_hdr(&m)->nlmsg_len, 0);
	printf("rc=%d/%d\n", rc, nlm_hdr(&m)->nlmsg_len);
	netlink_read(fd, NULL, NULL);
}
*/

int
netlink_link_del(const char *ifnam)
{
	int rc, fd;
	u_char buf[4096];
	struct ifinfomsg ifm;
	struct nlm m;

	fd = rc = rtnl_open(0);
	if (rc < 0) {
		goto err;
	}
	nlm_init(&m, buf, sizeof(buf));
	nlm_hdr(&m)->nlmsg_type = RTM_DELLINK;
	nlm_hdr(&m)->nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
	nlm_hdr(&m)->nlmsg_pid = 0;
	nlm_hdr(&m)->nlmsg_seq = 1;
	memset(&ifm, 0, sizeof(ifm));
	ifm.ifi_family = AF_UNSPEC;
	ifm.ifi_flags = 0;
	nlm_put(&m, &ifm, sizeof(ifm));
	NLM_PUT_STRING(&m, IFLA_IFNAME, ifnam);
	rc = send_record(fd, m.nlm_buf, nlm_hdr(&m)->nlmsg_len, 0);
	if (rc < 0) {
		goto err;
	}
	rc = rtnl_read(fd, NULL, NULL);
	if (rc < 0) {
		goto err;
	}
	sys_close(fd);
	return 0;
err:
	ERR(-rc, "Failed to del link '%s'", ifnam);
	return rc;
}
