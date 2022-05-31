// gpl2
#include "../internals.h"

#define REQUIRE(type) \
	if (msg_len < sizeof(type)) { \
		return -EPROTO; \
	} \

static int
ipaddr_from_sockaddr(struct ipaddr *dst, struct sockaddr *sa)
{
	struct sockaddr_in *sa_in;
	struct sockaddr_in6 *sa_in6;

	switch (sa->sa_family) {
	case AF_INET:
		sa_in = (struct sockaddr_in *)sa;
		dst->ipa_4 = sa_in->sin_addr.s_addr;
		return 0;
	case AF_INET6:
		sa_in6 = (struct sockaddr_in6 *)sa;
		memcpy(dst->ipa_6, sa_in6->sin6_addr.s6_addr, 16);
		return 0;
	default:
		return -EPROTO;
	}
}

static int
get_route_addrs(void *buf, size_t count, int flags, struct sockaddr **addrs)
{
	int i, size, sa_size;
	struct sockaddr *sa;

	size = 0;
	for (i = 0; i < RTAX_MAX; ++i) {
		if (flags & (1 << i)) {
			sa = (struct sockaddr *)((uint8_t *)buf + size);
			addrs[i] = sa;
			sa_size = SA_SIZE(sa);
			if (size + sa_size > count) {
				return -EPROTO;
			}
			size += sa_size;
		} else {
			addrs[i] = NULL;
		}
	}
	return 0;
}

static void
ifa_dl(struct route_msg_link *link, struct ifaddrs *ifa)
{
	struct sockaddr_dl *addr;

	addr = (struct sockaddr_dl *)ifa->ifa_addr;
	memcpy(link->rtml_hwaddr.ea_bytes, LLADDR(addr), 6);
	link->rtml_flags = ifa->ifa_flags;
}

static int
handle_link(struct route_msg *msg, int ifindex)
{
	int rc;
	char if_name[IFNAMSIZ];
	struct ifaddrs *ifap, *ifa;

	msg->rtm_type = ROUTE_MSG_LINK;
	msg->rtm_ifindex = ifindex;
	rc = sys_if_indextoname(ifindex, if_name);
	if (rc) {
		return rc;
	}
	rc = getifaddrs(&ifap);
	if (rc) {
		return rc;
	}
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family == AF_LINK &&
			!strcmp(ifa->ifa_name, if_name)) {
			ifa_dl(&msg->rtm_link, ifa);
			break;
		}
	}
	freeifaddrs(ifap);
	if (ifa == NULL) {
		return -EPROTO;
	}
	return 1;
}

static int
handle_addr(struct route_msg *msg, struct ifa_msghdr *ifam)
{
	int rc;
	struct sockaddr *addrs[RTAX_MAX];
	struct sockaddr *ifa, *ifp;
	struct sockaddr_dl *ifp_dl;

	msg->rtm_type = ROUTE_MSG_ADDR;
	rc = get_route_addrs(ifam + 1, ifam->ifam_msglen - sizeof(*ifam),
		ifam->ifam_addrs, addrs);
	if (rc) {
		return rc;
	}
	ifa = addrs[RTAX_IFA];
	ifp = addrs[RTAX_IFP];
	if (ifa == NULL || ifp == NULL) {
		return -EPROTO;
	}
	if (ifp->sa_family != AF_LINK) {
		return -EPROTO;
	}
	ifp_dl = (struct sockaddr_dl *)ifp;
	msg->rtm_ifindex = ifp_dl->sdl_index;
	if (ifa->sa_family != AF_INET &&
	    ifa->sa_family != AF_INET6) {
		return -EPROTO;
	}
	msg->rtm_af = ifa->sa_family;
	rc = ipaddr_from_sockaddr(&msg->rtm_addr, ifa);
	if (rc) {
		return rc;
	}
	return 1;
} 

static int
handle_route(struct route_msg *msg, struct rt_msghdr *rtm)
{
	int rc;
	struct sockaddr *addrs[RTAX_MAX];
	struct sockaddr *dst, *netmask, *gateway;
	struct sockaddr_dl *gateway_dl;
	struct ipaddr tmp;

	msg->rtm_type = ROUTE_MSG_ROUTE;
	rc = get_route_addrs(rtm + 1, rtm->rtm_msglen - sizeof(*rtm),
		rtm->rtm_addrs, addrs);
	if (rc) {
		return rc;
	}
	dst = addrs[RTAX_DST];
	netmask = addrs[RTAX_NETMASK];
	gateway = addrs[RTAX_GATEWAY];
	if (dst == NULL || netmask == NULL || gateway == NULL) {
		return -EPROTO;
	}
	if (dst->sa_family != AF_INET && dst->sa_family != AF_INET6) {
		return -EPROTO;
	}
	msg->rtm_af = dst->sa_family;
	msg->rtm_ifindex = rtm->rtm_index;
	msg->rtm_route.rtmr_via = ipaddr_zero;
	rc = ipaddr_from_sockaddr(&msg->rtm_route.rtmr_dst, dst);
	if (rc) {
		return rc;
	}
	if (gateway->sa_family == AF_LINK) {
		gateway_dl = (struct sockaddr_dl *)gateway;
		if (msg->rtm_ifindex != gateway_dl->sdl_index) {
			return -EPROTO;
		}
	} else if (gateway->sa_family == msg->rtm_af) {
		rc = ipaddr_from_sockaddr(&msg->rtm_route.rtmr_via, gateway);
		if (rc) {
			return rc;
		}
	} else {
		return -EPROTO;
	}
	if (netmask->sa_family != msg->rtm_af) {
		return -EPROTO;
	}
	rc = ipaddr_from_sockaddr(&tmp, netmask);
	if (rc) {
		return rc;
	}
	msg->rtm_route.rtmr_pfx = ipaddr_pfx(msg->rtm_af, &tmp);
	return 1;
}

static int
handle_rtmsg(struct rt_msghdr *rtm, size_t msg_len, route_msg_f fn)
{
	int rc;
	struct if_msghdr *ifm;
	struct ifa_msghdr *ifam;
	struct route_msg msg;

	if (rtm->rtm_version != RTM_VERSION) {
		return -EPROTO;
	}
	msg.rtm_cmd = ROUTE_MSG_DEL;
	switch (rtm->rtm_type) {
	case RTM_IFINFO:
		REQUIRE(struct if_msghdr);
		ifm = (struct if_msghdr *)rtm;
		if (ifm->ifm_msglen > msg_len) {
			rc = -EPROTO;
		} else {
			rc = handle_link(&msg, ifm->ifm_index);
		}
		break;
	case RTM_NEWADDR:
		msg.rtm_cmd = ROUTE_MSG_ADD;
	case RTM_DELADDR:
		REQUIRE(struct ifa_msghdr);
		ifam = (struct ifa_msghdr *)rtm;
		if (ifam->ifam_msglen > msg_len) {
			rc = -EPROTO;
		} else {
			rc = handle_addr(&msg, ifam);
		}
		break;
	case RTM_ADD:
		msg.rtm_cmd = ROUTE_MSG_ADD;
	case RTM_DELETE:
		if (rtm->rtm_msglen > msg_len) {
			rc = -EPROTO;
		} else {
			rc = handle_route(&msg, rtm);
		}
		break;
	default:
		rc = 0;
		break;
	}
	if (rc == 1) {
		(*fn)(&msg);
	}
	return rc;
}

static int
route_dump_ifaddrs(route_msg_f fn)
{
	int rc, ifindex;
	struct ifaddrs *ifap, *ifa;
	struct route_msg msg;

	rc = sys_getifaddrs(&ifap);
	if (rc) {
		return rc;
	}
	msg.rtm_cmd = ROUTE_MSG_ADD;
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		ifindex = if_nametoindex(ifa->ifa_name);
		if (ifindex == 0 && errno) {
			continue;
		}
		switch (ifa->ifa_addr->sa_family) {
		case AF_LINK:
			msg.rtm_type = ROUTE_MSG_LINK;
			msg.rtm_ifindex = ifindex;
			ifa_dl(&msg.rtm_link, ifa);			
			(*fn)(&msg);
			break;
		case AF_INET:
		case AF_INET6:
			msg.rtm_type = ROUTE_MSG_ADDR;
			msg.rtm_af = ifa->ifa_addr->sa_family;
			msg.rtm_ifindex = ifindex;
			rc = ipaddr_from_sockaddr(&msg.rtm_addr, ifa->ifa_addr);
			if (rc) {
				return rc;
			}
			(*fn)(&msg);
			break;
		}
	}
	freeifaddrs(ifap);
	return 0;
}

int
route_dump(route_msg_f fn)
{
	int rc, mib[7];
	u_char *buf;
	size_t i, len;
	uint net_fibs, net_my_fibnum;
	size_t net_fibs_size, net_my_fib_num_size;
	struct rt_msghdr *rtm;
	struct route_msg msg;

	rc = route_dump_ifaddrs(fn);
	if (rc) {
		return rc;
	}
	net_fibs_size = sizeof(net_fibs);
	rc = sysctlbyname("net.fibs", &net_fibs, &net_fibs_size, NULL, 0);
	if (rc == -1) {
		net_fibs = -1;
	}
	rc = sysctlbyname("net.my_fibnum", &net_my_fibnum,
	                  &net_my_fib_num_size, NULL, 0);
	if (rc == -1) {
		net_my_fibnum = 0;
	}
	if (net_my_fibnum >= net_fibs) {
		return -EPROTO;
	}
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_UNSPEC;
	mib[4] = NET_RT_DUMP;
	mib[5] = 0;
	mib[6] = net_my_fibnum;
	rc = sysctl(mib, ARRAY_SIZE(mib), NULL, &len, NULL, 0);
	if (rc == -1) {
		return -errno;
	}
	buf = sys_malloc(len);
	if (buf == NULL) {
		return -ENOMEM;
	}
	rc = sysctl(mib, ARRAY_SIZE(mib), buf, &len, NULL, 0);
	if (rc == -1) {
		return -errno;
	}
	for (i = 0; i < len; i += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)(buf + i);
		if (rtm->rtm_version != RTM_VERSION) {
			continue;
		}
		if (rtm->rtm_type != RTM_GET) {
			continue;
		}
		msg.rtm_cmd = ROUTE_MSG_ADD;
		rc = handle_route(&msg, rtm);
		if (rc == 1) {
			(*fn)(&msg);
		}
	}
	sys_free(buf);
	return 0; 
}

int
route_open()
{
	int rc;

	rc = sys_socket(PF_ROUTE, SOCK_RAW, 0);
	return rc;
}

int
route_read(int fd, route_msg_f fn)
{
	char msg[2048];
	int rc;

	rc = sys_read(fd, msg, sizeof(msg));
	if (rc < 0) {
		return rc;
	}
	handle_rtmsg((struct rt_msghdr *)msg, rc, fn);
	return 0;
}
