// SPDX-License-Identifier: LGPL-2.1-only

#include <arpa/inet.h>
#include <err.h>
#include <getopt.h>
#include <net/if.h>
#include <netdb.h>

#include <gbtcp/kernel/api.h>
#include <gbtcp/kernel/fd_event.h>
#include <gbtcp/kernel/gbtcp.h>
#include <gbtcp/kernel/inet.pb-c.h>
#include <gbtcp/kernel/ip.pb-c.h>
#include <gbtcp/kernel/worker.h>
#include <gbtcp/socket/socket.pb-c.h>

#define GT_PROTO_FLAG_ARP (1 << 0)
#define GT_PROTO_FLAG_IP (1 << 1)
#define GT_PROTO_FLAG_TCP (1 << 2)
#define GT_PROTO_FLAG_UDP (1 << 3)
#define GT_PROTO_FLAG_ALL 0xffffffff

struct gt_interface {
	struct gt_dlist link;
	char ifname[IFNAMSIZ];
	u64 ipackets;
	u64 idrops;
	u64 ibytes;
	u64 opackets;
	u64 odrops;
	u64 obytes;
};

struct gt_stat_entry {
	const char *name;
	u64 *ptr;
};

static const char *gt_tcpstates[GT_TCPS_MAX_STATES] = {
	[GT_TCPS_CLOSED] = "CLOSED",
	[GT_TCPS_LISTEN] = "LISTEN",
	[GT_TCPS_SYN_SENT] = "SYN_SENT",
	[GT_TCPS_SYN_RCVD] = "SYN_RCVD",
	[GT_TCPS_ESTABLISHED] = "ESTABLISHED",
	[GT_TCPS_CLOSE_WAIT] = "CLOSE_WAIT",
	[GT_TCPS_LAST_ACK] = "LAST_ACK",
	[GT_TCPS_FIN_WAIT_1] = "FIN_WAIT_1",
	[GT_TCPS_FIN_WAIT_2] = "FIN_WAIT_2",
	[GT_TCPS_CLOSING] = "CLOSING",
	[GT_TCPS_TIME_WAIT] = "TIME_WAIT"
};

#define GT_(n) u64 n;
struct gt_tcp_stat {
	GT_X_TCP_STAT(GT_);
	u64 states[GT_TCPS_MAX_STATES];
};

struct gt_udp_stat {
	GT_X_UDP_STAT(GT_);
};

struct gt_ip_stat {
	GT_X_IP_STAT(GT_);
};

struct gt_arp_stat {
	GT_X_ARP_STAT(GT_);
};
#undef GT_

static u8 gt_aflag;
static u8 gt_bflag;
static u8 gt_Hflag;
static u8 gt_lflag;
static u8 gt_nflag;
static u8 gt_sflag;
static u8 gt_zflag;
static uint gt_proto_mask;
static char *gt_interface_name;
static uint gt_interval;
static u8 gt_done;

struct gt_tcp_stat gt_tcps;
struct gt_udp_stat gt_udps;
struct gt_ip_stat gt_ips;
struct gt_arp_stat gt_arps;

#define GT_(n) { .name = #n, .ptr = &gt_tcps.n },
#define GT_STATE(i) { .name = "states." #i, .ptr = gt_tcps.states + i }
// clang-format off
struct gt_stat_entry stat_tcp_entries[] = {
	GT_X_TCP_STAT(GT_)
	GT_STATE(0),
	GT_STATE(1),
	GT_STATE(2),
	GT_STATE(3),
	GT_STATE(4),
	GT_STATE(5),
	GT_STATE(6),
	GT_STATE(7),
	GT_STATE(8),
	GT_STATE(9),
	GT_STATE(10),
	{ NULL, NULL }
};
#undef STATE
#undef GT_

#define GT_(n) { .name = #n, .ptr = &gt_udps.n },
struct gt_stat_entry gt_stat_udp_entries[] = {
	GT_X_UDP_STAT(GT_)
	{ NULL, NULL }
};
#undef GT_

#define GT_(n) { .name = #n, .ptr = &gt_ips.n },
struct gt_stat_entry stat_ip_entries[] = {
	GT_X_IP_STAT(GT_)
	{ NULL, NULL }
};
#undef GT_

#define GT_(n) { .name = #n, .ptr = &gt_arps.n },
struct gt_stat_entry gt_stat_arp_entries[] = {
	GT_X_ARP_STAT(GT_)
	{ NULL, NULL }
};
#undef GT_
// clang-format on

static void
gt_fatal(int errnum)
{
	errx(EXIT_FAILURE, "%s", strerror(errnum));
}

static struct gt_api_conn *
gt_new_conn(void)
{
	int rc;
	struct gt_api_conn *cp;

	// gbtcp-netstat never attaches: its connection always comes from the
	// system heap.
	cp = gt_api_conn_alloc(&gt_uallocator);
	if (cp == NULL) {
		gt_fatal(ENOMEM);
	}

	rc = gt_api_client_connect(cp, GT_API_SOCK_PATH);
	if (rc < 0) {
		gt_fatal(-rc);
	}

	return cp;
}

static void
gt_wait_for_reply(struct gt_api_conn *cp)
{
	gt_done = 0;
	while (!gt_done) {
		wait_for_fd_events();
	}

	gt_api_conn_close(cp);
	gt_api_conn_free(cp);
}

static void *
gt_xmalloc(int size)
{
	void *ptr;

	ptr = sys_malloc(size);
	if (ptr == NULL) {
		errx(1, "malloc(%d) failed", size);
	}
	return ptr;
}

static char *
gt_inetname(be32_t addr)
{
	char *cp;
	struct in_addr in;
	struct hostent *hp;
	static char line[256];

	cp = 0;
	if (gt_nflag == 0 && addr != INADDR_ANY) {
		hp = gethostbyaddr((char *)&addr, sizeof(addr), AF_INET);
		if (hp) {
			cp = hp->h_name;
			//trimdomain(cp, strlen(cp));
		}
	}

	if (addr == INADDR_ANY)
		strcpy(line, "*");
	else if (cp) {
		gt_strzcpy(line, cp, sizeof(line));
	} else {
		in.s_addr = addr;
		gt_strzcpy(line, inet_ntoa(in), sizeof(line));
	}

	return line;
}

static void
gt_print_sockaddr(be32_t addr, be16_t port, const char *proto_name)
{
	struct servent *sp = 0;
	char line[80], *cp;
	int width;
	int alen;

	snprintf(line, sizeof(line), "%.*s.", 16, gt_inetname(addr));
	alen = strlen(line);
	cp = line + alen;
	if (gt_nflag < 2 && port) {
		sp = getservbyport(port, proto_name);
	}
	if (sp || port == 0) {
		snprintf(cp, sizeof(line) - alen, "%.15s ",
			 sp ? sp->s_name : "*");
	} else {
		snprintf(cp, sizeof(line) - alen, "%d ", ntohs(port));
	}
	width = 22;
	printf("%-*.*s ", width, width, line);
}

// Interfaces
static void
print_interface_stat(int width, u64 value)
{
	if (0 && gt_Hflag) {
		// TODO: Print statistics in human readable form
	} else {
		printf(" %*" PRIu64, width, value);
	}
}

static void
print_interface_banner(void)
{
	printf("%-*.*s", 16, 16, "Name");
	printf(" %12.12s %12.12s", "Ipkts", "Idrop");
	if (gt_bflag) {
		printf(" %14.14s", "Ibytes");
	}
	printf(" %12.12s %12.12s", "Opkts", "Odrop");
	if (gt_bflag) {
		printf(" %14.14s", "Obytes");
	}
	printf("\n");
}

static void
print_interface(struct gt_interface *ifp)
{
	char name[IFNAMSIZ];

	gt_strzcpy(name, ifp->ifname, sizeof(name));
	printf("%-*.*s", 16, 16, name);
	print_interface_stat(12, ifp->ipackets);
	print_interface_stat(12, ifp->idrops);
	if (gt_bflag) {
		print_interface_stat(14, ifp->ibytes);
	}
	print_interface_stat(12, ifp->opackets);
	print_interface_stat(12, ifp->odrops);
	if (gt_bflag) {
		print_interface_stat(14, ifp->obytes);
	}
	printf("\n");
}

static struct gt_interface *
gt_get_interface(struct gt_dlist *head, const char *ifname)
{
	struct gt_interface *ifp;

	GT_DLIST_FOREACH(ifp, head, link) {
		if (!strcmp(ifp->ifname, ifname)) {
			return ifp;
		}
	}
	return NULL;
}

static int
gt_ip_link_details_api_handler(struct gt_api_conn *cp, u32 errnum,
			       Gt__IpLinkDetails *rp)
{
	struct gt_dlist *head;
	struct gt_interface *ifp;

	if (rp != NULL) {
		head = gt_api_conn_get_udata(cp);

		if (gt_interface_name != NULL &&
		    strcmp(gt_interface_name, rp->dev)) {
			return 0;
		}
		ifp = gt_get_interface(head, rp->dev);
		if (ifp == NULL) {
			ifp = gt_xmalloc(sizeof(*ifp));
			memset(ifp, 0, sizeof(*ifp));
			gt_strzcpy(ifp->ifname, rp->dev, sizeof(ifp->ifname));
			GT_DLIST_INSERT_HEAD(head, ifp, link);
		}

		ifp->ipackets += rp->rx_pkts;
		ifp->idrops += rp->rx_drop;
		ifp->ibytes += rp->rx_bytes;
		ifp->opackets += rp->tx_pkts;
		ifp->odrops += rp->tx_drop;
		ifp->obytes += rp->tx_bytes;
	}

	if (errnum != 0) {
		if (errnum != EAGAIN) {
			gt_fatal(errnum);
		}
		gt_done = 1;
	}

	return 0;
}

GT_API_CLIENT_DEFINE_HANDLER(ip_link_details, gt_ip_link_details_api_handler);

static void
gt_free_interfaces(struct gt_dlist *head)
{
	struct gt_interface *ifp;

	while (!gt_dlist_is_empty(head)) {
		ifp = GT_DLIST_FIRST(head, struct gt_interface, link);
		GT_DLIST_REMOVE(ifp, link);
		sys_free(ifp);
	}
}

static void
gt_get_interfaces(struct gt_dlist *head)
{
	int rc;
	struct gt_api_conn *cp;
	Gt__IpLinkDump *rq;

	gt_dlist_init(head);

	cp = gt_new_conn();
	gt_api_conn_set_udata(cp, head);

	rq = gt_api_alloc_dump(cp, rq, ip_link);
	if (rq == NULL) {
		gt_fatal(ENOMEM);
	}

	rc = gt_api_send_dump(cp, rq, ip_link);
	if (rc) {
		gt_fatal(-rc);
	}

	gt_wait_for_reply(cp);
}

static int
get_interfaces_stat(struct gt_interface *stat)
{
	int n;
	struct gt_interface *ifp;
	struct gt_dlist head;

	memset(stat, 0, sizeof(*stat));
	n = 0;
	gt_get_interfaces(&head);
	GT_DLIST_FOREACH(ifp, &head, link) {
		if (n == 0) {
			gt_strzcpy(stat->ifname, ifp->ifname,
				   sizeof(stat->ifname));
		}
		n++;
		stat->ipackets += ifp->ipackets;
		stat->ibytes += ifp->ibytes;
		stat->opackets += ifp->opackets;
		stat->obytes += ifp->obytes;
		stat->odrops += ifp->odrops;
	}
	if (n > 1) {
		gt_strzcpy(stat->ifname, "Total", sizeof(stat->ifname));
	}

	gt_free_interfaces(&head);

	return 0;
}

static void
gt_print_interfaces_rate(void)
{
	int n, rc;
	struct gt_interface if2[2], *new, *old, *tmp, diff;

	n = 0;
	new = &if2[0];
	old = &if2[1];
	rc = get_interfaces_stat(old);
	if (rc) {
		return;
	}
	print_interface_banner();
	while (1) {
		sleep(gt_interval);
		n++;
		rc = get_interfaces_stat(new);
		if (rc) {
			return;
		}
		gt_strzcpy(diff.ifname, new->ifname, sizeof(diff.ifname));
		diff.ipackets = new->ipackets - old->ipackets;
		diff.idrops = new->idrops - old->idrops;
		diff.ibytes = new->ibytes - old->ibytes;
		diff.opackets = new->opackets - old->opackets;
		diff.odrops = new->odrops - old->odrops;
		diff.obytes = new->obytes - old->obytes;
		print_interface(&diff);
		tmp = new;
		new = old;
		old = tmp;
		if (n == 21) {
			n = 0;
			print_interface_banner();
		}
	}
}

static void
gt_print_interfaces(void)
{
	struct gt_dlist head;
	struct gt_interface *ifp;

	gt_get_interfaces(&head);
	if (!gt_dlist_is_empty(&head)) {
		print_interface_banner();
		GT_DLIST_FOREACH(ifp, &head, link) {
			print_interface(ifp);
		}
	}
	gt_free_interfaces(&head);
}

// sockets
static int
gt_ipproto_is_filtered(int ipproto)
{
	if (GT_FLAG_ISSET(gt_proto_mask, GT_PROTO_FLAG_IP)) {
		return 0;
	} else if (ipproto == IPPROTO_UDP) {
		return !GT_FLAG_ISSET(gt_proto_mask, GT_PROTO_FLAG_UDP);
	} else if (ipproto == IPPROTO_TCP) {
		return !GT_FLAG_ISSET(gt_proto_mask, GT_PROTO_FLAG_TCP);
	} else {
		return 1;
	}
}

static int
gt_socket_details_api_handler(struct gt_api_conn *cp, u32 errnum,
			      Gt__SocketDetails *rp)
{
	int rc;
	be16_t lport, fport;
	const char *proto_name;

	if (errnum != 0) {
		if (errnum != EAGAIN) {
			gt_fatal(errnum);
		}
		gt_done = 1;
	}

	if (rp == NULL) {
		return 0;
	}

	rc = gt_ipproto_is_filtered(rp->proto);
	if (rc) {
		return 0;
	}
	lport = hton16(rp->src_port);
	fport = hton16(rp->dst_port);
	proto_name = rp->proto == IPPROTO_TCP ? "tcp" : "udp";
	printf("%-5.5s ", proto_name);
	gt_print_sockaddr(rp->src_addr->ip4_u32, lport, proto_name);
	gt_print_sockaddr(rp->dst_addr->ip4_u32, fport, proto_name);
	if (rp->proto == IPPROTO_TCP) {
		if (rp->tcp_state >= GT_TCPS_MAX_STATES) {
			printf("%-11d ", rp->tcp_state);
		} else {
			printf("%-11s ", gt_tcpstates[rp->tcp_state]);
		}
	} else {
		printf("%-11s ", "           ");
	}
	printf("%-7d\n", rp->pid);

	return 0;
}

GT_API_CLIENT_DEFINE_HANDLER(socket_details, gt_socket_details_api_handler)

static void
gt_get_sockets(u8 listening)
{
	int rc;
	struct gt_api_conn *cp;
	Gt__SocketDump *rq;

	cp = gt_new_conn();

	rq = gt_api_alloc_dump(cp, rq, socket);
	if (rq == NULL) {
		gt_fatal(ENOMEM);
	}

	rq->listening = listening;

	rc = gt_api_send_dump(cp, rq, socket);
	if (rc) {
		gt_fatal(-rc);
	}

	gt_wait_for_reply(cp);
}

static void
gt_print_sockets(void)
{
	printf("Active Internet connections");
	if (gt_aflag) {
		printf(" (including servers)");
	} else if (gt_lflag) {
		printf(" (only servers)");
	}
	printf("\n%-5.5s %-22.22s %-22.22s %-11.11s %-7.7s", "Proto",
	       "Local Address", "Foreign Address", "State", "PID");
	printf("\n");
	if (gt_lflag == 0) {
		gt_get_sockets(0);
	}
	gt_get_sockets(1);
}

// stats
static int
gt_get_stat_reply_api_handler(struct gt_api_conn *cp, u32 errnum,
			      Gt__GetStatReply *rp)
{
	struct gt_stat_entry *stat;

	if (rp != NULL) {
		stat = gt_api_conn_get_udata(cp);
		*stat->ptr = rp->counter;
	}
	gt_done = 1;
	return 0;
}

GT_API_CLIENT_DEFINE_HANDLER(get_stat_reply, gt_get_stat_reply_api_handler);

static void
gt_get_inet_stat(const char *name, struct gt_stat_entry *e)
{
	int rc;
	struct gt_api_conn *cp;
	Gt__GetStat *rq;

	cp = gt_new_conn();

	rq = gt_api_alloc_request(cp, rq, get_stat);
	if (rq == NULL) {
		gt_fatal(ENOMEM);
	}

	// Owned by the request message: freed via free_unpacked/gt_pbc_free.
	rq->proto_name = gt_pbc_strdup(cp, name);
	rq->stat_name = gt_pbc_strdup(cp, e->name);

	rc = gt_api_send_request(cp, rq, get_stat);
	if (rc) {
		gt_fatal(-rc);
	}

	gt_api_conn_set_udata(cp, e);

	gt_wait_for_reply(cp);
}

static void
gt_get_inet_stats(const char *name, struct gt_stat_entry *entries)
{
	struct gt_stat_entry *e;

	for (e = entries; e->name != NULL; ++e) {
		gt_get_inet_stat(name, e);
	}
}

static int
gt_print_arp_stats(void)
{
	gt_get_inet_stats("arp", gt_stat_arp_entries);

	printf("arp:\n");
	if (gt_arps.txrequests || gt_sflag > 1) {
		printf("\t%" PRIu64 " ARP requests sent\n", gt_arps.txrequests);
	}
	if (gt_arps.txreplies || gt_sflag > 1) {
		printf("\t%" PRIu64 " ARP replies sent\n", gt_arps.txreplies);
	}
	if (gt_arps.txrepliesdropped || gt_sflag > 1) {
		printf("\t%" PRIu64 " ARP replies tx dropped\n",
		       gt_arps.txrepliesdropped);
	}
	if (gt_arps.rxrequests || gt_sflag > 1) {
		printf("\t%" PRIu64 " ARP requests received\n",
		       gt_arps.rxrequests);
	}
	if (gt_arps.rxreplies || gt_sflag > 1) {
		printf("\t%" PRIu64 " ARP replies received\n",
		       gt_arps.rxreplies);
	}
	if (gt_arps.received || gt_sflag > 1) {
		printf("\t%" PRIu64 " ARP packets received\n",
		       gt_arps.received);
	}
	if (gt_arps.bypassed || gt_sflag > 1) {
		printf("\t%" PRIu64 " ARP packets bypassed\n",
		       gt_arps.bypassed);
	}
	if (gt_arps.filtered || gt_sflag > 1) {
		printf("\t%" PRIu64 " ARP packets filtered\n",
		       gt_arps.filtered);
	}
	if (gt_arps.dropped || gt_sflag > 1) {
		printf("\t%" PRIu64
		       " total packets dropped due to no ARP entry\n",
		       gt_arps.dropped);
	}
	if (gt_arps.timeouts || gt_sflag > 1) {
		printf("\t%" PRIu64 " ARP entries timed out\n",
		       gt_arps.timeouts);
	}
	//	printf("\t%"PRIu64" Duplicate IPs seen\n", gt_arps.dupips);
	return 0;
}

static int
gt_print_ip_stats(void)
{
	gt_get_inet_stats("ip", stat_ip_entries);

	printf("ip:\n");
	if (gt_ips.total || gt_sflag > 1) {
		printf("\t%" PRIu64 " total packets received\n", gt_ips.total);
	}
	if (gt_ips.badsum || gt_sflag > 1) {
		printf("\t%" PRIu64 " bad header checksums\n", gt_ips.badsum);
	}
	if (gt_ips.toosmall || gt_sflag > 1) {
		printf("\t%" PRIu64 " with size smaller than minimum\n",
		       gt_ips.toosmall);
	}
	if (gt_ips.tooshort || gt_sflag > 1) {
		printf("\t%" PRIu64 " with data size < data length\n",
		       gt_ips.tooshort);
	}
	if (gt_ips.toolong || gt_sflag > 1) {
		printf("\t%" PRIu64 " with ip length > max ip packet size\n",
		       gt_ips.toolong);
	}
	if (gt_ips.badhlen || gt_sflag > 1) {
		printf("\t%" PRIu64 " with header length < data size\n",
		       gt_ips.badhlen);
	}
	if (gt_ips.badlen || gt_sflag > 1) {
		printf("\t%" PRIu64 " with data length < header length\n",
		       gt_ips.badlen);
	}
	//	printf("\t%"PRIu64" with bad options\n", gt_ips.badoptions);
	if (gt_ips.badvers || gt_sflag > 1) {
		printf("\t%" PRIu64 " with incorrect version number\n",
		       gt_ips.badvers);
	}
	if (gt_ips.fragments || gt_sflag > 1) {
		printf("\t%" PRIu64 " fragments received\n", gt_ips.fragments);
	}
	if (gt_ips.fragdropped || gt_sflag > 1) {
		printf("\t%" PRIu64
		       " fragments dropped (dup or out of space)\n",
		       gt_ips.fragdropped);
	}
	//	printf("\t%"PRIu64" fragments dropped after timeout\n", gt_ips.fragtimeout);
	//	printf("\t%"PRIu64" packets reassembled ok\n", gt_ips.reassembled);
	if (gt_ips.delivered || gt_sflag > 1) {
		printf("\t%" PRIu64 " packets for this host\n",
		       gt_ips.delivered);
	}
	if (gt_ips.noproto || gt_sflag > 1) {
		printf("\t%" PRIu64
		       " packets for unknown/unsupported protocol\n",
		       gt_ips.noproto);
	}
	if (gt_ips.localout || gt_sflag > 1) {
		printf("\t%" PRIu64 " packets sent from this host\n",
		       gt_ips.localout);
	}
	if (gt_ips.noroute || gt_sflag > 1) {
		printf("\t%" PRIu64
		       " output packets discarded due to no route\n",
		       gt_ips.noroute);
	}
	if (gt_ips.fragmented || gt_sflag > 1) {
		printf("\t%" PRIu64 " output datagrams fragmented\n",
		       gt_ips.fragmented);
	}
	if (gt_ips.cantfrag || gt_sflag > 1) {
		printf("\t%" PRIu64 " datagrams that can't be fragmented\n",
		       gt_ips.cantfrag);
	}
	return 0;
}

static int
gt_print_tcp_stats(void)
{
	int i, first;

	gt_get_inet_stats("tcp", stat_tcp_entries);

	printf("tcp:\n");
	if (gt_tcps.sndtotal || gt_sflag > 1) {
		printf("\t%" PRIu64 " packets sent\n", gt_tcps.sndtotal);
	}
	if (gt_tcps.sndpack || gt_tcps.sndbyte || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " data packets (%" PRIu64 " bytes)\n",
		       gt_tcps.sndpack, gt_tcps.sndbyte);
	}
	if (gt_tcps.sndrexmitpack || gt_tcps.sndrexmitbyte || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " data packets (%" PRIu64
		       " bytes) retransmitted\n",
		       gt_tcps.sndrexmitpack, gt_tcps.sndrexmitbyte);
	}
	//	printf("\t\t%"PRIu64" data packets unnecessarily retransmitted\n", gt_tcps.sndrexmitbad);
	//	printf("\t\t%"PRIu64" resends initiated by MTU discovery\n", gt_tcps.mturesent);
	if (gt_tcps.sndacks || gt_tcps.delack || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " ack-only packets (%" PRIu64
		       " delayed)\n",
		       gt_tcps.sndacks, gt_tcps.delack);
	}
	if (gt_tcps.sndurg || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " URG only packets\n", gt_tcps.sndurg);
	}
	if (gt_tcps.sndprobe || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " window probe packets\n",
		       gt_tcps.sndprobe);
	}
	if (gt_tcps.sndwinup || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " window update packets\n",
		       gt_tcps.sndwinup);
	}
	if (gt_tcps.sndctrl || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " control packets\n", gt_tcps.sndctrl);
	}
	// packets received
	if (gt_tcps.rcvtotal || gt_sflag > 1) {
		printf("\t%" PRIu64 " packets received\n", gt_tcps.rcvtotal);
	}
	if (gt_tcps.rcvackpack || gt_tcps.rcvackbyte || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " acks (for %" PRIu64 " bytes)\n",
		       gt_tcps.rcvackpack, gt_tcps.rcvackbyte);
	}
	if (gt_tcps.rcvdupack || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " duplicate acks\n", gt_tcps.rcvdupack);
	}
	if (gt_tcps.rcvacktoomuch || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " acks for unsent data\n",
		       gt_tcps.rcvacktoomuch);
	}
	if (gt_tcps.rcvpack || gt_tcps.rcvbyte || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " packets (%" PRIu64
		       " bytes) received in-sequence\n",
		       gt_tcps.rcvpack, gt_tcps.rcvbyte);
	}
	if (gt_tcps.rcvduppack || gt_tcps.rcvdupbyte || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " completely duplicate packets (%" PRIu64
		       " bytes)\n",
		       gt_tcps.rcvduppack, gt_tcps.rcvdupbyte);
	}
	if (gt_tcps.pawsdrop || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " old duplicate packets\n",
		       gt_tcps.pawsdrop);
	}
	if (gt_tcps.rcvpartduppack || gt_tcps.rcvpartdupbyte || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " packets with some dup. data (%" PRIu64
		       " bytes duped)\n",
		       gt_tcps.rcvpartduppack, gt_tcps.rcvpartdupbyte);
	}
	if (gt_tcps.rcvoopack || gt_tcps.rcvoobyte || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " out-of-order packets (%" PRIu64
		       " bytes)\n",
		       gt_tcps.rcvoopack, gt_tcps.rcvoobyte);
	}
	if (gt_tcps.rcvpackafterwin || gt_tcps.rcvbyteafterwin ||
	    gt_sflag > 1) {
		printf("\t\t%" PRIu64 " packets (%" PRIu64
		       " bytes) of data after window\n",
		       gt_tcps.rcvpackafterwin, gt_tcps.rcvbyteafterwin);
	}
	if (gt_tcps.rcvwinprobe || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " window probes\n", gt_tcps.rcvwinprobe);
	}
	if (gt_tcps.rcvwinupd || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " window update packets\n",
		       gt_tcps.rcvwinupd);
	}
	if (gt_tcps.rcvafterclose || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " packets received after close\n",
		       gt_tcps.rcvafterclose);
	}
	if (gt_tcps.rcvbadsum || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " discarded for bad checksums\n",
		       gt_tcps.rcvbadsum);
	}
	if (gt_tcps.rcvbadoff || gt_sflag > 1) {
		printf("\t\t%" PRIu64
		       " discarded for bad header offset fields\n",
		       gt_tcps.rcvbadoff);
	}
	if (gt_tcps.rcvshort || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " discarded because packet too short\n",
		       gt_tcps.rcvshort);
	}
	if (gt_tcps.rcvmemdrop || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " discarded due to memory problems\n",
		       gt_tcps.rcvmemdrop);
	}
	// connection requests
	if (gt_tcps.connattempt || gt_sflag > 1) {
		printf("\t%" PRIu64 " connection requests\n",
		       gt_tcps.connattempt);
	}
	if (gt_tcps.accepts || gt_sflag > 1) {
		printf("\t%" PRIu64 " connection accepts\n", gt_tcps.accepts);
	}
	if (gt_tcps.badsyn || gt_sflag > 1) {
		printf("\t%" PRIu64 " bad connection attempts\n",
		       gt_tcps.badsyn);
	}
	if (gt_tcps.listendrop || gt_sflag > 1) {
		printf("\t%" PRIu64 " listen queue overflows\n",
		       gt_tcps.listendrop);
	}
	//	printf("\t%"PRIu64" ignored RSTs in the windows\n", gt_tcps.badrst);
	if (gt_tcps.connects || gt_sflag > 1) {
		printf("\t%" PRIu64
		       " connections established (including accepts)\n",
		       gt_tcps.connects);
	}
	//	printf("\t\t%"PRIu64" times used RTT from hostcache\n", gt_tcps.usedrtt);
	//	printf("\t\t%"PRIu64" times used RTT variance from hostcache\n", gt_tcps.usedrttvar);
	//	printf("\t\t%"PRIu64" times used slow-start threshold from hostcache\n", gt_tcps.usedssthresh);
	if (gt_tcps.closed || gt_tcps.drops || gt_sflag > 1) {
		printf("\t%" PRIu64 " connections closed (including %" PRIu64
		       " drops)\n",
		       gt_tcps.closed, gt_tcps.drops);
	}
	//	printf("\t\t%"PRIu64" connections updated cached RTT on close\n", gt_tcps.cachedrtt);
	//	printf("\t\t%"PRIu64" connections updated cached RTT variance on close\n", gt_tcps.cachedrttvar);
	//	printf("\t\t%"PRIu64" connections updated cached ssthresh on close\n", gt_tcps.cachedssthresh);
	if (gt_tcps.conndrops || gt_sflag > 1) {
		printf("\t%" PRIu64 " embryonic connections dropped\n",
		       gt_tcps.conndrops);
	}
	if (gt_tcps.rttupdated || gt_tcps.segstimed || gt_sflag > 1) {
		printf("\t%" PRIu64 " segments updated rtt (of %" PRIu64
		       " attempts)\n",
		       gt_tcps.rttupdated, gt_tcps.segstimed);
	}
	if (gt_tcps.rexmttimeo || gt_sflag > 1) {
		printf("\t%" PRIu64 " retransmit timeouts\n",
		       gt_tcps.rexmttimeo);
	}
	if (gt_tcps.timeoutdrop || gt_sflag > 1) {
		printf("\t\t%" PRIu64
		       " connections dropped by rexmit timeout\n",
		       gt_tcps.timeoutdrop);
	}
	if (gt_tcps.persisttimeo || gt_sflag > 1) {
		printf("\t%" PRIu64 " persist timeouts\n",
		       gt_tcps.persisttimeo);
	}
	//	printf("\t\t%"PRIu64" connections dropped by persist timeout\n", gt_tcps.persistdrop);
	//	printf("\t%"PRIu64" Connections (fin_wait_2) dropped because of timeout\n", gt_tcps.finwait2_drops);
	if (gt_tcps.keeptimeo || gt_sflag > 1) {
		printf("\t%" PRIu64 " keepalive timeouts\n", gt_tcps.keeptimeo);
	}
	if (gt_tcps.keepprobe || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " keepalive probes sent\n",
		       gt_tcps.keepprobe);
	}
	if (gt_tcps.keepdrops || gt_sflag > 1) {
		printf("\t\t%" PRIu64 " connections dropped by keepalive\n",
		       gt_tcps.keepdrops);
	}
	if (gt_tcps.predack || gt_sflag > 1) {
		printf("\t%" PRIu64 " correct ACK header predictions\n",
		       gt_tcps.predack);
	}
	if (gt_tcps.preddat || gt_sflag > 1) {
		printf("\t%" PRIu64 " correct data packet header predictions\n",
		       gt_tcps.preddat);
	}
	//	// syncache
	//	printf("\t%"PRIu64" syncache entries added\n", gt_tcps.sc_added);
	//	printf("\t\t%"PRIu64" retransmitted\n", gt_tcps.sc_retransmitted);
	//	printf("\t\t%"PRIu64" dupsyn\n", gt_tcps.sc_dupsyn);
	//	printf("\t\t%"PRIu64" dropped\n", gt_tcps.sc_dropped);
	//	printf("\t\t%"PRIu64" completed\n", gt_tcps.sc_completed);
	//	printf("\t\t%"PRIu64" bucket overflow\n", gt_tcps.sc_bucketoverflow);
	//	printf("\t\t%"PRIu64" cache overflow\n", gt_tcps.sc_cacheoverflow);
	//	printf("\t\t%"PRIu64" reset\n", gt_tcps.sc_reset);
	//	printf("\t\t%"PRIu64" stale\n", gt_tcps.sc_stale);
	//	printf("\t\t%"PRIu64" aborted\n", gt_tcps.sc_aborted);
	//	printf("\t\t%"PRIu64" badack\n", gt_tcps.sc_badack);
	//	printf("\t\t%"PRIu64" unreach\n", gt_tcps.sc_unreach);
	//	printf("\t\t%"PRIu64" zone failures\n", gt_tcps.sc_zonefail);
	//	// cookies
	//	printf("\t%"PRIu64" cookies sent\n", gt_tcps.sc_sendcookie);
	//	printf("\t%"PRIu64" cookies received\n", gt_tcps.sc_recvcookie);
	//	printf("\t%"PRIu64" hostcache entries added\n", gt_tcps.hc_added);
	//	printf("\t\t%"PRIu64" bucket overflow\n", gt_tcps.hc_bucketoverflow);
	//	// SACK
	//	printf("\t%"PRIu64" SACK recovery episodes\n", gt_tcps.sack_recovery_episode);
	//	printf("\t%"PRIu64" segment rexmits in SACK recovery episodes\n", gt_tcps.sack_rexmits);
	//	printf("\t%"PRIu64" byte rexmits in SACK recovery episodes\n", gt_tcps.sack_rexmit_bytes);
	//	printf("\t%"PRIu64" SACK options (SACK blocks) received\n", gt_tcps.sack_rcv_blocks);
	//	printf("\t%lu SACK options (SACK blocks) sent\n", gt_tcps.sack_send_blocks);
	//	printf("\t%"PRIu64" SACK scoreboard overflow\n", gt_tcps.sack_sboverflow);
	//	printf("\t%"PRIu64" packets with ECN CE bit set\n", gt_tcps.ecn_ce);
	//	printf("\t%"PRIu64" packets with ECN ECT(0) bit set\n", gt_tcps.ecn_ect0);
	//	printf("\t%"PRIu64" packets with ECN ECT(1) bit set\n", gt_tcps.ecn_ect1);
	//	printf("\t%"PRIu64" successful ECN handshakes\n", gt_tcps.ecn_shs);
	//	printf("\t%"PRIu64" times ECN reduced the congestion window\n", gt_tcps.ecn_rcwnd);
	//	printf("\t%"PRIu64" packets with matching signature received\n", gt_tcps.sig_rcvgoodsig);
	//	printf("\t%"PRIu64" packets with bad signature received\n", gt_tcps.sig_rcvbadsig);
	//	printf("\t%"PRIu64" times failed to make signature due to no SA\n", gt_tcps.sig_err_buildsig);
	//	printf("\t%"PRIu64" times unexpected signature received\n", gt_tcps.sig_err_sigopt);
	//	printf("\t%"PRIu64" times no signature provided by segment\n", gt_tcps.sig_err_nosigopt);
	first = 1;
	for (i = 0; i < GT_TCPS_MAX_STATES; ++i) {
		if (gt_tcps.states[i] || gt_sflag > 1) {
			if (first) {
				first = 0;
				printf("TCP connection count by state:\n");
			}
			printf("\t%" PRIu64 " connections in %s state\n",
			       gt_tcps.states[i], gt_tcpstates[i]);
		}
	}
	return 0;
}

static int
gt_print_udp_stats(void)
{
	u64 delivered;

	gt_get_inet_stats("udp", gt_stat_udp_entries);

	printf("udp:\n");
	if (gt_udps.ipackets || gt_sflag > 1) {
		printf("\t%" PRIu64 " datagrams received\n", gt_udps.ipackets);
	}
	if (gt_udps.hdrops || gt_sflag > 1) {
		printf("\t%" PRIu64 " with incomplete header\n",
		       gt_udps.hdrops);
	}
	if (gt_udps.badlen || gt_sflag > 1) {
		printf("\t%" PRIu64 " with bad data length field\n",
		       gt_udps.badlen);
	}
	if (gt_udps.badsum || gt_sflag > 1) {
		printf("\t%" PRIu64 " with bad checksum\n", gt_udps.badsum);
	}
	if (gt_udps.nosum || gt_sflag > 1) {
		printf("\t%" PRIu64 " with no checksum\n", gt_udps.nosum);
	}
	if (gt_udps.noport || gt_sflag > 1) {
		printf("\t%" PRIu64 " dropped due to no socket\n",
		       gt_udps.noport);
	}
	//	printf("\t%"PRIu64" broadcast/multicast datagrams undelivered\n", gt_udps.noportbcast);
	if (gt_udps.fullsock || gt_sflag > 1) {
		printf("\t%" PRIu64 " dropped due to full socket buffers\n",
		       gt_udps.fullsock);
	}
	//	printf("\t%"PRIu64" not for hashed pcb\n", udpps_pcbhashmiss);
	delivered = gt_udps.ipackets - gt_udps.hdrops - gt_udps.badlen -
		    gt_udps.badsum - gt_udps.noport -
		    //	            gt_udps.noportbcast -
		    gt_udps.fullsock;
	if (delivered || gt_sflag > 1) {
		printf("\t%" PRIu64 " delivered\n", delivered);
	}
	if (gt_udps.opackets || gt_sflag > 1) {
		printf("\t%" PRIu64 " datagrams output\n", gt_udps.opackets);
	}
	return 0;
}

static void
gt_print_stats(void)
{
	int rc;

	if (GT_FLAG_ISSET(gt_proto_mask, GT_PROTO_FLAG_ARP)) {
		rc = gt_print_arp_stats();
		if (rc) {
			return;
		}
	}
	if (GT_FLAG_ISSET(gt_proto_mask, GT_PROTO_FLAG_IP)) {
		rc = gt_print_ip_stats();
		if (rc) {
			return;
		}
	}
	if (GT_FLAG_ISSET(gt_proto_mask, GT_PROTO_FLAG_TCP)) {
		rc = gt_print_tcp_stats();
		if (rc) {
			return;
		}
	}

	if (GT_FLAG_ISSET(gt_proto_mask, GT_PROTO_FLAG_UDP)) {
		rc = gt_print_udp_stats();
		if (rc) {
			return;
		}
	}
}

static void
gt_usage(void)
{
	printf("%s",
	       "Usage: netstat [-aln] [--tcp] [--udp] [--ip]\n"
	       "       netstat -s [-z] [--tcp] [--udp] [--ip] [--arp]\n"
	       "       netstat {-i|-I interface} [-Hb] [-w wait]\n"
	       "\n"
	       "\t-h   Print this help\n"
	       "\t-a   Display all sockets (default: connected)\n"
	       "\t-l   Display listening server sockets\n"
	       "\t-n   Don't resolve names\n"
	       "\t-z   Zero statistics\n"
	       "\t-H   Display interface statistics in human readable form\n"
	       "\t-b   Display bytes interface statistics\n"
	       "\t-w   Repet interval in seconds for interface statistics\n");
}

struct option long_opts[] = {
	{ "ip", no_argument, 0, 0 },
	{ "udp", no_argument, 0, 0 },
	{ "tcp", no_argument, 0, 0 },
	{ "arp", no_argument, 0, 0 },
};

int
main(int argc, char **argv)
{
	u8 iflag;
	int rc, opt, long_opt;
	const char *long_opt_name;

	// TODO: not good name
	// Not a worker: no service slot, no shared memory — all further
	// allocations (API, protobuf) come from the system heap via
	// gt_get_allocator().
	rc = gt_utility_init();
	if (rc) {
		errx(1, "init failed (%s)", strerror(-rc));
	}

	while ((opt = getopt_long(argc, argv, "valnszI:iHbw:", long_opts,
				  &long_opt)) != -1) {
		switch (opt) {
		case 0:
			long_opt_name = long_opts[long_opt].name;
			if (!strcmp(long_opt_name, "arp")) {
				gt_proto_mask |= GT_PROTO_FLAG_ARP;
			} else if (!strcmp(long_opt_name, "ip")) {
				gt_proto_mask |= GT_PROTO_FLAG_IP;
			} else if (!strcmp(long_opt_name, "tcp")) {
				gt_proto_mask |= GT_PROTO_FLAG_TCP;
			} else if (!strcmp(long_opt_name, "tcp")) {
				gt_proto_mask |= GT_PROTO_FLAG_UDP;
			}
			break;

		case 'h':
			gt_usage();
			return 0;

		case 'a':
			gt_aflag = 1;
			break;

		case 'l':
			gt_lflag = 1;
			break;

		case 'n':
			gt_nflag++;
			break;

		case 's':
			gt_sflag++;
			break;

		case 'z':
			gt_zflag = 1;
			break;

		case 'I':
			iflag = 1;
			gt_interface_name = optarg;
			break;

		case 'i':
			iflag = 1;
			break;

		case 'H':
			gt_Hflag = 1;
			break;

		case 'b':
			gt_bflag = 1;
			break;

		case 'w':
			gt_interval = atoi(optarg);
			iflag = 1;
			break;
		}
	}

	if (gt_proto_mask == 0) {
		gt_proto_mask = GT_PROTO_FLAG_ALL;
	}

	if (iflag) {
		if (gt_interval) {
			gt_print_interfaces_rate();
		} else {
			gt_print_interfaces();
		}
	} else if (gt_sflag) {
		gt_print_stats();
	} else {
		gt_print_sockets();
	}

	return 0;
}
