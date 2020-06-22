#include <stdio.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <getopt.h>
#include <netdb.h>
#include <sys/queue.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <gbtcp/gbtcp.h>

typedef uint32_t be32_t;
typedef uint16_t be16_t;

struct interface {
	LIST_ENTRY(interface) list;
	char ifname[IFNAMSIZ];
	unsigned long long ipackets;
	unsigned long long idrops;
	unsigned long long ibytes;
	unsigned long long opackets;
	unsigned long long odrops;
	unsigned long long obytes;
};

LIST_HEAD(interface_head, interface);

#define PROTO_FLAG_ARP (1 << 0)
#define PROTO_FLAG_IP (1 << 1)
#define PROTO_FLAG_TCP (1 << 2) 
#define PROTO_FLAG_UDP (1 << 3)
#define PROTO_FLAG_ALL 0xffffffff

static const char *tcpstates[GT_TCP_NSTATES] = {
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

int aflag;
int bflag;
int Hflag;
int iflag;
int lflag;
int nflag;
int sflag;
int zflag;
int proto_mask;
int interval;
char *interface;

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define dbg gt_dbg

static char *
strzcpy(char *dest, const char *src, size_t n)
{
	size_t i;

	for (i = 0; i < n; ++i) {
		dest[i] = src[i];
		if (dest[i] == '\0') {
			break;
		}
	}
	dest[i] = '\0';
	return dest;
}

int
xsysctl(const char *path, char *old, const char *new)
{
	int rc;

	rc = gt_sysctl(path, old, new);
	if (rc < 0) {
		rc = -gt_errno;
		warnx("gt_sysctl('%s') failed (%s)", path, strerror(-rc));
	} else if (rc > 0) {
		warnx("gt_sysctl('%s') error (%s)", path, strerror(rc));		
	}
	return rc;
}

static void *
xmalloc(int size)
{
	void *ptr;

	ptr = malloc(size);
	if (ptr == NULL) {
		errx(1, "malloc(%d) failed", size);
	}
	return ptr;
}

static char *
inetname(be32_t addr)
{
	char *cp;
	struct in_addr in;
	struct hostent *hp;
	static char line[256];

	cp = 0;
	if (nflag == 0 && addr != INADDR_ANY) {		
		hp = gethostbyaddr((char *)&addr, sizeof(addr), AF_INET);
		if (hp) {
			cp = hp->h_name;
			//trimdomain(cp, strlen(cp));
		}
	}
	if (addr == INADDR_ANY)
		strcpy(line, "*");
	else if (cp) {
		strzcpy(line, cp, sizeof(line));
	} else {
		in.s_addr = addr;
		strzcpy(line, inet_ntoa(in), sizeof(line));
	}
	return line;
}

static void
print_sockaddr(be32_t addr, be16_t port, const char *proto_name)
{
	struct servent *sp = 0;
	char line[80], *cp;
	int width;
	int alen;

	snprintf(line, sizeof(line), "%.*s.", 16, inetname(addr));
	alen = strlen(line);
	cp = line + alen;
	if (nflag < 2 && port) {
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

static void
bad_format(const char *path, const char *data)
{
	warnx("sysctl('%s') bad format: '%s'", path, data);
}

int
sysctl_list_foreach(const char *path, void *udata,
	int (*fn)(const char *, void *, const char *))
{
	int rc, len;
	char pbuf[PATH_MAX];
	char vbuf[GT_SYSCTL_BUFSIZ];

	rc = xsysctl(path, vbuf, NULL);
	while (rc == 0 && vbuf[0] == ',') {
		len = snprintf(pbuf, sizeof(pbuf), "%s.%s", path, vbuf + 1);
		if (len + 1 >= sizeof(pbuf)) {
			return -ENAMETOOLONG;
		}
		rc = xsysctl(pbuf, vbuf, NULL);
		if (rc == 0) {
			rc = (*fn)(path, udata, vbuf);
			if (rc) {
				break;
			}
		}
		pbuf[len++] = '+';
		pbuf[len] = '\0';
		rc = xsysctl(pbuf, vbuf, NULL);
	}
	return rc;
}

// Interfaces
static void
print_interface_stat(int width, unsigned long long value)
{
	if (0 && Hflag) {
		// TODO: Print statistics in human readable form
	} else {
		printf(" %*llu", width, value);
	}
}

static void
print_interface_banner()
{
	printf("%-*.*s", 16, 16, "Name");
	printf(" %12.12s %12.12s", "Ipkts", "Idrop");
	if (bflag) {
		printf(" %14.14s", "Ibytes");
	}
	printf(" %12.12s %12.12s", "Opkts", "Odrop");
	if (bflag) {
		printf(" %14.14s", "Obytes");
	}
	printf("\n");
}

static void
print_interface(struct interface *ifp)
{
	char name[IFNAMSIZ];

	strzcpy(name, ifp->ifname, sizeof(name));
	printf("%-*.*s", 16, 16, name);
	print_interface_stat(12, ifp->ipackets);
	print_interface_stat(12, ifp->idrops);
	if (bflag) {
		print_interface_stat(14, ifp->ibytes);
	}
	print_interface_stat(12, ifp->opackets);
	print_interface_stat(12, ifp->odrops);
	if (bflag) {
		print_interface_stat(14, ifp->obytes);
	}
	printf("\n");
}

static struct interface *
get_interface(struct interface_head *head, const char *ifname)
{
	struct interface *ifp;

	LIST_FOREACH(ifp, head, list) {
		if (!strcmp(ifp->ifname, ifname)) {
			return ifp;
		}
	}
	return NULL;
}

static int
sysctl_route_if(const char *path, void *udata, const char *buf)
{
	int rc, tmpd, tmpx;
	char ifname[64], tmp32[32];
	unsigned long long ipackets, idrops, ibytes;
	unsigned long long opackets, odrops, obytes;
	struct interface *ifp;
	struct interface_head *head;

	head = udata;
	rc = sscanf(buf, "%64[^,],%d,%x,%32[^,],%llu,%llu,%llu,%llu,%llu,%llu",
	            ifname, &tmpd, &tmpx, tmp32,
	            &ipackets, &idrops, &ibytes, &opackets, &odrops, &obytes);
	if (rc != 10) {
		bad_format(path, buf);
		return -EPROTO;
	}
	if (interface != NULL && strcmp(interface, ifname)) {
		return 0;
	}
	ifp = get_interface(head, ifname);
	if (ifp == NULL) {
		ifp = xmalloc(sizeof(*ifp));
		memset(ifp, 0, sizeof(*ifp));
		strzcpy(ifp->ifname, ifname, sizeof(ifp->ifname));
		LIST_INSERT_HEAD(head, ifp, list);
	}
	ifp->ipackets += ipackets;
	ifp->idrops += idrops;
	ifp->ibytes += ibytes;
	ifp->opackets += opackets;
	ifp->odrops += odrops;
	ifp->obytes += obytes;
	return 0;
}

static void
free_interface_list(struct interface_head *head)
{
	struct interface *ifp;

	while (!LIST_EMPTY(head)) {
		ifp = LIST_FIRST(head);
		LIST_REMOVE(ifp, list);
		free(ifp);
	}
}

static int
alloc_interface_list(struct interface_head *head)
{
	int rc;

	LIST_INIT(head);
	rc = sysctl_list_foreach(GT_SYSCTL_ROUTE_IF_LIST, head,
		                 sysctl_route_if);
	if (rc) {
		free_interface_list(head);
	}
	return rc;
	
}

static int
get_interfaces_stat(struct interface *stat)
{
	int n, rc;
	struct interface *ifp;
	struct interface_head head;

	memset(stat, 0, sizeof(*stat));
	n = 0;
	rc = alloc_interface_list(&head);
	if (rc) {
		return rc;
	}
	LIST_FOREACH(ifp, &head, list) {
		if (n == 0) {
			strzcpy(stat->ifname, ifp->ifname,
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
		strzcpy(stat->ifname, "Total", sizeof(stat->ifname));
	}
	free_interface_list(&head);
	return 0;
}

static void
print_interfaces_rate()
{
	int n, rc;
	struct interface if2[2], *new, *old, *tmp, diff;

	n = 0;
	new = &if2[0];
	old = &if2[1];
	rc = get_interfaces_stat(old);
	if (rc) {
		return;
	}
	print_interface_banner();
	while (1) {
		sleep(interval);
		n++;
		rc = get_interfaces_stat(new);
		if (rc) {
			return;
		}
		strzcpy(diff.ifname, new->ifname, sizeof(diff.ifname));
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
print_interfaces()
{
	int rc;
	struct interface *ifp;
	struct interface_head head;

	rc = alloc_interface_list(&head);
	if (rc) {
		return;
	}
	if (!LIST_EMPTY(&head)) {
		print_interface_banner();
		LIST_FOREACH(ifp, &head, list) {
			print_interface(ifp);
		}
	}
	free_interface_list(&head);
}

// sockets
static int
ipproto_is_filtered(int ipproto)
{
	if (proto_mask & PROTO_FLAG_IP) {
		return 0;
	} else if (ipproto == IPPROTO_UDP) {
		return !(proto_mask & PROTO_FLAG_UDP);
	} else if (ipproto == IPPROTO_TCP) {
		return !(proto_mask & PROTO_FLAG_TCP);
	} else {
		return 1;
	}
}

static int
print_socket(const char *path, void *udata, const char *buf)
{
	int rc, fd, pid, ipproto, state;
	uint32_t laddr, faddr;
	uint16_t lport, fport;
	const char *proto_name;

	rc = sscanf(buf,
	            "%d,%d,%d,%d,"
	            "%x,%hu,"
	            "%x,%hu",
	            &fd, &pid, &ipproto, &state,
	            &laddr, &lport,
	            &faddr, &fport);
	if (rc != 8) {
		bad_format(path, buf);
		return -EPROTO;
	}
	rc = ipproto_is_filtered(ipproto);
	if (rc) {
		return 0;
	}
	laddr = htonl(laddr);
	faddr = htonl(faddr);
	lport = htons(lport);
	fport = htons(fport);
	proto_name = ipproto == IPPROTO_TCP ? "tcp" : "udp";
	printf("%-5.5s ", proto_name);
	print_sockaddr(laddr, lport, proto_name);
	print_sockaddr(faddr, fport, proto_name);
	if (ipproto == IPPROTO_TCP) {
		if (state >= GT_TCP_NSTATES) {
			printf("%-11d ", state);
		} else {
			printf("%-11s ", tcpstates[state]);
		}
	} else {
		printf("%-11s ", "           ");
	}
	printf("%-7d\n", pid);
	return 0;
}

static void
print_sockets()
{
	printf("Active Internet connections");
	if (aflag) {
		printf(" (including servers)");
	} else if (lflag) {
		printf(" (only servers)");	
	}
	printf("\n%-5.5s %-22.22s %-22.22s %-11.11s %-7.7s\n",
	       "Proto", "Local Address", "Foreign Address", "State", "PID");
	sysctl_list_foreach(GT_SYSCTL_SOCKET_ATTACHED_LIST, NULL, print_socket);
	sysctl_list_foreach(GT_SYSCTL_SOCKET_BINDED_LIST, NULL, print_socket);
}

// stats
struct stat_entry {
	const char *name;
	unsigned long long *ptr;
};

#define MYX(n) unsigned long long n;
struct tcp_stat {
	GT_TCP_STAT(MYX);
	unsigned long long states[GT_TCP_NSTATES];
};

struct udp_stat {
	GT_UDP_STAT(MYX);
};

struct ip_stat {
	GT_IP_STAT(MYX);
};

struct arp_stat {
	GT_ARP_STAT(MYX);
};
#undef MYX

struct tcp_stat tcps;
struct udp_stat udps;
struct ip_stat ips;
struct arp_stat arps;

#define MYX(n) { .name = #n, .ptr = &tcps.n },
#define STATE(i) { .name = "states." #i, .ptr = tcps.states + i },
struct stat_entry stat_tcp_entries[] = {
	GT_TCP_STAT(MYX)
	STATE(0)
	STATE(1)
	STATE(2)
	STATE(3)
	STATE(4)
	STATE(5)
	STATE(6)
	STATE(7)
	STATE(8)
	STATE(9)
	STATE(10)
	{ NULL, NULL }
};
#undef MYX

#define MYX(n) { .name = #n, .ptr = &udps.n },
struct stat_entry stat_udp_entries[] = {
	GT_UDP_STAT(MYX)
	{ NULL, NULL }
};
#undef MYX

#define MYX(n) { .name = #n, .ptr = &ips.n },
struct stat_entry stat_ip_entries[] = {
	GT_IP_STAT(MYX)
	{ NULL, NULL }
};
#undef MYX

#define MYX(n) { .name = #n, .ptr = &arps.n },
struct stat_entry stat_arp_entries[] = {
	GT_ARP_STAT(MYX)
	{ NULL, NULL }
};
#undef MYX

static int
sysctl_inet_stat(const char *name, struct stat_entry *e)
{
	int rc;
	char *endptr;
	char path[PATH_MAX];
	char buf[GT_SYSCTL_BUFSIZ];

	snprintf(path, sizeof(path), "inet.stat.%s.%s", name, e->name);
	rc = xsysctl(path, buf, zflag ? "0" : NULL);
	if (rc) {
		*e->ptr = 0;
		return rc;
	}
	*e->ptr += strtoul(buf, &endptr, 10);
	if (*endptr != '\0') {
		*e->ptr = 0;
		return -EINVAL;
	}
	return 0;
}

static int
sysctl_inet_stats(const char *name, struct stat_entry *entries)
{
	int rc;
	struct stat_entry *e;

	rc = 0;
	for (e = entries; e->name != NULL; ++e) {
		rc = sysctl_inet_stat(name, e);
		if (rc) {
			break;
		}
	}
	return rc;
}

static int
print_arp_stats()
{
	int rc;

	rc = sysctl_inet_stats("arp", stat_arp_entries);
	if (rc) {
		return rc;
	}
	printf("arp:\n");
	if (arps.txrequests || sflag > 1) {
		printf("\t%llu ARP requests sent\n", arps.txrequests);
	}
	if (arps.txreplies || sflag > 1) {
		printf("\t%llu ARP replies sent\n", arps.txreplies);
	}
	if (arps.txrepliesdropped || sflag > 1) {
		printf("\t%llu ARP replies tx dropped\n",
		       arps.txrepliesdropped);
	}
	if (arps.rxrequests || sflag > 1) {
		printf("\t%llu ARP requests received\n", arps.rxrequests);
	}
	if (arps.rxreplies || sflag > 1) {
		printf("\t%llu ARP replies received\n", arps.rxreplies);
	}
	if (arps.received || sflag > 1) {
		printf("\t%llu ARP packets received\n", arps.received);
	}
	if (arps.bypassed || sflag > 1) {
		printf("\t%llu ARP packets bypassed\n", arps.bypassed);
	}
	if (arps.filtered || sflag > 1) {
		printf("\t%llu ARP packets filtered\n", arps.filtered);
	}
	if (arps.dropped || sflag > 1) {
		printf("\t%llu total packets dropped due to no ARP entry\n",
		       arps.dropped);
	}
	if (arps.timeouts || sflag > 1) {
		printf("\t%llu ARP entries timed out\n", arps.timeouts);
	}
//	printf("\t%llu Duplicate IPs seen\n", arps.dupips);
	return 0;
}

static int
print_ip_stats()
{
	int rc;

	rc = sysctl_inet_stats("ip", stat_ip_entries);
	if (rc) {
		return rc;
	}
	printf("ip:\n");
	if (ips.total || sflag > 1) {
		printf("\t%llu total packets received\n", ips.total);
	}
	if (ips.badsum || sflag > 1) {
		printf("\t%llu bad header checksums\n", ips.badsum);
	}
	if (ips.toosmall || sflag > 1) {
		printf("\t%llu with size smaller than minimum\n",
		       ips.toosmall);
	}
	if (ips.tooshort || sflag > 1) {
		printf("\t%llu with data size < data length\n", ips.tooshort);
	}
	if (ips.toolong || sflag > 1) {
		printf("\t%llu with ip length > max ip packet size\n",
		       ips.toolong);
	}
	if (ips.badhlen || sflag > 1) {
		printf("\t%llu with header length < data size\n", ips.badhlen);
	}
	if (ips.badlen || sflag > 1) {
		printf("\t%llu with data length < header length\n",
		       ips.badlen);
	}
//	printf("\t%llu with bad options\n", ips.badoptions);
	if (ips.badvers || sflag > 1) {
		printf("\t%llu with incorrect version number\n", ips.badvers);
	}
	if (ips.fragments || sflag > 1) {
		printf("\t%llu fragments received\n", ips.fragments);
	}
	if (ips.fragdropped || sflag > 1) {
		printf("\t%llu fragments dropped (dup or out of space)\n",
		       ips.fragdropped);
	}
//	printf("\t%llu fragments dropped after timeout\n", ips.fragtimeout);
//	printf("\t%llu packets reassembled ok\n", ips.reassembled);
	if (ips.delivered || sflag > 1) {
		printf("\t%llu packets for this host\n", ips.delivered);
	}
	if (ips.noproto || sflag > 1) {
		printf("\t%llu packets for unknown/unsupported protocol\n",
		       ips.noproto);
	}
	if (ips.localout || sflag > 1) {
		printf("\t%llu packets sent from this host\n", ips.localout);
	}
	if (ips.noroute || sflag > 1) {
		printf("\t%llu output packets discarded due to no route\n",
		       ips.noroute);
	}
	if (ips.fragmented || sflag > 1) {
		printf("\t%llu output datagrams fragmented\n", ips.fragmented);
	}
	if (ips.cantfrag || sflag > 1) {
		printf("\t%llu datagrams that can't be fragmented\n",
		       ips.cantfrag);
	}
	return 0;
}

static int
print_tcp_stats()
{
	int i, rc, first;

	rc = sysctl_inet_stats("tcp", stat_tcp_entries);
	if (rc) {
		return rc;
	}
	printf("tcp:\n");
	if (tcps.sndtotal || sflag > 1) {
		printf("\t%llu packets sent\n",	tcps.sndtotal);
	}
	if (tcps.sndpack || tcps.sndbyte || sflag > 1) {
		printf("\t\t%llu data packets (%llu bytes)\n",
		       tcps.sndpack, tcps.sndbyte);
	}
	if (tcps.sndrexmitpack || tcps.sndrexmitbyte ||sflag > 1) {
		printf("\t\t%llu data packets (%llu bytes) retransmitted\n",
		       tcps.sndrexmitpack, tcps.sndrexmitbyte);
	}
//	printf("\t\t%llu data packets unnecessarily retransmitted\n", tcps.sndrexmitbad);
//	printf("\t\t%llu resends initiated by MTU discovery\n", tcps.mturesent);
	if (tcps.sndacks || tcps.delack || sflag > 1) {
		printf("\t\t%llu ack-only packets (%llu delayed)\n",
		       tcps.sndacks, tcps.delack);
	}
	if (tcps.sndurg || sflag > 1) {
		printf("\t\t%llu URG only packets\n", tcps.sndurg);
	}
	if (tcps.sndprobe || sflag > 1) {
		printf("\t\t%llu window probe packets\n", tcps.sndprobe);
	}
	if (tcps.sndwinup || sflag > 1) {
		printf("\t\t%llu window update packets\n", tcps.sndwinup);
	}
	if (tcps.sndctrl || sflag > 1) {
		printf("\t\t%llu control packets\n", tcps.sndctrl);
	}
	// packets received
	if (tcps.rcvtotal || sflag > 1) {
		printf("\t%llu packets received\n", tcps.rcvtotal);
	}
	if (tcps.rcvackpack || tcps.rcvackbyte || sflag > 1) {
		printf("\t\t%llu acks (for %llu bytes)\n",
		       tcps.rcvackpack, tcps.rcvackbyte);
	}
	if (tcps.rcvdupack || sflag > 1) {
		printf("\t\t%llu duplicate acks\n", tcps.rcvdupack);
	}
	if (tcps.rcvacktoomuch || sflag > 1) {
		printf("\t\t%llu acks for unsent data\n", tcps.rcvacktoomuch);
	}
	if (tcps.rcvpack || tcps.rcvbyte || sflag > 1) {
		printf("\t\t%llu packets (%llu bytes) received in-sequence\n",
		       tcps.rcvpack, tcps.rcvbyte);
	}
	if (tcps.rcvduppack || tcps.rcvdupbyte || sflag > 1) {
		printf("\t\t%llu completely duplicate packets (%llu bytes)\n",
		       tcps.rcvduppack, tcps.rcvdupbyte);
	}
	if (tcps.pawsdrop || sflag > 1) {
		printf("\t\t%llu old duplicate packets\n", tcps.pawsdrop);
	}
	if (tcps.rcvpartduppack || tcps.rcvpartdupbyte || sflag > 1) {
		printf("\t\t%llu packets with some dup. data (%llu bytes duped)\n",
		       tcps.rcvpartduppack, tcps.rcvpartdupbyte);
	}
	if (tcps.rcvoopack || tcps.rcvoobyte || sflag > 1) {
		printf("\t\t%llu out-of-order packets (%llu bytes)\n",
		       tcps.rcvoopack, tcps.rcvoobyte);
	}
	if (tcps.rcvpackafterwin || tcps.rcvbyteafterwin || sflag > 1) {
		printf("\t\t%llu packets (%llu bytes) of data after window\n",
		       tcps.rcvpackafterwin, tcps.rcvbyteafterwin);
	}
	if (tcps.rcvwinprobe || sflag > 1) {
		printf("\t\t%llu window probes\n", tcps.rcvwinprobe);
	}
	if (tcps.rcvwinupd || sflag > 1) {
		printf("\t\t%llu window update packets\n", tcps.rcvwinupd);
	}
	if (tcps.rcvafterclose || sflag > 1) {
		printf("\t\t%llu packets received after close\n",
		       tcps.rcvafterclose);
	}
	if (tcps.rcvbadsum || sflag > 1) {
		printf("\t\t%llu discarded for bad checksums\n",
		       tcps.rcvbadsum);
	}
	if (tcps.rcvbadoff || sflag > 1) {
		printf("\t\t%llu discarded for bad header offset fields\n",
		       tcps.rcvbadoff);
	}
	if (tcps.rcvshort || sflag > 1) {
		printf("\t\t%llu discarded because packet too short\n",
		       tcps.rcvshort);
	}
	if (tcps.rcvmemdrop || sflag > 1) {
		printf("\t\t%llu discarded due to memory problems\n",
		       tcps.rcvmemdrop);
	}
	// connection requests
	if (tcps.connattempt || sflag > 1) {
		printf("\t%llu connection requests\n", tcps.connattempt);
	}
	if (tcps.accepts || sflag > 1) {
		printf("\t%llu connection accepts\n", tcps.accepts);
	}
	if (tcps.badsyn || sflag > 1) {
		printf("\t%llu bad connection attempts\n", tcps.badsyn);
	}
	if (tcps.listendrop || sflag > 1) {
		printf("\t%llu listen queue overflows\n", tcps.listendrop);
	}
//	printf("\t%llu ignored RSTs in the windows\n", tcps.badrst);
	if (tcps.connects || sflag > 1) {
		printf("\t%llu connections established (including accepts)\n",
		       tcps.connects);
	}
//	printf("\t\t%llu times used RTT from hostcache\n", tcps.usedrtt);
//	printf("\t\t%llu times used RTT variance from hostcache\n", tcps.usedrttvar);
//	printf("\t\t%llu times used slow-start threshold from hostcache\n", tcps.usedssthresh);
	if (tcps.closed || tcps.drops || sflag > 1) {
		printf("\t%llu connections closed (including %llu drops)\n",
		       tcps.closed, tcps.drops);
	}
//	printf("\t\t%llu connections updated cached RTT on close\n", tcps.cachedrtt);
//	printf("\t\t%llu connections updated cached RTT variance on close\n", tcps.cachedrttvar);
//	printf("\t\t%llu connections updated cached ssthresh on close\n", tcps.cachedssthresh);
	if (tcps.conndrops || sflag > 1) {
		printf("\t%llu embryonic connections dropped\n",
		       tcps.conndrops);
	}
	if (tcps.rttupdated || tcps.segstimed || sflag > 1) {
		printf("\t%llu segments updated rtt (of %llu attempts)\n",
		       tcps.rttupdated, tcps.segstimed);
	}
	if (tcps.rexmttimeo || sflag > 1) {
		printf("\t%llu retransmit timeouts\n", tcps.rexmttimeo);
	}
	if (tcps.timeoutdrop || sflag > 1) {
		printf("\t\t%llu connections dropped by rexmit timeout\n",
		       tcps.timeoutdrop);
	}
	if (tcps.persisttimeo || sflag > 1) {
		printf("\t%llu persist timeouts\n", tcps.persisttimeo);
	}
//	printf("\t\t%llu connections dropped by persist timeout\n", tcps.persistdrop);
//	printf("\t%llu Connections (fin_wait_2) dropped because of timeout\n", tcps.finwait2_drops);
	if (tcps.keeptimeo || sflag > 1) {
		printf("\t%llu keepalive timeouts\n", tcps.keeptimeo);
	}
	if (tcps.keepprobe || sflag > 1) {
		printf("\t\t%llu keepalive probes sent\n", tcps.keepprobe);
	}
	if (tcps.keepdrops || sflag > 1) {
		printf("\t\t%llu connections dropped by keepalive\n",
		       tcps.keepdrops);
	}
	if (tcps.predack || sflag > 1) {
		printf("\t%llu correct ACK header predictions\n",
		       tcps.predack);
	}
	if (tcps.preddat || sflag > 1) {
		printf("\t%llu correct data packet header predictions\n",
		       tcps.preddat);
	}
//	// syncache
//	printf("\t%llu syncache entries added\n", tcps.sc_added);
//	printf("\t\t%llu retransmitted\n", tcps.sc_retransmitted);
//	printf("\t\t%llu dupsyn\n", tcps.sc_dupsyn);
//	printf("\t\t%llu dropped\n", tcps.sc_dropped); 
//	printf("\t\t%llu completed\n", tcps.sc_completed);
//	printf("\t\t%llu bucket overflow\n", tcps.sc_bucketoverflow);
//	printf("\t\t%llu cache overflow\n", tcps.sc_cacheoverflow);
//	printf("\t\t%llu reset\n", tcps.sc_reset);
//	printf("\t\t%llu stale\n", tcps.sc_stale);
//	printf("\t\t%llu aborted\n", tcps.sc_aborted);
//	printf("\t\t%llu badack\n", tcps.sc_badack);
//	printf("\t\t%llu unreach\n", tcps.sc_unreach);
//	printf("\t\t%llu zone failures\n", tcps.sc_zonefail);
//	// cookies
//	printf("\t%llu cookies sent\n", tcps.sc_sendcookie);
//	printf("\t%llu cookies received\n", tcps.sc_recvcookie);
//	printf("\t%llu hostcache entries added\n", tcps.hc_added);
//	printf("\t\t%llu bucket overflow\n", tcps.hc_bucketoverflow);
//	// SACK
//	printf("\t%llu SACK recovery episodes\n", tcps.sack_recovery_episode);
//	printf("\t%llu segment rexmits in SACK recovery episodes\n", tcps.sack_rexmits);
//	printf("\t%llu byte rexmits in SACK recovery episodes\n", tcps.sack_rexmit_bytes);
//	printf("\t%llu SACK options (SACK blocks) received\n", tcps.sack_rcv_blocks);
//	printf("\t%lu SACK options (SACK blocks) sent\n", tcps.sack_send_blocks);
//	printf("\t%llu SACK scoreboard overflow\n", tcps.sack_sboverflow);
//	printf("\t%llu packets with ECN CE bit set\n", tcps.ecn_ce);
//	printf("\t%llu packets with ECN ECT(0) bit set\n", tcps.ecn_ect0);
//	printf("\t%llu packets with ECN ECT(1) bit set\n", tcps.ecn_ect1);
//	printf("\t%llu successful ECN handshakes\n", tcps.ecn_shs);
//	printf("\t%llu times ECN reduced the congestion window\n", tcps.ecn_rcwnd);
//	printf("\t%llu packets with matching signature received\n", tcps.sig_rcvgoodsig);
//	printf("\t%llu packets with bad signature received\n", tcps.sig_rcvbadsig);
//	printf("\t%llu times failed to make signature due to no SA\n", tcps.sig_err_buildsig);
//	printf("\t%llu times unexpected signature received\n", tcps.sig_err_sigopt);
//	printf("\t%llu times no signature provided by segment\n", tcps.sig_err_nosigopt);
	first = 1;
	for (i = 0; i < GT_TCP_NSTATES; ++i) {
		if (tcps.states[i] || sflag > 1) {
			if (first) {
				first = 0;
				printf("TCP connection count by state:\n");
			}
			printf("\t%llu connections in %s state\n",
			       tcps.states[i], tcpstates[i]);
		}
	}
	return 0;
}

static int
print_udp_stats()
{
	int rc;
	unsigned long long delivered;

	rc = sysctl_inet_stats("udp", stat_udp_entries);
	if (rc) {
		return rc;
	}
	printf("udp:\n");
	if (udps.ipackets || sflag > 1) {
		printf("\t%llu datagrams received\n", udps.ipackets);
	}
	if (udps.hdrops || sflag > 1) {
		printf("\t%llu with incomplete header\n", udps.hdrops);
	}
	if (udps.badlen || sflag > 1) {
		printf("\t%llu with bad data length field\n", udps.badlen);
	}
	if (udps.badsum || sflag > 1) {
		printf("\t%llu with bad checksum\n", udps.badsum);
	}
	if (udps.nosum || sflag > 1) {
		printf("\t%llu with no checksum\n", udps.nosum);
	}
	if (udps.noport || sflag > 1) {
		printf("\t%llu dropped due to no socket\n", udps.noport);
	}
//	printf("\t%llu broadcast/multicast datagrams undelivered\n", udps.noportbcast);
	if (udps.fullsock || sflag > 1) {
		printf("\t%llu dropped due to full socket buffers\n",
		       udps.fullsock);
	}
//	printf("\t%llu not for hashed pcb\n", udpps_pcbhashmiss);
	delivered = udps.ipackets -
	            udps.hdrops -
	            udps.badlen -
	            udps.badsum -
	            udps.noport -
//	            udps.noportbcast -
	            udps.fullsock;
	if (delivered || sflag > 1) {
		printf("\t%llu delivered\n", delivered);
	}
	if (udps.opackets || sflag > 1) {
		printf("\t%llu datagrams output\n", udps.opackets);
	}
	return 0;
}

static void
print_stats()
{
	int rc;

	if (proto_mask & PROTO_FLAG_ARP) {
		rc = print_arp_stats();
		if (rc) {
			return;
		}
	}
	if (proto_mask & PROTO_FLAG_IP) {
		rc = print_ip_stats();
		if (rc) {
			return;
		}
	}
	if (proto_mask & PROTO_FLAG_TCP) {
		rc = print_tcp_stats();
		if (rc) {
			return;
		}
	}
	if (proto_mask & PROTO_FLAG_UDP) {
		rc = print_udp_stats();
		if (rc) {
			return;
		}
	}
}

static void
usage(void)
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
	"\t-w   Repet interval in seconds for interface statistics\n"
	);
}

struct option long_opts[] = {
	{ "ip",  no_argument, 0, 0 },
	{ "udp", no_argument, 0, 0 },
	{ "tcp", no_argument, 0, 0 },
	{ "arp", no_argument, 0, 0 },
};

int
main(int argc, char **argv)
{
	const char *long_opt_name;
	int opt, long_opt;

	gt_init("netstat", LOG_ERR);
	gt_preload_passthru = 1;
	while ((opt = getopt_long(argc, argv, "halnszI:iHbw:",
	                          long_opts, &long_opt)) != -1) {
		switch(opt) {
		case 0:
			long_opt_name = long_opts[long_opt].name;
			if (!strcmp(long_opt_name, "arp")) {
				proto_mask |= PROTO_FLAG_ARP;
			} else if (!strcmp(long_opt_name, "ip")) {
				proto_mask |= PROTO_FLAG_IP;
			} else if (!strcmp(long_opt_name, "tcp")) {
				proto_mask |= PROTO_FLAG_TCP;
			} else if (!strcmp(long_opt_name, "tcp")) {
				proto_mask |= PROTO_FLAG_UDP;
			}
			break;
		case 'h':
			usage();
			return 0;
		case 'a':
			aflag = 1;
			break;
		case 'l':
			lflag = 1;
			break;
		case 'n':
			nflag++;
			break;
		case 's':
			sflag++;
			break;
		case 'z':
			zflag = 1;
			break;
		case 'I':
			iflag = 1;
			interface = optarg;
			break;
		case 'i':
			iflag = 1;
			break;
		case 'H':
			Hflag = 1;
			break;
		case 'b':
			bflag = 1;
			break;
		case 'w':
			interval = atoi(optarg);
			iflag = 1;
			break;
		}
	}
	if (proto_mask == 0) {
		proto_mask |= PROTO_FLAG_ALL;
	}
	if (iflag) {
		if (interval) {
			print_interfaces_rate();
		} else {
			print_interfaces();
		}
	} else if (sflag) {
		print_stats();
	} else {
		print_sockets();
	}
	return 0;
}
