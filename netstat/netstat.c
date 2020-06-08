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

int aflag;      /* show all sockets (including servers) */
int bflag;       /* show i/f total bytes in/out */
int Pflag = -1;
int Hflag;       /* show counters in human readable format */
int iflag;       /* show interfaces */
int Lflag;       /* show size of listen queues */
int nflag;       /* show numerically */
int pflag;       /* show given protocol */
int sflag;       /* show protocol statistics */
int zflag;       /* zero stats */
int interval;    /* repeat interval for i/f stats */
char *interface;

void tcp_stats();
void udp_stats();
void arp_stats();
void ip_stats();

struct proto {
	void (*pr_stats)();
	const char *pr_name;
	int pr_ipproto;
};

struct proto protos[] = {
	{ tcp_stats, "tcp",  IPPROTO_TCP },
	{ udp_stats, "udp",  IPPROTO_UDP },
	{ ip_stats,  "ip",   IPPROTO_RAW },
	{ arp_stats, "arp",  0 },
	{ NULL,      NULL,   0 }
};

struct in_addr;
char *inetname(be32_t);

static const char *tcpstates[GT_TCP_NSTATES] = {
	[GT_TCP_S_CLOSED] = "CLOSED",
	[GT_TCP_S_LISTEN] = "LISTEN",
	[GT_TCP_S_SYN_SENT] = "SYN_SENT",
	[GT_TCP_S_SYN_RCVD] = "SYN_RCVD",
	[GT_TCP_S_ESTABLISHED] = "ESTABLISHED",
	[GT_TCP_S_CLOSE_WAIT] = "CLOSE_WAIT",
	[GT_TCP_S_LAST_ACK] = "LAST_ACK",
	[GT_TCP_S_FIN_WAIT_1] = "FIN_WAIT_1",
	[GT_TCP_S_FIN_WAIT_2] = "FIN_WAIT_2",
	[GT_TCP_S_CLOSING] = "CLOSING",
	[GT_TCP_S_TIME_WAIT] = "TIME_WAIT"
};

void pr_sockaddr(be32_t, be16_t, const char *, int);

struct netif {
	LIST_ENTRY(netif) list;
	char name[IFNAMSIZ];
	unsigned long long ipackets;
	unsigned long long ibytes;
	unsigned long long opackets;
	unsigned long long obytes;
	unsigned long long odrops;
};

LIST_HEAD(netif_head, netif);

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
		return rc;
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

static void
bad_format(const char *path)
{
	warnx("sysctl('%s') bad format", path);
}

// Interfaces
static void
show_stat(int width, unsigned long long value)
{
	if (0 && Hflag) {
		// TODO: Print statistics in human readable form
	} else {
		printf(" %*llu", width, value);
	}
}

static void
print_if_banner()
{
	printf("%-*.*s %12.12s",
	       16, 16, "Name", "Ipkts");
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
print_if_rate_banner()
{
	const char *banner;

	if (interface != NULL) {
		banner = interface;
	} else {
		banner = "(Total)";
	}
	printf("%40s\n", banner);
	printf(" %12s %12s %12s %12s %12s\n",
	       "Ipkts", "Ibytes", "Opkts", "Odrop", "Obytes");
}

static void
netif_print(struct netif *ifp)
{
	char name[IFNAMSIZ];

	strzcpy(name, ifp->name, sizeof(name));
	printf("%-*.*s", 16, 16, name);
	show_stat(12, ifp->ipackets);
	if (bflag) {
		show_stat(14, ifp->ibytes);
	}
	show_stat(12, ifp->opackets);
	show_stat(12, ifp->odrops);
	if (bflag) {
		show_stat(14, ifp->obytes);
	}
	printf("\n");
}

static void
netif_set_name(struct netif *ifp, const char *ifname)
{
	strzcpy(ifp->name, ifname, ARRAY_SIZE(ifp->name));
}

static struct netif *
get_if(struct netif_head *head, const char *ifname)
{
	struct netif *ifp;

	LIST_FOREACH(ifp, head, list) {
		if (!strcmp(ifp->name, ifname)) {
			return ifp;
		}
	}
	return NULL;
}

int
sysctl_list_foreach(const char *name, void *udata,
	int (*fn)(void *, const char *))
{
	int rc, len;
	char path[PATH_MAX];
	char buf[GT_SYSCTL_BUFSIZ];

	rc = xsysctl(name, buf, NULL);
	while (rc == 0 && buf[0] == ',') {
		len = snprintf(path, sizeof(path), "%s.%s", name, buf + 1);
		if (len + 1 >= sizeof(path)) {
			return -ENAMETOOLONG;
		}
		rc = xsysctl(path, buf, NULL);
		if (rc == 0) {
			rc = (*fn)(udata, buf);
			if (rc) {
				break;
			}
		}
		path[len++] = '+';
		path[len] = '\0';
		rc = xsysctl(path, buf, NULL);
	}
	return rc;
}

static int
sc_if(void *udata, const char *buf)
{
	int rc, tmpd, tmpx;
	char ifname[64], tmp32[32];
	unsigned long long ipackets, ibytes, opackets, obytes, odrops;
	struct netif *ifp;
	struct netif_head *head;

	head = udata;
	rc = sscanf(buf, "%64[^,],%d,%x,%32[^,],%llu,%llu,%llu,%llu,%llu",
	            ifname, &tmpd, &tmpx, tmp32,
	            &ipackets, &ibytes, &opackets, &obytes, &odrops);
	if (rc != 9) {
		bad_format(buf);
		return -EPROTO;
	}
	if (interface != NULL && strcmp(interface, ifname)) {
		return 0;
	}
	ifp = get_if(head, ifname);
	if (ifp == NULL) {
		ifp = xmalloc(sizeof(*ifp));
		memset(ifp, 0, sizeof(*ifp));
		netif_set_name(ifp, ifname);
		LIST_INSERT_HEAD(head, ifp, list);
	}
	ifp->ipackets += ipackets;
	ifp->ibytes += ibytes;
	ifp->opackets += opackets;
	ifp->obytes += obytes;
	ifp->odrops += odrops;
	return 0;
}

static void
get_ifs(struct netif_head *head)
{
	sysctl_list_foreach(GT_SYSCTL_ROUTE_IF_LIST, head, sc_if);
}

static void
free_ifs(struct netif_head *head)
{
	struct netif *ifp;

	while (!LIST_EMPTY(head)) {
		ifp = LIST_FIRST(head);
		LIST_REMOVE(ifp, list);
		free(ifp);
	}
}

static void
get_if_stat(struct netif *res)
{
	struct netif *ifp;
	struct netif_head head;

	memset(res, 0, sizeof(*res));
	get_ifs(&head);
	LIST_FOREACH(ifp, &head, list) {
		res->ipackets += ifp->ipackets;
		res->ibytes += ifp->ibytes;
		res->opackets += ifp->opackets;
		res->obytes += ifp->obytes;
		res->odrops += ifp->odrops;
	}
	free_ifs(&head);
}

static void
print_if_rate()
{
	struct netif if2[2], *new, *old, *tmp;
	int n;

	n = 0;
	new = &if2[0];
	old = &if2[1];
	get_if_stat(old);
	print_if_rate_banner();
	while (1) {
		sleep(interval);
		n++;
		get_if_stat(new);
		show_stat(12, new->ipackets - old->ipackets);
		show_stat(12, new->ibytes - old->ibytes);
		show_stat(12, new->opackets - old->opackets);
		show_stat(12, new->odrops - old->odrops);
		show_stat(12, new->obytes - old->obytes);
		printf("\n");
		tmp = new;
		new = old;
		old = tmp;
		if (n == 21) {
			n = 0;
			print_if_rate_banner();
		}
	}
}

static void
print_if()
{
	struct netif *ifp;
	struct netif_head head;

	if (interval) {
		return print_if_rate();
	}
	get_ifs(&head);
	if (!LIST_EMPTY(&head)) {
		print_if_banner();
		LIST_FOREACH(ifp, &head, list) {
			netif_print(ifp);
		}
	}
	free_ifs(&head);
}

static void
pr_sockets_banner()
{
	if (!Lflag) {
		printf("Active Internet connections");
		if (aflag) {
			printf(" (including servers)");
		}
	} else {
		printf("Current listen queue sizes (qlen/incqlen/maxqlen)");
	}
	printf("\n%-5.5s %-22.22s ", "Proto", "Local Address");
	if (Lflag) {
		printf("%-32.32s ", "Listen");
	} else {
		printf("%-22.22s %-11.11s", "Foreign Address", "State ");
	}
	printf("\n");
}

static int
pr_socket(void *udata, const char *buf)
{
	int rc, fd, proto, state, q_len, inc_q_len, q_lim;
	uint32_t laddr, faddr;
	uint16_t lport, fport;
	const char *name;
	char buf1[33];
	struct proto *p;

	p = udata;
	rc = sscanf(buf,
	            "%d,%d,%d,"
	            "%x,%hu,"
	            "%x,%hu,"
	            "%d,%d,%d",
	            &fd, &proto, &state,
	            &laddr, &lport,
	            &faddr, &fport,
	            &q_len, &inc_q_len, &q_lim);
	if (rc != 10) {
		bad_format(buf);
		return -EPROTO;
	}
	if (p != NULL && p->pr_ipproto != proto) {
		return 0;
	}
	laddr = htonl(laddr);
	faddr = htonl(faddr);
	lport = htons(lport);
	fport = htons(fport);
	name = proto == IPPROTO_TCP ? "tcp" : "udp";
	printf("%-5.5s ", name);
	pr_sockaddr(laddr, lport, name, nflag > 1);
	if (state == GT_TCP_S_LISTEN) {
		snprintf(buf1, sizeof(buf1), "%u/%u/%u",
			 q_len, inc_q_len, q_lim);
		printf("%-32.32s ", buf1);
	} else {
		pr_sockaddr(faddr, fport, name, 1);
		if (proto == IPPROTO_TCP) {
			if (state >= GT_TCP_NSTATES) {
				printf("%-11d", state);
			} else {
				printf("%-11s", tcpstates[state]);
			}
		} else {
			printf("%-11s", "           ");
		}
	}
	printf("\n");
	return 0;
}

void
pr_sockets(struct proto *p)
{
	sysctl_list_foreach(GT_SYSCTL_SOCKET_ATTACHED_LIST, p, pr_socket);
}

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
sysctl_net_stat(const char *name, struct stat_entry *e)
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

static void
sysctl_net_stats(const char *name, struct stat_entry *entries)
{
	struct stat_entry *e;

	for (e = entries; e->name != NULL; ++e) {
		sysctl_net_stat(name, e);
	}
}

void
tcp_stats()
{
	int i, first;

	sysctl_net_stats("tcp", stat_tcp_entries);
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
}

void
udp_stats()
{
	unsigned long long delivered;

	sysctl_net_stats("udp", stat_udp_entries);
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
}

void
ip_stats(const char *name, int proto)
{
	sysctl_net_stats("ip", stat_ip_entries);
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
}

void
arp_stats()
{
	sysctl_net_stats("arp", stat_arp_entries);
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
}

void
pr_sockaddr(be32_t addr, be16_t port, const char *proto, int num_port)
{
	struct servent *sp = 0;
	char line[80], *cp;
	int width;
	int alen;

	snprintf(line, sizeof(line), "%.*s.", 16, inetname(addr));
	alen = strlen(line);
	cp = line + alen;
	if (!num_port && port) {
		sp = getservbyport(port, proto);
	}
	if (sp || port == 0) {
		snprintf(cp, sizeof(line) - alen,
			"%.15s ", sp ? sp->s_name : "*");
	} else {
		snprintf(cp, sizeof(line) - alen,
			"%d ", ntohs(port));
	}
	width = 22;
	printf("%-*.*s ", width, width, line);
}

char *
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


static struct proto *
get_proto(const char *name)
{
	struct proto *p;

	for (p = protos; p->pr_name != NULL; ++p) {
		if (!strcmp(p->pr_name, name)) {
			return p;
		}
	}
	return NULL;
}

static void
usage(void)
{
	printf("%s",
	"Usage: netstat [-avLn] [--tcp] [--udp] [--ip] [--arp]\n"
	"       netstat -s [-z] [--tcp] [--udp] [--ip] [--arp]\n"
	"       netstat {-i|-I interface} [-Hb] [-w wait]\n"
	"\n"
	"\t-h   Print this help\n"
	"\t-a   Display all sockets (default: connected)\n"
	"\t-b   Display bytes interface statistics\n"
	"\t-L   Display listening server sockets\n"
	"\t-n   Don't resolve names\n"
	"\t-z   Zero statistics\n"
	"\t-H   Display interface statistics in human readable form\n"
	);
}

struct option long_opts[] = {
	{ "tcp", no_argument, 0, 0 },
	{ "udp", no_argument, 0, 0 },
	{ "ip",  no_argument, 0, 0 },
	{ "arp", no_argument, 0, 0 },
};

int
main(int argc, char **argv)
{
	struct proto *proto, *p;
	int opt, long_opt;

	gt_init();
	gt_preload_passthru = 1;
	proto = NULL;
	while ((opt = getopt_long(argc, argv, "habHI:iLnsw:z",
	                          long_opts, &long_opt)) != -1) {
		switch(opt) {
		case 0:
			proto = get_proto(long_opts[long_opt].name);
			break;
		case 'h':
			usage();
			return 0;
		case 'a':
			aflag = 1;
			break;
		case 'b':
			bflag = 1;
			break;
		case 'H':
			Hflag = 1;
			break;
		case 'I':
			iflag = 1;
			interface = optarg;
			break;
		case 'i':
			iflag = 1;
			break;
		case 'L':
			Lflag = 1;
			break;
		case 'n':
			nflag++;
			break;
		case 's':
			sflag++;
			break;
		case 'w':
			interval = atoi(optarg);
			iflag = 1;
			break;
		case 'z':
			zflag = 1;
			break;
		}
	}
	if (iflag) {
		print_if();
		return 0;
	}
	if (sflag) {
		for (p = protos; p->pr_name != NULL; ++p) {
			if (proto == NULL || proto == p) {
				(*p->pr_stats)(p->pr_name);
			}
		}
	} else {
		pr_sockets_banner();
		pr_sockets(proto);
	}
	return 0;
}
