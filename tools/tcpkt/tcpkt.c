#include "ip.h"

#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_RESET   "\x1b[0m"

#define ERR_BUF_SIZE 256

#define PKT_DELAY_DISP 10
#define DEF_RPORT 7385

#define NODE_NAME_MAX 32

struct interval {
	int min;
	int max;
};

enum pkt_dir {
	PKT_OUTGOING,
	PKT_INCOMING
};

enum pkt_req {
	PKT_MANDATORY = 1,
	PKT_OPTIONAL
};

struct pkt {
	unsigned int line_num;

	enum pkt_dir dir;
	enum pkt_req req;
	int add_icmp_ip;
	int print_ip;
	struct interval delay;

	struct proto_cb pcb;
	long flags;
};

struct play_context {
	int af;
	ipaddr_t laddr;
	ipaddr_t faddr;
	be16_t lport;
	be16_t fport;
	uint16_t ip_id;
	unsigned int time;
	int incoming;
	uint32_t seq;
	uint32_t ack;
	uint32_t seq_isn;
	uint32_t ack_isn;
};

struct proto_node;

TAILQ_HEAD(proto_node_head, proto_node);

typedef char *(*node_parse_t)(struct pkt *p, struct proto_node *node, char *s, char *eb);
typedef int   (*node_compar_t)(struct pkt *l, struct pkt *r);
typedef void  (*node_print_t)(struct pkt *p, struct proto_node *node,
                              long c_flags, long m_flags);

struct proto_node {
	TAILQ_ENTRY(proto_node) list;

	unsigned int id;
	const char *name;

	struct proto_node_head params;
	struct proto_node_head protos;

	node_parse_t  parse;
	node_compar_t compar;
	node_print_t  print;
};

enum proto_node_type {
	NODE_TYPE_PARAM,
	NODE_TYPE_PROTO,
};

enum proto_node_id {
	NODE_DELAY,
	NODE_ROOT,
	NODE_IP,
	NODE_IP_ID,
	NODE_IP_FLAGS,
	NODE_IP_FRAG_OFF,
	NODE_IP_LEN,
	NODE_IPV6,
	NODE_ARP,
	NODE_ARP_REQUEST,
	NODE_ARP_REPLY,
	NODE_TCP,
	NODE_UDP,
	NODE_ICMP,
	NODE_ICMP_MTU,
	NODE_ICMP_ID,
	NODE_ICMP_SEQ,
	NODE_ICMPV6,
	NODE_TCP_SEQ,
	NODE_TCP_ACK,
	NODE_TCP_WIN,
	NODE_TCP_OPTS,
	NODE_TCP_LEN,
	NODE_TCP_OPT_MSS,
	NODE_TCP_OPT_WSCALE,
	NODE_TCP_OPT_SACK_PERMITED,
};

static struct {
	uint8_t id;
	char ch;
} tcp_flags_table[] = {
	{ TCP_FLAG_FIN, 'F' },
	{ TCP_FLAG_SYN, 'S' },
	{ TCP_FLAG_RST, 'R' },
	{ TCP_FLAG_PSH, 'P' },
	{ TCP_FLAG_ACK, '.' },
	{ TCP_FLAG_URG, 'U' },
};

static int quiet;
static int verbose;
static int use_color;
static int use_line_num;
static int line_num_width;
static int abs_seq;
static int match_tcp_flags_mask = TCP_FLAG_CHRISTMAS_TREE & (~TCP_FLAG_PSH);
static struct if_dev dev;
static struct play_context play;
static struct proto_node *node_ROOT;
static struct proto_node *node_IPVX;
static uint8_t icmp_ip_data[68];
static int icmp_ip_data_len;

#define SET_FLAG(p, flag) set_bit(&(p)->flags, NODE_##flag)

static int
print_color(const char *color)
{
	if (use_color) {
		printf(color);
		return 1;
	} else {
		return 0;
	}
}

static void
unset_color(int colored)
{
	if (use_color) {
		if (colored) {
			printf(COLOR_RESET);
			fflush(stdout);
		}
	}
}

static void outf(const char *format, ...)
	__attribute__((format(printf, 1, 2)));

static void errf(char *eb, const char *format, ...)
	__attribute__((format(printf, 2, 3)));

static void
outf(const char *format, ...)
{
	va_list ap;

	if (quiet) {
		return;
	}
	va_start(ap, format);
	vfprintf(stdout, format, ap);
	va_end(ap);
}

static void
errf(char *eb, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	if (eb != NULL) {
		vsnprintf(eb, ERR_BUF_SIZE, format, ap);
	}
	va_end(ap);
}

const char *
tcp_flags_string(uint8_t tcp_flags)
{
	static char buf[8];
	int i;
	char *ptr;

	ptr = buf;
	for (i = 0; i < ARRAY_SIZE(tcp_flags_table); ++i) {
		if (tcp_flags & tcp_flags_table[i].id)
			*ptr++ = tcp_flags_table[i].ch;
	}
	*ptr = '\0';
	return buf;
}

static uint32_t
tcp_flags_seq(uint8_t tcp_flags)
{
	uint32_t seq;

	seq = 0;
	if (tcp_flags & TCP_FLAG_SYN) {
		seq++;
	}
	if (tcp_flags & TCP_FLAG_FIN) {
		seq++;
	}
	return seq;
}

static const char *
node_type_string(enum proto_node_type type)
{
	switch (type) {
	case NODE_TYPE_PARAM: return "param";
	case NODE_TYPE_PROTO: return "proto";
	default:
		assert(!"not implamented");
		return NULL;
	}
}

static int
set_color(long c_flags, long m_flags, unsigned int id)
{
	if (use_color && test_bit(c_flags, id)) {
		if (test_bit(m_flags, id)) {
			return print_color(COLOR_GREEN);
		} else {
			return print_color(COLOR_RED);
		}
	}
	return 0;
}

static void
print_interval(struct interval *inter)
{
	assert(inter->max >= inter->min);
	if (inter->min == inter->max) {
		outf("%u", inter->min);
	} else if (inter->min == 0) {
		if (inter->max != UINT_MAX) {
			outf("<%u", inter->max);
		}
	} else if (inter->max == UINT_MAX) {
		outf(">%u", inter->min);
	} else {
		outf("%u-%u", inter->min, inter->max);
	}
}

static void
print_delay(struct pkt *p)
{
	outf("[");
	print_interval(&p->delay);
	outf("]");
}

struct proto_node *
new_node(unsigned int id, const char *name,
         node_parse_t parse, node_compar_t compar, node_print_t print)
{
	struct proto_node *node;

	assert(strlen(name) < NODE_NAME_MAX);
	node = xmalloc(sizeof(*node));
	node->name = name;
	node->id = id;
	assert(node->id < sizeof(long) * CHAR_BIT);
	node->parse = parse;
	node->compar = compar;
	node->print = print;
	TAILQ_INIT(&node->params);
	TAILQ_INIT(&node->protos);
	return node;
}

void
add_param(struct proto_node *parent, struct proto_node *param)
{
	TAILQ_INSERT_TAIL(&parent->params, param, list);
}

void
add_proto(struct proto_node *parent, struct proto_node *proto)
{
	TAILQ_INSERT_TAIL(&parent->protos, proto, list);
}

static void
set_tcp_opt(struct tcp_opt *tcp_opt, int field_id)
{
	set_bit(&tcp_opt->flags, field_id);
}

static char *
skip_spaces(char *s)
{
	for (;*s != '\0'; ++s) {
		if (!isspace(*s)) {
			break;
		}
	}
	return s;
}

static int
parse_scope(char **ps, char **pscope)
{
	char *s;

	s = *ps;
	if (*s != '[') {
		return '[';
	}
	s++;
	*pscope = s;
	s = strchr(s, ']');
	if (s == NULL) {
		return ']';
	}
	*s = '\0';
	s++;
	*ps = s;
	return 0;
}

#define BAD_UINT64 ((uint64_t)-1)

static uint64_t
parse_uint64(char **s, uint64_t val_max)
{
	uint64_t x;
	char *ep;

	x = strtoull(*s, &ep, 10);
	ep = skip_spaces(ep);
	if (*ep == ',' || *ep == ':' || *ep == '\0') {
		*s = ep;
		if (x > val_max) {
			return BAD_UINT64;
		}
		return x;
	} else {
		return BAD_UINT64;
	}
}

static uint64_t
parse_uint32(char **s)
{
	return parse_uint64(s, UINT32_MAX);
}

static uint64_t
parse_uint16(char **s)
{
	return parse_uint64(s, UINT16_MAX);
}

static uint64_t
parse_uint8(char **s)
{
	return parse_uint64(s, UINT8_MAX);
}

// []
// [0]
// [100]
// [<100]
// [>100]
// [100-200]
static int
parse_interval(char *s, struct interval *inter)
{
	char *endptr;

	switch (*s) {
	case '\0':
		inter->min = INT_MIN;
		inter->max = INT_MAX;
		break;
	case '<':
		s++;
		inter->min = 0;
		inter->max = strtoul(s, &endptr, 10);
		if (*endptr != '\0') {
			return -EINVAL;
		}
		break;
	case '>':
		s++;
		inter->max = INT_MAX;
		inter->min = strtoul(s, &endptr, 10);
		if (*endptr != '\0') {
			return -EINVAL;
		}
		break;
	default:
		inter->min = strtoul(s, &endptr, 10);
		switch (*endptr) {
		case '\0':
			inter->max = inter->min;
			break;
		case '-':
			s = endptr + 1;
			inter->max = strtoul(s, &endptr, 10);
			if (inter->max < inter->min) {
				return -EINVAL;
			}
			if (*endptr != '\0') {
				return -1;
			}
			break;
		default:
			return -EINVAL;
		}
		break;
	}
	return 0;
}

static int
isname(int ch)
{
	switch (ch) {
	case '0'...'9':
	case 'a'...'z':
	case 'A'...'Z':
	case '_':
	case '-':
		return 1;

	default:
		return 0;
	}
}

// ICMP unreachable - need to frag, mtu 1396, length 48
// IP, flags [DF]: Flags [P.], length 1200
// Flags [P.], length 1200
static char *
parse_node_name(char *name, char *s, char *eb)
{
	int i;

	for (i = 0; isname(*s); ++s, ++i) {
		if (i == NODE_NAME_MAX - 1) {
			name[NODE_NAME_MAX - 1] = '\0';
			errf(eb, "too long name '%s'", name);
			return NULL;
		}
		name[i] = *s;
	}
	if (i == 0) {
		errf(eb, "expected name at '%s'", trim(s, "\r\n\t"));
		return NULL;
	}
	name[i] = '\0';
	return s;
}

static char *
parse_next_node(struct pkt *p, struct proto_node *parent,
                enum proto_node_type type, char *s, char *eb)
{
	char name_buf[NODE_NAME_MAX];
	struct proto_node *node;
	struct proto_node_head *nodes;

	nodes = type == NODE_TYPE_PARAM ? &parent->params : &parent->protos;
	s = parse_node_name(name_buf, s, eb);
	if (s == NULL) {
		return NULL;
	}
	s = skip_spaces(s);
	TAILQ_FOREACH(node, nodes, list) {
		if (!strcmp(name_buf, node->name)) {
			eb[0] = '\0';
			s = (*node->parse)(p, node, s, eb);
			if (s == NULL) {
				if (*eb == '\0') {
					errf(eb, "broken value: '%s'", name_buf);
				}
			} else {
				set_bit(&p->flags, node->id);
			}
			return s;
		}
	}
	errf(eb, "unknown %s: '%s'", node_type_string(type), name_buf);
	return NULL;
}

static char *
parse_root(struct pkt *p, char *s, char *eb)
{
	char name_buf[NODE_NAME_MAX];
	struct proto_node *node;

	s = skip_spaces(s);
	if (parse_node_name(name_buf, s, eb) == NULL) {
		return NULL;
	}
	TAILQ_FOREACH(node, &node_ROOT->protos, list) {
		if (!strcmp(name_buf, node->name)) {
			p->print_ip = 1;
			return parse_next_node(p, node_ROOT, NODE_TYPE_PROTO, s, eb);
		}
	}
	s = parse_next_node(p, node_IPVX, NODE_TYPE_PROTO, s, eb);
	if (s != NULL) {
		if (node_IPVX->id == NODE_IP) {
			SET_FLAG(p, IP);
			p->pcb.eth_type = ETH_TYPE_IPV4;
		} else {
			SET_FLAG(p, IPV6);
			p->pcb.eth_type = ETH_TYPE_IPV6;
		}
	}
	return s;
}

static char *
parse_node(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	while (*(s = skip_spaces(s)) != '\0') {
		if (*s == ':') {
			s = skip_spaces(s + 1);
			return parse_next_node(p, node, NODE_TYPE_PROTO, s, eb);
		}
		if (*s == ',') {
			s++;
		}
		s = skip_spaces(s);
		s = parse_next_node(p, node, NODE_TYPE_PARAM, s, eb);
		if (s == NULL) {
			return NULL;
		}
	}
	return s;
}

static int match_node(struct pkt *p, struct pkt *r,
                      struct proto_node *node, long *m_flags);

static int
match_branch(struct pkt *p, struct pkt *r,
             struct proto_node *parent, long *m_flags)
{
	int rc;
	struct proto_node *node;

	TAILQ_FOREACH(node, &parent->params, list) {
		match_node(p, r, node, m_flags);
	}
	TAILQ_FOREACH(node, &parent->protos, list) {
		rc = match_node(p, r, node, m_flags);
		if (rc == -1) {
			return -EINVAL;
		}
		if (rc == 1) {
			break;
		}
	}
	return 0;
}

static int
match_node(struct pkt *p, struct pkt *r,
           struct proto_node *node, long *m_flags)
{
	int rc;

	if (!test_bit(p->flags, node->id)) {
		return 0;
	}
	if (!test_bit(r->flags, node->id)) {
		return -EINVAL;
	}
	rc = match_branch(p, r, node, m_flags);
	if ((*node->compar)(p, r)) {
		return -EINVAL;
	} else {
		set_bit(m_flags, node->id);
		return rc;
	}
}

static void
match_root(struct pkt *p, struct pkt *r, long *m_flags)
{
	struct proto_node *node;

	TAILQ_FOREACH(node, &node_ROOT->protos, list) {
		if (match_node(p, r, node, m_flags)) {
			return;
		}
	}
}

static void
print_branch(struct pkt *p, struct proto_node *node,
             long c_flags, long m_flags)
{
	outf("%s", node->name);
	(*node->print)(p, node, c_flags, m_flags);
}

static void
print_node(struct pkt *p, struct proto_node *parent,
           long c_flags, long m_flags, const char *sep)
{
	int is_first;
	struct proto_node *node;

	is_first = 1;
	TAILQ_FOREACH(node, &parent->params, list) {
		if (test_bit(p->flags, node->id)) {
			if (is_first) {
				is_first = 0;
				outf("%s", sep);
			} else {
				outf(", ");
			}
			print_branch(p, node, c_flags, m_flags);
		}
	}
	TAILQ_FOREACH(node, &parent->protos, list) {
		if (test_bit(p->flags, node->id)) {
			outf(": ");
			print_branch(p, node,  c_flags, m_flags);
			return;
		}
	}
}

static void
print_protos(struct pkt *p, struct proto_node *parent, long c_flags, long m_flags)
{
	struct proto_node *node;

	TAILQ_FOREACH(node, &parent->protos, list) {
		if (test_bit(p->flags, node->id)) {
			print_branch(p, node, c_flags, m_flags);
			return;
		}
	}
}

static void
print_root(struct pkt *p, long c_flags, long m_flags)
{
	struct proto_node *node;
	int is_ip;

	TAILQ_FOREACH(node, &node_ROOT->protos, list) {
		if (test_bit(p->flags, node->id)) {
			is_ip = node->id == NODE_IP || node->id == NODE_IPV6;
			if (is_ip && p->print_ip == 0) {
				print_protos(p, node, c_flags, m_flags);
			} else {
				print_branch(p, node, c_flags, m_flags);
			}
			return;
		}
	}
	print_protos(p, node_IPVX, c_flags, m_flags);
}

#define SET_COLOR \
	int color = set_color(c_flags, m_flags, node->id);

static char *
parse_IP(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	p->pcb.eth_type = ETH_TYPE_IPV4;
	return parse_node(p, node, s, eb);
}

static int
compar_IP(struct pkt *p, struct pkt *r)
{
	return 0;
}

static void
print_IP(struct pkt *p, struct proto_node *node,
         long c_flags, long m_flags)
{
	print_node(p, node, c_flags, m_flags, " ");
}

static char *
parse_IP_ID(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	uint64_t x;

	x = parse_uint16(&s);
	if (x == BAD_UINT64) {
		return NULL;
	}
	p->pcb.ip.v4.id = x;
	return s;
}

static int
compar_IP_ID(struct pkt *p, struct pkt *r)
{
	return p->pcb.ip.v4.id - r->pcb.ip.v4.id;
}

static void
print_IP_ID(struct pkt *p, struct proto_node *node,
            long c_flags, long m_flags)
{
	SET_COLOR;
	outf(" %"PRIu16, p->pcb.ip.v4.id);
	unset_color(color);
}

static char *
parse_IP_FLAGS(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	int flags;
	char *flags_str;

	if (parse_scope(&s, &flags_str)) {
		return NULL;
	}
	if (!strcmp(flags_str, "DF")) {
		flags = IPV4_FLAG_DF;
	} else if (!strcmp(flags_str, "+")) {
		flags = IPV4_FLAG_MF;
	} else if (!strcmp(flags_str, "+,DF")) {
		flags = IPV4_FLAG_DF|IPV4_FLAG_MF;
	} else if (!strcmp(flags_str, "none")) {
		flags = 0;
	} else {
		return NULL;
	}
	p->pcb.ip.v4.flags = flags;
	return s;
}

static int
compar_IP_FLAGS(struct pkt *p, struct pkt *r)
{
	return p->pcb.ip.v4.flags - r->pcb.ip.v4.flags;
}

static void
print_IP_FLAGS(struct pkt *p, struct proto_node *node,
            long c_flags, long m_flags)
{
	int df, mf;

	outf(" [");
	df = p->pcb.ip.v4.flags & IPV4_FLAG_DF;
	mf = p->pcb.ip.v4.flags & IPV4_FLAG_MF;
	SET_COLOR;
	if (mf) {
		outf("+");
		if (df) {
			outf(",DF");
		}
	} else if (mf) {
		outf("+");
	} else {
		outf("none");
	}
	unset_color(color);
	outf("]");
}

static char *
parse_IP_FRAG_OFF(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	uint64_t x;

	x = parse_uint16(&s);
	if (x == BAD_UINT64) {
		return NULL;
	}
	if (x & 0x7) {
		return NULL;
	}
	p->pcb.ip.v4.frag_off = x >> 3;
	return s;
}

static int
compar_IP_FRAG_OFF(struct pkt *p, struct pkt *r)
{
	return p->pcb.ip.v4.frag_off - r->pcb.ip.v4.frag_off;
}

static void
print_IP_FRAG_OFF(struct pkt *p, struct proto_node *node,
                  long c_flags, long m_flags)
{
	SET_COLOR;
	outf(" %"PRIu16, p->pcb.ip.v4.frag_off << 3);
	unset_color(color);
}

static char *
parse_IP_LEN(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	uint64_t x;

	x = parse_uint16(&s);
	if (x == BAD_UINT64) {
		return NULL;
	}
	if (x < 20) {
		return NULL;
	}
	p->pcb.ip.v4.len = x;
	return s;
}

static int
compar_IP_LEN(struct pkt *p, struct pkt *r)
{
	return p->pcb.ip.v4.len - r->pcb.ip.v4.len;
}

static void
print_IP_LEN(struct pkt *p, struct proto_node *node,
            long c_flags, long m_flags)
{
	SET_COLOR;
	outf(" %"PRIu16, p->pcb.ip.v4.len);
	unset_color(color);
}

// ARP, Request who-has 2.2.2.1 (ff:ff:ff:ff:ff:ff) tell 2.2.2.2
// ARP, Reply 2.2.2.1 is-at 8a:00:0d:bb:f1:b7
static char *
parse_ARP(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	p->pcb.eth_type = ETH_TYPE_ARP;
	return parse_node(p, node, s, eb);
}

static int
compar_ARP(struct pkt *p, struct pkt *r)
{
	return 0;
}

static void
print_ARP(struct pkt *p, struct proto_node *node,
          long c_flags, long m_flags)
{
	print_node(p, node, c_flags, m_flags, ",");
}

static void
make_arp_request(struct pkt *p)
{
	struct arp_ipv4 *data;

	p->pcb.arp.op = ARP_OP_REQUEST;
	data = &p->pcb.arp.ipv4;
	data->tip = play.faddr.ipv4;
	memset(&data->tha, -1, sizeof(data->tha)); // Broadcast
	data->sip = play.laddr.ipv4;
	data->sha = dev.s_hwaddr;
}

static char *
parse_ARP_REQUEST(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	make_arp_request(p);
	return s;
}

static int
compar_ARP_REQUEST(struct pkt *p, struct pkt *r)
{
	struct arp_ipv4 *data;

	data = &p->pcb.arp.ipv4;
	if (data->tip != play.laddr.ipv4) {
		return -EINVAL;
	}
	if (data->sip != play.faddr.ipv4) {
		return -EINVAL;
	}
	return memcmp(&data->tha, &dev.s_hwaddr, sizeof(data->tha));
}

static void
print_ARP_REQUEST(struct pkt *p, struct proto_node *node,
                  long c_flags, long m_flags)
{
	char tha_buf[ETH_ADDRSTRLEN];
	struct in_addr tip, sip;
	struct eth_addr *tha;

	tip.s_addr = p->pcb.arp.ipv4.tip;
	sip.s_addr = p->pcb.arp.ipv4.sip;
	tha = &p->pcb.arp.ipv4.tha;
	SET_COLOR;
	outf(" who-has %s (%s) tell ", inet_ntoa(tip), eth_ntoa(tha, tha_buf));
	outf("%s", inet_ntoa(sip));
	unset_color(color);
}

static char *
parse_ARP_REPLY(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	struct arp_ipv4 *data;

	p->pcb.arp.op = ARP_OP_REPLY;
	data = &p->pcb.arp.ipv4;
	data->tip = play.faddr.ipv4;
	data->tha = dev.d_hwaddr;
	data->sip = play.laddr.ipv4;
	data->sha = dev.s_hwaddr;
	return s;
}

static int
compar_ARP_REPLY(struct pkt *p, struct pkt *r)
{
	struct arp_ipv4 *data;

	data = &p->pcb.arp.ipv4;
	if (data->tip != play.laddr.ipv4) {
		return -EINVAL;
	}
	if (data->sip != play.faddr.ipv4) {
		return -EINVAL;
	}
	return memcmp(&data->sha, &dev.d_hwaddr, sizeof(data->sha));
}

static void
print_ARP_REPLY(struct pkt *p, struct proto_node *node,
                long c_flags, long m_flags)
{
	char sha_buf[ETH_ADDRSTRLEN];
	struct in_addr sip;
	struct eth_addr *sha;

	sip.s_addr = p->pcb.arp.ipv4.sip;
	sha = &p->pcb.arp.ipv4.sha;
	SET_COLOR;
	outf(" %s is-at %s", inet_ntoa(sip), eth_ntoa(sha, sha_buf));
	unset_color(color);
}

static char *
parse_TCP(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	int i;
	char *tcp_flags;

	if (parse_scope(&s, &tcp_flags)) {
		return NULL;
	}
	p->pcb.ip.proto = IPPROTO_TCP;
	p->pcb.tcp.flags = 0;
	for (; *tcp_flags != '\0'; ++tcp_flags) {
		for (i = 0; i < ARRAY_SIZE(tcp_flags_table); ++i) {
			if (tcp_flags_table[i].ch == *tcp_flags) {
				break;
			}
		}
		if (i == ARRAY_SIZE(tcp_flags_table)) {
			return NULL;
		} else {
			p->pcb.tcp.flags |= tcp_flags_table[i].id;
		}
	}
	return parse_node(p, node, s, eb);
}

static int
compar_tcp_flags(uint8_t a, uint8_t b)
{
	return (a & match_tcp_flags_mask) - (b & match_tcp_flags_mask);
}

static int
compar_TCP(struct pkt *p, struct pkt *r)
{
	return compar_tcp_flags(p->pcb.tcp.flags, r->pcb.tcp.flags);
}

static void
print_TCP(struct pkt *p, struct proto_node *node,
          long c_flags, long m_flags)
{
	outf(" [");
	SET_COLOR;
	outf("%s", tcp_flags_string(p->pcb.tcp.flags));
	unset_color(color);
	outf("]");
	print_node(p, node, c_flags, m_flags, ", ");
}

// ICMP echo request id 12728, seq 2
static char *
parse_ICMP(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	int i, nr_toks;
	char *e, *str, e_ch;
	char *toks[16];

	p->pcb.ip.proto = IPPROTO_ICMP;
	for (e = s; *e != '\0'; ++e) {
		if (strchr(",:", *e) != NULL) {
			break;
		}
	}
	e_ch = *e;
	*e = '\0';
	nr_toks = 0;
	for (str = strtok(s, " \r\n\t");
	     str != NULL; 
	     str = strtok(NULL, " \r\n\t")) {
		if (nr_toks == ARRAY_SIZE(toks)) {
			return NULL;
		}
		toks[nr_toks++] = str;
	}
	for (i = nr_toks; i < ARRAY_SIZE(toks); ++i) {
		toks[i] = "";
	}
	if (!strcmp(toks[0], "unreachable")) {
		p->pcb.icmpv4.type = ICMPV4_TYPE_DEST_UNREACHABLE;
		p->add_icmp_ip = 1;
		if (!strcmp(toks[1], "-") &&
		    !strcmp(toks[2], "need") &&
		    !strcmp(toks[3], "to") &&
		    !strcmp(toks[4], "frag")) {
			p->pcb.icmpv4.code = ICMPV4_CODE_FRAG_NEEDED_AND_DF_WAS_SET;
		} else {
			return NULL;
		}
	} else if (!strcmp(toks[0], "echo")) {
		if (!strcmp(toks[1], "request")) {
			p->pcb.icmpv4.type = ICMPV4_TYPE_ECHO;
		} else if (!strcmp(toks[1], "reply")) {
			p->pcb.icmpv4.type = ICMPV4_TYPE_ECHO_REPLY;
		} else {
			return NULL;
		}
	} else {
		return NULL;
	}
	*e = e_ch;
	return parse_node(p, node, e, eb);
}

static int
compar_ICMP(struct pkt *p, struct pkt *r)
{
	return p->pcb.icmpv4.type - r->pcb.icmpv4.type ||
	       p->pcb.icmpv4.code - r->pcb.icmpv4.code;
}

static void
print_ICMP(struct pkt *p, struct proto_node *node,
           long c_flags, long m_flags)
{
	switch (p->pcb.icmpv4.type) {
	case ICMPV4_TYPE_ECHO_REPLY:
		outf(" echo reply");
		break;
	case ICMPV4_TYPE_DEST_UNREACHABLE:
		outf(" unreachable");
		switch (p->pcb.icmpv4.code) {
		case ICMPV4_CODE_FRAG_NEEDED_AND_DF_WAS_SET:
			outf(" - need to frag");
			break;
		default:
			assert(!"not implemented");
			break;
		}
		break;
	case ICMPV4_TYPE_ECHO:
		outf(" echo request");
		break;
	default:
		die(0, "-- type =%d", p->pcb.icmpv4.type);
		assert(!"not implemented");
		break;
	}
	print_node(p, node, c_flags, m_flags, ", ");
}

static char *
parse_ICMP_MTU(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	uint64_t x;

	x = parse_uint16(&s);
	if (x == BAD_UINT64) {
		return NULL;
	}
	p->pcb.icmpv4.ptb.mtu = x;
	return s;
}

static int
compar_ICMP_MTU(struct pkt *p, struct pkt *r)
{
	return p->pcb.icmpv4.ptb.mtu - r->pcb.icmpv4.ptb.mtu;
}

static void
print_ICMP_MTU(struct pkt *p, struct proto_node *node,
           long c_flags, long m_flags)
{
	SET_COLOR;
	outf(" %"PRIu16,  p->pcb.icmpv4.ptb.mtu);
	unset_color(color);
}

static char *
parse_ICMP_ID(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	uint64_t x;

	x = parse_uint16(&s);
	if (x == BAD_UINT64) {
		return NULL;
	}
	p->pcb.icmpv4.echo.id = x;
	return s;
}

static int
compar_ICMP_ID(struct pkt *p, struct pkt *r)
{
	return p->pcb.icmpv4.echo.id - r->pcb.icmpv4.echo.id;
}

static void
print_ICMP_ID(struct pkt *p, struct proto_node *node,
           long c_flags, long m_flags)
{
	SET_COLOR;
	outf(" %"PRIu16,  p->pcb.icmpv4.echo.id);
	unset_color(color);
}

static char *
parse_ICMP_SEQ(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	uint64_t x;

	x = parse_uint16(&s);
	if (x == BAD_UINT64) {
		return NULL;
	}
	p->pcb.icmpv4.echo.seq = x;
	return s;
}

static int
compar_ICMP_SEQ(struct pkt *p, struct pkt *r)
{
	return p->pcb.icmpv4.echo.seq - r->pcb.icmpv4.echo.seq;
}

static void
print_ICMP_SEQ(struct pkt *p, struct proto_node *node,
           long c_flags, long m_flags)
{
	SET_COLOR;
	outf(" %"PRIu16,  p->pcb.icmpv4.echo.seq);
	unset_color(color);
}

static char *
parse_TCP_OPTS(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	char *scope;

	if (parse_scope(&s, &scope)) {
		return NULL;
	}
	if (parse_node(p, node, scope, eb) == NULL) {
		return NULL;
	}
	return s;
}

static int
compar_TCP_OPTS(struct pkt *p, struct pkt *r)
{
	return 0;
}

static void
print_TCP_OPTS(struct pkt *p, struct proto_node *node,
               long c_flags, long m_flags)
{
	outf(" [");
	print_node(p, node, c_flags, m_flags, "");
	outf("]");
}

static char *
parse_TCP_SEQ(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	uint64_t x;

	x = parse_uint32(&s);
	if (x == BAD_UINT64) {
		return NULL;
	}
	p->pcb.tcp.seq = x;
	return s;
}

static int
compar_TCP_SEQ(struct pkt *p, struct pkt *r)
{
	return r->pcb.tcp.seq - (p->pcb.tcp.seq + play.ack_isn);
}

static void
print_TCP_SEQ(struct pkt *p, struct proto_node *node,
              long c_flags, long m_flags)
{
	uint32_t seq;

	seq = p->pcb.tcp.seq;
	if (!abs_seq) {
		if (p->dir == PKT_OUTGOING) {
			seq -= play.seq_isn;
		} else {
			seq -= play.ack_isn;
		}
	}
	SET_COLOR;
	outf(" %"PRIu32, seq);
	unset_color(color);
}

static char *
parse_TCP_ACK(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	uint64_t x;

	x = parse_uint32(&s);
	if (x == BAD_UINT64) {
		return NULL;
	}
	p->pcb.tcp.ack = x;
	return s;
}

static int
compar_TCP_ACK(struct pkt *p, struct pkt *r)
{
	return r->pcb.tcp.ack - (p->pcb.tcp.ack + play.seq_isn);
}

static void
print_TCP_ACK(struct pkt *p, struct proto_node *node,
              long c_flags, long m_flags)
{
	uint32_t ack;

	ack = p->pcb.tcp.ack;
	if (!abs_seq) {
		if (p->dir == PKT_OUTGOING) {
			ack -= play.ack_isn;
		} else {
			ack -= play.seq_isn;
		}
	}
	SET_COLOR;
	outf(" %"PRIu32, ack);
	unset_color(color);
}

static char *
parse_TCP_WIN(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	uint64_t x;

	x = parse_uint16(&s);
	if (x == BAD_UINT64) {
		return NULL;
	}
	p->pcb.tcp.win = x;
	return s;
}

static int
compar_TCP_WIN(struct pkt *p, struct pkt *r)
{
	return p->pcb.tcp.win - r->pcb.tcp.win;
}

static void
print_TCP_WIN(struct pkt *p, struct proto_node *node,
              long c_flags, long m_flags)
{
	SET_COLOR;
	outf(" %"PRIu16, p->pcb.tcp.win);
	unset_color(color);
}

static char *
parse_TCP_LEN(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	uint64_t x;

	x = parse_uint16(&s);
	if (x == BAD_UINT64) {
		return NULL;
	}
	p->pcb.ip.len = x;
	return s;
}

static int
compar_TCP_LEN(struct pkt *p, struct pkt *r)
{
	return p->pcb.ip.len - r->pcb.ip.len;
}

static void
print_TCP_LEN(struct pkt *p, struct proto_node *node,
              long c_flags, long m_flags)
{
	SET_COLOR;
	outf(" %"PRIu16, p->pcb.ip.len);
	unset_color(color);
}

static char *
parse_TCP_OPT_MSS(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	uint64_t x;

	x = parse_uint16(&s);
	if (x == BAD_UINT64) {
		return NULL;
	}
	p->pcb.tcp.opt.mss = x;
	set_tcp_opt(&p->pcb.tcp.opt, TCP_OPT_MSS);
	return s;
}

static int
compar_TCP_OPT_MSS(struct pkt *p, struct pkt *r)
{
	return p->pcb.tcp.opt.mss - r->pcb.tcp.opt.mss;
}

static void
print_TCP_OPT_MSS(struct pkt *p, struct proto_node *node,
                  long c_flags, long m_flags)
{
	SET_COLOR;
	outf(" %"PRIu16, p->pcb.tcp.opt.mss);
	unset_color(color);
}

static char *
parse_TCP_OPT_WSCALE(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	uint64_t x;

	x = parse_uint8(&s);
	if (x == BAD_UINT64) {
		return NULL;
	}
	p->pcb.tcp.opt.wscale = x;
	set_tcp_opt(&p->pcb.tcp.opt, TCP_OPT_WSCALE);
	return s;
}

static int
compar_TCP_OPT_WSCALE(struct pkt *p, struct pkt *r)
{
	return p->pcb.tcp.opt.wscale - r->pcb.tcp.opt.wscale;
}

static void
print_TCP_OPT_WSCALE(struct pkt *p, struct proto_node *node,
                     long c_flags, long m_flags)
{
	SET_COLOR;
	outf(" %"PRIu8, p->pcb.tcp.opt.wscale);
	unset_color(color);
}

static char *
parse_TCP_OPT_SACK_PERMITED(struct pkt *p, struct proto_node *node, char *s, char *eb)
{
	set_tcp_opt(&p->pcb.tcp.opt, TCP_OPT_SACK_PERMITED);
	return s;
}

static int
compar_TCP_OPT_SACK_PERMITED(struct pkt *p, struct pkt *r)
{
	return p->pcb.tcp.opt.wscale - r->pcb.tcp.opt.wscale;
}

static void
print_TCP_OPT_SACK_PERMITED(struct pkt *p, struct proto_node *node,
                            long c_flags, long m_flags)
{
}

/*static void
print_TCP_OPT_TS(struct pkt *p, struct proto_node *node,
                 long c_flags, long m_flags)
{
	SET_COLOR;
	printf(" val %"PRIu32" ecr %"PRIu32,
		p->pcb.tcp.opt.ts.val,
		p->pcb.tcp.opt.ts.ecr);
	unset_color(color);
}*/

static int
parse_pkt(struct pkt *p, char *s, char *eb)
{
	int rc;
	char *scope;

	switch (*s) {
	case '>':
		p->dir = PKT_OUTGOING;
		p->req = PKT_MANDATORY;
		break;
	case '!':
		p->dir = PKT_INCOMING;
		p->req = PKT_MANDATORY;
		break;
	case '?':
		p->dir = PKT_INCOMING;
		p->req = PKT_OPTIONAL;
		break;
	default:
		errf(eb, "invalid action '%c'", *s);
		return -EINVAL;
	}
	s = skip_spaces(s + 1);
	if (p->req == PKT_MANDATORY) {
		rc = parse_scope(&s, &scope);
		if (rc != 0) {
			errf(eb, "expected symbol: '%c'", rc);
			return -EINVAL;
		}
		rc = parse_interval(scope, &p->delay);
		if (rc) {
			errf(eb, "invalid delay interval: %s", scope);
			return rc;
		}
		SET_FLAG(p, DELAY);
	}
	rc = parse_root(p, s, eb) == NULL ? -EINVAL : 0;
	return rc;
}

static void
print_pkt(struct pkt *p, long c_flags, long m_flags)
{
	char ch;

	if (quiet) {
		return;
	}
	if (verbose > 1) {
		p->print_ip = 1;
	}
	if (use_line_num) {
		if (p->line_num) {
			outf("%*d ", line_num_width, p->line_num);
		} else {
			outf("%*s ", line_num_width, "");
		}
	}
	if (p->dir == PKT_OUTGOING) {
		ch = '>';
	} else {
		switch (p->req) {
		case PKT_MANDATORY:
			ch = '!';
			break;
		case PKT_OPTIONAL:
			ch = '?';
			break;
		default:
			ch = ' ';
			break;
		}
	}
	outf("%c ", ch);
	print_delay(p);
	outf(" ");
	print_root(p, c_flags, m_flags);
	outf("\n");
}

static void
send_pkt(struct pkt *p)
{
	u_char buf[SNAPLEN];
	int len, af;
	unsigned int t;
	uint16_t lport;
	struct sockaddr_in addr;

	p->pcb.eth_saddr = dev.s_hwaddr;
	p->pcb.eth_daddr = dev.d_hwaddr;
	p->dir = PKT_OUTGOING;
	addr.sin_family = AF_INET;
	if (p->pcb.eth_type != ETH_TYPE_ARP) {
		af = play.af;
		assert((af == AF_INET  && p->pcb.eth_type == ETH_TYPE_IPV4) ||
		       (af == AF_INET6 && p->pcb.eth_type == ETH_TYPE_IPV6));
		if (play.lport == 0) {
			lport = 1024 + getpid() % 50000;
			dbg("set local port: %hu", lport);
			play.lport = CPU_TO_BE16(lport);
		}
		if (play.fport == 0) {
			dbg("set foreign port: %d", DEF_RPORT);
			play.fport = CPU_TO_BE16(DEF_RPORT);
		}
		ipaddr_cpy(af, &p->pcb.ip.saddr, &play.laddr);
		ipaddr_cpy(af, &p->pcb.ip.daddr, &play.faddr);
		if (p->pcb.ip.proto == IPPROTO_TCP ||
		    p->pcb.ip.proto == IPPROTO_UDP) {
			p->pcb.tcp.sport = play.lport;
			p->pcb.tcp.dport = play.fport;
		} else {
			if (p->add_icmp_ip) {
				p->pcb.ip.len = icmp_ip_data_len;
			}
		}
		addr.sin_addr.s_addr = play.faddr.ipv4;
		addr.sin_port = play.fport;
	}
	len = fill_pkt(&dev, buf, &p->pcb, p->add_icmp_ip ? icmp_ip_data : NULL);
	assert(len > 0);
	dev_send(&dev, &addr, buf, len);
	t = get_mseconds();
	p->delay.min = p->delay.max = t - play.time;
	play.time = t;
}

static int
match_laddr(const ipaddr_t *laddr)
{
	int af;

	af = play.af;
	if (!ipaddr_cmp(af, laddr, &play.laddr)) {
		return 1;
	}
	dbg("missmatch local address: %s != %s",
	    INET_NTOP(af, laddr), INET_NTOP(af, &play.laddr));
	return 0;	
}

static int
match_faddr(const ipaddr_t *faddr)
{
	int af;

	af = play.af;
	if (!ipaddr_cmp(af, faddr, &play.faddr)) {
		return 1;
	}
	dbg("missmatch foreign address: %s != %s",
	    INET_NTOP(af, faddr), INET_NTOP(af, &play.faddr));
	return 0;
}

static int
match_ports(be16_t lport, be16_t fport)
{
	if (play.lport != 0 && play.lport != lport) {
		dbg("missmatch local port: %hu != %hu",
		    BE16_TO_CPU(lport), BE16_TO_CPU(play.lport));
		return 0;
	}
	if (play.fport != 0 && play.fport != fport) {
		dbg("missmatch foreign port: %hu != %hu",
		    BE16_TO_CPU(fport), BE16_TO_CPU(play.fport));
		return 0;
	}
	if (play.lport == 0) {
		dbg("set local port: %hu", BE16_TO_CPU(lport));
		play.lport = lport;
	}
	if (play.fport == 0) {
		dbg("set foreign port: %hu", BE16_TO_CPU(fport));
		play.fport = fport;
	}
	return 1;
}

static void
recv_arp(struct pkt *r)
{
//	struct arp_ipv4 *data;

	SET_FLAG(r, ARP);
	if (r->pcb.arp.op == ARP_OP_REQUEST) {
		SET_FLAG(r, ARP_REQUEST);
	} else {
		SET_FLAG(r, ARP_REPLY);
		/*data = &r->pcb.arp.ipv4;
		if (data->tip == play.laddr.ipv4 &&
		    data->sip == play.faddr.ipv4) {
			dev.d_hwaddr = data->sha;
		}*/
	}
}

static void
recv_tcp(struct pkt *r)
{
	SET_FLAG(r, TCP);
	SET_FLAG(r, TCP_SEQ);
	if (r->pcb.tcp.flags & TCP_FLAG_ACK)
		SET_FLAG(r, TCP_ACK);
	SET_FLAG(r, TCP_WIN);
	SET_FLAG(r, TCP_LEN);
	if (r->pcb.tcp.opt.flags) {
		SET_FLAG(r, TCP_OPTS);

		if (test_bit(r->pcb.tcp.opt.flags, TCP_OPT_MSS))
			SET_FLAG(r, TCP_OPT_MSS);

		if (test_bit(r->pcb.tcp.opt.flags, TCP_OPT_WSCALE))
			SET_FLAG(r, TCP_OPT_WSCALE);
	}

	if (play.incoming == 0) {
		play.incoming = 1;
		play.ack_isn = r->pcb.tcp.seq;
	}

	play.ack = r->pcb.tcp.seq + r->pcb.ip.len + tcp_flags_seq(r->pcb.tcp.flags);
}

static int
recv_icmp(struct pkt *r)
{
	SET_FLAG(r, ICMP);
	switch (r->pcb.icmpv4.type) {
	case ICMPV4_TYPE_ECHO:
	case ICMPV4_TYPE_ECHO_REPLY:
		SET_FLAG(r, ICMP_ID);
		SET_FLAG(r, ICMP_SEQ);
		break;

	case ICMPV4_TYPE_DEST_UNREACHABLE:
		switch (r->pcb.icmpv4.code) {
		case ICMPV4_CODE_FRAG_NEEDED_AND_DF_WAS_SET:
			SET_FLAG(r, ICMP_MTU);
			break;
		default:
			return -1;
		}
		break;

	default:
		return -1;
	}

	return 0;
}

static int
process_pkt(struct pkt *r, const uint8_t *data, size_t len)
{
	unsigned int t, ip_h_len;
	const void *ip_h;
	const struct ipv4_hdr *ipv4_h;
	struct proto_cb pcb;

	if (tcp_input(&dev, &pcb, data, len) == NULL) {
		return 0;
	}
	ip_h = data + pcb.l2_len;
	ip_h_len = 0;
	t = get_mseconds();
	r->delay.min = r->delay.max = t - play.time;
	play.time = t;
	r->flags = 0;
	r->dir = PKT_INCOMING;
	r->pcb = pcb;
	SET_FLAG(r, DELAY);
	switch (pcb.eth_type) {
	case ETH_TYPE_ARP:
		recv_arp(r);
		return 1;
	case ETH_TYPE_IPV4:
		if (play.af != AF_INET) {
			return 0;
		}
		SET_FLAG(r, IP);
		SET_FLAG(r, IP_ID);
		SET_FLAG(r, IP_FLAGS);
		SET_FLAG(r, IP_FRAG_OFF);
		SET_FLAG(r, IP_LEN);
		ipv4_h = ip_h;
		ip_h_len = ipv4_hdr_len(ipv4_h->ver_ihl);
		break;
	case ETH_TYPE_IPV6:
		if (play.af != AF_INET6) {
			dbg("2.2");
			return 0;
		}
		SET_FLAG(r, IPV6);
		assert(!"not implemented");
		ip_h_len = 0;
		break;
	default:
		assert(!"not implemented");
		break;
	}
	if (!match_laddr(&pcb.ip.daddr)) {
		return 0;
	}
	if (pcb.ip.proto == IPPROTO_TCP || pcb.ip.proto == IPPROTO_UDP) {
		if (!match_faddr(&pcb.ip.saddr)) {
			return 0;
		}
		if (!match_ports(pcb.tcp.dport, pcb.tcp.sport)) {
			return 0;
		}
	}
	assert(ip_h_len);
	icmp_ip_data_len = ip_h_len + 8;
	memcpy(icmp_ip_data, ip_h, icmp_ip_data_len);
	switch (pcb.ip.proto) {
	case IPPROTO_TCP:
		recv_tcp(r);
		break;
	case IPPROTO_UDP:
		SET_FLAG(r, UDP);
		break;
	case IPPROTO_ICMP:
		if (recv_icmp(r)) {
			return 0;
		}
		break;
	case IPPROTO_ICMPV6:
		return 0;
	default:
		return 0;
	}
	return 1;
}

static int
recv_pkt(struct pkt *r, unsigned int *to)
{
	int len;
	const uint8_t *data;

	memset(r, 0, sizeof(*r));
	while ((len = dev_recv(&dev, &data, to))) {
		if (process_pkt(r, data, len)) {
			if (r->pcb.ip.proto != IPPROTO_TCP) {
				dev_put(data, len);
			}
			return 1;
		} else {
			dev_put(data, len);
		}
	}
	return 0;
}

static void
wait_pkts(unsigned int to)
{
	struct pkt r;

	while (recv_pkt(&r, &to)) {
		print_pkt(&r, 0, 0);
	}
}

static int
set_frag_proto(struct pkt **pkts, int nr_pkts, struct pkt *p)
{
	int i;
	struct pkt *x;

	assert(p->pcb.eth_type == ETH_TYPE_IPV4 && "not implemented");
	if (p->pcb.ip.v4.id == 0 || p->pcb.ip.v4.frag_off == 0) {
		return -EINVAL;
	}
	for (i = 0; i < nr_pkts; ++i) {
		x = pkts[i];
		if (x->pcb.ip.proto && x->pcb.ip.v4.id == p->pcb.ip.v4.id) {
			p->pcb.ip.proto = x->pcb.ip.proto;
			p->pcb.ip.len = x->pcb.ip.len;
			switch (p->pcb.ip.proto) {
			case IPPROTO_TCP:
				p->pcb.tcp = x->pcb.tcp;
				break;
			case IPPROTO_ICMP:
				p->pcb.icmpv4 = x->pcb.icmpv4;
				break;
			case IPPROTO_ICMPV6:
				p->pcb.icmpv6 = x->pcb.icmpv6;
				break;
			default:
				assert(!"not implemented");
				break;
			}
			return 0;
		}
	}
	return -EINVAL;
}

static void
validate_script(struct pkt **pkts, int nr_pkts, const char *filename)
{
	uint8_t pkt_buf[SNAPLEN];
	int i;
	struct pkt *p;

	for (i = 0; i < nr_pkts; ++i) {
		p = pkts[i];
		if (p->dir != PKT_OUTGOING) {
			continue;
		}
		if (p->pcb.ip.proto == 0 && set_frag_proto(pkts, nr_pkts, p)) {
			die(0, "%s:%u: error: proto not specified",
			    filename, p->line_num);
		}
		if (fill_pkt(&dev, pkt_buf, &p->pcb, NULL) < 0) {
			die(0, "%s:%u: error: too long packet", filename, p->line_num);
		}
	}
}

static int
read_script(struct pkt ***ppkts, const char *filename)
{
	char buf[256], eb[ERR_BUF_SIZE];
	char *s;
	int rc, nr_pkts, line_num;
	FILE *file;
	struct pkt *p, **pkts;

	file = fopen(filename, "r");
	if (file == NULL) {
		die(errno, "fopen('%s') failed", filename);
	}
	p = NULL;
	line_num = 0;
	pkts = NULL;
	nr_pkts = 0;
	while ((s = fgets(buf, sizeof(buf), file)) != NULL) {
		++line_num;
		s = skip_spaces(s);
		if (*s == '\0' || *s == '#') {
			continue;
		}
		p = xmalloc_zero(sizeof(*p));
		rc = parse_pkt(p, s, eb);
		if (rc) {
			die(0, "%s:%u: error: %s", filename, line_num, eb);
			free(p);
		}
		p->line_num = line_num;
		pkts = xrealloc(pkts, (nr_pkts + 1) * sizeof(struct pkt *));
		pkts[nr_pkts++] = p;
	}
	validate_script(pkts, nr_pkts, filename);
	if (line_num < 10) {
		line_num_width = 1;
	} else if (line_num < 100) {
		line_num_width = 2;
	} else {
		line_num_width = 3;
	}
	fclose(file);
	*ppkts = pkts;
	return nr_pkts;
}

static int
match_code(struct pkt *p, long m_flags)
{
	return p->flags ^ m_flags;
}

static int
match_pkt(struct pkt *p, struct pkt *r, long *m_flags)
{
	*m_flags = 0;

	if (test_bit(p->flags, NODE_DELAY)) {
		if (p->delay.min == p->delay.max) {
			if (p->delay.min - r->delay.min < PKT_DELAY_DISP) {
				set_bit(m_flags, NODE_DELAY);
			}
		} else {
			if (r->delay.min >= p->delay.min &&
			    r->delay.min <= p->delay.max) {
				set_bit(m_flags, NODE_DELAY);
			}
		}
	}

	match_root(p, r, m_flags);

	return match_code(p, *m_flags);
}

#define ADD_NEW_CHILD(p, type, n, n_name) \
	struct proto_node *node_##n; \
	node_##n = new_node(NODE_##n, n_name, parse_##n, compar_##n, print_##n); \
	add_##type(node_##p, node_##n);

#define ADD_CHILD(p, type, n) \
	add_##type(node_##p, node_##n);

static void
init(struct play_context *cx)
{
	cx->seq_isn = lrand48();
	cx->seq = cx->seq_isn;
	cx->incoming = 0;
	cx->ack_isn = 0;
	cx->ack = 0;
	node_ROOT = new_node(NODE_ROOT, "ROOT", NULL, NULL, NULL);
	ADD_NEW_CHILD(ROOT, proto, IP, "IP");
	ADD_NEW_CHILD(IP, param, IP_ID, "id");
	ADD_NEW_CHILD(IP, param, IP_FLAGS, "flags");
	ADD_NEW_CHILD(IP, param, IP_FRAG_OFF, "offset");
	ADD_NEW_CHILD(IP, param, IP_LEN, "length");
	ADD_NEW_CHILD(ROOT, proto, ARP, "ARP");
	ADD_NEW_CHILD(ARP, proto, ARP_REQUEST, "Request");
	ADD_NEW_CHILD(ARP, proto, ARP_REPLY, "Reply");
	ADD_NEW_CHILD(IP, proto, TCP, "Flags");
	ADD_NEW_CHILD(IP, proto, ICMP, "ICMP");
	ADD_NEW_CHILD(ICMP, param, ICMP_MTU, "mtu");
	ADD_NEW_CHILD(ICMP, param, ICMP_ID, "id");
	ADD_NEW_CHILD(ICMP, param, ICMP_SEQ, "seq");
	ADD_NEW_CHILD(TCP, param, TCP_SEQ, "seq");
	ADD_NEW_CHILD(TCP, param, TCP_ACK, "ack");
	ADD_NEW_CHILD(TCP, param, TCP_WIN, "win");
	ADD_NEW_CHILD(TCP, param, TCP_OPTS, "options");
	ADD_NEW_CHILD(TCP, param, TCP_LEN, "length");
	ADD_NEW_CHILD(TCP_OPTS, param, TCP_OPT_MSS, "mss");
	ADD_NEW_CHILD(TCP_OPTS, param, TCP_OPT_WSCALE, "wscale");
	ADD_NEW_CHILD(TCP_OPTS, param, TCP_OPT_SACK_PERMITED, "sackOK");
	node_IPVX = node_IP;
}

static int
test_proto(struct pkt *r, long flags)
{
	int proto_flag;

	if (r->pcb.eth_type == ETH_TYPE_ARP) {
		proto_flag = NODE_ARP;
	} else {
		switch (r->pcb.ip.proto) {
		case IPPROTO_ICMP:
			proto_flag = NODE_ICMP;
			break;
		case IPPROTO_ICMPV6:
			proto_flag = NODE_ICMPV6;
			break;
		case IPPROTO_TCP:
			proto_flag = NODE_TCP;
			break;
		default:
			return 0;
		}
	}
	return test_bit(flags, proto_flag);
}

static void
print_matching_pkt(struct pkt *p, struct pkt *r, long m_flags)
{
	r->line_num = p->line_num;
	r->print_ip = p->print_ip;
	r->req = p->req;

	if (verbose == 0) {
		if (match_code(p, m_flags) == 0)
			r->flags = p->flags;
	}

	print_pkt(r, p->flags, m_flags);
}

static void
play_outgoing(struct pkt *p)
{
	long flags;

	flags = p->flags;

	if (test_bit(flags, NODE_IP)) {
		if (!set_bit(&flags, NODE_IP_ID)) {
			p->pcb.ip.v4.id = play.ip_id++;
		}
		if (!set_bit(&flags, NODE_IP_FLAGS)) {
			p->pcb.ip.v4.flags = IPV4_FLAG_DF;
		}
		if (!set_bit(&flags, NODE_IP_FRAG_OFF)) {
			p->pcb.ip.v4.frag_off = 0;
		}
		if (!set_bit(&flags, NODE_IP_LEN)) {
			p->pcb.ip.v4.len = 0;
		}
	}
	if (test_bit(flags, NODE_TCP)) {
		if (!set_bit(&flags, NODE_TCP_LEN)) {
			p->pcb.ip.len = 0;
		}
		if (set_bit(&flags, NODE_TCP_SEQ)) {
			p->pcb.tcp.seq += play.seq_isn;
		} else {
			p->pcb.tcp.seq = play.seq;
		}
		play.seq = p->pcb.tcp.seq + p->pcb.ip.len + tcp_flags_seq(p->pcb.tcp.flags);
		if (p->pcb.tcp.flags & TCP_FLAG_ACK) {
			if (set_bit(&flags, NODE_TCP_ACK)) {
				p->pcb.tcp.ack += play.ack_isn;
			} else {
				p->pcb.tcp.ack = play.ack;
			}
		}
		if (!set_bit(&flags, NODE_TCP_WIN)) {
			p->pcb.tcp.win = 29200;
		}
	}
	send_pkt(p);
	if (verbose > 0) {
		p->flags = flags;
	}
	print_pkt(p, 0, 0);
}

static int
recv_pkts_play_outgoing(struct pkt **pkts, int nr_pkts)
{
	int i, color;
	unsigned int to;
	long m_flags;
	struct pkt r, *p, *o_p;

	assert(nr_pkts);
	o_p = pkts[nr_pkts - 1];
	--nr_pkts;
	if (o_p->delay.min < 0) {
		goto out;
	}
	to = o_p->delay.min;
	i = 0;
	while (recv_pkt(&r, &to)) {
		if (!test_proto(&r, o_p->flags)) {
			print_pkt(&r, 0, 0);
			continue;
		}
		for (; i < nr_pkts; ++i) {
			p = pkts[i];
			if (match_pkt(p, &r, &m_flags) == 0) {
				break;
			}
		}
		if (i == nr_pkts) {
			color = print_color(COLOR_RED);
			print_pkt(&r, 0, 0);
			unset_color(color);
			return -EINVAL;
		}
	}
out:
	play_outgoing(o_p);
	return 0;
}

static int
recv_pkts_play_incoming(struct pkt **pkts, int nr_pkts)
{
	int i, color;
	unsigned int to, delay;
	long m_flags;
	struct pkt r, *p, *i_p;

	assert(nr_pkts);
	i_p = pkts[nr_pkts - 1];
	to = delay = i_p->delay.max;
	i = 0;
	while (recv_pkt(&r, &to)) {
		if (!test_proto(&r, i_p->flags)) {
			print_pkt(&r, 0, 0);
			continue;
		}
		p = NULL;
		for (; i < nr_pkts; ++i) {
			p = pkts[i];
			if (match_pkt(p, &r, &m_flags) == 0) {
				break;
			}
		}
		print_matching_pkt(p, &r, m_flags);
		if (i == nr_pkts) {
			return -1;
		}
		++i;
		if (i == nr_pkts) {
			return 0;
		}
	}
	color = print_color(COLOR_RED);
	outf("[>%d]\n", delay);
	unset_color(color);
	return -1;
}

static int
play_script(struct pkt **pkts, int nr_pkts)
{
	int i, j;
	struct pkt *p;

	play.time = get_mseconds();
	for (i = 0, j = 0; i < nr_pkts; ++i) {
		p = pkts[i];
		if (p->req != PKT_MANDATORY) {
			continue;
		}
		if (p->dir == PKT_INCOMING) {
			if (recv_pkts_play_incoming(pkts + j, i - j + 1)) {
				return -1;
			}
		} else {
			if (recv_pkts_play_outgoing(pkts + j, i - j + 1)) {
				return -1;
			}
		}
		j = i + 1;
	}
	return 0;
}

static void
invalid_argument(int opt, const char *val)
{
	die(0, "Invalid argument '-%c': %s", opt, val);
}

static void
option_not_specified(int opt)
{
	die(0, "Option '-%c' not specified", opt);
}

static int
print_usage()
{
	printf(
	"Usage: tcpkt [options] {-i interface}\n"
	"             {-l ip[:port]} {-f ip[:[prt]} {script}\n"
	"\n"
	"\tOptions:\n"
	"\t-h            Print this help\n"
	"\t-v            Be verbose\n"
	"\t-q            Be quiet\n"
	"\t-d            Print debug messages\n"
	"\t-C            Color output\n"
	"\t-L            Print line numbers\n"
	"\t-A            Print absolute seq\n"
	"\t-P            Match tcp PSH flag\n"
	"\t-w            Time in ms to wait before quit (0 - don't quit)\n"
	"\t-i interface  Specify interface\n"
	"\t-S hw-addr    Specify source ethernet address\n"
	"\t-D hw-addr    Specify destination ethernet address\n"
	"\t-l ip[:port]  Specify local ip (port)\n"
	"\t-f ip[:port]  Specify foreign ip (port)\n"
	);
	return 4;
}

int
main(int argc, char **argv)
{
	int rc, af, opt, nr_pkts, failed, wait_ms;
	const char *ifname, *filename;
	struct pkt **pkts;

	play.af = af = AF_INET;
	wait_ms = 0;
	ifname = NULL;
	eth_aton(&dev.s_hwaddr, "00:00:00:00:00:00");
	eth_aton(&dev.d_hwaddr, "ff:ff:ff:ff:ff:ff");
	while ((opt = getopt(argc, argv, "hvqdCLAPw:i:S:D:l:f:")) != -1) {
		switch (opt) {
		case 'h':
			return print_usage();
		case 'v':
			verbose++;
			break;
		case 'q':
			quiet = 1;
			break;
		case 'd':
			debuging = 1;
			break;
		case 'C':
			use_color = 1;
			break;
		case 'L':
			use_line_num = 1;
			break;
		case 'A':
			abs_seq = 1;
			break;
		case 'P':
			match_tcp_flags_mask |= TCP_FLAG_PSH;
			break;
		case 'w':
			wait_ms = strtoul(optarg, NULL, 10);
			if (wait_ms == 0) {
				wait_ms = -1;
			}
			break;
		case 'i':
			ifname = optarg;
			break;
		case 'S':
			rc = eth_aton(&dev.s_hwaddr, optarg);
			if (rc) {
				invalid_argument(opt, optarg);
			}
			break;
		case 'D':
			rc = eth_aton(&dev.d_hwaddr, optarg);
			if (rc) {
				invalid_argument(opt, optarg);
			}
			break;
		case 'l':
			rc = ipport_pton(af, optarg, &play.laddr, &play.lport);
			if (rc) {
				invalid_argument(opt, optarg);
			}
			break;
		case 'f':
			rc = ipport_pton(af, optarg, &play.faddr, &play.fport);
			if (rc) {
				invalid_argument(opt, optarg);
			}
			break;
		}
	}
	if (ifname == NULL) {
		option_not_specified('i');
	}
	if (ipaddr_is_zero(af, &play.laddr)) {
		option_not_specified('l');
	}
	if (ipaddr_is_zero(af, &play.faddr)) {
		option_not_specified('f');
	}
	if (optind == argc) {
		return print_usage();
	}
	if (quiet) {
		use_color = 0;
	}
	filename = argv[optind];
	dev_init(&dev, ifname);
	srand48(time(NULL) & getpid());
	init(&play);
	nr_pkts = read_script(&pkts, filename);
	failed = play_script(pkts, nr_pkts);
	if (wait_ms) {
		wait_pkts(wait_ms);
	}
	return failed ? 3 : 0;
}
