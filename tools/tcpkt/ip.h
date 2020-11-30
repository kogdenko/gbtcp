#ifndef TCPKT_IP_H
#define TCPKT_IP_H

#include "core.h"

#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_IPV4_BE CPU_TO_BE16(ETH_TYPE_IPV4)
#define ETH_TYPE_IPV6 0x86DD
#define ETH_TYPE_IPV6_BE CPU_TO_BE16(ETH_TYPE_IPV6)
#define ETH_TYPE_ARP  0x0806
#define ETH_TYPE_ARP_BE  CPU_TO_BE16(ETH_TYPE_ARP)

#define ARP_HRD_ETH 1 
#define ARP_HRD_ETH_BE CPU_TO_BE16(ARP_HRD_ETH)
 
#define ARP_OP_REQUEST 1
#define ARP_OP_REQUEST_BE CPU_TO_BE16(ARP_OP_REQUEST)
#define ARP_OP_REPLY 2
#define ARP_OP_REPLY_BE CPU_TO_BE16(ARP_OP_REPLY)

#define IPV4_VER_IHL (0x40|0x05)

#define IPV4_FLAG_DF (1 << 6)
#define IPV4_FLAG_MF (1 << 5)

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

#define TCP_FLAG_CHRISTMAS_TREE (\
	TCP_FLAG_FIN|TCP_FLAG_SYN|TCP_FLAG_RST|\
	TCP_FLAG_PSH|TCP_FLAG_ACK|TCP_FLAG_URG)

#define TCP_OPT_EOL 0
#define TCP_OPT_NOP 1
#define TCP_OPT_MSS 2
#define TCP_OPT_WSCALE 3
#define TCP_OPT_SACK_PERMITED 4
#define TCP_OPT_TIMESTAMPS 8
#define TCP_OPT_MAX 9

#define TCP_HDR_LEN_MAX 60

#define ICMPV4_TYPE_ECHO_REPLY 0

#define ICMPV4_TYPE_DEST_UNREACHABLE 3
#define ICMPV4_CODE_NET_UNREACHANLE 0
#define ICMPV4_CODE_HOST_UNREACHABLE 1
#define ICMPV4_CODE_PROTO_UNREACHABLE 2
#define ICMPV4_CODE_PORT_UNREACHABLE 3
#define ICMPV4_CODE_FRAG_NEEDED_AND_DF_WAS_SET 4
#define ICMPV4_CODE_SRC_ROUTE_FAILED 5
#define ICMPV4_CODE_DEST_NET_UNKNOWN 6
#define ICMPV4_CODE_DEST_HOST_UNKNOWN 7
#define ICMPV4_CODE_SRC_HOST_ISOLATED 8
#define ICMPV4_CODE_COMMUNICATION_WITH_DEST_NET_IS_ADMIN_PROHIBITED 9
#define ICMPV4_CODE_COMMUNICATION_WITH_DEST_HOST_IS_ADMIN_PROHIBITED 10
#define ICMPV4_CODE_DEST_NET_UNREACHABLE_FOR_TYPE_OF_SVC 11
#define ICMPV4_CODE_DEST_HOST_UNREACHABLE_FOR_TYPE_OF_SVC 12
#define ICMPV4_CODE_COMMUNICATION_ADMINISTRATIVELY_PROHIBITED 13
#define ICMPV4_CODE_HOST_PRECEDENCE_VIOLATION 14
#define ICMPV4_CODE_PRECEDENCE_CUTOFF_IN_EFFECT 15

#define ICMPV4_TYPE_ECHO 8

#define ICMPV4_TYPE_TIME_EXCEEDED 11

#define ICMPV4_TYPE_PARAM_PROBLEM 12
#define ICMPV4_CODE_POINTER_INDICATES_THE_ERR 0
#define ICMPV4_CODE_MISSING_A_REQUIRED_OPT 1
#define ICMPV4_CODE_BAD_LEN 2

#define SNAPLEN 262144

struct eth_hdr {
	struct eth_addr daddr;
	struct eth_addr saddr;
	be16_t type;
} __attribute__((packed));

struct arp_ipv4 {
	struct eth_addr sha;
	be32_t sip;
	struct eth_addr tha;
	be32_t tip;
} __attribute__((packed));

struct arp_hdr {
	be16_t hrd;
	be16_t pro;
	uint8_t hlen;
	uint8_t plen;
	be16_t op;
	struct arp_ipv4 data;
} __attribute__((packed));

struct ipv4_hdr {
	uint8_t ver_ihl;
	uint8_t type_of_svc;
	be16_t total_len;
	be16_t id;
	be16_t frag_off;
	uint8_t ttl;
	uint8_t proto;
	uint16_t cksum;
	be32_t saddr;
	be32_t daddr;
} __attribute__((packed));

struct tcp_hdr {
	be16_t sport;
	be16_t dport;
	be32_t seq;
	be32_t ack;
	uint8_t data_off;
	uint8_t flags;
	be16_t win_size;
	uint16_t cksum;
	be16_t urgent_ptr;
} __attribute__((packed));

struct icmpv4_hdr {
	uint8_t  type;
	uint8_t  code;
	uint16_t cksum;
	union {
		uint32_t unused;
		struct {
			be16_t id;
			be16_t seq;
		} echo;
		struct {
			uint8_t ptr;
			uint8_t unused[3];
		} ppm; // Parameter Problem Message
		struct {
 			be16_t unused;
			be16_t mtu;
		} ptb; // Packet Too Big
	};
} __attribute__((packed));

struct ipv4_pseudo_hdr {
	be32_t saddr;
	be32_t daddr;
	uint8_t pad;
	uint8_t proto;
	be16_t len;
} __attribute__((packed));

struct tcp_opt_ts {
	uint32_t val;
	uint32_t ecr;
};

struct tcp_opt {
	long flags;
	uint16_t mss;
	uint8_t wscale;
	uint8_t sack_permited;
	struct tcp_opt_ts ts;
};

struct tcp_opt_field {
	uint8_t kind;
	uint8_t len;
	const char *name;
};

struct ipv4_cb {
	uint16_t id;
	uint8_t flags;
	uint16_t frag_off;
	uint16_t len;
};

struct ipv6_cb {
};

struct tcp_cb {
	be16_t sport;
	be16_t dport;
	struct tcp_opt opt;
	uint8_t flags;
	uint16_t win;
	uint32_t seq;
	uint32_t ack;
};

struct icmpv4_cb {
	uint8_t type;
	uint8_t code;
	union {
		struct {
			uint16_t id;
			uint16_t seq;
		} echo;
		struct {
			uint8_t ptr;	
		} ppm;
		struct {
			uint16_t mtu;
		} ptb;
	};
};

struct icmpv6_cb {
};

struct proto_cb {
	int l2_len;
	uint16_t eth_type;
	struct eth_addr eth_saddr;
	struct eth_addr eth_daddr;
	union {
		struct {
			ipaddr_t saddr;
			ipaddr_t daddr;
			int proto;
			int len;
			union {
				struct ipv4_cb v4;
				struct ipv6_cb v6;
			};
		} ip;
		struct {
			int op;
			struct arp_ipv4 ipv4;
		} arp;
	};
	union {
		struct tcp_cb tcp;
		struct icmpv4_cb icmpv4;
		struct icmpv6_cb icmpv6;
	};
};

struct if_dev {
	struct eth_addr s_hwaddr;
	struct eth_addr d_hwaddr;
	int ifindex;
	char ifname[16 + IFNAMSIZ];

};

unsigned int get_mseconds();

const struct tcp_opt_field *find_tcp_opt_field(unsigned int kind);
const struct tcp_opt_field *tcp_opt_field(unsigned int field_id);

size_t ipv4_hdr_len(uint8_t ver_ihl);
size_t tcp_hdr_len(uint8_t data_off);

void dev_init(struct if_dev *dev, const char *ifname);
int dev_recv(struct if_dev *dev, const uint8_t **data, unsigned int *to);
void dev_send(struct if_dev *dev, const struct sockaddr_in *addr,
              const void *buf, size_t count);
void dev_put(const void *buf, size_t count);
int fill_pkt(struct if_dev *dev, void *buf, struct proto_cb *pcb, const uint8_t *payload);
int fill_arp_request(uint8_t *buf, struct eth_addr *eth_saddr, be32_t saddr, be32_t daddr);

const void *tcp_input(struct if_dev *dev, struct proto_cb *pcb, const uint8_t *buf, size_t n);

#endif /* TCPKT_IP_H */
