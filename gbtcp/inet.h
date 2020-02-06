#ifndef GBTCP_INET_H
#define GBTCP_INET_H

#include "route.h"

#define GT_ETH_TYPE_IP4 0x0800
#define GT_ETH_TYPE_IP4_BE GT_HTON16(GT_ETH_TYPE_IP4)
#define GT_ETH_TYPE_IP6 0x86DD
#define GT_ETH_TYPE_IP6_BE GT_HTON16(GT_ETH_TYPE_IP6)
#define GT_ETH_TYPE_ARP 0x0806
#define GT_ETH_TYPE_ARP_BE GT_HTON16(GT_ETH_TYPE_ARP)

#define GT_ARP_HRD_ETH 1
#define GT_ARP_HRD_ETH_BE GT_HTON16(GT_ARP_HRD_ETH)

#define GT_ARP_OP_REQUEST 1
#define GT_ARP_OP_REQUEST_BE GT_HTON16(GT_ARP_OP_REQUEST)
#define GT_ARP_OP_REPLY 2
#define GT_ARP_OP_REPLY_BE GT_HTON16(GT_ARP_OP_REPLY)

#define GT_IP4_MTU_MIN 68

#define GT_IP4H_VER_IHL (0x40|0x05)
#define GT_IP4H_FRAG_MASK 0xFF3F

#define GT_IP4H_FLAG_DF (1 << 6)
#define GT_IP4H_FLAG_MF (1 << 5)

#define GT_IP6_MTU_GT_MIN 1280

#define GT_IP6H_VER_TC_FL 0x60

#define GT_TCP_FLAG_FIN 0x01
#define GT_TCP_FLAG_SYN 0x02
#define GT_TCP_FLAG_RST 0x04
#define GT_TCP_FLAG_PSH 0x08
#define GT_TCP_FLAG_ACK 0x10
#define GT_TCP_FLAG_URG 0x20

#define GT_TCP_OPT_EOL 0 
#define GT_TCP_OPT_NOP 1
#define GT_TCP_OPT_MSS 2 
#define GT_TCP_OPT_WSCALE 3
#define GT_TCP_OPT_SACK_PERMITED 4
#define GT_TCP_OPT_TIMESTAMPS 8
#define GT_TCP_OPT_MAX 9

#define GT_INET_OK 0
#define GT_INET_DROP 1
#define GT_INET_BYPASS 2
#define GT_INET_BCAST 3

struct gt_eth_hdr {
	struct gt_eth_addr ethh_daddr;
	struct gt_eth_addr ethh_saddr;
	be16_t ethh_type;
} __attribute__((packed));

struct gt_ip4_hdr {
	uint8_t ip4h_ver_ihl;
	uint8_t ip4h_type_of_svc;
	be16_t ip4h_total_len;
	be16_t ip4h_id;
	be16_t ip4h_frag_off;
	uint8_t ip4h_ttl;
	uint8_t ip4h_proto;
	uint16_t ip4h_cksum;
	be32_t ip4h_saddr;
	be32_t ip4h_daddr;
} __attribute__((packed));

struct gt_ip6_hdr {
	be32_t ip6h_ver_tc_fl;
	be16_t ip6h_payload_len;
	uint8_t ip6h_next_hdr;
	uint8_t ip6h_hop_limit;
	uint8_t ip6h_saddr[GT_IP6_ADDR_LEN];
	uint8_t ip6h_daddr[GT_IP6_ADDR_LEN];
} __attribute__((packed));

struct gt_udp_hdr {
	be16_t udph_sport;
	be16_t udph_dport;
	be16_t udph_len;
	uint16_t udph_cksum;
} __attribute__((packed));

struct gt_tcp_hdr {
	be16_t tcph_sport;
	be16_t tcph_dport;
	be32_t tcph_seq;
	be32_t tcph_ack;
	uint8_t tcph_data_off;
	uint8_t tcph_flags;
	be16_t tcph_win_size;
	uint16_t tcph_cksum;
	be16_t tcph_urgent_ptr;
} __attribute__((packed));

struct gt_icmp4_hdr {
	uint8_t icmp4h_type;
	uint8_t icmp4h_code;
	uint16_t icmp4h_cksum;
	union {
		uint32_t icmp4h_unused;
		struct {
			be16_t icmp4echo_id;
			be16_t icmp4echo_seq;
		} icmp4h_echo;
		struct {
			uint8_t icmp4ppm_ptr;
			uint8_t icmp4ppm_unused[3];
		} icmp4h_ppm; // Parameter Problem Message
		struct {
 			be16_t icmp4ptb_unused;
			be16_t icmp4ptb_mtu;
		} icmp4h_ptb; // Packet Too Big
	};
} __attribute__((packed));

struct gt_icmp6_hdr {
	uint8_t icmp6h_type;
	uint8_t icmp6h_code;
	uint16_t icmp6h_cksum;
} __attribute__((packed));

struct gt_icmp6_opt_hdr {
	uint8_t icmp6oh_type;
	uint8_t icmp6oh_len;
} __attribute__((packed));

struct gt_icmp6_opt {
	uint8_t icmp6o_type;
	uint8_t icmp6o_len;
	struct gt_eth_addr icmp6o_lladdr;
} __attribute__((packed));

struct icmp6_nd {
	uint8_t icmp6nd_flags;
	uint32_t icmp6nd_reserved : 24;
	uint8_t icmp6nd_target[GT_IP6_ADDR_LEN];
} __attribute__((packed));

struct gt_arp_ip4 {
	struct gt_eth_addr arpip_sha;
	be32_t arpip_sip;
	struct gt_eth_addr arpip_tha;
	be32_t arpip_tip;
} __attribute__((packed));

struct gt_arp_hdr {
	be16_t arph_hrd;
	be16_t arph_pro;
	uint8_t arph_hlen;
	uint8_t arph_plen;
	be16_t arph_op;
	struct gt_arp_ip4 arph_data;
} __attribute__((packed));

struct gt_tcp_opt_ts {
	uint32_t tcpots_val;
	uint32_t tcpots_ecr;
};

struct gt_tcp_opts {
	int tcpo_flags;
	uint16_t tcpo_mss;
	uint8_t tcpo_wscale;
	struct gt_tcp_opt_ts tcpo_ts;
};

struct gt_tcpcb {
	uint16_t tcb_win;
	uint16_t tcb_len;
	uint8_t tcb_flags;
	uint32_t tcb_seq;
	uint32_t tcb_ack;
	struct gt_tcp_opts tcb_opts;
};

struct gt_inet_context {
	struct gt_route_if *inp_ifp;
	uint8_t *inp_cur;
	int inp_rem;
	int inp_eno;
	struct gt_eth_hdr *inp_eth_h;
	struct gt_arp_hdr *inp_arp_h;
	struct gt_ip4_hdr *inp_ip4_h;
	int inp_ip_h_len;
	uint16_t inp_ip_payload_len;
	uint8_t inp_ipproto;
	uint8_t inp_emb_ipproto;
	int inp_tcp_h_len;
	struct gt_tcpcb inp_tcb;
	union {
		struct gt_udp_hdr *inp_udp_h;
		struct gt_tcp_hdr *inp_tcp_h;
		struct gt_icmp4_hdr *inp_icmp4_h;
	};
	struct gt_ip4_hdr *inp_emb_ip4_h;
	union {
		struct gt_udp_hdr *inp_emb_udp_h;
		struct gt_tcp_hdr *inp_emb_tcp_h;
		struct gt_icmp4_hdr *inp_emb_icmp4_h;
	};
	void *inp_payload;
};

#define GT_INET_TCP_STAT_VAR(n) uint64_t tcps_##n;
struct gt_tcp_stat {
	GT_TCP_STAT(GT_INET_TCP_STAT_VAR)
	uint64_t tcps_states[GT_TCP_NSTATES];
};
#undef GT_INET_TCP_STAT_VAR

#define GT_INET_UDP_STAT_VAR(n) uint64_t udps_##n;
struct gt_udp_stat {
	GT_UDP_STAT(GT_INET_UDP_STAT_VAR)
};
#undef GT_INET_UDP_STAT_VAR

#define GT_INET_IP_STAT_VAR(n) uint64_t ips_##n;
struct gt_ip_stat {
	GT_IP_STAT(GT_INET_IP_STAT_VAR)
};
#undef GT_INET_IP_STAT_VAR

#define GT_INET_ICMP_STAT_VAR(n) uint64_t icmps_##n;
struct gt_icmp_stat {
	GT_ICMP_STAT(GT_INET_ICMP_STAT_VAR)
	uint64_t icmps_inhist[ICMP_MAXTYPE + 1];
};
#undef GT_INET_ICMP_STAT_VAR

#define GT_INET_ARP_STAT_VAR(n) uint64_t arps_##n;
struct gt_arp_stat {
	GT_ARP_STAT(GT_INET_ARP_STAT_VAR)
};
#undef GT_INET_ARP_STAT_VAR

extern struct gt_tcp_stat gt_tcps;
extern struct gt_udp_stat gt_udps;
extern struct gt_ip_stat gt_ips;
extern struct gt_icmp_stat gt_icmps;
extern struct gt_arp_stat gt_arps;

#define GT_IP4_HDR_LEN(ver_ihl)	(((ver_ihl) & 0x0f) << 2)

#define GT_TCP_HDR_LEN(data_off) ((data_off & 0xf0) >> 2)

int gt_inet_mod_init();

void gt_inet_mod_deinit(struct gt_log *log);

int gt_inet_eth_in(struct gt_inet_context *ctx, struct gt_route_if *ifp,
	void *buf, int cnt);

void gt_inet_ip4_set_cksum(struct gt_ip4_hdr *ip4_h, void *l4_h);

int gt_tcp_opts_fill(struct gt_tcp_opts *opt, void *buf);

int gt_tcp_opts_len(struct gt_tcp_opts *opt);

#endif /* GBTCP_INET_H */
