// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_INET_H
#define GBTCP_INET_H

#include "route.h"

#define ETH_TYPE_IP4 0x0800
#define ETH_TYPE_IP4_BE hton16(ETH_TYPE_IP4)
#define ETH_TYPE_IP6 0x86DD
#define ETH_TYPE_IP6_BE hton16(ETH_TYPE_IP6)
#define ETH_TYPE_ARP 0x0806
#define ETH_TYPE_ARP_BE hton16(ETH_TYPE_ARP)

#define ARP_HRD_ETH 1
#define ARP_HRD_ETH_BE hton16(ARP_HRD_ETH)

#define ARP_OP_REQUEST 1
#define ARP_OP_REQUEST_BE hton16(ARP_OP_REQUEST)
#define ARP_OP_REPLY 2
#define ARP_OP_REPLY_BE hton16(ARP_OP_REPLY)

#define GT_IP4_VER 4

#define IP4_MTU_MIN 68

#define IP4_VER_IHL (0x40|0x05)
#define IP4_FRAG_MASK 0xFF3F

#define IP4H_FLAG_DF (1 << 6)
#define IP4H_FLAG_MF (1 << 5)

#define IP6_MTU_MIN 1280

#define IP6H_VER_TC_FL 0x60

#define GT_TCPF_FIN 0x01
#define GT_TCPF_SYN 0x02
#define GT_TCPF_RST 0x04
#define GT_TCPF_PSH 0x08
#define GT_TCPF_ACK 0x10
#define GT_TCPF_URG 0x20

#define TCP_OPT_EOL 0 
#define TCP_OPT_NOP 1
#define TCP_OPT_MSS 2 
#define TCP_OPT_WSCALE 3
#define TCP_OPT_SACK_PERMITED 4
#define TCP_OPT_TIMESTAMPS 8
#define TCP_OPT_MAX 9

#define IN_OK -1
#define IN_BYPASS -2

#define GT_INET_PARSER_SHIFT(in, size) \
	do { \
		in->in_cur += size; \
		in->in_rem -= size; \
	} while (0)

struct eth_hdr {
	struct eth_addr eh_daddr;
	struct eth_addr eh_saddr;
	be16_t eh_type;
} __attribute__((packed));

struct ip4_hdr {
	uint8_t ih_ver_ihl;
	uint8_t ih_tos;
	be16_t ih_total_len;
	be16_t ih_id;
	be16_t ih_frag_off;
	uint8_t ih_ttl;
	uint8_t ih_proto;
	uint16_t ih_cksum;
	be32_t ih_saddr;
	be32_t ih_daddr;
} __attribute__((packed));

struct ip6_hdr {
	be32_t ih6_ver_tc_fl;
	be16_t ih6_payload_len;
	uint8_t ih6_next_hdr;
	uint8_t ih6_hop_limit;
	uint8_t ih6_saddr[IP6ADDR_LEN];
	uint8_t ih6_daddr[IP6ADDR_LEN];
} __attribute__((packed));

struct udp_hdr {
	be16_t uh_sport;
	be16_t uh_dport;
	be16_t uh_len;
	uint16_t uh_cksum;
} __attribute__((packed));

struct tcp_hdr {
	be16_t th_sport;
	be16_t th_dport;
	be32_t th_seq;
	be32_t th_ack;
	uint8_t th_data_off;
	uint8_t th_flags;
	be16_t th_win_size;
	uint16_t th_cksum;
	be16_t th_urgent_ptr;
} __attribute__((packed));

struct icmp4_hdr {
	uint8_t icmp_type;
	uint8_t icmp_code;
	uint16_t icmp_cksum;
	union {
		uint32_t icmp_unused;
		struct {
			be16_t icmp_echo_id;
			be16_t icmp_echo_seq;
		} icmp4h_echo;
		struct {
			uint8_t icmp_ppm_ptr;
			uint8_t icmp_ppm_unused[3];
		} icmp4h_ppm; // Parameter Problem Message
		struct {
 			be16_t icmp_ptb_unused;
			be16_t icmp_ptb_mtu;
		} icmp4h_ptb; // Packet Too Big
	};
} __attribute__((packed));

struct arp_ip4 {
	struct eth_addr aip_sha;
	be32_t aip_sip;
	struct eth_addr aip_tha;
	be32_t aip_tip;
} __attribute__((packed));

struct arp_hdr {
	be16_t ah_hrd;
	be16_t ah_pro;
	uint8_t ah_hlen;
	uint8_t ah_plen;
	be16_t ah_op;
	struct arp_ip4 ah_data;
} __attribute__((packed));

struct tcp_opt_ts {
	uint32_t tcp_ts_val;
	uint32_t tcp_ts_ecr;
};

struct tcp_opts {
	int tcp_opt_flags;
	uint16_t tcp_opt_mss;
	uint8_t tcp_opt_wscale;
	struct tcp_opt_ts tcp_opt_ts;
};

#define TCP_STAT_DECLARE(n) uint64_t tcps_##n;
struct tcp_stat {
	GT_X_TCP_STAT(TCP_STAT_DECLARE)
	uint64_t tcps_states[GT_TCPS_MAX_STATES];
};
#undef TCP_STAT_DECLARE

#define UDP_STAT_DECLARE(n) uint64_t udps_##n;
struct udp_stat {
	GT_X_UDP_STAT(UDP_STAT_DECLARE)
};
#undef UDP_STAT_DECLARE

#define IP_STAT_DECLARE(n) uint64_t ips_##n;
struct ip_stat {
	GT_X_IP_STAT(IP_STAT_DECLARE)
};
#undef IP_STAT_DECLARE

#define ICMP_STAT_DECLARE(n) uint64_t icmps_##n;
struct icmp_stat {
	GT_X_ICMP_STAT(ICMP_STAT_DECLARE)
	uint64_t icmps_inhist[ICMP_MAXTYPE + 1];
};
#undef ICMP_STAT_DECLARE

#define ARP_STAT_DECLARE(n) uint64_t arps_##n;
struct arp_stat {
	GT_X_ARP_STAT(ARP_STAT_DECLARE)
};
#undef ARP_STAT_DECLARE

struct in_context {
	struct route_if *in_ifp;
	u_char *in_cur;
	int in_rem;
	int in_errnum;
	struct eth_hdr *in_eh;
	struct arp_hdr *in_ah;
	struct ip4_hdr *in_ih;
	int in_ih_len;
	uint16_t in_ip_payload_len;
	uint8_t in_ipproto;
	uint8_t in_emb_ipproto;
	int in_th_len;
	u_char in_events;
	uint16_t in_tcp_win;
	uint16_t in_len;
	uint8_t in_tcp_flags;
	uint32_t in_tcp_seq;
	uint32_t in_tcp_ack;
	struct tcp_opts in_tcp_opts;
	union {
		struct udp_hdr *in_uh;
		struct tcp_hdr *in_th;
		struct icmp4_hdr *in_icp;
	};
	struct ip4_hdr *in_emb_ih;
	union {
		struct udp_hdr *in_emb_uh;
		struct tcp_hdr *in_emb_th;
		struct icmp4_hdr *in_emb_icp;
	};
	u_char *in_payload;
};

#define IP4_HDR_LEN(ver_ihl) (((ver_ihl) & 0x0f) << 2)
#define IP4_HDR_VER(ver_ihl) ((ver_ihl) & 0xf0)

#define TCP_HDR_LEN(data_off) ((data_off & 0xf0) >> 2)

int inet_mod_init(void);

void in_context_init(struct in_context *, void *, int);
int eth_input(struct in_context *);
void ip4_set_cksum(struct ip4_hdr *, void *);
int gt_ip4_validate_cksum(struct ip4_hdr *);
int gt_tcp_validate_cksum(struct ip4_hdr *, struct tcp_hdr *, int);
int tcp_opts_fill(struct tcp_opts *, void *);
int tcp_opts_len(struct tcp_opts *);

#endif // GBTCP_INET_H
