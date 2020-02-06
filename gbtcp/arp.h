#ifndef GBTCP_ARP_H
#define GBTCP_ARP_H

#include "mbuf.h"
#include "ip_addr.h"

struct gt_route_if;
struct gt_arp_hdr;
struct gt_dev_pkt;

struct gt_arp_advert_msg {
	int arpam_af;
	be32_t arpam_next_hop;
	struct gt_eth_addr arpam_addr;
	int arpam_advert;
	int arpam_solicited;
	int arpam_override;
};

int gt_arp_mod_init();

void gt_arp_mod_deinit(struct gt_log *log);

void gt_arp_resolve(struct gt_route_if *ifp, be32_t next_hop,
	struct gt_dev_pkt *pkt);

void gt_arp_update(struct gt_arp_advert_msg *msg);

int gt_arp_add(be32_t next_hop, struct gt_eth_addr *addr);

void gt_arp_reply(struct gt_route_if *ifp, struct gt_arp_hdr *in_arp_h);

#endif /* GBTCP_ARP_H */
