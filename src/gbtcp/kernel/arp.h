// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_ARP_H
#define GBTCP_ARP_H

#include <gbtcp/kernel/subr.h>

struct arp_hdr;
struct dev_pkt;
struct route_entry;
struct route_if;
struct service;
struct gt_timer;

struct arp_advert {
	int arpa_af;
	be32_t arpa_next_hop;
	struct gt_eth_addr arpa_addr;
	int arpa_advert;
	int arpa_solicited;
	int arpa_override;
};

int gt_arp_init(void);
void gt_arp_deinit(void);
int service_init_arp(struct service *);
void service_deinit_arp(struct service *);

void arp_resolve(struct route_entry *, struct dev_pkt *);
void arp_update(struct arp_advert *);
int arp_add(be32_t next_hop, struct gt_eth_addr *addr);
int arp_del(be32_t);
void arp_reply(struct route_if *, struct arp_hdr *);
int gt_arp_input(struct route_if *, void *, int);

#endif // GBTCP_ARP_H
