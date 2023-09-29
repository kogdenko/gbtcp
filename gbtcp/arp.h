// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_ARP_H
#define GBTCP_ARP_H

#include "subr.h"

struct arp_hdr;
struct dev_pkt;
struct route_entry;
struct route_if;
struct service;
struct timer;

struct arp_advert {
	int arpa_af;
	be32_t arpa_next_hop;
	struct eth_addr arpa_addr;
	int arpa_advert;
	int arpa_solicited;
	int arpa_override;
};

int arp_mod_init(void);
void arp_mod_deinit(void);
void arp_mod_timer(struct timer *, u_char);

int service_init_arp(struct service *);
void service_deinit_arp(struct service *);

void arp_resolve(struct route_entry *, struct dev_pkt *);
void arp_update(struct arp_advert *);
int arp_add(be32_t, struct eth_addr *);
int arp_del(be32_t);
void arp_reply(struct route_if *, struct arp_hdr *);
int gt_arp_input(struct route_if *, void *, int);

#endif // GBTCP_ARP_H
