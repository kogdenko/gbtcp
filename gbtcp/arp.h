// gpl2
#ifndef GBTCP_ARP_H
#define GBTCP_ARP_H

#include "subr.h"

struct arp_advert_msg {
	int arpam_af;
	be32_t arpam_next_hop;
	struct eth_addr arpam_addr;
	int arpam_advert;
	int arpam_solicited;
	int arpam_override;
};

int arp_mod_init();
void arp_mod_deinit();
void arp_mod_timer(struct timer *, u_char);

int service_init_arp(struct service *);
void service_deinit_arp(struct service *);

void arp_resolve(struct route_if *, be32_t, struct dev_pkt *);
void arp_update(struct arp_advert_msg *);
int arp_add(be32_t, struct eth_addr *);
void arp_reply(struct route_if *, struct arp_hdr *);

#endif // GBTCP_ARP_H
