// gpl2 license
#ifndef GBTCP_ARP_H
#define GBTCP_ARP_H

#include "mbuf.h"
#include "ip_addr.h"

struct arp_advert_msg {
	int arpam_af;
	be32_t arpam_next_hop;
	struct eth_addr arpam_addr;
	int arpam_advert;
	int arpam_solicited;
	int arpam_override;
};

int arp_mod_init();
int arp_mod_service_init(struct service *);
void arp_mod_deinit();
void arp_mod_service_deinit(struct service *);
void arp_mod_timer_handler(struct timer *, u_char);

void arp_resolve(struct route_if *, be32_t, struct dev_pkt *);
void arp_update(struct arp_advert_msg *);
int arp_add(be32_t, struct eth_addr *);
void arp_reply(struct route_if *, struct arp_hdr *);

#endif // GBTCP_ARP_H
