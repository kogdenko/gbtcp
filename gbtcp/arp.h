// GPL2 license
#ifndef GBTCP_ARP_H
#define GBTCP_ARP_H

#include "mbuf.h"
#include "ip_addr.h"

struct route_if;
struct gt_arp_hdr;
struct dev_pkt;


struct gt_arp_advert_msg {
	int arpam_af;
	be32_t arpam_next_hop;
	struct ethaddr arpam_addr;
	int arpam_advert;
	int arpam_solicited;
	int arpam_override;
};

int arp_mod_init(struct log *, void **);
int arp_mod_attach(struct log *, void *);
int arp_proc_init(struct log *, struct proc *);
void arp_mod_deinit(struct log *, void *);
void arp_mod_detach(struct log *);

void gt_arp_resolve(struct route_if *, be32_t,	struct dev_pkt *);
void gt_arp_update(struct gt_arp_advert_msg *);
int gt_arp_add(be32_t, struct ethaddr *);
void gt_arp_reply(struct route_if *, struct gt_arp_hdr *);

#endif // GBTCP_ARP_H
