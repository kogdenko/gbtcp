// SPDX-License-Identifier: BSD-4-Clause

#ifndef GBTCP_BSD44_IP_VAR_H
#define GBTCP_BSD44_IP_VAR_H

#include "types.h"

struct ip4_hdr;
struct packet;
struct route_if;

void ip_drain(void);
void ip_init(void);
int ip_output(struct route_entry *r, struct dev_pkt *pkt, struct ip4_hdr *ip);
int ip_input(struct route_if *, struct ip4_hdr *, int, int);

#endif // GBTCP_BSD44_IP_VAR_H
