// SPDX-License-Identifier: BSD-4-Clause

#ifndef GBTCP_BSD44_UDP_VAR_H
#define GBTCP_BSD44_UDP_VAR_H

#include "types.h"
#include "ip_var.h"

/*
 * UDP kernel structures and variables.
 */
struct bsd_udp_hdr {
	be16_t   uh_sport;  /* source port */
	be16_t   uh_dport;  /* destination port */
	be16_t   uh_ulen;   /* udp length */
	uint16_t uh_sum;    /* udp checksum */
} __attribute__((packed));

void udp_ctlinput(int, be32_t, struct ip4_hdr *);
void udp_init(void);
int udp_input(struct ip4_hdr *, int, int);
int udp_output(struct socket *, const void *, int, const struct sockaddr_in *);
int udp_connect(struct socket *);
int udp_send(struct socket *, const void *, int, const struct sockaddr_in *);
int udp_disconnect(struct socket *);
void udp_detach(struct socket *);
//int udp_attach(struct socket *);
void udp_abort(struct socket *);
void udp_shutdown(struct socket *);

#endif // GBTCP_BSD44_UDP_VAR_H
