/*
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef BSD44_UDP_VAR_H
#define BSD44_UDP_VAR_H

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


void udp_ctlinput(int, be32_t, struct ip *);
void udp_init(void);
void udp_input(struct ip *, int, int);
int udp_output(struct socket *, const void *, int, const struct sockaddr_in *);
int udp_connect(struct socket *);
int udp_send(struct socket *, const void *, int, const struct sockaddr_in *);
int udp_disconnect(struct socket *);
void udp_detach(struct socket *);
//int udp_attach(struct socket *);
void udp_abort(struct socket *);
void udp_shutdown(struct socket *);

#endif /* BSD44_UDP_VAR_H */

