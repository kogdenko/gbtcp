/*
 * Copyright (c) 1982, 1986, 1991, 1993
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

#include "socket.h"
#include "ip.h"
#include "in_pcb.h"
#include "ip_var.h"
#include "udp_var.h"
#include "../gbtcp/htable.h"

int
in_pcbbind(struct socket *so, be16_t lport)
{
	uint16_t i;

	if (!lport) {
		return EINVAL;
	}
	if (so->inp_lport || so->inp_laddr != INADDR_ANY) {
		return EINVAL;
	}
	i = ntohs(lport);
	if (i >= ARRAY_SIZE(current->t_in_binded)) {
		return EADDRINUSE;
	}
	if (current->t_in_binded[i] != NULL) {
		return EADDRINUSE;
	}
	current->t_in_binded[i] = so;
	so->inp_laddr = htonl(current->t_ip_laddr_min);
	so->inp_lport = lport;
	return 0;
}

int
in_pcbattach(struct socket *so, uint32_t *ph)
{
	int rc;

	if (so->so_state & SS_ISATTACHED) {
		return -EALREADY;
	}
	rc = ip_connect(&so->so_base, ph);
	if (rc == 0) {
		so->so_state |= SS_ISATTACHED;
	}
	return rc;
}

int
in_pcbconnect(struct socket *so, uint32_t *ph)
{
	int rc;

//	if (sin->sin_family != AF_INET) {
//		return -EAFNOSUPPORT;
//	}
//	if (sin->sin_port == 0) {
//		return -EADDRNOTAVAIL;
//	}
//	if (sin->sin_addr.s_addr == INADDR_ANY ||
//	    sin->sin_addr.s_addr == INADDR_BROADCAST) {
//		return -ENOTSUP;
//	}
	if (so->inp_faddr != INADDR_ANY) {
		return -EISCONN;
	}
	if (so->so_state & SS_ISATTACHED) {
		return -EISCONN;
	}
	rc = ip_connect(&so->so_base, ph);
	if (rc == 0) {
		so->so_state |= SS_ISATTACHED;
	}
	return rc;
}

int
in_pcbdetach(struct socket *so)
{
	int lport;

	lport = ntohs(so->inp_lport);
	if (lport < EPHEMERAL_MIN) {
		if (current->t_in_binded[lport] == so) {
			current->t_in_binded[lport] = NULL;
		}
	}
	if (so->so_state & SS_ISATTACHED) {
		so->so_state &= ~SS_ISATTACHED;
		ip_disconnect(&so->so_base);
		sofree(so);
	}
	return 0;
}

void
in_pcbdisconnect(struct socket *so)
{
	so->inp_faddr = INADDR_ANY;
	so->inp_fport = 0;
}

void
in_pcbnotify(int proto, be32_t laddr, be16_t lport, be32_t faddr, be16_t fport,
	int err, void (*notify)(struct socket *, int))
{
	struct socket *so;

	so = in_pcblookup(proto, laddr, lport, faddr, fport);
	if (so != NULL) {
		(*notify)(so, err);
	}
}

void
bsd_get_so_info(void *e, struct socket_info *x)
{
	struct socket *so;
	struct tcpcb *tp;

	so = container_of(e, struct socket, inp_list);
	x->soi_laddr = so->inp_laddr;
	x->soi_lport = so->inp_lport;
	x->soi_faddr = so->inp_faddr;
	x->soi_fport = so->inp_fport;
	x->soi_ipproto = so->so_proto;
	if (so->so_proto == IPPROTO_TCP) {
		tp = &so->inp_ppcb;
		x->soi_state = tp->t_state;
		x->soi_idle = tp->t_idle;
	}
	snprintf(x->soi_debug, sizeof(x->soi_debug), "0x%x", so->so_state);
}

struct socket *
in_pcblookup(int proto, be32_t laddr, be16_t lport, be32_t faddr, be16_t fport)
{
	int i;
	uint32_t h;
	struct dlist *b;
	struct socket *so;

	h = SO_HASH(faddr, lport, fport);
	b = htable_bucket_get(&current->t_in_htable, h);
	DLIST_FOREACH(so, b, inp_list) {	
		if (so->so_proto == proto &&
		    so->inp_laddr == laddr &&
		    so->inp_lport == lport &&
		    so->inp_faddr == faddr &&
		    so->inp_fport == fport) {
			return so;
		}
	}
	i = ntohs(lport);
	if (i < EPHEMERAL_MIN) {
		return current->t_in_binded[i];
	} else {
		return NULL;
	}
}
