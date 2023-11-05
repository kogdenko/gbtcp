// SPDX-License-Identifier: BSD-4-Clause

#include "socket.h"
#include "ip.h"
#include "in_pcb.h"
#include "ip_var.h"
#include "udp_var.h"
#include "../htable.h"

int
in_pcbattach(struct socket *so, uint32_t *ph)
{
	if (so->so_state & SS_ISATTACHED) {
		return -EALREADY;
	}

	gt_so_addto_connected(&so->so_base, ph);
	so->so_state |= SS_ISATTACHED;
	
	return 0;
}

int
in_pcbconnect(struct socket *so, const struct sockaddr_in *faddr_in, uint32_t *ph)
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
	rc = gt_so_bind_ephemeral(&so->so_base, faddr_in->sin_addr.s_addr, faddr_in->sin_port);
	if (rc == 0) {
		so->so_state |= SS_ISATTACHED;
	}
	return rc;
}

int
in_pcbdetach(struct socket *so)
{
	gt_so_rmfrom_binded(&so->so_base);

	if (so->so_state & SS_ISATTACHED) {
		so->so_state &= ~SS_ISATTACHED;
		gt_so_rmfrom_connected(&so->so_base);
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
in_pcbnotify(int proto, be32_t laddr, be32_t faddr, be16_t lport, be16_t fport,
		int err, void (*notify)(struct socket *, int))
{
	int rc;
	struct socket *so;

	rc = in_pcblookup(&so, proto, laddr, lport, faddr, fport);
	if (rc == IN_OK && so != NULL) {
		(*notify)(so, err);
	}
}

int
in_pcblookup(struct socket **pso,
		int proto, be32_t laddr, be32_t faddr, be16_t lport, be16_t fport)
{
	int rc;

	rc = gt_so_lookup((struct gt_sock **)pso, proto, laddr, faddr, lport, fport);

	return rc;
}
