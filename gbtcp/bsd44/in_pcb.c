#include "socket.h"
#include "ip.h"
#include "in_pcb.h"
#include "ip_var.h"
#include "udp_var.h"
#include "../htable.h"

int
in_pcbattach(struct socket *so, uint32_t *ph)
{
	int rc;

	if (so->so_state & SS_ISATTACHED) {
		return -EALREADY;
	}
	gt_so_bind_ephemeral();
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

int
in_pcblookup(struct socket **pso,
		int proto, be32_t laddr, be32_t faddr, be16_t lport, be16_t fport)
{
	gt_so_lookup
	return NULL;
}
