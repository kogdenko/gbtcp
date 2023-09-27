// SPDX-License-Identifier: LGPL-2.1-only

#include "gbtcp/socket.h"
#include "global.h"
#include "mod.h"
#include "service.h"
#include "socket.h"

#define GT_IMPL_GBTCP 0
#define GT_IMPL_BSD44 1

#define curmod ((struct gt_module_socket *)gt_module_get(GT_MODULE_SOCKET))

static void
sysctl_socket(struct file *fp, struct strbuf *out)
{
	int ipproto;
	socklen_t optlen;
	struct sockaddr_in sockname, peername;
	struct tcp_info tcpi;
	struct service *s;

	optlen = sizeof(ipproto);
	gt_vso_getsockopt(fp, SOL_SOCKET, SO_PROTOCOL, &ipproto, &optlen);

	optlen = sizeof(tcpi);
	gt_vso_getsockopt(fp, IPPROTO_TCP, TCP_INFO, &tcpi, &optlen);

	optlen = sizeof(sockname);
	gt_vso_getsockname(fp, (struct sockaddr *)&sockname, &optlen);
	optlen = sizeof(peername);
	gt_vso_getpeername(fp, (struct sockaddr *)&peername, &optlen);

	s = service_get_by_sid(fp->fl_sid);
	assert(s->p_pid);

	strbuf_addf(out, "%d,%d,%d,%d,%x,%hu,%x,%hu",
			file_get_fd(fp),
			s->p_pid,
			ipproto,
			tcpi.tcpi_state,
			ntoh32(sockname.sin_addr.s_addr),
			ntoh16(sockname.sin_port),
			ntoh32(peername.sin_addr.s_addr),
			ntoh16(peername.sin_port));
}

static void
sysctl_socket_connected(void *udata, const char *new, struct strbuf *out)
{
	struct gt_sock *so;

	so = container_of(udata, struct gt_sock, sobase_connect_list);
	sysctl_socket(&so->sobase_file, out);
}

static void
sysctl_socket_binded(void *udata, const char *new, struct strbuf *out)
{
	struct gt_sock *so;

	so = container_of(udata, struct gt_sock, sobase_bind_list);
	sysctl_socket(&so->sobase_file, out);
}

static uint32_t
gt_vso_hash(void *e)
{
	struct gt_sock *so;
	uint32_t hash;

	so = (struct gt_sock *)e;
	hash = GT_VSO_HASH(so->sobase_faddr, so->sobase_lport, so->sobase_fport);
	return hash;
}

static int
sysctl_tcp_fin_timeout(const long long *new, long long *old)
{
	*old = curmod->tcp_fin_timeout / NSEC_SEC;
	if (new != NULL) {
		curmod->tcp_fin_timeout = (*new) * NSEC_SEC;
	}
	return 0;
}

static int
sysctl_tcp_time_wait_timeout(const long long *new, long long *old)
{
	*old = curmod->tcp_time_wait_timeout / NSEC_SEC;
	if (new != NULL) {
		curmod->tcp_time_wait_timeout = (*new) * NSEC_SEC;
	}
	return 0;
}

int
socket_mod_init(void)
{
	int rc;

	rc = gt_module_init(GT_MODULE_SOCKET, sizeof(struct gt_module_socket));
	if (rc) {
		return rc;
	}
	rc = htable_init(&curmod->tbl_connected, 65536, gt_vso_hash, HTABLE_SHARED|HTABLE_POWOF2);
	if (rc) {
		socket_mod_deinit();
		return rc;
	}
	rc = htable_init(&curmod->tbl_binded, EPHEMERAL_PORT_MAX, NULL, HTABLE_SHARED);
	if (rc) {
		socket_mod_deinit();
		return rc;
	}
	sysctl_add_htable_list(GT_SYSCTL_SOCKET_CONNECTED_LIST, SYSCTL_RD,
			&curmod->tbl_connected, sysctl_socket_connected);
	sysctl_add_htable_size(GT_SYSCTL_SOCKET_CONNECTED_SIZE,
			&curmod->tbl_connected);
	sysctl_add_htable_list(GT_SYSCTL_SOCKET_BINDED_LIST, SYSCTL_RD,
			&curmod->tbl_binded, sysctl_socket_binded);
	curmod->tcp_fin_timeout = NSEC_MINUTE;
	curmod->tcp_time_wait_timeout = 0;
	sysctl_add_intfn(GT_SYSCTL_TCP_FIN_TIMEOUT, SYSCTL_WR,
			&sysctl_tcp_fin_timeout, 1, 24 * 60 * 60);
	sysctl_add_intfn(GT_SYSCTL_TCP_TIME_WAIT_TIMEOUT, SYSCTL_WR,
			&sysctl_tcp_time_wait_timeout, 0, 4 * 60);
	curmod->impl = GT_IMPL_GBTCP;
	return 0;
}

void
socket_mod_deinit(void)
{
	sysctl_del(GT_SYSCTL_SOCKET);
	sysctl_del(GT_SYSCTL_TCP);
	htable_deinit(&curmod->tbl_connected);
	htable_deinit(&curmod->tbl_binded);
	gt_module_deinit(GT_MODULE_SOCKET);
}

void
socket_mod_timer(struct timer *timer, u_char fn_id)
{
	gt_vso_timer(timer, fn_id);
}

int
gt_so_route(be32_t laddr, be32_t faddr, struct route_entry *r)
{
	int rc;

	r->rt_dst.ipa_4 = faddr;
	rc = route_get4(laddr, r);
	if (rc) {
		ipstat.ips_noroute++;
	}
	return rc;
}

int
gt_foreach_binded_socket(gt_foreach_socket_f fn, void *udata)
{
	int rc, lport;
	struct htable_bucket *bucket;
	struct file *fp;
	struct gt_sock *so;

	for (lport = 0; lport < EPHEMERAL_PORT_MAX; ++lport) {
		bucket = htable_bucket_get(&curmod->tbl_binded, lport);
		GT_DLIST_FOREACH_RCU(so, &bucket->htb_head, sobase_bind_list) {
			fp = (struct file *)so;
			rc = (*fn)(fp, udata);
			if (rc != 0) {
				return rc;
			}
		}
	}
	return 0;
}

struct gt_sock *
gt_so_lookup_connected(struct htable_bucket *b,
		int proto, be32_t laddr, be32_t faddr, be16_t lport, be16_t fport)
{
	struct gt_sock *so;

	GT_DLIST_FOREACH_RCU(so, &b->htb_head, sobase_connect_list) {
		if (so->sobase_proto == proto &&
		    so->sobase_laddr == laddr && so->sobase_faddr == faddr &&
		    so->sobase_lport == lport && so->sobase_fport == fport) {
			return so;
		}
	}
	return NULL;
}

struct gt_sock *
gt_so_lookup_binded(struct htable_bucket *b,
		int proto, be32_t laddr, be32_t faddr, be16_t lport, be16_t fport)
{
	int active, res_active;
	struct gt_sock *so, *res;

	res = NULL;
	res_active = 0;
	GT_DLIST_FOREACH_RCU(so, &b->htb_head, sobase_bind_list) {
		if (so->sobase_proto == proto &&
		    (so->sobase_laddr == 0 || so->sobase_laddr == laddr)) {
			active = !gt_dlist_is_empty(&so->sobase_file.fl_aio_head);
			if (res == NULL ||
			    (active && !res_active) ||
			    (!(!active && res_active) &&
			     (so->sobase_file.fl_sid == current->p_sid))) {
				res = so;
				res_active = active;
			}
		}
	}
	return res;
}

int
gt_vso_struct_size(void)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_struct_size();
	} else {
		assert(0);
		return -ENOTSUP;
	} 
}

int
gt_vso_get(int fd, struct file **fpp)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_get(fd, fpp);
	} else {
		assert(0);
		return -ENOTSUP;
	}
}

int
gt_vso_get_err(struct file *fp)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_get_err(fp);
	} else {
		assert(0);
		return -ENOTSUP;
	}
}

short
gt_vso_get_events(struct file *fp)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_get_events(fp);
	} else {
		assert(0);
		return 0;
	}
}

void gt_vso_timer(struct timer *timer, u_char fn_id)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		gt_gbtcp_so_timer(timer, fn_id);
	} else {
		assert(0);
	}
}

int
gt_vso_nread(struct file *fp)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_nread(fp);
	} else {
		assert(0);
		return -ENOTSUP;
	}

}

void
gt_vso_tx_flush(void)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		gt_gbtcp_so_tx_flush();
	} else {
		assert(0);
	}
}

int
gt_vso_socket6(struct file **fpp, int fd, int domain, int type, int flags, int ipproto)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_socket6(fpp, fd, domain, type, flags, ipproto);
	} else {
		assert(0);
		return -ENOTSUP;
	}
}

int
gt_vso_connect(struct file *fp, const struct sockaddr_in *faddr_in, struct sockaddr_in *laddr_in)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_connect(fp, faddr_in, laddr_in);
	} else {
		assert(0);
		return -ENOTSUP;
	}
}

int
gt_vso_bind(struct file *fp, const struct sockaddr_in *addr)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_bind(fp, addr);
	} else {
		assert(0);
		return -ENOTSUP;
	}
}

int
gt_vso_listen(struct file *fp, int backlog)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_listen(fp, backlog);
	} else {
		assert(0);
		return -ENOTSUP;
	}
}

int
gt_vso_accept(struct file **fpp, struct file *lfp,
		struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_accept(fpp, lfp, addr, addrlen, flags);
	} else {
		assert(0);
		return -ENOTSUP;
	}
}

void
gt_vso_close(struct file *fp)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		gt_gbtcp_so_close(fp);
	} else {
		assert(0);
	}
}

int
gt_vso_recvfrom(struct file *fp, const struct iovec *iov, int iovcnt,
		int flags, struct sockaddr *addr, socklen_t *addrlen)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_recvfrom(fp, iov, iovcnt, flags, addr, addrlen);
	} else {
		assert(0);
		return -ENOTSUP;
	}
}

int
gt_vso_aio_recvfrom(struct file *fp, struct iovec *iov, int flags,
		struct sockaddr *addr, socklen_t *addrlen)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_aio_recvfrom(fp, iov, flags, addr, addrlen);
	} else {
		assert(0);
		return -ENOTSUP;
	}
}

int
gt_vso_recvdrain(struct file *fp, int len)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_recvdrain(fp, len);
	} else {
		assert(0);
		return -ENOTSUP;
	}
}

int
gt_vso_sendto(struct file *fp, const struct iovec *iov, int iovcnt, int flags,
		be32_t daddr, be16_t dport)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_sendto(fp, iov, iovcnt, flags, daddr, dport);
	} else {
		assert(0);
		return -ENOTSUP;
	}
}

int
gt_vso_ioctl(struct file *fp, unsigned long request, uintptr_t arg)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_ioctl(fp, request, arg);
	} else {
		assert(0);
		return -ENOTSUP;
	}
}

int gt_vso_getsockopt(struct file *fp, int level, int optname, void *optval, socklen_t *optlen)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_getsockopt(fp, level, optname, optval, optlen);
	} else {
		assert(0);
		return -ENOTSUP;
	}
}

int
gt_vso_setsockopt(struct file *fp, int level, int optname,
		const void *optval, socklen_t optlen)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_setsockopt(fp, level, optname, optval, optlen);
	} else {
		assert(0);
		return -ENOTSUP;
	}
}

int
gt_vso_getsockname(struct file *fp, struct sockaddr *addr, socklen_t *addrlen)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_getsockname(fp, addr, addrlen);
	} else {
		assert(0);
		return -ENOTSUP;
	}
}

int
gt_vso_getpeername(struct file *fp, struct sockaddr *addr, socklen_t *addrlen)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_getpeername(fp, addr, addrlen);
	} else {
		assert(0);
		return -ENOTSUP;
	}
}

int
gt_vso_rx(struct route_if *ifp, void *data, int len)
{
	if (curmod->impl == GT_IMPL_GBTCP) {
		return gt_gbtcp_so_rx(ifp, data, len);
	} else {
		assert(0);
		return -ENOTSUP;
	}
}
