// GPL V2 License
#include "internals.h"

#define CURMOD api

static __thread int api_locked;

__thread int gt_errno;

#define API_LOCK \
	if (api_lock()) { \
		return -1; \
	}

#define API_UNLOCK api_unlock()

static inline int
api_lock(void)
{
	int rc;

	if (api_locked == 0) {
		if (current == NULL) {
			rc = service_attach();
			if (rc) {
				GT_RETURN(-ECANCELED);
			}
		}
		SERVICE_LOCK;
	}
	api_locked++;
	return 0;
}

static inline void
api_unlock(void)
{
	assert(api_locked > 0);
	api_locked--;
	if (api_locked == 0) {
		if (current != NULL) {
			check_fd_events();
			SERVICE_UNLOCK;
		}
	}
}

void
gt_init(void)
{
	dlsym_all();
	rd_nanoseconds();
	srand48(nanoseconds ^ getpid());
	log_init_early();
}

pid_t
gt_fork(void)
{
	int rc;

	API_LOCK;
	INFO(0, "gt_fork()");
	rc = service_fork();
	if (rc < 0) {
		ERR(-rc, "gt_fork() failed");
	} else {
		INFO(0, "gt_fork() return pid=%d", rc);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

int
gt_socket(int domain, int type, int proto)
{
	int rc, flags, type_noflags;
	struct sock *so;

	API_LOCK;
	flags = SOCK_TYPE_FLAGS(type);
	type_noflags = SOCK_TYPE_NOFLAGS(type);
	INFO(0, "gt_socket('%s', '%s')",
		log_add_socket_type(type_noflags),
		log_add_socket_flags(flags));
	rc = so_socket(&so, domain, type_noflags, flags, proto);
	if (rc < 0) {
		INFO(-rc, "gt_socket('%s', '%s') failed",
			log_add_socket_type(type_noflags),
			log_add_socket_flags(flags));
	} else {
		INFO(0, "gt_socket(%s, %s) return fd=%d",
			log_add_socket_type(type_noflags),
			log_add_socket_flags(flags), rc);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

int
gt_connect_locked(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc, error;
	socklen_t optlen;
	const struct sockaddr_in *faddr_in;
	struct sockaddr_in laddr_in;
	struct sock *so;

	if (addr->sa_family != AF_INET) {
		return -EAFNOSUPPORT;
	}
	if (addrlen < sizeof(*faddr_in)) {
		return -EINVAL;
	}
	rc = so_get(fd, &so);
	if (rc) {
		return rc;
	}
	faddr_in = (const struct sockaddr_in *)addr;
	rc = so_connect(so, faddr_in, &laddr_in);
restart:
	if (rc == -EINPROGRESS && so->so_blocked) {
		file_wait(&so->so_file, POLLOUT);
		rc = so_get(fd, &so);
		if (rc == 0) {
			optlen = sizeof(error);
			rc = so_getsockopt(so, SOL_SOCKET, SO_ERROR,
				&error, &optlen);
			assert(rc == 0 && "so_getsockopt");
			rc = -error;
			goto restart;
		}

	}
	return rc;
}

int
gt_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;

	API_LOCK;
	INFO(0, "gt_connect(fd=%d, '%s')",
		fd, log_add_sockaddr(addr, addrlen));
	rc = gt_connect_locked(fd, addr, addrlen);
	if (rc < 0) {
		INFO(-rc, "gt_connect(fd=%d, '%s') failed",
			fd, log_add_sockaddr(addr, addrlen));
	} else {
		INFO(0, "gt_connect(fd=%d, '%s') return '%s'",
			fd, log_add_sockaddr(addr, addrlen),
			log_add_sockaddr(addr, addrlen));
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

static int
gt_bind_locked(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;
	const struct sockaddr_in *addr_in;
	struct sock *so;

	if (addr->sa_family != AF_INET) {
		return -EAFNOSUPPORT;
	}
	if (addrlen < sizeof(*addr_in)) {
		return -EINVAL;
	}
	rc = so_get(fd, &so);
	if (rc) {
		return rc;
	}
	addr_in = (const struct sockaddr_in *)addr;
	rc = so_bind(so, addr_in);
	return rc;
}

int
gt_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;

	API_LOCK;
	INFO(0, "gt_bind(fd=%d, '%s')", fd, log_add_sockaddr(addr, addrlen));
	rc = gt_bind_locked(fd, addr, addrlen);
	if (rc < 0) {
		INFO(-rc, "gt_bind(fd=%d, '%s') failed", fd, log_add_sockaddr(addr, addrlen));
	} else {
		INFO(0, "gt_bind(fd=%d, '%s') ok", fd, log_add_sockaddr(addr, addrlen));
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

int
gt_listen(int fd, int backlog)
{
	int rc;
	struct sock *so;

	API_LOCK;
	INFO(0, "gt_listen(lfd=%d)", fd);
	rc = so_get(fd, &so);
	if (rc == 0) {
		rc = so_listen(so, backlog);
	}
	if (rc < 0) {
		INFO(rc, "gt_listen(lfd=%d) failed", fd);
	} else {
		INFO(0, "gt_listen(lfd=%d) ok", fd);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

int
gt_accept4_locked(int lfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	int rc;
	struct sock *so, *lso;

	rc = so_get(lfd, &lso);
	if (rc) {
		return rc;
	}
restart:
	rc = so_accept(&so, lso, addr, addrlen, flags);
	if (rc == -EAGAIN && lso->so_blocked) {
		file_wait(&lso->so_file, POLLIN);
		rc = so_get(lfd, &lso);
		if (rc == 0) {
			goto restart;
		}
	}
	return rc;
}

int
gt_accept4(int lfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	int rc;

	API_LOCK;
	INFO(0, "gt_accept4(lfd=%d, '%s')",
		lfd, log_add_socket_flags(flags));
	rc = gt_accept4_locked(lfd, addr, addrlen, flags);
	if (rc < 0) {
		INFO(-rc, "gt_accept4(lfd=%d, '%s') failed",
			lfd, log_add_socket_flags(flags));
	} else {
		INFO(0, "gt_accept4(lfd=%d, '%s') return fd=%d",
			lfd, log_add_socket_flags(flags), rc);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

int
gt_shutdown(int fd, int how)
{
	int rc;

	API_LOCK;
	INFO(0, "gt_shutdown(fd=%d, '%s')", fd, log_add_shutdown_how(how));
	rc = -ENOTSUP;
	if (rc < 0) {
		INFO(-rc, "gt_shutdown(fd=%d, '%s') failed", fd, log_add_shutdown_how(how));
	} else {
		INFO(0, "gt_shutdown(fd=%d, '%s') ok", fd, log_add_shutdown_how(how));
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

int
gt_close(int fd)
{
	int rc;
	struct file *fp;

	API_LOCK;
	INFO(0, "gt_close(fd=%d)", fd);
	rc = file_get(fd, &fp);
	if (rc == 0) {
		file_close(fp);
	}
	if (rc == 0) {
		INFO(-rc, "gt_close(fd=%d) failed", fd);
	} else {
		INFO(0, "gt_close(fd=%d) ok", fd);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

ssize_t
gt_read(int fd, void *buf, size_t count)
{
	int rc;

	rc = gt_recvfrom(fd, buf, count, 0, NULL, NULL);
	return rc;
}

ssize_t
gt_recvfrom_locked(int fd, const struct iovec *iov, int iovcnt, int flags,
	struct sockaddr *addr, socklen_t *addrlen)
{
	ssize_t rc;
	struct sock *so;

	rc = so_get(fd, &so);
	if (rc) {
		return rc;
	}
restart:
	rc = so_recvfrom(so, iov, iovcnt, flags, addr, addrlen);
	if (rc == -EAGAIN && so->so_blocked) {
		file_wait(&so->so_file, POLLIN);
		rc = so_get(fd, &so);
		if (rc == 0) {
			goto restart;
		}
	}
	return rc;
}

ssize_t
gt_readv(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t rc;

	API_LOCK;
	INFO(0, "gt_readv(fd=%d, %d)", fd, iovec_accum_len(iov, iovcnt));
	rc = gt_recvfrom_locked(fd, iov, iovcnt, 0, NULL, NULL);
	if (rc < 0) {
		INFO(-rc, "gt_readv(fd=%d, %d) failed", fd, iovec_accum_len(iov, iovcnt));
	} else {
		INFO(0, "gt_readv(fd=%d, %d) return %zd", fd, iovec_accum_len(iov, iovcnt), rc);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

ssize_t
gt_recv(int fd, void *buf, size_t len, int flags)
{
	ssize_t rc;

	rc = gt_recvfrom(fd, buf, len, flags, NULL, NULL);
	return rc;
}

ssize_t
gt_recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *addr, socklen_t *addrlen)
{
	ssize_t rc;
	struct iovec iov;

	iov.iov_base = buf;
	iov.iov_len = len;
	API_LOCK;
	INFO(0, "gt_recvfrom(fd=%d, %zu)", fd, len);
	rc = gt_recvfrom_locked(fd, &iov, 1, flags, addr, addrlen);
	if (rc < 0) {
		INFO(-rc, "gt_recvfrom(fd=%d, %zu) failed", fd, len);
	} else {
		INFO(0, "gt_recvfrom(fd=%d, %zu) return %zd", fd, len, rc);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

ssize_t
gt_recvmsg(int fd, struct msghdr *msg, int flags)
{
	assert(!"not implemented");
	GT_RETURN(-ENOTSUP);
}

ssize_t
gt_write(int fd, const void *buf, size_t count)
{
	ssize_t rc;

	rc = gt_send(fd, buf, count, 0);
	return rc;
}

int
gt_send_locked(int fd, const struct iovec *iov, int iovcnt, int flags,
	const void *name, int namelen)
{
	int rc;
	be32_t faddr;
	be16_t fport;
	const struct sockaddr_in *addr_in;
	struct sock *so;

	rc = so_get(fd, &so);
	if (rc) {
		return rc;
	}
	if (namelen >= sizeof(*addr_in)) {
		addr_in = name;
		faddr = addr_in->sin_addr.s_addr;
		fport = addr_in->sin_port;
	} else {
		faddr = 0;
		fport = 0;
	}
restart:
	rc = so_sendto(so, iov, iovcnt, flags, faddr, fport);
	if (rc == -EAGAIN && so->so_blocked) {
		file_wait(&so->so_file, POLLOUT);
		rc = so_get(fd, &so);
		if (rc == 0) {
			goto restart;
		}
	}
	return rc;
}

ssize_t
gt_writev(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t rc;

	API_LOCK;
	INFO(0, "gt_writev(fd=%d, %d)", fd, iovec_accum_len(iov, iovcnt));
	rc = gt_send_locked(fd, iov, iovcnt, 0, NULL, 0);
	if (rc < 0) {
		INFO(-rc, "gt_writev(fd=%d, %d) failed", fd, iovec_accum_len(iov, iovcnt));
	} else {
		INFO(0, "gt_writev(fd=%d, %d) return %zd", fd, iovec_accum_len(iov, iovcnt), rc);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

ssize_t
gt_send(int fd, const void *buf, size_t cnt, int flags)
{
	ssize_t rc;

	rc = gt_sendto(fd, buf, cnt, flags, NULL, 0);
	return rc;
}

ssize_t
gt_sendto(int fd, const void *buf, size_t len, int flags,
	const struct sockaddr *addr, socklen_t addrlen)
{
	ssize_t rc;
	struct iovec iov;

	iov.iov_base = (void *)buf;
	iov.iov_len = len;
	API_LOCK;
	INFO(0, "gt_sendto(fd=%d, %zu)", fd, len);
	rc = gt_send_locked(fd, &iov, 1, flags, addr, addrlen);
	if (rc < 0) {
		INFO(-rc, "gt_sendto(fd=%d, %zu) failed", fd, len);
	} else {
		INFO(0, "gt_sendto(fd=%d, %zu) return %zd", rc);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

ssize_t
gt_sendmsg(int fd, const struct msghdr *msg, int flags)
{
	ssize_t rc;
	int iovcnt;
	struct iovec *iov;

	API_LOCK;
	iov = msg->msg_iov;
	iovcnt = msg->msg_iovlen;
	INFO(0, "gt_sendmsg(fd=%d, %d)", fd, iovec_accum_len(iov, iovcnt));
	if (msg->msg_flags != 0 || msg->msg_controllen != 0) {
		rc = -ENOTSUP;
	} else {
		rc = gt_send_locked(fd, iov, iovcnt, msg->msg_flags,
			msg->msg_name, msg->msg_namelen);
	}
	if (rc < 0) {
		INFO(-rc, "gt_sendmsg(fd=%d, %d) failed", fd, iovec_accum_len(iov, iovcnt));
	} else {
		INFO(0, "gt_sendmsg(fd=%d, %d) return %zd", fd, iovec_accum_len(iov, iovcnt));
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

int
gt_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
	int rc;
	struct sock *so;

	API_LOCK;
	INFO(0, "gt_getsockopt(fd=%d, '%s', '%s')",
		fd, log_add_sockopt_level(level),
		log_add_sockopt_optname(level, optname));
	rc = so_get(fd, &so);
	if (rc == 0) {
		rc = so_getsockopt(so, level, optname, optval, optlen);
	}
	if (rc < 0) {
		INFO(-rc, "gt_getsockopt(fd=%d, '%s', '%s') failed",
			fd, log_add_sockopt_level(level),
			log_add_sockopt_optname(level, optname));
	} else if (level == SOL_SOCKET && optname == SO_ERROR && *optlen >= sizeof(int)) {
		INFO(*(int *)optval, "gt_getsockopt(fd=%d, '%s', '%s') return error",
			fd, log_add_sockopt_level(level),
			log_add_sockopt_optname(level, optname));
	} else {
		INFO(0, "gt_getsockopt(fd=%d, '%s', '%s') ok",
			fd, log_add_sockopt_level(level),
			log_add_sockopt_optname(level, optname));
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

int
gt_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
	int rc;
	struct sock *so;

	API_LOCK;
	INFO(0, "gt_setsockopt(fd=%d, '%s', '%s')",
		fd, log_add_sockopt_level(level),
		log_add_sockopt_optname(level, optname));
	rc = so_get(fd, &so);
	if (rc == 0) {
		rc = so_setsockopt(so, level, optname, optval, optlen);
	}
	if (rc < 0) {
		INFO(-rc, "gt_setsockopt(fd=%d, '%s', '%s') failed",
			fd, log_add_sockopt_level(level),
			log_add_sockopt_optname(level, optname));
	} else {
		INFO(0, "gt_setsockopt(fd=%d, '%s', '%s') ok",
			fd, log_add_sockopt_level(level),
			log_add_sockopt_optname(level, optname));
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

int
gt_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;
	struct sock *so;

	API_LOCK;
	INFO(0, "gt_getpeername(fd=%d)", fd);
	rc = so_get(fd, &so);
	if (rc == 0) {
		rc = so_getpeername(so, addr, addrlen);
	}
	if (rc < 0) {
		INFO(-rc, "gt_getpeername(fd=%d) failed", fd);
	} else {
		INFO(0, "gt_getpeername(fd=%d) ok", fd);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

int
gt_fcntl(int fd, int cmd, uintptr_t arg)
{
	int rc;
	struct file *fp;

	API_LOCK;
	INFO(0, "gt_fcntl(fd=%d, '%s')", fd, log_add_fcntl_cmd(cmd));
	rc = file_get(fd, &fp);
	if (rc == 0) {
		rc = file_fcntl(fp, cmd, arg);
	}
	if (rc < 0) {
		INFO(-rc, "gt_fcntl(fd=%d, '%s') failed", fd, log_add_fcntl_cmd(cmd));
	} else {
		INFO(0, "gt_fcntl(fd=%d, '%s') return 0x%x", fd, log_add_fcntl_cmd(cmd), rc);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

int
gt_ioctl(int fd, unsigned long req, uintptr_t arg)
{
	int rc;
	struct file *fp;

	API_LOCK;
	INFO(0, "gt_ioctl(fd=%d, '%s')", fd, log_add_ioctl_req(req, arg));
	rc = file_get(fd, &fp);
	if (rc == 0) {
		rc = file_ioctl(fp, req, arg);
	}
	if (rc < 0) {
		INFO(-rc, "gt_ioctl(fd=%d, '%s') failed", fd, log_add_ioctl_req(req, arg));
	} else {
		INFO(0, "gt_ioctl(fd=%d, '%s') return 0x%x", fd, log_add_ioctl_req(req, arg), rc);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

int
gt_poll(struct pollfd *fds, nfds_t nfds, int timeout_ms)
{
	int rc;
	uint64_t to;

	if (timeout_ms == -1) {
		to = NSEC_INFINITY;
	} else {
		to = timeout_ms * NSEC_MSEC;
	}
	API_LOCK;
	DBG(0, "gt_poll(to=%d, '%s')",
		timeout_ms, log_add_pollfds_events(fds, nfds));
	rc = u_poll(fds, nfds, to, NULL);
	if (rc < 0) {
		DBG(-rc, "gt_poll(to=%d, '%s') failed",
			timeout_ms, log_add_pollfds_events(fds, nfds));
	} else {
		DBG(0, "gt_poll(to=%d, '%s') return %d, '%s'",
			timeout_ms, log_add_pollfds_events(fds, nfds),
			rc, log_add_pollfds_revents(fds, nfds));
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

int
gt_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout, const sigset_t *sigmask)
{
	int rc;
	uint64_t to;

	if (timeout == NULL) {
		to = NSEC_INFINITY;
	} else {
		to = NSEC_SEC * timeout->tv_sec + timeout->tv_nsec;
	}
	API_LOCK;
	DBG(0, "gt_ppoll(to=%s, '%s')",
	    log_add_ppoll_timeout(timeout),
	    log_add_pollfds_events(fds, nfds));
	rc = u_poll(fds, nfds, to, sigmask);
	if (rc < 0) {
		DBG(-rc, "gt_ppoll(to=%s, '%s') failed",
			log_add_ppoll_timeout(timeout),
			log_add_pollfds_events(fds, nfds));
	} else {
		DBG(0, "gt_ppoll(to=%s, '%s') return %d, '%s'",
			log_add_ppoll_timeout(timeout),
			log_add_pollfds_events(fds, nfds),
			rc, log_add_pollfds_revents(fds, rc));
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

unsigned int
gt_sleep(unsigned int seconds)
{
	int rc;
	unsigned int left;
	uint64_t start;

	API_LOCK;
	start = nanoseconds;
	rc = u_poll(NULL, 0, seconds * NSEC_SEC, NULL);
	if (rc < 0) {
		left = seconds - (nanoseconds - start)/NSEC_SEC;
	} else {
		left = 0;
	}
	API_UNLOCK;
	return left;
}

int
gt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	int rc;

	API_LOCK;
	INFO(0, "gt_sigprocmask('%s')", log_add_sigprocmask_how(how));
	rc = service_sigprocmask(how, set, oldset);
	if (rc < 0) {
		WARN(-rc, "gt_sigprocmask('%s') failed", log_add_sigprocmask_how(how));
	} else {
		INFO(0, "gt_sigprocmask('%s') ok", log_add_sigprocmask_how(how));
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

int
gt_aio_cancel(int fd)
{
	int rc;
	struct sock *so;	

	API_LOCK;
	INFO(0, "gt_aio_cancel(fd=%d)", fd);
	rc = so_get(fd, &so);
	if (rc == 0) {
		file_aio_cancel(&so->so_file.fl_aio);
	}
	if (rc < 0) {
		INFO(-rc, "gt_aio_cancel(fd=%d) failed", fd);
	} else {
		INFO(0, "gt_aio_cancel(fd=%d) ok", fd);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

int
gt_aio_set(int fd, gt_aio_f fn)
{
	int rc;
	struct sock *so;

	API_LOCK;
	INFO(0, "gt_aio_set(fd=%d)", fd);
	rc = so_get(fd, &so);
	if (rc == 0) {
		file_aio_add(&so->so_file, &so->so_file.fl_aio, fn);
	}
	if (rc < 0) {
		INFO(-rc, "gt_aio(set(fd=%d) failed", fd);
	} else {
		INFO(0, "gt_aio_set(fd=%d) ok", fd);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

ssize_t
gt_aio_recvfrom(int fd, struct iovec *iov, int flags, struct sockaddr *addr, socklen_t *addrlen)
{
	ssize_t rc;
	struct sock *so;

	API_LOCK;
	INFO(0, "gt_aio_recvfrom(fd=%d)", fd);
	rc = so_get(fd, &so);
	if (rc == 0) {
		rc = so_aio_recvfrom(so, iov, flags, addr, addrlen);
	}
	if (rc < 0) {
		INFO(-rc, "gt_aio_recvfrom(fd=%d) failed");
	} else {
		INFO(0, "gt_aio_recvfrom(fd=%d) return %zd", fd, rc);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

ssize_t
gt_recvdrain(int fd, size_t cnt)
{
	ssize_t rc;
	struct sock *so;

	API_LOCK;
	INFO(0, "gt_aio_recvfrain(fd=%d)", fd);
	rc = so_get(fd, &so);
	if (rc == 0) {
		rc = so_recvdrain(so, cnt);
	}
	if (rc < 0) {
		INFO(-rc, "gt_aio_recvdrain(fd=%d) failed");
	} else {
		INFO(0, "gt_aio_recvdrain(fd=%d) return %zd", fd, rc);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

#ifdef __linux__
int
gt_clone(int (*fn)(void *), void *child_stack, int flags, void *arg,
	void *ptid, void *tls, void *ctid)
{
	int rc;

	API_LOCK;
	INFO(0, "gt_clone('%s')", log_add_clone_flags(flags));
	rc = service_clone(fn, child_stack, flags, arg, ptid, tls, ctid);
	if (rc < 0) {
		INFO(-rc, "gt_clone('%s') failed", log_add_clone_flags(flags));
	} else {
		INFO(0, "gt_clone('%s') return pid=%d", log_add_clone_flags(flags), rc);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

int
gt_epoll_create1(int flags)
{
	int rc, fd;

	API_LOCK;
	INFO(0, "gt_epoll_create1()");
	rc = sys_epoll_create1(EPOLL_CLOEXEC);
	if (rc >= 0) {
		fd = rc;
		rc = u_epoll_create(fd);
		if (rc < 0) {
			sys_close(fd);
		}
	}
	if (rc < 0) {
		INFO(-rc, "gt_epoll_create1() failed");
	} else {
		INFO(0, "gt_epoll_create1() return ep_fd=%d", rc);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

int
gt_epoll_ctl(int ep_fd, int op, int fd, struct epoll_event *event)
{
	int rc;

	API_LOCK;
	INFO(0, "gt_epoll_ctl(ep_fd=%d, '%s', fd=%d, '%s')",
		ep_fd, log_add_epoll_op(op), fd,
		log_add_epoll_event_events(event->events));
	rc = u_epoll_ctl(ep_fd, op, fd, event);
	if (rc) {
		INFO(-rc, "gt_epoll_ctl(ep_fd=%d, '%s', fd=%d, '%s') failed",
			ep_fd, log_add_epoll_op(op), fd,
			log_add_epoll_event_events(event->events));
	} else {
		INFO(-rc, "gt_epoll_ctl(ep_fd=%d, '%s', fd=%d, '%s') ok",
			ep_fd, log_add_epoll_op(op), fd,
			log_add_epoll_event_events(event->events));
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

int
gt_epoll_pwait(int ep_fd, struct epoll_event *events, int maxevents,
	int timeout_ms, const sigset_t *sigmask)
{
	int rc;
	uint64_t to;

	if (timeout_ms == -1) {
		to = NSEC_INFINITY;
	} else {
		to = timeout_ms * NSEC_MSEC;
	}
	API_LOCK;
	DBG(0, "gt_epoll_pwait(ep_fd=%d)", ep_fd);
	rc = u_epoll_pwait(ep_fd, events, maxevents, to, sigmask);
	if (rc < 0) {
		DBG(-rc, "gt_epoll_pwait(ep_fd=%d) failed", ep_fd);
	} else {
		DBG(0, "gt_epoll_pwait(ep_fd=%d) return %d", ep_fd, rc);
	}
	API_UNLOCK;
	GT_RETURN(rc);	
}
#else // __linux__
int
gt_kqueue()
{
	int rc, fd;

	API_LOCK;
	INFO(0, "gt_kqueue()");
	rc = (*sys_kqueue_fn)();
	if (rc == -1) {
		rc = -errno;
		assert(rc);
	} else {
		fd = rc;
		rc = u_epoll_create(fd);
		if (rc < 0) {
			(*sys_close_fn)(fd);
		}
	}
	if (rc < 0) {
		INFO(-rc, "gt_kqueue() failed");
	} else {
		INFO(0, "gt_kqueue() return kq_fd=%d", rc);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}

int
gt_kevent(int kq_fd, const struct kevent *changelist, int nchanges,
	struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
	int rc;

	API_LOCK;
	DBG(0, "gt_kevent(kq_fd=%d, %d, %d)", kq_fd, nchanges, nevents);
	rc = u_kevent(kq_fd, changelist, nchanges, eventlist, nevents, timeout);
	if (rc < 0) {
		DBG(-rc, "gt_kevent(kq_fd=%d, %d, %d) failed", kq_fd, nchanges, nevents);
	} else {
		DBG(0, "gt_kevent(kq_fd=%d, %d, %d) return %d", kq_fd, rc);
	}
	API_UNLOCK;
	GT_RETURN(rc);
}
#endif // __linux__

void
gt_dbg5(const char *file, u_int line, const char *func, int suppressed, const char *fmt, ...)
{
	char buf[BUFSIZ];
	va_list ap;
	struct strbuf sb;

	strbuf_init(&sb, buf, sizeof(buf));
	strbuf_addf(&sb, "%-6d: %-20s: %-4d: %-20s: ", getpid(), file, line, func);
	va_start(ap, fmt);
	strbuf_vaddf(&sb, fmt, ap);
	va_end(ap);
	if (suppressed) {
		strbuf_addf(&sb, " (suppressed %d)", suppressed);	
	}
	printf("%s\n", strbuf_cstr(&sb));
}
