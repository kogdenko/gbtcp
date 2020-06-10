// gpl2 license
#include "internals.h"

#define CURMOD api

static __thread int api_passthru;

__thread int gt_errno;


#define API_LOCK \
	if (api_lock()) { \
		return -1; \
	}

#define API_UNLOCK api_unlock()

static inline int
api_lock()
{
	int rc;

	if (api_passthru) {
		API_RETURN(-EBADF);
	}
	api_passthru = 1;
	if (current == NULL) {
		rc = service_attach();
		if (rc) {
			api_passthru = 0;
			API_RETURN(-ECANCELED);
		}
	}
	SERVICE_LOCK;
	return 0;
}

static inline void
api_unlock()
{
	if (current != NULL) {
		check_fd_events();
		SERVICE_UNLOCK;
	}
	api_passthru = 0;
}

void
gt_init(const char *comm, int log_level)
{
	dlsym_all();
	rd_nanoseconds();
	srand48(time(NULL));
	log_init_early(comm, log_level);
	sigemptyset(&service_sigprocmask);
}

pid_t
gt_fork()
{
	int rc;

	API_LOCK;
	INFO(0, "hit;");
	rc = service_fork();
	if (rc >= 0) {
		INFO(0, "ok; pid=%d", rc);
	}
	API_UNLOCK;
	API_RETURN(rc);
}

int
api_socket(int domain, int type, int proto)
{
	int rc, flags, type_noflags, use, use_tcp, use_udp;
	struct sock *so;

	use_tcp = 1; // TODO: in ctl
	use_udp = 0;
	flags = type & (SOCK_NONBLOCK|SOCK_CLOEXEC);
	type_noflags = type & (~(SOCK_NONBLOCK|SOCK_CLOEXEC));
	switch (type_noflags) {
	case SOCK_STREAM:
		use = use_tcp;
		break;
	case SOCK_DGRAM:
		use = use_udp;
		break;
	default:
		use = 0;
		break;
	}
	if (domain == AF_INET && use) {
		rc = so_socket(&so, domain, type_noflags, flags, proto);
		if (rc < 0) {
			INFO(-rc, "failed; type=%s, flags=%s",
			     log_add_socket_type(type_noflags),
			     log_add_socket_flags(flags));
		} else {
			INFO(0, "ok; fd=%d, type=%s, flags=%s",
			     rc, log_add_socket_type(type_noflags),
			     log_add_socket_flags(flags));
		}
	} else {
		rc = -EBADF;
	}
	return rc;
}

int
gt_socket(int domain, int type, int proto)
{
	int rc;

	API_LOCK;
	rc = api_socket(domain, type, proto);
	API_UNLOCK;
	API_RETURN(rc);
}

int
api_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
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
	INFO(0, "hit; fd=%d, faddr=%s", fd, log_add_sockaddr_in(faddr_in));
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
	if (rc < 0) {
		INFO(-rc, "failed");
	} else {
		INFO(0, "ok; laddr=%s", log_add_sockaddr_in(&laddr_in));
	}
	return rc;
}

int
gt_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;

	API_LOCK;
	rc = api_connect(fd, addr, addrlen);
	API_UNLOCK;
	API_RETURN(rc);
}

int
api_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;
	const struct sockaddr_in *addr_in;
	struct sock *so;

	rc = so_get(fd, &so);
	if (rc) {
		return rc;
	}
	if (addr->sa_family != AF_INET) {
		return -EAFNOSUPPORT;
	}
	if (addrlen < sizeof(*addr_in)) {
		return -EINVAL;
	}
	addr_in = (const struct sockaddr_in *)addr;
	INFO(0, "hit; fd=%d, laddr=%s", fd, log_add_sockaddr_in(addr_in));
	rc = so_bind(so, addr_in);
	if (rc < 0) {
		INFO(-rc, "failed");
	} else {
		INFO(0, "ok");
	}
	return rc;
}

int
gt_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;

	API_LOCK;
	rc = api_bind(fd, addr, addrlen);
	API_UNLOCK;
	API_RETURN(rc);
}

int 
api_listen(int fd, int backlog)
{
	int rc;
	struct sock *so;

	rc = so_get(fd, &so);
	if (rc) {
		return rc;
	}
	INFO(0, "hit; lfd=%d", fd);
	rc = so_listen(so, backlog);
	if (rc < 0) {
		INFO(rc, "failed;");
	} else {
		INFO(0, "ok;");
	}
	return rc;
}

int
gt_listen(int fd, int backlog)
{
	int rc;

	API_LOCK;
	rc = api_listen(fd, backlog);
	API_UNLOCK;
	API_RETURN(rc);
}

int
api_accept4(int lfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	int rc;
	struct sock *so, *lso;

	rc = so_get(lfd, &lso);
	if (rc) {
		return rc;
	}
	INFO(0, "hit; lfd=%d, flags=%s)", lfd, log_add_socket_flags(flags));
restart:
	rc = so_accept(&so, lso, addr, addrlen, flags);
	if (rc == -EAGAIN && lso->so_blocked) {
		file_wait(&lso->so_file, POLLIN);
		rc = so_get(lfd, &lso);
		if (rc == 0) {
			goto restart;
		}
	}
	if (rc < 0) {
		INFO(-rc, "failed");
	} else {
		INFO(0, "ok; fd=%d", rc);
	}
	return rc;
}

int
gt_accept4(int lfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	int rc;

	API_LOCK;
	rc = api_accept4(lfd, addr, addrlen, flags);
	API_UNLOCK;
	API_RETURN(rc);
}

int
api_shutdown(int fd, int how)
{
	return -ENOTSUP;
}

int
gt_shutdown(int fd, int how)
{
	int rc;

	API_LOCK;
	rc = api_shutdown(fd, how);
	API_UNLOCK;
	API_RETURN(rc);
}

int
api_close(int fd)
{
	int rc;
	struct file *fp;

	rc = file_get(fd, &fp);
	if (rc) {
		return rc;
	}
	INFO(0, "hit; fd=%d", fd);
	file_close(fp);
	INFO(0, "ok");
	return 0;
}

int
gt_close(int fd)
{
	int rc;

	API_LOCK;
	rc = api_close(fd);	
	API_UNLOCK;
	API_RETURN(rc);
}

ssize_t
gt_read(int fd, void *buf, size_t count)
{
	int rc;

	rc = gt_recvfrom(fd, buf, count, 0, NULL, NULL);
	return rc;
}

ssize_t
api_recvfrom(int fd, const struct iovec *iov, int iovcnt, int flags,
	struct sockaddr *addr, socklen_t *addrlen)
{
	ssize_t rc;
	struct sock *so;

	rc = so_get(fd, &so);
	if (rc) {
		return rc;
	}
	INFO(0, "hit; fd=%d", fd);
restart:
	rc = so_recvfrom(so, iov, iovcnt, flags, addr, addrlen);
	if (rc == -EAGAIN && so->so_blocked) {
		file_wait(&so->so_file, POLLIN);
		rc = so_get(fd, &so);
		if (rc == 0) {
			goto restart;
		}
	}
	if (rc < 0) {
		INFO(-rc, "failed;");
	} else {
		INFO(0, "ok; rc=%zd", rc);
	}
	return rc;
}

ssize_t
gt_readv(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t rc;

	API_LOCK;
	rc = api_recvfrom(fd, iov, iovcnt, 0, NULL, NULL);
	API_UNLOCK;
	API_RETURN(rc);
}

ssize_t
gt_recv(int fd, void *buf, size_t len, int flags)
{
	ssize_t rc;

	rc = gt_recvfrom(fd, buf, len, flags, NULL, NULL);
	return rc;
}

ssize_t
gt_recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *addr,
	socklen_t *addrlen)
{
	ssize_t rc;
	struct iovec iov;

	iov.iov_base = buf;
	iov.iov_len = len;
	API_LOCK;
	rc = api_recvfrom(fd, &iov, 1, flags, addr, addrlen);
	API_UNLOCK;
	API_RETURN(rc);
}

ssize_t
gt_recvmsg(int fd, struct msghdr *msg, int flags)
{
	assert(!"not implemented");
	API_RETURN(-ENOTSUP);
}

ssize_t
gt_write(int fd, const void *buf, size_t count)
{
	ssize_t rc;

	rc = gt_send(fd, buf, count, 0);
	return rc;
}

int
api_send(int fd, const struct iovec *iov, int iovcnt, int flags,
	be32_t faddr, be16_t fport)
{
	int rc;
	struct sock *so;

	rc = so_get(fd, &so);
	if (rc) {
		return rc;
	}
	INFO(0, "hit; fd=%d, count=%d", fd, iovec_accum_len(iov, iovcnt));
restart:
	rc = so_sendto(so, iov, iovcnt, flags, faddr, fport);
	if (rc == -EAGAIN && so->so_blocked) {
		file_wait(&so->so_file, POLLOUT);
		rc = so_get(fd, &so);
		if (rc == 0) {
			goto restart;
		}
	}
	if (rc < 0) {
		INFO(-rc, "failed");
	} else {
		INFO(0, "ok; rc=%d", rc);
	}
	return rc;
}

ssize_t
gt_writev(int fd, const struct iovec *iov, int iovcnt)
{
	int rc;

	API_LOCK;
	rc = api_send(fd, iov, iovcnt, 0, 0, 0);
	API_UNLOCK;
	API_RETURN(rc);
}

ssize_t
gt_send(int fd, const void *buf, size_t cnt, int flags)
{
	ssize_t rc;

	rc = gt_sendto(fd, buf, cnt, flags, NULL, 0);
	return rc;
}

static int
api_send6(int fd, struct iovec *iov, int iovlen, int flags,
	const void *name, int namelen)
{
	int rc;
	be32_t faddr;
	be16_t fport;
	const struct sockaddr_in *addr_in;

	if (namelen >= sizeof(*addr_in)) {
		addr_in = name;
		faddr = addr_in->sin_addr.s_addr;
		fport = addr_in->sin_port;
	} else {
		faddr = 0;
		fport = 0;
	}
	API_LOCK;
	rc = api_send(fd, iov, iovlen, flags, faddr, fport);
	API_UNLOCK;
	API_RETURN(rc);
}

ssize_t
gt_sendto(int fd, const void *buf, size_t len, int flags,
	const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;
	struct iovec iov;

	iov.iov_base = (void *)buf;
	iov.iov_len = len;
	rc = api_send6(fd, &iov, 1, flags, addr, addrlen);
	return rc;
}

ssize_t
gt_sendmsg(int fd, const struct msghdr *msg, int flags)
{
	int rc;

	rc = api_send6(fd, msg->msg_iov, msg->msg_iovlen, msg->msg_flags,
	               msg->msg_name, msg->msg_namelen);
	if (rc >= 0) {
		if (msg->msg_flags != 0) {
			API_RETURN(-ENOTSUP);
		}
		if (msg->msg_controllen != 0) {
			API_RETURN(-ENOTSUP);
		}
	}
	return rc;
}

int
api_fcntl(int fd, int cmd, uintptr_t arg)
{
	int rc;
	struct file *fp;

	rc = file_get(fd, &fp);
	if (rc) {
		return rc;
	}
	INFO(0, "hit; fd=%d, cmd=%s", fd, log_add_fcntl_cmd(cmd));
	rc = file_fcntl(fp, cmd, arg);
	if (rc < 0) {
		INFO(-rc, "failed;");
	} else {
		INFO(0, "ok; rc=0x%x", rc);
	}
	return rc;
}

int
gt_fcntl(int fd, int cmd, uintptr_t arg)
{
	int rc;

	API_LOCK;
	rc = api_fcntl(fd, cmd, arg);
	API_UNLOCK;
	API_RETURN(rc);
}

int
api_ioctl(int fd, unsigned long req, uintptr_t arg)
{
	int rc;
	struct file *fp;

	rc = file_get(fd, &fp);
	if (rc) {
		return rc;
	}
	INFO(0, "hit, fd=%d, req=%s", fd, log_add_ioctl_req(req, arg));
	rc = file_ioctl(fp, req, arg);
	if (rc < 0) {
		INFO(-rc, "failed");
	} else {
		INFO(0, "ok; rc=0x%x", rc);
	}
	return rc;
}

int
gt_ioctl(int fd, unsigned long req, uintptr_t arg)
{
	int rc;

	API_LOCK;
	rc = api_ioctl(fd, req, arg);
	API_UNLOCK;
	API_RETURN(rc);
}

int
api_getsockopt(int fd, int level, int optname, void *optval,
	socklen_t *optlen)
{
	int rc;
	struct sock *so;

	rc = so_get(fd, &so);
	if (rc) {
		return rc;
	}
	INFO(0, "hit; fd=%d, level=%s, optname=%s",
	     fd, log_add_sockopt_level(level),
	     log_add_sockopt_optname(level, optname));
	rc = so_getsockopt(so, level, optname, optval, optlen);
	if (rc < 0) {
		INFO(-rc, "failed;");
	} else if (level == SOL_SOCKET &&
		   optname == SO_ERROR && *optlen >= sizeof(int)) {
		INFO(*(int *)optval, "error;");
	} else {
		INFO(0, "ok;");
	}
	return rc;
}

int
gt_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
	int rc;

	API_LOCK;
	rc = api_getsockopt(fd, level, optname, optval, optlen);
	API_UNLOCK;
	API_RETURN(rc);
}

int
api_setsockopt(int fd, int level, int optname, const void *optval,
	socklen_t optlen)
{
	int rc;
	struct sock *so;

	rc = so_get(fd, &so);
	if (rc) {
		return rc;
	}
	INFO(0, "hit; fd=%d, level=%s, optname=%s",
	     fd, log_add_sockopt_level(level),
	     log_add_sockopt_optname(level, optname));
	rc = so_setsockopt(so, level, optname, optval, optlen);
	if (rc < 0) {
		INFO(-rc, "failed");
	} else {
		INFO(0, "ok");
	}
	return rc;
}

int
gt_setsockopt(int fd, int level, int optname, const void *optval,
	socklen_t optlen)
{
	int rc;

	API_LOCK;
	rc = api_setsockopt(fd, level, optname, optval, optlen);
	API_UNLOCK;
	API_RETURN(rc);
}

int
api_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;
	struct sock *so;

	rc = so_get(fd, &so);
	if (rc) {
		return rc;
	}
	INFO(0, "hit; fd=%d", fd);
	rc = so_getpeername(so, addr, addrlen);
	if (rc < 0) {
		INFO(-rc, "failed");
	} else {
		INFO(0, "ok");
	}
	return rc;
}

int
gt_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;

	API_LOCK;
	rc = api_getpeername(fd, addr, addrlen);
	API_UNLOCK;
	API_RETURN(rc);
}

int
gt_poll(struct pollfd *fds, nfds_t nfds, int timeout_ms)
{
	int rc;
	uint64_t to;

	if (timeout_ms == -1) {
		to = NANOSECONDS_INFINITY;
	} else {
		to = timeout_ms * NANOSECONDS_MILLISECOND;
	}
	API_LOCK;
	DBG(0, "hit; to=%d, events={%s}",
	    timeout_ms, log_add_pollfds_events(fds, nfds));
	rc = u_poll(fds, nfds, to, NULL);
	if (rc < 0) {
		DBG(-rc, "failed");
	} else {
		DBG(0, "ok; rc=%d, revents={%s}",
		    rc, log_add_pollfds_revents(fds, nfds));
	}
	API_UNLOCK;
	API_RETURN(rc);
}

int
gt_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout,
	const sigset_t *sigmask)
{
	int rc;
	uint64_t to;

	if (timeout == NULL) {
		to = NANOSECONDS_INFINITY;
	} else {
		to = NANOSECONDS_SECOND * timeout->tv_sec + timeout->tv_nsec;
	}
	API_LOCK;
	DBG(0, "hit; to={%s}, events={%s}",
	    log_add_ppoll_timeout(timeout),
	    log_add_pollfds_events(fds, nfds));
	rc = u_poll(fds, nfds, to, sigmask);
	if (rc < 0) {
		DBG(-rc, "failed;");
	} else {
		DBG(0, "ok; rc=%d, revents={%s}",
		    rc, log_add_pollfds_revents(fds, rc));
	}
	API_UNLOCK;
	API_RETURN(rc);
}

int
gt_first_fd()
{
	int rc;

	API_LOCK;
	rc = file_first_fd();
	INFO(0, "hit; first_fd=%d", rc);
	API_UNLOCK;
	API_RETURN(rc);
}

#ifdef __linux__
int
gt_clone(int (*fn)(void *), void *child_stack, int flags, void *arg,
	void *ptid, void *tls, void *ctid)
{
	int rc;

	API_LOCK;
	INFO(0, "hit; flags=%s", log_add_clone_flags(flags));
	rc = service_clone(fn, child_stack, flags, arg, ptid, tls, ctid);
	if (rc < 0) {
		INFO(-rc, "failed;");
	} else {
		INFO(0, "ok; pid=%d", rc);
	}
	API_UNLOCK;
	API_RETURN(rc);
}

int
gt_epoll_create1(int flags)
{
	int rc, fd;

	API_LOCK;
	INFO(0, "hit;");
	rc = sys_epoll_create1(EPOLL_CLOEXEC);
	if (rc >= 0) {
		fd = rc;
		rc = u_epoll_create(fd);
		if (rc < 0) {
			sys_close(fd);
		}
	}
	if (rc < 0) {
		INFO(-rc, "failed;");
	} else {
		INFO(0, "ok; ep_fd=%d", rc);
	}
	API_UNLOCK;
	API_RETURN(rc);
}

int
gt_epoll_ctl(int ep_fd, int op, int fd, struct epoll_event *event)
{
	int rc;

	API_LOCK;
	DBG(0, "hit; ep_fd=%d, op=%s, fd=%d, events={%s}",
	    ep_fd, log_add_epoll_op(op), fd,
	    log_add_epoll_event_events(event->events));
	rc = u_epoll_ctl(ep_fd, op, fd, event);
	if (rc) {
		DBG(-rc, "failed;");
	} else {
		DBG(0, "ok;");
	}
	API_UNLOCK;
	API_RETURN(rc);
}

int
gt_epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
	int timeout_ms, const sigset_t *sigmask)
{
	int rc;
	uint64_t to;

	if (timeout_ms == -1) {
		to = NANOSECONDS_INFINITY;
	} else {
		to = timeout_ms * NANOSECONDS_MILLISECOND;
	}
	API_LOCK;
	DBG(0, "hit; epfd=%d", epfd);
	rc = u_epoll_pwait(epfd, events, maxevents, to, sigmask);
	if (rc < 0) {
		DBG(-rc, "failed");
	} else {
		DBG(0, "ok; rc=%d", rc);
	}
	API_UNLOCK;
	API_RETURN(rc);	
}
#else /* __linux__ */
int
gt_kqueue()
{
	int rc, fd;

	API_LOCK;
	INFO(0, "hit;");
	rc = (*sys_kqueue_fn)();
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
	} else {
		fd = rc;
		rc = gt_epoll_create(fd);
		if (rc < 0) {
			(*sys_close_fn)(fd);
		}
	}
	if (rc < 0) {
		LOGF(log, LOG_INFO, -rc, "failed");
	} else {
		LOGF(log, LOG_INFO, 0, "ok; fd=%d", rc);
	}
	API_UNLOCK;
	API_RETURN(rc);
}

int
gt_kevent(int kq, const struct kevent *changelist, int nchanges,
	struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
	int rc;

	API_LOCK;
	log = log_trace0();
	DBG(log, 0, "hit; kq=%d, nchanges=%d, nevents=%d",
	    kq, nchanges, nevents);
	rc = gt_epoll_kevent(kq, changelist, nchanges, eventlist, nevents, timeout);
	if (rc < 0) {
		DBG(log, -rc, "failed; kq=%d", kq);
	} else {
		DBG(log, 0, "ok; kq=%d, rc=%d", kq, rc);
	}
	API_UNLOCK;
	API_RETURN(rc);
}
#endif /* __linux__ */
