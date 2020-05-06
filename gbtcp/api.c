/* GPL2 license */
#include "internals.h"

struct api_mod {
	struct log_scope log_scope;
};

__thread int api_locked;
static struct api_mod *curmod;


#define API_LOCK \
	if (!api_lock()) { \
		API_RETURN(-ENOTSUP); \
	}

#define API_UNLOCK \
	do { \
		gt_fd_event_mod_try_check(); \
		api_locked--; \
		SERVICE_UNLOCK; \
	} while (0)

static inline int
api_lock()
{
	int rc;
	ptrdiff_t stack_off;

	if (api_locked) {
		return 0;
	}
	stack_off = (u_char *)&rc - (u_char *)gt_signal_stack;
	if (stack_off < gt_signal_stack_size) {
		// Called from signal handler
		return 0;
	} else if (current == NULL) {
		rc = service_init();
		if (rc) {
			return 0;
		}
	}
	SERVICE_LOCK;
	api_locked++;
	return 1;
}

int
api_mod_init(struct log *log, void **pp)
{
	int rc;
	struct api_mod *mod;

	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (rc == 0) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "api");
	}
	return rc;
}

int
api_mod_attach(struct log *log, void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

int
api_proc_init(struct log *log, struct proc *p)
{
	return 0;
}

void
api_mod_deinit(struct log *log, void *raw_mod)
{
	struct api_mod *mod;

	LOG_TRACE(log);
	mod = raw_mod;
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}

void
api_mod_detach(struct log *log)
{
	curmod = NULL;
}

pid_t
gbtcp_fork()
{
	int rc;
	struct log *log;

	API_LOCK;
	log = log_trace0();
	LOGF(log, LOG_INFO, 0, "hit");
	rc = gt_service_fork(log);
	if (rc >= 0)
		LOGF(log, LOG_INFO, 0, "ok, pid=%d", rc);
	API_UNLOCK;
	API_RETURN(rc);
}

int
api_socket(struct log *log, int fd, int domain, int type, int proto)
{
	int rc, flags, type_noflags, use, use_tcp, use_udp;

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
		LOG_TRACE(log);
		rc = gt_sock_socket(log, fd, domain, type_noflags,
		                    flags, proto);
		if (rc < 0) {
			DBG(log, -rc, "failed; type=%s, flags=%s",
			    log_add_socket_type(type_noflags),
			    log_add_socket_flags(flags));
		} else {
			DBG(log, 0, "ok; fd=%d, type=%s, flags=%s",
			    rc, log_add_socket_type(type_noflags),
			    log_add_socket_flags(flags));
		}
		return rc;
	} else {
		return -ENOTSUP;
	}
}

int
gbtcp_socket(int domain, int type, int proto)
{
	int rc;

	API_LOCK;
	rc = api_socket(NULL, 0, domain, type, proto);
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
	struct log *log;
	struct file *fp;

	log = log_trace0();
	rc = gt_sock_get(fd, &fp);
	if (rc) {
		return rc;
	}
	if (addr->sa_family != AF_INET) {
		DBG(log, 0, "bad sa family; fd=%d", fd);
		return -EAFNOSUPPORT;
	}
	if (addrlen < sizeof(*faddr_in)) {
		DBG(log, 0, "bad sa len; fd=%d", fd);
		return -EINVAL;
	}
	faddr_in = (const struct sockaddr_in *)addr;
	DBG(log, 0, "hit; fd=%d, faddr=%s",
	    fd, log_add_sockaddr_in(faddr_in));
	if (!current->p_active) {
		service_activate(log);
	}
	rc = gt_sock_connect(fp, faddr_in, &laddr_in);
restart:
	if (rc == -EINPROGRESS && fp->fl_blocked) {
		rc = file_wait(fp, POLLOUT);
		if (rc == 0) {
			rc = gt_sock_get(fd, &fp);
			goto restart;
		}
		optlen = sizeof(error);
		rc = gt_sock_getsockopt(fp, SOL_SOCKET, SO_ERROR,
		                        &error, &optlen);
		ASSERT(rc == 0);
		rc = -error;
	}
	if (rc < 0) {
		DBG(log, -rc, "failed");
	} else {
		DBG(log, 0, "ok; laddr=%s",
		    log_add_sockaddr_in(&laddr_in));
	}
	return rc;
}

int
gbtcp_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;

	API_LOCK;
	rc = api_connect(fd, addr, addrlen);
	API_UNLOCK;
	API_RETURN(rc);
}

int
api_bind(struct log *log, int fd, const struct sockaddr *addr,
	socklen_t addrlen)
{
	int rc;
	const struct sockaddr_in *addr_in;
	struct file *fp;

	rc = gt_sock_get(fd, &fp);
	if (rc) {
		return rc;
	}
	LOG_TRACE(log);
	if (addr->sa_family != AF_INET) {
		LOGF(log, LOG_INFO, 0,
		     "bad sa family; fd=%d", fd);
		return -EAFNOSUPPORT;
	}
	if (addrlen < sizeof(*addr_in)) {
		LOGF(log, LOG_INFO, 0,
		     "bad sa len; fd=%d", fd);
		return -EINVAL;
	}
	addr_in = (const struct sockaddr_in *)addr;
	LOGF(log, LOG_INFO, 0, "hit; fd=%d, laddr=%s",
	     fd, log_add_sockaddr_in(addr_in));
	if (!current->p_active) {
		service_activate(log);
	}
	rc = gt_sock_bind(fp, addr_in);
	if (rc < 0) {
		LOGF(log, LOG_INFO, -rc, "failed");
	} else {
		LOGF(log, LOG_INFO, 0, "ok");
	}
	return rc;
}

int
gbtcp_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;

	API_LOCK;
	rc = api_bind(NULL, fd, addr, addrlen);
	API_UNLOCK;
	API_RETURN(rc);
}

int 
api_listen(struct log *log, int fd, int backlog)
{
	int rc;
	struct file *fp;

	rc = gt_sock_get(fd, &fp);
	if (rc) {
		return rc;
	}
	LOG_TRACE(log);
	LOGF(log, LOG_INFO, 0, "hit; lfd=%d", fd);
	rc = gt_sock_listen(fp, backlog);
	if (rc < 0) {
		LOGF(log, LOG_INFO, rc, "failed");
	} else {
		LOGF(log, LOG_INFO, 0, "ok");
	}
	return rc;
}

int
gbtcp_listen(int fd, int backlog)
{
	int rc;

	API_LOCK;
	rc = api_listen(NULL, fd, backlog);
	API_UNLOCK;
	API_RETURN(rc);
}

int
api_accept4(int lfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	int rc;
	struct log *log;
	struct file *fp;

	rc = gt_sock_get(lfd, &fp);
	if (rc) {
		return rc;
	}
	log = log_trace0();
	DBG(log, 0, "hit; lfd=%d, flags=%s)",
	    lfd, log_add_socket_flags(flags));
restart:
	if (rc == 0) {
		rc = gt_sock_accept(fp, addr, addrlen, flags);
		if (rc == -EAGAIN && fp->fl_blocked) {
			rc = file_wait(fp, POLLIN);
			if (rc == 0) {
				rc = gt_sock_get(lfd, &fp);
				goto restart;
			}
		}
	}
	if (rc < 0) {
		DBG(log, -rc, "failed");
	} else {
		DBG(log, 0, "ok; fd=%d", rc);
	}
	return rc;
}

int
gbtcp_accept4(int lfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
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
	int rc;
	struct file *fp;

//	GT_DBG(shutdown, 0, "hit; fd=%d, how=%s")
	rc = gt_sock_get(fd, &fp);
	if (rc) {
		return rc;
	} else {
		rc = -ENOTSUP;
	}
	return rc;
}

int
gbtcp_shutdown(int fd, int how)
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
	struct log *log;
	struct file *fp;

	rc = gt_sock_get(fd, &fp);
	if (rc) {
		return rc;
	}
	log = log_trace0();
	DBG(log, 0, "hit; fd=%d", fd);
	file_close(fp, GT_SOCK_GRACEFULL);
	DBG(log, 0, "ok");
	return 0;
}

int
gbtcp_close(int fd)
{
	int rc;

	API_LOCK;
	rc = api_close(fd);	
	API_UNLOCK;
	API_RETURN(rc);
}

ssize_t
gbtcp_read(int fd, void *buf, size_t count)
{
	int rc;

	rc = gbtcp_recvfrom(fd, buf, count, 0, NULL, NULL);
	return rc;
}

ssize_t
api_recvfrom(int fd, const struct iovec *iov, int iovcnt, int flags,
	struct sockaddr *addr, socklen_t *addrlen)
{
	ssize_t rc;
	struct log *log;
	struct file *fp;

	rc = gt_sock_get(fd, &fp);
	if (rc) {
		return rc;
	}
	log = log_trace0();
	DBG(log, 0, "hit; fd=%d", fd);
restart:
	if (rc == 0) {
		rc = gt_sock_recvfrom(fp, iov, iovcnt, flags, addr, addrlen);
		if (rc == -EAGAIN && fp->fl_blocked) {
			rc = file_wait(fp, POLLIN);
			if (rc == 0) {
				rc = gt_sock_get(fd, &fp);
				goto restart;
			}
		}
	}
	if (rc < 0) {
		DBG(log, -rc, "failed");
	} else {
		DBG(log, 0, "ok; rc=%zd", rc);
	}
	return rc;
}

ssize_t
gbtcp_readv(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t rc;

	API_LOCK;
	rc = api_recvfrom(fd, iov, iovcnt, 0, NULL, NULL);
	API_UNLOCK;
	API_RETURN(rc);
}

ssize_t
gbtcp_recv(int fd, void *buf, size_t len, int flags)
{
	ssize_t rc;

	rc = gbtcp_recvfrom(fd, buf, len, flags, NULL, NULL);
	return rc;
}

ssize_t
gbtcp_recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *addr,
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
gbtcp_recvmsg(int fd, struct msghdr *msg, int flags)
{
	BUG;
	API_RETURN(-ENOTSUP);
}

ssize_t
gbtcp_write(int fd, const void *buf, size_t count)
{
	ssize_t rc;

	rc = gbtcp_send(fd, buf, count, 0);
	return rc;
}

int
api_send(int fd, const struct iovec *iov, int iovcnt, int flags,
	be32_t faddr, be16_t fport)
{
	int rc;
	struct log *log;
	struct file *fp;

	rc = gt_sock_get(fd, &fp);
	if (rc) {
		return rc;
	}
	log = log_trace0();
	DBG(log, 0, "hit; fd=%d, count=%d",
	    fd, iovec_len(iov, iovcnt));
restart:
	if (rc == 0) {
		rc = gt_sock_sendto(fp, iov, iovcnt, flags, faddr, fport);
		if (rc == -EAGAIN && fp->fl_blocked) {
			rc = file_wait(fp, POLLOUT);
			if (rc == 0) {
				rc = gt_sock_get(fd, &fp);
				goto restart;
			}
		}
	}
	if (rc < 0) {
		DBG(log, -rc, "failed");
	} else {
		DBG(log, 0, "ok; rc=%d", rc);
	}
	return rc;
}

ssize_t
gbtcp_writev(int fd, const struct iovec *iov, int iovcnt)
{
	int rc;

	API_LOCK;
	rc = api_send(fd, iov, iovcnt, 0, 0, 0);
	API_UNLOCK;
	API_RETURN(rc);
}

ssize_t
gbtcp_send(int fd, const void *buf, size_t cnt, int flags)
{
	ssize_t rc;

	rc = gbtcp_sendto(fd, buf, cnt, flags, NULL, 0);
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
gbtcp_sendto(int fd, const void *buf, size_t len, int flags,
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
gbtcp_sendmsg(int fd, const struct msghdr *msg, int flags)
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

ssize_t
gbtcp_sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
	int rc;

	API_LOCK;
	rc = -EBADF;
	API_UNLOCK;
	API_RETURN(rc);
}

int
api_fcntl(int fd, int cmd, uintptr_t arg)
{
	int rc;
	struct log *log;
	struct file *fp;

	rc = file_get(fd, &fp);
	if (rc) {
		return rc;
	}
	log = log_trace0();
	DBG(log, 0, "hit; fd=%d, cmd=%s",
	    fd, log_add_fcntl_cmd(cmd));
	rc = file_cntl(fp, cmd, arg);
	if (rc < 0) {
		DBG(log, -rc, "failed");
	} else {
		DBG(log, 0, "ok; rc=0x%x", rc);
	}
	return rc;
}

int
gbtcp_fcntl(int fd, int cmd, uintptr_t arg)
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
	struct log *log;
	struct file *fp;

	rc = file_get(fd, &fp);
	if (rc) {
		return rc;
	}
	log = log_trace0();
	DBG(log, 0, "hit, fd=%d, req=%s",
	    fd, log_add_ioctl_req(req));
	rc = file_ioctl(fp, req, arg);
	if (rc < 0) {
		DBG(log, -rc, "failed");
	} else {
		DBG(log, 0, "ok; rc=0x%x", rc);
	}
	return rc;
}

int
gbtcp_ioctl(int fd, unsigned long req, uintptr_t arg)
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
	struct log *log;
	struct file *fp;

	rc = gt_sock_get(fd, &fp);
	if (rc) {
		return rc;
	}
	log = log_trace0();
	DBG(log, 0, "hit; fd=%d, level=%s, optname=%s",
	    fd, log_add_sockopt_level(level),
	    log_add_sockopt_optname(level, optname));
	rc = gt_sock_getsockopt(fp, level, optname, optval, optlen);
	if (rc < 0) {
		DBG(log, -rc, "failed");
	} else if (level == SOL_SOCKET &&
		   optname == SO_ERROR && *optlen >= sizeof(int)) {
		DBG(log, 0, "error; error=%d",
		    *(int *)optval);
	} else {
		DBG(log, 0, "ok");
	}
	return rc;
}

int
gbtcp_getsockopt(int fd, int level, int optname, void *optval,
	socklen_t *optlen)
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
	struct log *log;
	struct file *fp;

	rc = gt_sock_get(fd, &fp);
	if (rc) {
		return rc;
	}
	log = log_trace0();
	DBG(log, 0, "hit; fd=%d, level=%s, optname=%s",
	    fd, log_add_sockopt_level(level),
	    log_add_sockopt_optname(level, optname));
	rc = gt_sock_setsockopt(fp, level, optname, optval, optlen);
	if (rc < 0) {
		DBG(log, -rc, "failed");
	} else {
		DBG(log, 0, "ok");
	}
	return rc;
}

int
gbtcp_setsockopt(int fd, int level, int optname, const void *optval,
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
	struct log *log;
	struct file *fp;

	rc = gt_sock_get(fd, &fp);
	if (rc) {
		return rc;
	}
	log = log_trace0();
	DBG(log, 0, "hit; fd=%d", fd);
	rc = gt_sock_getpeername(fp, addr, addrlen);
	if (rc < 0) {
		DBG(log, -rc, "failed");
	} else {
		DBG(log, 0, "ok");
	}
	return rc;
}

int
gbtcp_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;

	API_LOCK;
	rc = api_getpeername(fd, addr, addrlen);
	API_UNLOCK;
	API_RETURN(rc);
}

int
gbtcp_poll(struct pollfd *fds, nfds_t nfds, int timeout_ms)
{
	int rc;
	uint64_t to;
	struct log *log;

	if (timeout_ms == -1) {
		to = NANOSECONDS_INFINITY;
	} else {
		to = timeout_ms * NANOSECONDS_MILLISECOND;
	}
	API_LOCK;
	log = log_trace0();
	DBG(log, 0, "hit; to=%d, events={%s}",
	    timeout_ms, log_add_pollfds_events(fds, nfds));
	rc = gt_poll(fds, nfds, to, NULL);
	if (rc < 0) {
		DBG(log, -rc, "failed");
	} else {
		DBG(log, 0, "ok; rc=%d, revents={%s}",
		    rc, log_add_pollfds_revents(fds, nfds));
	}
	API_UNLOCK;
	API_RETURN(rc);
}

int
gbtcp_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout,
	const sigset_t *sigmask)
{
	int rc;
	uint64_t to;
	struct log *log;

	if (timeout == NULL) {
		to = NANOSECONDS_INFINITY;
	} else {
		to = NANOSECONDS_SECOND * timeout->tv_sec + timeout->tv_nsec;
	}
	API_LOCK;
	log = log_trace0();
	if (timeout == NULL) {
		DBG(log, 0, "hit; to={inf}, events={%s}",
		    log_add_pollfds_events(fds, nfds));
	} else {
		DBG(log, 0, "hit; to={sec=%ld, nsec=%ld}, events={%s}",
		    timeout->tv_sec, timeout->tv_nsec,
		    log_add_pollfds_events(fds, nfds));
	}
	rc = gt_poll(fds, nfds, to, sigmask);
	if (rc < 0) {
		DBG(log, -rc, "failed");
	} else {
		DBG(log, 0, "ok; rc=%d, revents={%s}",
		    rc, log_add_pollfds_revents(fds, nfds));
	}
	API_UNLOCK;
	API_RETURN(rc);
}

gt_sighandler_t 
gbtcp_signal(int signum, gt_sighandler_t new_sa_handler)
{
	int rc;
	struct sigaction act, oldact;

	memset(&act, 0, sizeof(act));
	act.sa_handler = *new_sa_handler;
	rc = gbtcp_sigaction(signum, &act, &oldact);
	if (rc < 0) {
		return SIG_ERR;
	}
	if (oldact.sa_flags & SA_SIGINFO) {
		// TODO: ? check how works in OS
		return (gt_sighandler_t)oldact.sa_sigaction;
	} else {
		return oldact.sa_handler;
	}
}

int
gbtcp_sigaction(int signum, const struct sigaction *act,
	struct sigaction *oldact)
{
	int rc;
	void *fn;
	struct log *log;

	API_LOCK;
	if (act == NULL) {
		fn = NULL;
	} else if (act->sa_flags & SA_SIGINFO) {
		fn = act->sa_sigaction;
	} else {
		fn = act->sa_handler;
	}
	UNUSED(fn);
	log = log_trace0();
	DBG(log, 0, "hit; signum=%d, handler=%s",
	    signum, log_add_sighandler(fn));
	rc = gt_signal_sigaction(signum, act, oldact);
	if (rc < 0) {
		DBG(log, -rc, "failed");
	} else {
		DBG(log, 0, "ok");
	}
	API_UNLOCK;
	API_RETURN(rc);
}

int
gt_first_fd()
{
	int rc;
	struct log *log;

	API_LOCK;
	log = log_trace0();
	rc = file_first_fd();
	DBG(log, 0, "hit; first_fd=%d", rc);
	API_UNLOCK;
	API_RETURN(rc);
}

#ifdef __linux__
int
gbtcp_clone(int (*fn)(void *), void *child_stack, int flags, void *arg,
	void *ptid, void *tls, void *ctid)
{
	int rc;
	struct log *log;

	API_LOCK;
	log = log_trace0();
	LOGF(log, LOG_INFO, 0, "hit; flags=%s", log_add_clone_flags(flags));
	rc = gt_service_clone(fn, child_stack, flags, arg, ptid, tls, ctid);
	if (rc < 0) {
		LOGF(log, LOG_INFO, -rc, "failed");
	} else {
		LOGF(log, LOG_INFO, 0, "ok; pid=%d", rc);
	}
	API_UNLOCK;
	API_RETURN(rc);
}

int
gbtcp_epoll_create1(int flags)
{
	int rc, fd;
	struct log *log;

	API_LOCK;
	log = log_trace0();
	LOGF(log, LOG_INFO, 0, "hit");
	rc = sys_epoll_create1(log, EPOLL_CLOEXEC);
	if (rc >= 0) {
		fd = rc;
		rc = uepoll_create(fd);
		if (rc < 0) {
			sys_close(log, fd);
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
gbtcp_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	int rc;
	struct log *log;

	API_LOCK;
	log = log_trace0();
	DBG(log, 0, "hit; epfd=%d, op=%s, fd=%d, events={%s}",
	    epfd, log_add_epoll_op(op), fd,
	    log_add_epoll_event_events(event->events));
	rc = uepoll_ctl(epfd, op, fd, event);
	if (rc) {
		DBG(log, -rc, "failed");
	} else {
		DBG(log, 0, "ok");
	}
	API_UNLOCK;
	API_RETURN(rc);
}
int
gbtcp_epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
	int timeout_ms, const sigset_t *sigmask)
{
	int rc;
	uint64_t to;
	struct log *log;

	if (timeout_ms == -1) {
		to = NANOSECONDS_INFINITY;
	} else {
		to = timeout_ms * NANOSECONDS_MILLISECOND;
	}
	API_LOCK;
	log = log_trace0();
	DBG(log, 0, "hit; epfd=%d", epfd);
	rc = uepoll_pwait(epfd, events, maxevents, to, sigmask);
	if (rc < 0) {
		DBG(log, -rc, "failed");
	} else {
		DBG(log, 0, "ok; rc=%d", rc);
	}
	API_UNLOCK;
	API_RETURN(rc);	
}
#else /* __linux__ */
int
gbtcp_kqueue()
{
	int rc, fd;
	struct log *log;

	API_LOCK;
	log = log_trace0();
	LOGF(log, LOG_INFO, 0, "hit");
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
gbtcp_kevent(int kq, const struct kevent *changelist, int nchanges,
	struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
	int rc;
	struct log *log;

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
