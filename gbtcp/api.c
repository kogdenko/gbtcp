/* GPL2 license */
#include "internals.h"

#define API_LOG_MSG_FOREACH(x) \
	x(fork) \
	x(socket) \
	x(connect) \
	x(bind) \
	x(listen) \
	x(accept) \
	x(close) \
	x(recvfrom) \
	x(sendto) \
	x(fcntl) \
	x(ioctl) \
	x(getsockopt) \
	x(setsockopt) \
	x(getpeername) \
	x(poll) \
	x(ppoll) \
	x(sysctl) \
	x(ctl_get_pids) \
	x(try_fd) \
	x(sigaction) \

#ifdef __linux__
#define API_LOG_MSG_FOREACH_OS(x) \
	x(clone) \
	x(epoll_create) \
	x(epoll_ctl) \
	x(epoll_pwait) \
 
#else /* __linux__ */
#define API_LOG_MSG_FOREACH_OS(x) \
	x(kqueue) \
	x(kevent) \

#endif /* __linux__ */

struct api_mod {
	struct log_scope log_scope;
	API_LOG_MSG_FOREACH(LOG_MSG_DECLARE);
	API_LOG_MSG_FOREACH_OS(LOG_MSG_DECLARE);
};

static struct api_mod *current_mod;

static inline int api_lock();

#define API_RETURN(rc) \
	do { \
		if (rc < 0) { \
			gbtcp_errno = -rc; \
			return -1; \
		} else { \
			return rc; \
		} \
	} while (0)

#define GT_API_LOCK \
	if (api_lock()) { \
		return -1; \
	}

#define GT_API_UNLOCK \
	do { \
		gt_fd_event_mod_try_check(); \
		GT_GLOBAL_UNLOCK; \
	} while (0)

#ifdef __linux__
static void
api_mod_init_os(struct api_mod *mod)
{
	LOG_MSG2(mod, clone) = LOG_INFO;
}
#else /* __linux__ */
static void
api_mod_init_os(struct api_mod *mod)
{
}
#endif /* __linux__ */

int
api_mod_init(struct log *log, void **pp)
{
	int rc;
	struct api_mod *mod;
	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (rc) {
		return rc;
	}
	mod = *pp;
	log_scope_init(&mod->log_scope, "api");
	LOG_MSG2(mod, fork) = LOG_INFO;
	api_mod_init_os(mod);
	return 0;
}

int
api_mod_attach(struct log *log, void *raw_mod)
{
	current_mod = raw_mod;
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
	current_mod = NULL;
}

pid_t
gbtcp_fork()
{
	int rc;
	struct log *log;
	GT_API_LOCK;
	log = log_trace0();
	LOGF(log, LOG_MSG(fork), LOG_INFO, 0, "hit");
	rc = gt_service_fork(log);
	if (rc >= 0)
		LOGF(log, LOG_MSG(fork), LOG_INFO, 0, "ok, pid=%d", rc);
	GT_API_UNLOCK;
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
			DBG(log, LOG_MSG(socket), -rc,
			    "failed; type=%s, flags=%s",
			    log_add_socket_type(type_noflags),
			    log_add_socket_flags(flags));
		} else {
			DBG(log, LOG_MSG(socket), 0,
			    "ok; fd=%d, type=%s, flags=%s",
			    rc,
			    log_add_socket_type(type_noflags),
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
	GT_API_LOCK;
	rc = api_socket(NULL, 0, domain, type, proto);
	GT_API_UNLOCK;
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
		DBG(log, LOG_MSG(connect), 0, "bad sa family; fd=%d", fd);
		return -EAFNOSUPPORT;
	}
	if (addrlen < sizeof(*faddr_in)) {
		DBG(log, LOG_MSG(connect), 0, "bad sa len; fd=%d", fd);
		return -EINVAL;
	}
	faddr_in = (const struct sockaddr_in *)addr;
	DBG(log, LOG_MSG(connect), 0, "hit; fd=%d, faddr=%s",
	    fd, log_add_sockaddr_in(faddr_in));
	rc = service_start(log);
	if (rc == 0) {
		rc = gt_sock_connect(fp, faddr_in, &laddr_in);
	}
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
		DBG(log, LOG_MSG(connect), -rc, "failed");
	} else {
		DBG(log, LOG_MSG(connect), 0, "ok; laddr=%s",
		    log_add_sockaddr_in(&laddr_in));
	}
	return rc;
}

int
gbtcp_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;
	GT_API_LOCK;
	rc = api_connect(fd, addr, addrlen);
	GT_API_UNLOCK;
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
		LOGF(log, LOG_MSG(bind), LOG_INFO, 0,
		     "bad sa family; fd=%d", fd);
		return -EAFNOSUPPORT;
	}
	if (addrlen < sizeof(*addr_in)) {
		LOGF(log, LOG_MSG(bind), LOG_INFO, 0,
		     "bad sa len; fd=%d", fd);
		return -EINVAL;
	}
	addr_in = (const struct sockaddr_in *)addr;
	LOGF(log, LOG_MSG(bind), LOG_INFO, 0, "hit; fd=%d, laddr=%s",
	     fd, log_add_sockaddr_in(addr_in));
	rc = service_start(log);
	if (rc == 0)
		rc = gt_sock_bind(fp, addr_in);
	if (rc < 0)
		LOGF(log, LOG_MSG(bind), LOG_INFO, -rc, "failed");
	else
		LOGF(log, LOG_MSG(bind), LOG_INFO, 0, "ok");
	return rc;
}

int
gbtcp_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;
	GT_API_LOCK;
	rc = api_bind(NULL, fd, addr, addrlen);
	GT_API_UNLOCK;
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
	LOGF(log, LOG_MSG(listen), LOG_INFO, 0, "hit; lfd=%d", fd);
	rc = service_start(log);
	if (rc == 0) {
		rc = gt_sock_listen(fp, backlog);
	}
	if (rc < 0) {
		LOGF(log, LOG_MSG(listen), LOG_INFO, rc, "failed");
	} else {
		LOGF(log, LOG_MSG(listen), LOG_INFO, 0, "ok");
	}
	return rc;
}

int
gbtcp_listen(int fd, int backlog)
{
	int rc;
	GT_API_LOCK;
	rc = api_listen(NULL, fd, backlog);
	GT_API_UNLOCK;
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
	DBG(log, LOG_MSG(accept), 0, "hit; lfd=%d, flags=%s)",
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
		DBG(log, LOG_MSG(accept), -rc, "failed");
	} else {
		DBG(log, LOG_MSG(accept), 0, "ok; fd=%d", rc);
	}
	return rc;
}

int
gbtcp_accept4(int lfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	int rc;

	GT_API_LOCK;
	rc = api_accept4(lfd, addr, addrlen, flags);
	GT_API_UNLOCK;
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
	GT_API_LOCK;
	rc = api_shutdown(fd, how);
	GT_API_UNLOCK;
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
	DBG(log, LOG_MSG(close), 0, "hit; fd=%d", fd);
	file_close(fp, GT_SOCK_GRACEFULL);
	DBG(log, LOG_MSG(close), 0, "ok");
	return 0;
}

int
gbtcp_close(int fd)
{
	int rc;
	GT_API_LOCK;
	rc = api_close(fd);	
	GT_API_UNLOCK;
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
	DBG(log, LOG_MSG(recvfrom), 0, "hit; fd=%d", fd);
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
		DBG(log, LOG_MSG(recvfrom), -rc, "failed");
	} else {
		DBG(log, LOG_MSG(recvfrom), 0, "ok; rc=%zd", rc);
	}
	return rc;
}

ssize_t
gbtcp_readv(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t rc;

	GT_API_LOCK;
	rc = api_recvfrom(fd, iov, iovcnt, 0, NULL, NULL);
	GT_API_UNLOCK;
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
	GT_API_LOCK;
	rc = api_recvfrom(fd, &iov, 1, flags, addr, addrlen);
	GT_API_UNLOCK;
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
	DBG(log, LOG_MSG(sendto), 0, "hit; fd=%d, count=%d",
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
		DBG(log, LOG_MSG(sendto), -rc, "failed");
	} else {
		DBG(log, LOG_MSG(sendto), 0, "ok; rc=%d", rc);
	}
	return rc;
}
ssize_t
gbtcp_writev(int fd, const struct iovec *iov, int iovcnt)
{
	int rc;
	GT_API_LOCK;
	rc = api_send(fd, iov, iovcnt, 0, 0, 0);
	GT_API_UNLOCK;
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
	GT_API_LOCK;
	rc = api_send(fd, iov, iovlen, flags, faddr, fport);
	GT_API_UNLOCK;
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

	GT_API_LOCK;
	rc = -EBADF;
	GT_API_UNLOCK;
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
	DBG(log, LOG_MSG(fcntl), 0, "hit; fd=%d, cmd=%s",
	    fd, log_add_fcntl_cmd(cmd));
	rc = file_cntl(fp, cmd, arg);
	if (rc < 0) {
		DBG(log, LOG_MSG(fcntl), -rc, "failed");
	} else {
		DBG(log, LOG_MSG(fcntl), 0, "ok; rc=0x%x", rc);
	}
	return rc;
}
int
gbtcp_fcntl(int fd, int cmd, uintptr_t arg)
{
	int rc;
	GT_API_LOCK;
	rc = api_fcntl(fd, cmd, arg);
	GT_API_UNLOCK;
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
	DBG(log, LOG_MSG(ioctl), 0, "hit, fd=%d, req=%s",
	    fd, log_add_ioctl_req(req));
	rc = file_ioctl(fp, req, arg);
	if (rc < 0) {
		DBG(log, LOG_MSG(ioctl), -rc, "failed");
	} else {
		DBG(log, LOG_MSG(ioctl), 0, "ok; rc=0x%x", rc);
	}
	return rc;
}
int
gbtcp_ioctl(int fd, unsigned long req, uintptr_t arg)
{
	int rc;
	GT_API_LOCK;
	rc = api_ioctl(fd, req, arg);
	GT_API_UNLOCK;
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
	DBG(log, LOG_MSG(getsockopt), 0, "hit; fd=%d, level=%s, optname=%s",
	    fd, log_add_sockopt_level(level),
	    log_add_sockopt_optname(level, optname));
	rc = gt_sock_getsockopt(fp, level, optname, optval, optlen);
	if (rc < 0) {
		DBG(log, LOG_MSG(getsockopt), -rc, "failed");
	} else if (level == SOL_SOCKET &&
		   optname == SO_ERROR && *optlen >= sizeof(int)) {
		DBG(log, LOG_MSG(getsockopt), 0, "error; error=%d",
		    *(int *)optval);
	} else {
		DBG(log, LOG_MSG(getsockopt), 0, "ok");
	}
	return rc;
}
int
gbtcp_getsockopt(int fd, int level, int optname, void *optval,
	socklen_t *optlen)
{
	int rc;
	GT_API_LOCK;
	rc = api_getsockopt(fd, level, optname, optval, optlen);
	GT_API_UNLOCK;
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
	DBG(log, LOG_MSG(setsockopt), 0, "hit; fd=%d, level=%s, optname=%s",
	    fd, log_add_sockopt_level(level),
	    log_add_sockopt_optname(level, optname));
	rc = gt_sock_setsockopt(fp, level, optname, optval, optlen);
	if (rc < 0) {
		DBG(log, LOG_MSG(setsockopt), -rc, "failed");
	} else {
		DBG(log, LOG_MSG(setsockopt), 0, "ok");
	}
	return rc;
}

int
gbtcp_setsockopt(int fd, int level, int optname, const void *optval,
	socklen_t optlen)
{
	int rc;
	GT_API_LOCK;
	rc = api_setsockopt(fd, level, optname, optval, optlen);
	GT_API_UNLOCK;
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
	DBG(log, LOG_MSG(getpeername), 0, "hit; fd=%d", fd);
	rc = gt_sock_getpeername(fp, addr, addrlen);
	if (rc < 0) {
		DBG(log, LOG_MSG(getpeername), -rc, "failed");
	} else {
		DBG(log, LOG_MSG(getpeername), 0, "ok");
	}
	return rc;
}
int
gbtcp_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;

	GT_API_LOCK;
	rc = api_getpeername(fd, addr, addrlen);
	GT_API_UNLOCK;
	API_RETURN(rc);
}
int
gbtcp_poll(struct pollfd *fds, nfds_t nfds, int timeout_ms)
{
	int rc;
	uint64_t to;
	struct log *log;

	if (timeout_ms == -1) {
		to = GT_NSEC_MAX;
	} else {
		to = timeout_ms * GT_MSEC;
	}
	GT_API_LOCK;
	log = log_trace0();
	DBG(log, LOG_MSG(poll), 0, "hit; to=%d, events={%s}",
	    timeout_ms, log_add_pollfds_events(fds, nfds));
	rc = gt_poll(fds, nfds, to, NULL);
	if (rc < 0) {
		DBG(log, LOG_MSG(poll), -rc, "failed");
	} else {
		DBG(log, LOG_MSG(poll), 0, "ok; rc=%d, revents={%s}",
		    rc, log_add_pollfds_revents(fds, nfds));
	}
	GT_API_UNLOCK;
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
		to = GT_NSEC_MAX;
	} else {
		to = GT_SEC * timeout->tv_sec + timeout->tv_nsec;
	}
	GT_API_LOCK;
	log = log_trace0();
	if (timeout == NULL) {
		DBG(log, LOG_MSG(ppoll), 0, "hit; to={inf}, events={%s}",
		    log_add_pollfds_events(fds, nfds));
	} else {
		DBG(log, LOG_MSG(ppoll), 0,
		    "hit; to={sec=%ld, nsec=%ld}, events={%s}",
		    timeout->tv_sec, timeout->tv_nsec,
		    log_add_pollfds_events(fds, nfds));
	}
	rc = gt_poll(fds, nfds, to, sigmask);
	if (rc < 0) {
		DBG(log, LOG_MSG(ppoll), -rc, "failed");
	} else {
		DBG(log, LOG_MSG(ppoll), 0, "ok; rc=%d, revents={%s}",
		    rc, log_add_pollfds_revents(fds, nfds));
	}
	GT_API_UNLOCK;
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
	GT_API_LOCK;
	if (act == NULL) {
		fn = NULL;
	} else if (act->sa_flags & SA_SIGINFO) {
		fn = act->sa_sigaction;
	} else {
		fn = act->sa_handler;
	}
	UNUSED(fn);
	log = log_trace0();
	DBG(log, LOG_MSG(sigaction), 0, "hit; signum=%d, handler=%s",
	    signum, log_add_sighandler(fn));
	rc = gt_signal_sigaction(signum, act, oldact);
	if (rc < 0) {
		DBG(log, LOG_MSG(sigaction), -rc, "failed");
	} else {
		DBG(log, LOG_MSG(sigaction), 0, "ok");
	}
	GT_API_UNLOCK;
	API_RETURN(rc);
}
int
gt_sysctl(int pid, const char *path, char *old, int len, const char *new)
{
	int rc;
	struct log *log;
	GT_API_LOCK;
	log = log_trace0();
	LOGF(log, LOG_MSG(sysctl), LOG_INFO, 0,
	     "hit; pid=%d, path='%s'", pid, path);
	rc = usysctl(log, pid, path, old, len, new);
	if (rc < 0) {
		LOGF(log, LOG_MSG(sysctl), LOG_INFO, -rc, "failed");
	} else {
		LOGF(log, LOG_MSG(sysctl), LOG_INFO, 0, "ok");
	}
	GT_API_UNLOCK;
	API_RETURN(rc);
}
int
gbtcp_try_fd(int fd)
{
	int rc;
	struct log *log;
	GT_API_LOCK;
	log = log_trace0();
	DBG(log, LOG_MSG(try_fd), 0, "hit; fd=%d", fd);
	rc = file_try_fd(fd);
	if (rc == 0) {
		DBG(log, LOG_MSG(try_fd), 0, "ok");
	} else {
		DBG(log, LOG_MSG(try_fd), -rc, "failed");
	}
	GT_API_UNLOCK;
	API_RETURN(rc);
}
#ifdef __linux__
int
gbtcp_clone(int (*fn)(void *), void *child_stack, int flags, void *arg,
	void *ptid, void *tls, void *ctid)
{
	int rc;
	struct log *log;
	GT_API_LOCK;
	log = log_trace0();
	LOGF(log, LOG_MSG(clone), LOG_INFO, 0, "hit; flags=%s",
	     log_add_clone_flags(flags));
	rc = gt_service_clone(fn, child_stack, flags, arg, ptid, tls, ctid);
	if (rc < 0) {
		LOGF(log, LOG_MSG(clone), LOG_INFO, -rc, "failed");
	} else {
		LOGF(log, LOG_MSG(clone), LOG_INFO, 0, "ok; pid=%d", rc);
	}
	GT_API_UNLOCK;
	API_RETURN(rc);
}
int
gbtcp_epoll_create()
{
	int rc, fd;
	struct log *log;
	GT_API_LOCK;
	log = log_trace0();
	LOGF(log, LOG_MSG(epoll_create), LOG_INFO, 0, "hit");
	rc = (*sys_epoll_create1_fn)(EPOLL_CLOEXEC);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
	} else {
		fd = rc;
		rc = uepoll_create(fd);
		if (rc < 0) {
			(*sys_close_fn)(fd);
		}
	}
	if (rc < 0) {
		LOGF(log, LOG_MSG(epoll_create), LOG_INFO, -rc, "failed");
	} else {
		LOGF(log, LOG_MSG(epoll_create), LOG_INFO, 0, "ok; fd=%d", rc);
	}
	GT_API_UNLOCK;
	API_RETURN(rc);
}
int
gbtcp_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	int rc;
	struct log *log;
	GT_API_LOCK;
	log = log_trace0();
	DBG(log, LOG_MSG(epoll_ctl), 0,
	    "hit; epfd=%d, op=%s, fd=%d, events={%s}",
	    epfd, log_add_epoll_op(op), fd,
	    log_add_epoll_event_events(event->events));
	rc = uepoll_ctl(epfd, op, fd, event);
	if (rc) {
		DBG(log, LOG_MSG(epoll_ctl), -rc, "failed");
	} else {
		DBG(log, LOG_MSG(epoll_ctl), 0, "ok");
	}
	GT_API_UNLOCK;
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
		to = GT_NSEC_MAX;
	} else {
		to = timeout_ms * GT_MSEC;
	}
	GT_API_LOCK;
	log = log_trace0();
	DBG(log, LOG_MSG(epoll_pwait), 0, "hit; epfd=%d", epfd);
	rc = uepoll_pwait(epfd, events, maxevents, to, sigmask);
	if (rc < 0) {
		DBG(log, LOG_MSG(epoll_pwait), -rc, "failed");
	} else {
		DBG(log, LOG_MSG(epoll_pwait), 0, "ok; rc=%d", rc);
	}
	GT_API_UNLOCK;
	API_RETURN(rc);	
}
#else /* __linux__ */
int
gbtcp_kqueue()
{
	int rc, fd;
	struct log *log;

	GT_API_LOCK;
	log = log_trace0();
	LOGF(log, LOG_MSG(kqueue), LOG_INFO, 0, "hit");
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
		LOGF(log, LOG_MSG(kqueue), LOG_INFO, -rc, "failed");
	} else {
		LOGF(log, LOG_MSG(kqueue), LOG_INFO, 0, "ok; fd=%d", rc);
	}
	GT_API_UNLOCK;
	API_RETURN(rc);
}
int
gbtcp_kevent(int kq, const struct kevent *changelist, int nchanges,
	struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
	int rc;
	struct log *log;
	GT_API_LOCK;
	log = log_trace0();
	DBG(log, LOG_MSG(kevent), 0, "hit; kq=%d, nchanges=%d, nevents=%d",
	    kq, nchanges, nevents);
	rc = gt_epoll_kevent(kq, changelist, nchanges, eventlist, nevents, timeout);
	if (rc < 0) {
		DBG(log, LOG_MSG(kevent), -rc, "failed; kq=%d", kq);
	} else {
		DBG(log, LOG_MSG(kevent), 0, "ok; kq=%d, rc=%d", kq, rc);
	}
	GT_API_UNLOCK;
	API_RETURN(rc);
}
#endif /* __linux__ */
static inline int
api_lock()
{
	int rc;
	ptrdiff_t stack_off;
	stack_off = (u_char *)&rc - (u_char *)gt_signal_stack;
	if (stack_off < gt_signal_stack_size) {
		// Called from signal handler
		API_RETURN(ENOTSUP);
	}
	GT_GLOBAL_LOCK;
	if (current != NULL) {
		rdtsc_update_time();
	} else {
		rc = service_init();
		if (rc) {
			GT_GLOBAL_UNLOCK;
			API_RETURN(ECANCELED);
		}
	}
	return 0;
}
