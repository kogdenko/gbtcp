#include "sys.h"
#include "log.h"
#include "strbuf.h"
#include "gbtcp.h"

#define SYS_CALL(func, ...) \
({ \
	if (sys_##func##_fn == NULL) { \
 		SYS_DLSYM(func); \
	} \
	(sys_##func##_fn)(__VA_ARGS__); \
})

#define GT_PRELOAD_CALL(func, ...) \
({ \
	ssize_t rc; \
 \
	rc = gbtcp_##func(__VA_ARGS__); \
	if (rc == -1) { \
		if (gbtcp_errno == EBADF || gbtcp_errno == ENOTSOCK) { \
			rc = SYS_CALL(func, __VA_ARGS__); \
		} else { \
			gt_preload_set_errno(gbtcp_errno); \
		} \
	} \
	rc; \
})

#if 1
#define GT_PRELOAD_FORK fork
#define GT_PRELOAD_VFORK vfork
#define GT_PRELOAD_SOCKET socket
#define GT_PRELOAD_BIND bind
#define GT_PRELOAD_CONNECT connect
#define GT_PRELOAD_LISTEN listen
#define GT_PRELOAD_ACCEPT accept
#define GT_PRELOAD_ACCEPT4 accept4
#define GT_PRELOAD_SHUTDOWN shutdown
#define GT_PRELOAD_CLOSE close
#define GT_PRELOAD_READ read
#define GT_PRELOAD_READV readv
#define GT_PRELOAD_RECV recv
#define GT_PRELOAD_RECVFROM recvfrom
#define GT_PRELOAD_WRITE write
#define GT_PRELOAD_WRITEV writev
#define GT_PRELOAD_SEND send
#define GT_PRELOAD_SENDTO sendto
#define GT_PRELOAD_SENDMSG sendmsg
#define GT_PRELOAD_SENDFILE sendfile___x
#define GT_PRELOAD_FCNTL fcntl
#define GT_PRELOAD_IOCTL ioctl
#define GT_PRELOAD_GETSOCKOPT getsockopt
#define GT_PRELOAD_SETSOCKOPT setsockopt
#define GT_PRELOAD_GETPEERNAME getpeername
#define GT_PRELOAD_PPOLL ppoll
#define GT_PRELOAD_POLL poll
#define GT_PRELOAD_PSELECT pselect
#define GT_PRELOAD_SELECT select
#define GT_PRELOAD_SIGNAL signal
#define GT_PRELOAD_SIGACTION sigaction
#ifdef __linux__
#define GT_PRELOAD_CLONE clone
#define GT_PRELOAD_EPOLL_CREATE epoll_create
#define GT_PRELOAD_EPOLL_CREATE1 epoll_create1
#define GT_PRELOAD_EPOLL_CTL epoll_ctl
#define GT_PRELOAD_EPOLL_PWAIT epoll_pwait
#define GT_PRELOAD_EPOLL_WAIT epoll_wait
#else /* __linux__ */
#define GT_PRELOAD_RFORK rfork
#define GT_PRELOAD_KEVENT kevent
#define GT_PRELOAD_KQUEUE kqueue
#endif /* __linux__ */
#endif /* 1 */

static inline void
gt_preload_set_errno(int e)
{
	errno = e;
}

pid_t
GT_PRELOAD_FORK()
{
	int rc;

	rc = gbtcp_fork();
	if (rc == -1) {
		gt_preload_set_errno(gbtcp_errno);
	}
	return rc;
}

pid_t
GT_PRELOAD_VFORK()
{
	assert(0);
	errno = EINVAL;
	return -1;
}

int
GT_PRELOAD_SOCKET(int domain, int type, int protocol)
{
	int rc, fd;

	rc = gbtcp_socket(domain, type, protocol);
	if (rc >= 0) {
		return rc;
	}
	rc = SYS_CALL(socket, domain, type, protocol);
	if (rc == -1) {
		return rc;
	}
	fd = rc;
	rc = gbtcp_try_fd(fd);
	if (rc == -1) {
		SYS_CALL(close, fd);
		gt_preload_set_errno(gbtcp_errno);
		return -1;
	} else {
		return fd;
	}
}

int
GT_PRELOAD_BIND(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;

	rc = GT_PRELOAD_CALL(bind, fd, addr, addrlen);
	return rc;
}

int
GT_PRELOAD_CONNECT(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;

	rc = GT_PRELOAD_CALL(connect, fd, addr, addrlen);
	return rc;
}

int
GT_PRELOAD_LISTEN(int fd, int backlog)
{
	int rc;

	rc = GT_PRELOAD_CALL(listen, fd, backlog);
	return rc;
}

int
GT_PRELOAD_ACCEPT4(int fd, struct sockaddr *addr, socklen_t *addrlen,
	int flags)
{
	int rc;

	rc = gbtcp_accept4(fd, addr, addrlen, flags);
	if (rc == -1) {
		if (gbtcp_errno == EBADF || gbtcp_errno == ENOTSOCK) {
			rc = SYS_CALL(accept4, fd, addr, addrlen, flags);
			if (rc == -1) {
				return rc;
			}
			fd = rc;
			rc = gbtcp_try_fd(fd);
			if (rc == -1) {
				SYS_CALL(close, fd);
				gt_preload_set_errno(gbtcp_errno);
				return -1;
			} else {
				return fd;
			}
		} else {
			gt_preload_set_errno(gbtcp_errno);
			return -1;
		}
	} else {
		return rc;
	}
}

int
GT_PRELOAD_ACCEPT(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;

	rc =  GT_PRELOAD_ACCEPT4(fd, addr, addrlen, 0);
	return rc;
}

int
GT_PRELOAD_SHUTDOWN(int fd, int how)
{
	int rc;

	rc = GT_PRELOAD_CALL(shutdown, fd, how);
	return rc;
}

int
GT_PRELOAD_CLOSE(int fd)
{
	int rc;

	rc = GT_PRELOAD_CALL(close, fd);
	return rc;
}

ssize_t
GT_PRELOAD_READ(int fd, void *buf, size_t count)
{
	ssize_t rc;

	rc = GT_PRELOAD_CALL(read, fd, buf, count);
	return rc;
}

ssize_t
GT_PRELOAD_READV(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t rc;

	rc = GT_PRELOAD_CALL(readv, fd, iov, iovcnt);
	return rc;
}

ssize_t
GT_PRELOAD_RECV(int fd, void *buf, size_t len, int flags)
{
	ssize_t rc;

	rc = GT_PRELOAD_CALL(recv, fd, buf, len, flags);
	return rc;
}

ssize_t
GT_PRELOAD_RECVFROM(int fd, void *buf, size_t len, int flags,
	struct sockaddr *src_addr, socklen_t *addrlen)
{
	ssize_t rc;

	rc = GT_PRELOAD_CALL(recvfrom, fd, buf, len, flags, src_addr, addrlen);
	return rc;
}

ssize_t
PRELOAD_RECVMSG(int fd, struct msghdr *msg, int flags)
{
	ssize_t rc;

	rc = GT_PRELOAD_CALL(recvmsg, fd, msg, flags);
	return rc;
}

ssize_t
GT_PRELOAD_WRITE(int fd, const void *buf, size_t count)
{
	ssize_t rc;

	rc = GT_PRELOAD_CALL(write, fd, buf, count);
	return rc;
}

ssize_t
GT_PRELOAD_WRITEV(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t rc;

	rc = GT_PRELOAD_CALL(writev, fd, iov, iovcnt);
	return rc;
}

ssize_t
GT_PRELOAD_SEND(int fd, const void *buf, size_t len, int flags)
{
	ssize_t rc;

	rc = GT_PRELOAD_CALL(send, fd, buf, len, flags);
	return rc;
}

ssize_t
GT_PRELOAD_SENDTO(int fd, const void *buf, size_t len, int flags,
	const struct sockaddr *dest_addr, socklen_t addrlen)
{
	ssize_t rc;

	rc = GT_PRELOAD_CALL(sendto, fd, buf, len, flags, dest_addr, addrlen);
	return rc;
}

ssize_t
GT_PRELOAD_SENDMSG(int fd, const struct msghdr *msg, int flags)
{
	ssize_t rc;

	rc = GT_PRELOAD_CALL(sendmsg, fd, msg, flags);
	return rc;
}

size_t
GT_PRELOAD_SENDFILE(int out_fd, int in_fd, off_t *offset, size_t count)
{
	int rc;

	rc = GT_PRELOAD_CALL(sendfile, out_fd, in_fd, offset, count);
	return rc;
}

int
GT_PRELOAD_FCNTL(int fd, int cmd, ...)
{
	int rc;
	uintptr_t arg;
	va_list ap;

	va_start(ap, cmd);
	arg = va_arg(ap, uintptr_t);
	va_end(ap);
	rc = GT_PRELOAD_CALL(fcntl, fd, cmd, arg);
	return rc;
}

int
GT_PRELOAD_IOCTL(int fd, unsigned long request, ...)
{
	int rc;
	va_list ap;
	uintptr_t arg;

	va_start(ap, request);
	arg = va_arg(ap, uintptr_t);
	va_end(ap);
	rc = GT_PRELOAD_CALL(ioctl, fd, request, arg);
	return rc;
}

int
GT_PRELOAD_PPOLL(struct pollfd *pfds, nfds_t npfds, const struct timespec *to,
	const sigset_t *sigmask)
{
	int rc;

	rc = gbtcp_ppoll(pfds, npfds, to, sigmask);
	if (rc == -1) {
		gt_preload_set_errno(gbtcp_errno);
	}
	return rc;
}

int
GT_PRELOAD_POLL(struct pollfd *fds, nfds_t nfds, int timeout)
{
	int rc;
	struct timespec ts;

	if (timeout < 0) {
		rc = GT_PRELOAD_PPOLL(fds, nfds, NULL, NULL);
	} else {
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout - ts.tv_sec * 1000) * 1000000;
		rc = GT_PRELOAD_PPOLL(fds, nfds, &ts, NULL);
	}
	return rc;
}

int
GT_PRELOAD_PSELECT(int n, fd_set *rfds, fd_set *wfds, fd_set *efds,
	const struct timespec *timeout, const sigset_t *sigmask)
{
	int i, m, s, fd, npfds;
	struct pollfd *pfd, pfds[FD_SETSIZE];

	npfds = 0;
	for (fd = 0; fd < MIN(n, FD_SETSIZE); ++fd) {
		pfd = pfds + npfds;
		pfd->fd = -1;
		pfd->events = 0;
		pfd->revents = 0;
		if (rfds != NULL && FD_ISSET(fd, rfds)) {
			pfd->fd = fd;
			pfd->events |= POLLIN;
		}
		if (wfds != NULL && FD_ISSET(fd, wfds)) {
			pfd->fd = fd;
			pfd->events |= POLLOUT;
		}
		if (pfd->fd != -1) {
			++npfds;
		}
	}
	if (rfds != NULL) {
		FD_ZERO(rfds);
	}
	if (wfds != NULL) {
		FD_ZERO(wfds);
	}
	if (efds != NULL) {
		FD_ZERO(efds);
	}
	n = GT_PRELOAD_PPOLL(pfds, npfds, timeout, sigmask);
	if (n <= 0) {
		return n;
	}
	for (i = 0, m = 0; i < npfds && n; ++i) {
		pfd = pfds + i;
		if (pfd->revents == 0 || pfd->fd == -1) {
			continue;
		}
		n--;
		s = 0;
		if (pfd->revents & ~POLLOUT) {
			if (rfds != NULL) {
				FD_SET(pfd->fd, rfds);
				s = 1;
			}
		}
		if (s == 0 || pfd->revents & POLLOUT) {
			if (wfds != NULL) {
				FD_SET(pfd->fd, wfds);
				s = 1;
			}
		}
		if (s == 0) {
			if (efds != NULL) {
				FD_SET(pfd->fd, efds);
				s = 1;
			}
		}
		m += s;
	}
	return m;
}

int
GT_PRELOAD_SELECT(int nfds, fd_set *readfds, fd_set *writefds,
	fd_set *exceptfds, struct timeval *tv)
{
	int rc;
	struct timespec *ts, ts_buf;

	if (tv == NULL) {
		ts = NULL;
	} else {
		ts = &ts_buf;
		ts->tv_sec = tv->tv_sec;
		ts->tv_nsec = tv->tv_usec * 1000;
	}
	rc = GT_PRELOAD_PSELECT(nfds, readfds, writefds, exceptfds, ts, NULL);
	return rc;
}

int
GT_PRELOAD_GETSOCKOPT(int fd, int level, int optname, void *optval,
	socklen_t *optlen)
{
	int rc;

	rc = GT_PRELOAD_CALL(getsockopt, fd, level, optname, optval, optlen);
	return rc;
}

int
GT_PRELOAD_SETSOCKOPT(int fd, int level, int optname, const void *optval,
	socklen_t optlen)
{
	int rc;

	rc = GT_PRELOAD_CALL(setsockopt, fd, level, optname, optval, optlen);
	return rc;
}

int
GT_PRELOAD_GETPEERNAME(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;

	rc = GT_PRELOAD_CALL(getpeername, fd, addr, addrlen);
	return rc;
}

gt_sighandler_t 
GT_PRELOAD_SIGNAL(int signum, gt_sighandler_t fn)
{
	gt_sighandler_t res;

	res = gbtcp_signal(signum, fn);
	if (res == SIG_ERR) {
		gt_preload_set_errno(gbtcp_errno);
	}
	return res;
}

int
GT_PRELOAD_SIGACTION(int signum, const struct sigaction *act,
	struct sigaction *oldact)
{
	int rc;

	rc = gbtcp_sigaction(signum, act, oldact);
	if (rc == -1) {
		gt_preload_set_errno(gbtcp_errno);
	}
	return rc;
}

#if 0
int
__xstat(int ver, const char * path, struct stat * stat_buf)
{
	printf("-- __xstat\n");
	assert(0);
	return 0;
}

int
__lxstat(int ver, const char * path, struct stat * stat_buf)
{
	printf("-- __lxstat\n");
	assert(0);
	return 0;
}

int
__fxstat(int ver, int fildes, struct stat * stat_buf)
{
	printf("-- __fxstat\n");
	assert(0);
	return 0;
}

int
 __xstat64(int ver, const char * path, struct stat64 * stat_buf)
{
	printf("-- __xstat64\n");
	//assert(0);
	return 0;
}

int
__lxstat64(int ver, const char * path, struct stat64 * stat_buf)
{
	printf("-- __lxstat64\n");
	assert(0);
	return 0;
}

int
__fxstat64(int ver, int fildes, struct stat64 * stat_buf)
{
	printf("-- __fxstat64\n");
	assert(0);
	return 0;
}
#endif

#ifdef __linux__
int
GT_PRELOAD_CLONE(int (*fn)(void *), void *child_stack, int flags,
	void *arg, ...)
{
	int rc;
	void *ptid, *tls, *ctid;
	va_list ap;

	va_start(ap, arg);
	ptid = va_arg(ap, void *);
	tls = va_arg(ap, void *);
	ctid = va_arg(ap, void *);
	va_end(ap);
	rc = gbtcp_clone(fn, child_stack, flags, arg, ptid, tls, ctid);
	return rc;
}

int
GT_PRELOAD_EPOLL_CREATE1(int flags)
{
	int rc;

	rc = gbtcp_epoll_create();
	if (rc == -1) {
		gt_preload_set_errno(gbtcp_errno);
	}
	return rc;	
}

int
GT_PRELOAD_EPOLL_CREATE(int size)
{
	int rc;

	rc = GT_PRELOAD_EPOLL_CREATE1(EPOLL_CLOEXEC);
	return rc;
}

int
GT_PRELOAD_EPOLL_CTL(int epfd, int op, int fd, struct epoll_event *event)
{
	int rc;

	rc = gbtcp_epoll_ctl(epfd, op, fd, event);
	if (rc == -1) {
		gt_preload_set_errno(gbtcp_errno);
	}
	return rc;
}

int
GT_PRELOAD_EPOLL_PWAIT(int epfd, struct epoll_event *events, int maxevents,
	int timeout, const sigset_t *sigmask)
{
	int rc;

	rc = gbtcp_epoll_pwait(epfd, events, maxevents,
	                       timeout, sigmask);
	if (rc == -1) {
		gt_preload_set_errno(gbtcp_errno);
	}
	return rc;
}

int
GT_PRELOAD_EPOLL_WAIT(int epfd, struct epoll_event *events, int maxevents,
	int timeout)
{
	int rc;

	rc = GT_PRELOAD_EPOLL_PWAIT(epfd, events, maxevents, timeout, NULL);
	return rc;
}

#else /* __linux__ */
pid_t
GT_PRELOAD_RFORK(int flags)
{
	assert(0);
	gt_preload_set_errno(EINVAL);
	return -1;
}

int
GT_PRELOAD_KQUEUE()
{
	int rc;

	rc = gbtcp_kqueue();
	if (rc == -1) {
		gt_preload_set_errno(gbtcp_errno);
	}
	return rc;
}

int
GT_PRELOAD_KEVENT(int kq, const struct kevent *changelist, int nchanges,
	struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
	int rc;

	rc = gbtcp_kevent(kq, changelist, nchanges,
	                  eventlist, nevents, timeout);
	if (rc == -1) {
		gt_preload_set_errno(gbtcp_errno);
	}
	return rc;
}
#endif /* __linux__ */
