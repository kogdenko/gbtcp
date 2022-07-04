// GPL V2 License
#include "internals.h"

static __thread int preload_called;

int gt_preload_passthru = 0;

#define PRELOAD_FLAG_FD_ARG (1 << 0)
#define PRELOAD_FLAG_FD_RET (1 << 1)
#define PRELOAD_FLAG_PASSTHRU (1 << 2)

#define SYS_CALL(fn, ...) \
({ \
	if (sys_##fn##_fn == NULL) { \
 		SYS_DLSYM(fn); \
	} \
	(sys_##fn##_fn)(__VA_ARGS__); \
})

#define PRELOAD_CALL(fn, fd, flags, ...) \
({ \
	int new_fd; \
	ssize_t rc; \
 \
	if (gt_preload_passthru || ((flags) & PRELOAD_FLAG_PASSTHRU) || preload_called || \
			(((flags) & PRELOAD_FLAG_FD_ARG) && fd < GT_FIRST_FD)) { \
		rc = SYS_CALL(fn, ##__VA_ARGS__); \
	} else { \
		preload_called = 1; \
		rc = gt_##fn(__VA_ARGS__); \
		preload_called = 0; \
		if (rc == -1) { \
			if (gt_errno == ENOTSUP && \
			    ((flags) & PRELOAD_FLAG_FD_RET)) { \
				rc = SYS_CALL(fn, ##__VA_ARGS__); \
				if (rc > GT_FIRST_FD) {\
					new_fd = rc; \
					SYS_CALL(close, new_fd); \
					preload_set_errno(ENFILE); \
					rc = -1; \
				} \
			} else { \
				preload_set_errno(gt_errno); \
			} \
		} \
	} \
	rc; \
})

#if 1
#define preload_fork fork
#define preload_vfork vfork
#define preload_socket socket
#define preload_bind bind
#define preload_connect connect
#define preload_listen listen
#define preload_accept accept
#define preload_accept4 accept4
#define preload_shutdown shutdown
#define preload_close close
#define preload_read read
#define preload_readv readv
#define preload_recv recv
#define preload_recvfrom recvfrom
#define preload_write write
#define preload_writev writev
#define preload_send send
#define preload_sendto sendto
#define preload_sendmsg sendmsg
#define preload_fcntl fcntl
#define preload_ioctl ioctl
#define preload_getsockopt getsockopt
#define preload_setsockopt setsockopt
#define preload_getpeername getpeername
#define preload_ppoll ppoll
#define preload_poll poll
#define preload_pselect pselect
#define preload_select select
#define preload_sleep sleep
#define preload_sigprocmask sigprocmask
#define preload_sigsuspend sigsuspend

#ifdef __linux__
#define preload_clone clone
#define preload_epoll_create1 epoll_create1
#define preload_epoll_create epoll_create
#define preload_epoll_ctl epoll_ctl
#define preload_epoll_pwait epoll_pwait
#define preload_epoll_wait epoll_wait
#else // __linux__
#define preload_rfork rfork
#define preload_kevent kevent
#define preload_kqueue kqueue
#endif // __linux__
#endif // 1

static inline void
preload_set_errno(int e)
{
	errno = e;
}

pid_t
preload_fork(void)
{
	int rc;

	rc = PRELOAD_CALL(fork, 0, 0);
	return rc;
}

pid_t
preload_vfork(void)
{
	assert(0);
	errno = EINVAL;
	return -1;
}

int
preload_socket(int domain, int type, int protocol)
{
	int rc, pf;

	pf = PRELOAD_FLAG_FD_RET;
	if (domain != AF_INET) {
		pf |= PRELOAD_FLAG_PASSTHRU;
	}
	rc = PRELOAD_CALL(socket, 0, pf, domain, type, protocol);
	return rc;
}

int
preload_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;

	rc = PRELOAD_CALL(bind, fd, PRELOAD_FLAG_FD_ARG, fd, addr, addrlen);
	return rc;
}

int
preload_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;

	rc = PRELOAD_CALL(connect, fd, PRELOAD_FLAG_FD_ARG, fd, addr, addrlen);
	return rc;
}

int
preload_listen(int fd, int backlog)
{
	int rc;

	rc = PRELOAD_CALL(listen, fd, PRELOAD_FLAG_FD_ARG, fd, backlog);
	return rc;
}

int
preload_accept4(int fd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	int rc;

	rc = PRELOAD_CALL(accept4, fd, PRELOAD_FLAG_FD_ARG|PRELOAD_FLAG_FD_RET,
		fd, addr, addrlen, flags);
	return rc;
}

int
preload_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;

	rc =  preload_accept4(fd, addr, addrlen, 0);
	return rc;
}

int
preload_shutdown(int fd, int how)
{
	int rc;

	rc = PRELOAD_CALL(shutdown, fd, PRELOAD_FLAG_FD_ARG, fd, how);
	return rc;
}

int
preload_close(int fd)
{
	int rc;

	rc = PRELOAD_CALL(close, fd, PRELOAD_FLAG_FD_ARG, fd);
	return rc;
}

ssize_t
preload_read(int fd, void *buf, size_t count)
{
	ssize_t rc;

	rc = PRELOAD_CALL(read, fd, PRELOAD_FLAG_FD_ARG, fd, buf, count);
	return rc;
}

ssize_t
preload_readv(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t rc;

	rc = PRELOAD_CALL(readv, fd, PRELOAD_FLAG_FD_ARG, fd, iov, iovcnt);
	return rc;
}

ssize_t
preload_recv(int fd, void *buf, size_t len, int flags)
{
	ssize_t rc;

	rc = PRELOAD_CALL(recv, fd, PRELOAD_FLAG_FD_ARG, fd, buf, len, flags);
	return rc;
}

ssize_t
preload_recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *src_addr,
	socklen_t *addrlen)
{
	ssize_t rc;

	rc = PRELOAD_CALL(recvfrom, fd, PRELOAD_FLAG_FD_ARG, fd, buf, len, flags,
		src_addr, addrlen);
	return rc;
}

ssize_t
preload_recvmsg(int fd, struct msghdr *msg, int flags)
{
	ssize_t rc;

	rc = PRELOAD_CALL(recvmsg, fd, PRELOAD_FLAG_FD_ARG, fd, msg, flags);
	return rc;
}

ssize_t
preload_write(int fd, const void *buf, size_t count)
{
	ssize_t rc;

	rc = PRELOAD_CALL(write, fd, PRELOAD_FLAG_FD_ARG, fd, buf, count);
	return rc;
}

ssize_t
preload_writev(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t rc;

	rc = PRELOAD_CALL(writev, fd, PRELOAD_FLAG_FD_ARG, fd, iov, iovcnt);
	return rc;
}

ssize_t
preload_send(int fd, const void *buf, size_t len, int flags)
{
	ssize_t rc;

	rc = PRELOAD_CALL(send, fd, PRELOAD_FLAG_FD_ARG, fd, buf, len, flags);
	return rc;
}

ssize_t
preload_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr,
	socklen_t addrlen)
{
	ssize_t rc;

	rc = PRELOAD_CALL(sendto, fd, PRELOAD_FLAG_FD_ARG, fd, buf, len, flags, dest_addr,
		addrlen);
	return rc;
}

ssize_t
preload_sendmsg(int fd, const struct msghdr *msg, int flags)
{
	ssize_t rc;

	rc = PRELOAD_CALL(sendmsg, fd, PRELOAD_FLAG_FD_ARG, fd, msg, flags);
	return rc;
}

int
preload_fcntl(int fd, int cmd, ...)
{
	int rc;
	uintptr_t arg;
	va_list ap;

	va_start(ap, cmd);
	arg = va_arg(ap, uintptr_t);
	va_end(ap);
	rc = PRELOAD_CALL(fcntl, fd, PRELOAD_FLAG_FD_ARG, fd, cmd, arg);
	return rc;
}

int
preload_ioctl(int fd, unsigned long request, ...)
{
	int rc;
	va_list ap;
	uintptr_t arg;

	va_start(ap, request);
	arg = va_arg(ap, uintptr_t);
	va_end(ap);
	rc = PRELOAD_CALL(ioctl, fd, PRELOAD_FLAG_FD_ARG, fd, request, arg);
	return rc;
}

int
preload_ppoll(struct pollfd *pfds, nfds_t npfds, const struct timespec *to,
	const sigset_t *sigmask)
{
	int rc;

	rc = PRELOAD_CALL(ppoll, 0, 0, pfds, npfds, to, sigmask);
	return rc;
}

int
preload_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	int rc;
	struct timespec ts;

	if (timeout < 0) {
		rc = preload_ppoll(fds, nfds, NULL, NULL);
	} else {
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout - ts.tv_sec * 1000) * 1000000;
		rc = preload_ppoll(fds, nfds, &ts, NULL);
	}
	return rc;
}

int
preload_pselect(int n, fd_set *rfds, fd_set *wfds, fd_set *efds, const struct timespec *timeout,
	const sigset_t *sigmask)
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
	n = ppoll(pfds, npfds, timeout, sigmask);
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
preload_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *tv)
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
	rc = preload_pselect(nfds, readfds, writefds, exceptfds, ts, NULL);
	return rc;
}

unsigned int
preload_sleep(unsigned int seconds)
{
	int rc;

	rc = PRELOAD_CALL(sleep, 0, 0, seconds);
	return rc; 
}

int
preload_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
	int rc;

	rc = PRELOAD_CALL(getsockopt, fd, PRELOAD_FLAG_FD_ARG, fd, level, optname, optval, optlen);
	return rc;
}

int
preload_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
	int rc;

	rc = PRELOAD_CALL(setsockopt, fd, PRELOAD_FLAG_FD_ARG, fd, level, optname, optval, optlen);
	return rc;
}

int
preload_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;

	rc = PRELOAD_CALL(getpeername, fd, PRELOAD_FLAG_FD_ARG, fd, addr, addrlen);
	return rc;
}

int
preload_sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	int rc;

	rc = PRELOAD_CALL(sigprocmask, 0, 0, how, set, oldset);
	return rc;
}

int
preload_sigsuspend(const sigset_t *mask)
{
	return preload_ppoll(NULL, 0, NULL, mask);
}

#ifdef __linux__
int
preload_clone(int (*fn)(void *), void *child_stack, int flags, void *arg, ...)
{
	int rc;
	void *ptid, *tls, *ctid;
	va_list ap;

	va_start(ap, arg);
	ptid = va_arg(ap, void *);
	tls = va_arg(ap, void *);
	ctid = va_arg(ap, void *);
	va_end(ap);
	rc = PRELOAD_CALL(clone, 0, 0, fn, child_stack, flags, arg, ptid, tls, ctid);
	return rc;
}

int
preload_epoll_create1(int flags)
{
	int rc;

	rc = PRELOAD_CALL(epoll_create1, 0, PRELOAD_FLAG_FD_RET, flags);
	return rc;	
}

int
preload_epoll_create(int size)
{
	int rc;

	rc = preload_epoll_create1(EPOLL_CLOEXEC);
	return rc;
}

int
preload_epoll_ctl(int ep_fd, int op, int fd, struct epoll_event *event)
{
	int rc;

	rc = PRELOAD_CALL(epoll_ctl, ep_fd, PRELOAD_FLAG_FD_ARG, ep_fd, op, fd, event);
	return rc;
}

int
preload_epoll_pwait(int ep_fd, struct epoll_event *events, int maxevents, int timeout,
	const sigset_t *sigmask)
{
	int rc;

	rc = PRELOAD_CALL(epoll_pwait, ep_fd, PRELOAD_FLAG_FD_ARG, ep_fd, events, maxevents,
		timeout, sigmask);
	return rc;
}

int
preload_epoll_wait(int ep_fd, struct epoll_event *events, int maxevents, int timeout)
{
	int rc;

	rc = preload_epoll_pwait(ep_fd, events, maxevents, timeout, NULL);
	return rc;
}

#else // __linux__
pid_t
preload_rfork(int flags)
{
	assert(0);
	preload_set_errno(EINVAL);
	return -1;
}

int
preload_kqueue()
{
	int rc;

	rc = PRELOAD_CALL(kqueue, 0, PRELOAD_FLAG_FD_RET);
	return rc;
}

int
preload_kevent(int kq, const struct kevent *changelist, int nchanges,
	struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
	int rc;

	rc = PRELOAD_CALL(kevent, kq, PRELOAD_FLAG_FD_ARG, kq, changelist, nchanges,
		eventlist, nevents, timeout);
	return rc;
}
#endif // __linux__
