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
#define gt_preload_fork fork
#define gt_preload_vfork vfork
#define gt_preload_socket socket
#define gt_preload_bind bind
#define gt_preload_connect connect
#define gt_preload_listen listen
#define gt_preload_accept accept
#define gt_preload_accept4 accept4
#define gt_preload_shutdown shutdown
#define gt_preload_close close
#define gt_preload_read read
#define gt_preload_readv readv
#define gt_preload_recv recv
#define gt_preload_recvfrom recvfrom
#define gt_preload_write write
#define gt_preload_writev writev
#define gt_preload_send send
#define gt_preload_sendto sendto
#define gt_preload_sendmsg sendmsg
#define gt_preload_fcntl fcntl
#define gt_preload_ioctl ioctl
#define gt_preload_getsockopt getsockopt
#define gt_preload_setsockopt setsockopt
#define gt_preload_getpeername getpeername
#define gt_preload_ppoll ppoll
#define gt_preload_poll poll
#define gt_preload_pselect pselect
#define gt_preload_select select
#define gt_preload_sleep sleep
#define gt_preload_sigprocmask sigprocmask
#define gt_preload_sigsuspend sigsuspend

#ifdef __linux__
#define gt_preload_clone clone
#define gt_preload_epoll_create1 epoll_create1
#define gt_preload_epoll_create epoll_create
#define gt_preload_epoll_ctl epoll_ctl
#define gt_preload_epoll_pwait epoll_pwait
#define gt_preload_epoll_wait epoll_wait
#else // __linux__
#define gt_preload_rfork rfork
#define gt_preload_kevent kevent
#define gt_preload_kqueue kqueue
#endif // __linux__
#endif // 1

pid_t gt_preload_fork(void) GT_EXPORT;
pid_t gt_preload_vfork(void) GT_EXPORT;
int gt_preload_socket(int, int, int) GT_EXPORT;
int gt_preload_bind(int, const struct sockaddr *, socklen_t) GT_EXPORT;
int gt_preload_connect(int, const struct sockaddr *, socklen_t) GT_EXPORT;
int gt_preload_listen(int, int) GT_EXPORT;
int gt_preload_accept(int, struct sockaddr *, socklen_t *) GT_EXPORT;
int gt_preload_accept4(int, struct sockaddr *, socklen_t *, int) GT_EXPORT;
int gt_preload_shutdown(int, int) GT_EXPORT;
int gt_preload_close(int) GT_EXPORT;
ssize_t gt_preload_read(int, void *, size_t) GT_EXPORT;
ssize_t gt_preload_readv(int, const struct iovec *, int) GT_EXPORT;
ssize_t gt_preload_recv(int, void *, size_t, int) GT_EXPORT;
ssize_t gt_preload_recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *) GT_EXPORT;
ssize_t gt_preload_write(int, const void *, size_t) GT_EXPORT;
ssize_t gt_preload_writev(int, const struct iovec *, int) GT_EXPORT;
ssize_t gt_preload_send(int, const void *, size_t, int) GT_EXPORT;
ssize_t gt_preload_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t)
	GT_EXPORT;
ssize_t gt_preload_sendmsg(int, const struct msghdr *, int) GT_EXPORT;
int gt_preload_fcntl(int, int, ...) GT_EXPORT;
int gt_preload_ioctl(int, unsigned long, ...) GT_EXPORT;
int gt_preload_getsockopt(int, int, int, void *, socklen_t *) GT_EXPORT;
int gt_preload_setsockopt(int, int, int, const void *, socklen_t) GT_EXPORT;
int gt_preload_getpeername(int, struct sockaddr *, socklen_t *) GT_EXPORT;
int gt_preload_ppoll(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *) GT_EXPORT;
int gt_preload_poll(struct pollfd *, nfds_t, int) GT_EXPORT;
int gt_preload_pselect(int, fd_set *, fd_set *, fd_set *, const struct timespec *,
	const sigset_t *) GT_EXPORT;
int gt_preload_select(int, fd_set *, fd_set *, fd_set *, struct timeval *) GT_EXPORT;
unsigned int gt_preload_sleep(unsigned int) GT_EXPORT;
int gt_preload_sigprocmask(int, const sigset_t *, sigset_t *) GT_EXPORT;
int gt_preload_sigsuspend(const sigset_t *) GT_EXPORT;
#ifdef __linux__
int gt_preload_clone(int (*)(void *), void *, int, void *, ...) GT_EXPORT;
int gt_preload_epoll_create1(int) GT_EXPORT;
int gt_preload_epoll_create(int) GT_EXPORT;
int gt_preload_epoll_ctl(int, int, int, struct epoll_event *) GT_EXPORT;
int gt_preload_epoll_pwait(int, struct epoll_event *, int, int, const sigset_t *) GT_EXPORT;
int gt_preload_epoll_wait(int, struct epoll_event *, int, int) GT_EXPORT;
#else // __linux__
pid_t gt_preload_rfork(int) GT_EXPORT;
int gt_preload_kevent(int, const struct kevent *, int, struct kevent *, int,
	const struct timespec *) GT_EXPORT;
int gt_preload_kqueue(void) GT_EXPORT;
#endif // __linux__

static inline void
preload_set_errno(int e)
{
	errno = e;
}

pid_t
gt_preload_fork(void)
{
	int rc;

	rc = PRELOAD_CALL(fork, 0, 0);
	return rc;
}

pid_t
gt_preload_vfork(void)
{
	assert(0);
	errno = EINVAL;
	return -1;
}

int
gt_preload_socket(int domain, int type, int protocol)
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
gt_preload_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;

	rc = PRELOAD_CALL(bind, fd, PRELOAD_FLAG_FD_ARG, fd, addr, addrlen);
	return rc;
}

int
gt_preload_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;

	rc = PRELOAD_CALL(connect, fd, PRELOAD_FLAG_FD_ARG, fd, addr, addrlen);
	return rc;
}

int
gt_preload_listen(int fd, int backlog)
{
	int rc;

	rc = PRELOAD_CALL(listen, fd, PRELOAD_FLAG_FD_ARG, fd, backlog);
	return rc;
}

int
gt_preload_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;

	rc =  gt_preload_accept4(fd, addr, addrlen, 0);
	return rc;
}

int
gt_preload_accept4(int fd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	int rc;

	rc = PRELOAD_CALL(accept4, fd, PRELOAD_FLAG_FD_ARG|PRELOAD_FLAG_FD_RET,
		fd, addr, addrlen, flags);
	return rc;
}

int
gt_preload_shutdown(int fd, int how)
{
	int rc;

	rc = PRELOAD_CALL(shutdown, fd, PRELOAD_FLAG_FD_ARG, fd, how);
	return rc;
}

int
gt_preload_close(int fd)
{
	int rc;

	rc = PRELOAD_CALL(close, fd, PRELOAD_FLAG_FD_ARG, fd);
	return rc;
}

ssize_t
gt_preload_read(int fd, void *buf, size_t count)
{
	ssize_t rc;

	rc = PRELOAD_CALL(read, fd, PRELOAD_FLAG_FD_ARG, fd, buf, count);
	return rc;
}

ssize_t
gt_preload_readv(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t rc;

	rc = PRELOAD_CALL(readv, fd, PRELOAD_FLAG_FD_ARG, fd, iov, iovcnt);
	return rc;
}

ssize_t
gt_preload_recv(int fd, void *buf, size_t len, int flags)
{
	ssize_t rc;

	rc = PRELOAD_CALL(recv, fd, PRELOAD_FLAG_FD_ARG, fd, buf, len, flags);
	return rc;
}

ssize_t
gt_preload_recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *src_addr,
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
gt_preload_write(int fd, const void *buf, size_t count)
{
	ssize_t rc;

	rc = PRELOAD_CALL(write, fd, PRELOAD_FLAG_FD_ARG, fd, buf, count);
	return rc;
}

ssize_t
gt_preload_writev(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t rc;

	rc = PRELOAD_CALL(writev, fd, PRELOAD_FLAG_FD_ARG, fd, iov, iovcnt);
	return rc;
}

ssize_t
gt_preload_send(int fd, const void *buf, size_t len, int flags)
{
	ssize_t rc;

	rc = PRELOAD_CALL(send, fd, PRELOAD_FLAG_FD_ARG, fd, buf, len, flags);
	return rc;
}

ssize_t
gt_preload_sendto(int fd, const void *buf, size_t len, int flags,
	const struct sockaddr *dest_addr, socklen_t addrlen)
{
	ssize_t rc;

	rc = PRELOAD_CALL(sendto, fd, PRELOAD_FLAG_FD_ARG, fd, buf, len, flags, dest_addr,
		addrlen);
	return rc;
}

ssize_t
gt_preload_sendmsg(int fd, const struct msghdr *msg, int flags)
{
	ssize_t rc;

	rc = PRELOAD_CALL(sendmsg, fd, PRELOAD_FLAG_FD_ARG, fd, msg, flags);
	return rc;
}

int
gt_preload_fcntl(int fd, int cmd, ...)
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
gt_preload_ioctl(int fd, unsigned long request, ...)
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
gt_preload_ppoll(struct pollfd *pfds, nfds_t npfds, const struct timespec *to,
	const sigset_t *sigmask)
{
	int rc;

	rc = PRELOAD_CALL(ppoll, 0, 0, pfds, npfds, to, sigmask);
	return rc;
}

int
gt_preload_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	int rc;
	struct timespec ts;

	if (timeout < 0) {
		rc = gt_preload_ppoll(fds, nfds, NULL, NULL);
	} else {
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout - ts.tv_sec * 1000) * 1000000;
		rc = gt_preload_ppoll(fds, nfds, &ts, NULL);
	}
	return rc;
}

int
gt_preload_pselect(int n, fd_set *rfds, fd_set *wfds, fd_set *efds, const struct timespec *timeout,
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
gt_preload_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
	struct timeval *tv)
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
	rc = gt_preload_pselect(nfds, readfds, writefds, exceptfds, ts, NULL);
	return rc;
}

unsigned int
gt_preload_sleep(unsigned int seconds)
{
	int rc;

	rc = PRELOAD_CALL(sleep, 0, 0, seconds);
	return rc; 
}

int
gt_preload_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
	int rc;

	rc = PRELOAD_CALL(getsockopt, fd, PRELOAD_FLAG_FD_ARG, fd, level, optname, optval, optlen);
	return rc;
}

int
gt_preload_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
	int rc;

	rc = PRELOAD_CALL(setsockopt, fd, PRELOAD_FLAG_FD_ARG, fd, level, optname, optval, optlen);
	return rc;
}

int
gt_preload_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;

	rc = PRELOAD_CALL(getpeername, fd, PRELOAD_FLAG_FD_ARG, fd, addr, addrlen);
	return rc;
}

int
gt_preload_sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	int rc;

	rc = PRELOAD_CALL(sigprocmask, 0, 0, how, set, oldset);
	return rc;
}

int
gt_preload_sigsuspend(const sigset_t *mask)
{
	return gt_preload_ppoll(NULL, 0, NULL, mask);
}

#ifdef __linux__
int
gt_preload_clone(int (*fn)(void *), void *child_stack, int flags, void *arg, ...)
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
gt_preload_epoll_create1(int flags)
{
	int rc;

	rc = PRELOAD_CALL(epoll_create1, 0, PRELOAD_FLAG_FD_RET, flags);
	return rc;	
}

int
gt_preload_epoll_create(int size)
{
	int rc;

	rc = gt_preload_epoll_create1(EPOLL_CLOEXEC);
	return rc;
}

int
gt_preload_epoll_ctl(int ep_fd, int op, int fd, struct epoll_event *event)
{
	int rc;

	rc = PRELOAD_CALL(epoll_ctl, ep_fd, PRELOAD_FLAG_FD_ARG, ep_fd, op, fd, event);
	return rc;
}

int
gt_preload_epoll_pwait(int ep_fd, struct epoll_event *events, int maxevents, int timeout,
		const sigset_t *sigmask)
{
	int rc;

	rc = PRELOAD_CALL(epoll_pwait, ep_fd, PRELOAD_FLAG_FD_ARG, ep_fd, events, maxevents,
		timeout, sigmask);
	return rc;
}

int
gt_preload_epoll_wait(int ep_fd, struct epoll_event *events, int maxevents, int timeout)
{
	int rc;

	rc = gt_preload_epoll_pwait(ep_fd, events, maxevents, timeout, NULL);
	return rc;
}

#else // __linux__
pid_t
gt_preload_rfork(int flags)
{
	assert(0);
	preload_set_errno(EINVAL);
	return -1;
}

int
gt_preload_kqueue(void)
{
	int rc;

	rc = PRELOAD_CALL(kqueue, 0, PRELOAD_FLAG_FD_RET);
	return rc;
}

int
gt_preload_kevent(int kq, const struct kevent *changelist, int nchanges,
	struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
	int rc;

	rc = PRELOAD_CALL(kevent, kq, PRELOAD_FLAG_FD_ARG, kq, changelist, nchanges,
		eventlist, nevents, timeout);
	return rc;
}
#endif // __linux__
