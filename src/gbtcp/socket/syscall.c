// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/kernel/api.h>
#include <gbtcp/kernel/backtrace.h>
#include <gbtcp/socket/epoll.h>
#include <gbtcp/kernel/fd_event.h>
#include <gbtcp/kernel/global.h>
#include <gbtcp/kernel/poll.h>
#include <gbtcp/socket/socket.h>
#include <gbtcp/socket/syscall.h>
#include <gbtcp/kernel/worker.h>

#define gt_debug(...) gt_debug3(&gt_so_main->so_logger, ##__VA_ARGS__)
#define gt_info(...) gt_info3(&gt_so_main->so_logger, ##__VA_ARGS__)
#define gt_notice(...) gt_notice3(&gt_so_main->so_logger, ##__VA_ARGS__)
#define gt_warning(...) gt_warning3(&gt_so_main->so_logger, ##__VA_ARGS__)
#define gt_err(...) gt_err3(&gt_so_main->so_logger, ##__VA_ARGS__)

static __thread int gt_syscall_lock_count; // Keep as __thread
__thread int gt_errno; // Keep as __thread

#define GT_SYSCALL_LOCK \
	({ \
		int rc; \
		rc = gt_syscall_lock(); \
		if (rc) { \
			GT_SYSCALL_RETURN(rc); \
		} \
	})

#define GT_SYSCALL_UNLOCK gt_syscall_unlock()

int gt_worker_fork(void);

static int
service_pipe(int fd[2])
{
	int rc;

	rc = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
	assert(rc == 0);
	return rc;
}

static int
service_peer_recv(int fd)
{
	int rc, msg;
	uint64_t to;

	to = 4 * GT_NSEC_PER_SEC;
	rc = gt_read_timed(fd, &msg, sizeof(msg), &to);
	if (rc == 0) {
		gt_err(0, "Service peer closed");
		return -EPIPE;
	} else if (rc == sizeof(msg)) {
		if (msg >= 0) {
			if (msg > 0) {
				gt_err(msg, "Service peer error");
			}
			return msg;
		} else {
			rc = msg;
			gt_err(-rc, "Service peer failed");
			return rc;
		}
	} else if (rc > 0) {
		gt_err(0, "Service peer truncated (%d) reply ", rc);
		return -EINVAL;
	} else {
		return rc;
	}
}

int
gt_syscall_lock(void)
{
	int rc;

	if (gt_syscall_lock_count == 0) {
		if (current == NULL) {
			rc = service_attach();
			if (rc) {
				return -EHOSTUNREACH;
			}
		}
		if (gt_so_main == NULL) {
			// The socket module may not have been loaded yet when
			// this worker attached (the controller's play file
			// runs after its API server starts accepting): the
			// worker_module_load fanout can already be sitting
			// unread on the conn — and without pumping here it
			// never lands, because every syscall of a socketless
			// worker bails right below (and the controller wedges
			// in its fanout exec waiting for the reply).
			wait_for_fd_events2(1, 0);
			if (gt_so_main == NULL) {
				SERVICE_UNLOCK;
				return -EACCES;
			}
		}
	}

	gt_syscall_lock_count++;
	return 0;
}

void
gt_syscall_unlock(void)
{
	assert(gt_syscall_lock_count > 0);
	gt_syscall_lock_count--;
	if (gt_syscall_lock_count == 0) {
		if (current != NULL) {
			check_fd_events();
			SERVICE_UNLOCK;
		}
	}
}

pid_t
gt_fork(void)
{
	int rc;

	GT_SYSCALL_LOCK;
	gt_notice(0, "gt_fork() enter");
	rc = gt_worker_fork();
	if (rc < 0) {
		gt_err(-rc, "gt_fork() failed");
	} else {
		gt_notice(0, "gt_fork() return pid=%d", rc);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

int
gt_socket(int domain, int type, int proto)
{
	int rc, flags, type_noflags;
	struct gt_file *fp;

	GT_SYSCALL_LOCK;
	flags = SOCK_TYPE_FLAGS(type);
	type_noflags = SOCK_TYPE_NOFLAGS(type);
	gt_debug(0, "gt_socket('%s', '%s') enter",
		 log_add_socket_type(type_noflags),
		 log_add_socket_flags(flags));
	rc = gt_so_socket(&fp, domain, type_noflags, flags, proto);
	if (rc < 0) {
		gt_info(-rc, "gt_socket('%s', '%s') failed",
			log_add_socket_type(type_noflags),
			log_add_socket_flags(flags));
	} else {
		gt_info(0, "gt_socket(%s, %s) return fd:%d",
			log_add_socket_type(type_noflags),
			log_add_socket_flags(flags), rc);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

int
gt_connect_locked(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc, error;
	socklen_t optlen;
	const struct sockaddr_in *faddr_in;
	struct sockaddr_in laddr_in;
	struct gt_file *fp;

	if (addr->sa_family != AF_INET) {
		return -EAFNOSUPPORT;
	}
	if (addrlen < sizeof(*faddr_in)) {
		return -EINVAL;
	}
	rc = gt_so_get(fd, &fp);
	if (rc) {
		return rc;
	}
	faddr_in = (const struct sockaddr_in *)addr;
	rc = gt_so_connect(fp, faddr_in, &laddr_in);
restart:
	if (rc == -EINPROGRESS && fp->fl_blocked) {
		file_wait(fp, POLLOUT);
		rc = gt_so_get(fd, &fp);
		if (rc == 0) {
			optlen = sizeof(error);
			rc = gt_so_getsockopt(fp, SOL_SOCKET, SO_ERROR, &error,
					      &optlen);
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

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_connect(fd=%d, '%s') enter", fd,
		 log_add_sockaddr(addr, addrlen));
	rc = gt_connect_locked(fd, addr, addrlen);
	if (rc < 0) {
		gt_info(-rc, "gt_connect(fd=%d, '%s') failed", fd,
			log_add_sockaddr(addr, addrlen));
	} else {
		gt_info(0, "gt_connect(fd=%d, '%s') ok", fd,
			log_add_sockaddr(addr, addrlen));
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

static int
gt_bind_locked(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;
	const struct sockaddr_in *addr_in;
	struct gt_file *fp;

	if (addr->sa_family != AF_INET) {
		return -EAFNOSUPPORT;
	}
	if (addrlen < sizeof(*addr_in)) {
		return -EINVAL;
	}
	rc = gt_so_get(fd, &fp);
	if (rc) {
		return rc;
	}
	addr_in = (const struct sockaddr_in *)addr;
	rc = gt_so_bind(fp, addr_in);
	return rc;
}

int
gt_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_bind(fd=%d, '%s') enter", fd,
		 log_add_sockaddr(addr, addrlen));
	rc = gt_bind_locked(fd, addr, addrlen);
	if (rc < 0) {
		gt_info(-rc, "gt_bind(fd=%d, '%s') failed", fd,
			log_add_sockaddr(addr, addrlen));
	} else {
		gt_info(0, "gt_bind(fd=%d, '%s') ok", fd,
			log_add_sockaddr(addr, addrlen));
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

int
gt_listen(int fd, int backlog)
{
	int rc;
	struct gt_file *fp;

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_listen(lfd=%d) enter", fd);
	rc = gt_so_get(fd, &fp);
	if (rc == 0) {
		rc = gt_so_listen(fp, backlog);
	}
	if (rc < 0) {
		gt_info(rc, "gt_listen(lfd=%d) failed", fd);
	} else {
		gt_info(0, "gt_listen(lfd=%d) ok", fd);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

int
gt_accept4_locked(int lfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	int rc;
	struct gt_file *fp, *lfp;

	rc = gt_so_get(lfd, &lfp);
	if (rc) {
		return rc;
	}
restart:
	rc = gt_so_accept(&fp, lfp, addr, addrlen, flags);
	if (rc == -EAGAIN && lfp->fl_blocked) {
		file_wait(lfp, POLLIN);
		rc = gt_so_get(lfd, &lfp);
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

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_accept4(lfd=%d, '%s') enter", lfd,
		 log_add_socket_flags(flags));
	rc = gt_accept4_locked(lfd, addr, addrlen, flags);
	if (rc < 0) {
		gt_info(-rc, "gt_accept4(lfd=%d, '%s') failed", lfd,
			log_add_socket_flags(flags));
	} else {
		gt_info(0, "gt_accept4(lfd=%d, '%s') return fd=%d", lfd,
			log_add_socket_flags(flags), rc);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

int
gt_shutdown(int fd, int how)
{
	int rc;

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_shutdown(fd=%d, '%s') enter", fd,
		 log_add_shutdown_how(how));
	rc = -ENOTSUP;
	if (rc < 0) {
		gt_info(-rc, "gt_shutdown(fd=%d, '%s') failed", fd,
			log_add_shutdown_how(how));
	} else {
		gt_info(0, "gt_shutdown(fd=%d, '%s') ok", fd,
			log_add_shutdown_how(how));
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

int
gt_close(int fd)
{
	int rc;
	struct gt_file *fp;

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_close(fd=%d) enter", fd);
	rc = file_get(fd, &fp);
	if (rc == 0) {
		file_close(fp);
	}
	if (rc < 0) {
		gt_info(-rc, "gt_close(fd=%d) failed", fd);
	} else {
		gt_info(0, "gt_close(fd=%d) ok", fd);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
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
	struct gt_file *fp;

	rc = gt_so_get(fd, &fp);
	if (rc) {
		return rc;
	}
restart:
	rc = gt_so_recvfrom(fp, iov, iovcnt, flags, addr, addrlen);
	if (rc == -EAGAIN && fp->fl_blocked) {
		file_wait(fp, POLLIN);
		rc = gt_so_get(fd, &fp);
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

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_readv(fd=%d, %d) enter", fd,
		 iovec_accum_len(iov, iovcnt));
	rc = gt_recvfrom_locked(fd, iov, iovcnt, 0, NULL, NULL);
	if (rc < 0) {
		gt_info(-rc, "gt_readv(fd=%d, %d) failed", fd,
			iovec_accum_len(iov, iovcnt));
	} else {
		gt_info(0, "gt_readv(fd=%d, %d) return %zd", fd,
			iovec_accum_len(iov, iovcnt), rc);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
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
	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_recvfrom(fd=%d, %zu) enter", fd, len);
	rc = gt_recvfrom_locked(fd, &iov, 1, flags, addr, addrlen);
	if (rc < 0) {
		gt_info(-rc, "gt_recvfrom(fd=%d, %zu) failed", fd, len);
	} else {
		gt_info(0, "gt_recvfrom(fd=%d, %zu) return %zd", fd, len, rc);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

ssize_t
gt_recvmsg(int fd, struct msghdr *msg, int flags)
{
	assert(!"not implemented");
	GT_SYSCALL_RETURN(-ENOTSUP);
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
	       const struct sockaddr *dest_addr, socklen_t addrlen)
{
	int rc;
	const struct sockaddr_in *nam;
	struct gt_file *fp;

	rc = gt_so_get(fd, &fp);
	if (rc) {
		return rc;
	}

	if (addrlen >= sizeof(*nam)) {
		if (dest_addr->sa_family != AF_INET) {
			return -EINVAL;
		}
	} else if (addrlen != 0) {
		return -EINVAL;
	} else {
		dest_addr = NULL;
	}

restart:
	rc = gt_so_sendto(fp, iov, iovcnt, flags,
			  (const struct sockaddr_in *)dest_addr);
	if (rc == -EAGAIN && fp->fl_blocked) {
		file_wait(fp, POLLOUT);
		rc = gt_so_get(fd, &fp);
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

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_writev(fd=%d, %d) enter", fd,
		 iovec_accum_len(iov, iovcnt));
	rc = gt_send_locked(fd, iov, iovcnt, 0, NULL, 0);
	if (rc < 0) {
		gt_info(-rc, "gt_writev(fd=%d, %d) failed", fd,
			iovec_accum_len(iov, iovcnt));
	} else {
		gt_info(0, "gt_writev(fd=%d, %d) return %zd", fd,
			iovec_accum_len(iov, iovcnt), rc);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
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
	  const struct sockaddr *dest_addr, socklen_t addrlen)
{
	ssize_t rc;
	struct iovec iov;

	iov.iov_base = (void *)buf;
	iov.iov_len = len;
	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_sendto(fd=%d, %zu) enter", fd, len);
	rc = gt_send_locked(fd, &iov, 1, flags, dest_addr, addrlen);
	if (rc < 0) {
		gt_info(-rc, "gt_sendto(fd=%d, %zu) failed", fd, len);
	} else {
		gt_info(0, "gt_sendto(fd=%d, %zu) return %zd", fd, len, rc);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

ssize_t
gt_sendmsg(int fd, const struct msghdr *msg, int flags)
{
	ssize_t rc;
	int iovcnt;
	struct iovec *iov;

	GT_SYSCALL_LOCK;
	iov = msg->msg_iov;
	iovcnt = msg->msg_iovlen;
	gt_debug(0, "gt_sendmsg(fd=%d, %d) enter", fd,
		 iovec_accum_len(iov, iovcnt));
	if (msg->msg_flags != 0 || msg->msg_controllen != 0) {
		rc = -ENOTSUP;
	} else {
		rc = gt_send_locked(fd, iov, iovcnt, msg->msg_flags,
				    msg->msg_name, msg->msg_namelen);
	}
	if (rc < 0) {
		gt_info(-rc, "gt_sendmsg(fd=%d, %d) failed", fd,
			iovec_accum_len(iov, iovcnt));
	} else {
		gt_info(0, "gt_sendmsg(fd=%d, %d) returns %zd", fd,
			iovec_accum_len(iov, iovcnt), rc);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

int
gt_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
	int rc;
	struct gt_file *fp;

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_getsockopt(fd=%d, '%s', '%s') enter", fd,
		 log_add_sockopt_level(level),
		 log_add_sockopt_optname(level, optname));
	rc = gt_so_get(fd, &fp);
	if (rc == 0) {
		rc = gt_so_getsockopt(fp, level, optname, optval, optlen);
	}
	if (rc < 0) {
		gt_info(-rc, "gt_getsockopt(fd=%d, '%s', '%s') failed", fd,
			log_add_sockopt_level(level),
			log_add_sockopt_optname(level, optname));
	} else if (level == SOL_SOCKET && optname == SO_ERROR &&
		   *optlen >= sizeof(int)) {
		gt_info(*(int *)optval,
			"gt_getsockopt(fd=%d, '%s', '%s') return error", fd,
			log_add_sockopt_level(level),
			log_add_sockopt_optname(level, optname));
	} else {
		gt_info(0, "gt_getsockopt(fd=%d, '%s', '%s') ok", fd,
			log_add_sockopt_level(level),
			log_add_sockopt_optname(level, optname));
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

int
gt_setsockopt(int fd, int level, int optname, const void *optval,
	      socklen_t optlen)
{
	int rc;
	struct gt_file *fp;

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_setsockopt(fd=%d, '%s', '%s') enter", fd,
		 log_add_sockopt_level(level),
		 log_add_sockopt_optname(level, optname));
	rc = gt_so_get(fd, &fp);
	if (rc == 0) {
		rc = gt_so_setsockopt(fp, level, optname, optval, optlen);
	}
	if (rc < 0) {
		gt_info(-rc, "gt_setsockopt(fd=%d, '%s', '%s') failed", fd,
			log_add_sockopt_level(level),
			log_add_sockopt_optname(level, optname));
	} else {
		gt_info(0, "gt_setsockopt(fd=%d, '%s', '%s') ok", fd,
			log_add_sockopt_level(level),
			log_add_sockopt_optname(level, optname));
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

int
gt_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;
	struct gt_file *fp;

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_getpeername(fd=%d) enter", fd);
	rc = gt_so_get(fd, &fp);
	if (rc == 0) {
		rc = gt_so_getpeername(fp, addr, addrlen);
	}
	if (rc < 0) {
		gt_info(-rc, "gt_getpeername(fd=%d) failed", fd);
	} else {
		gt_info(0, "gt_getpeername(fd=%d) ok", fd);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

int
gt_fcntl(int fd, int cmd, uintptr_t arg)
{
	int rc;
	struct gt_file *fp;

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_fcntl(fd=%d, '%s') enter", fd, log_add_fcntl_cmd(cmd));
	rc = file_get(fd, &fp);
	if (rc == 0) {
		rc = file_fcntl(fp, cmd, arg);
	}
	if (rc < 0) {
		gt_info(-rc, "gt_fcntl(fd=%d, '%s') failed", fd,
			log_add_fcntl_cmd(cmd));
	} else {
		gt_info(0, "gt_fcntl(fd=%d, '%s') return 0x%x", fd,
			log_add_fcntl_cmd(cmd), rc);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

int
gt_ioctl(int fd, unsigned long req, uintptr_t arg)
{
	int rc;
	struct gt_file *fp;

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_ioctl(fd=%d, '%s') enter", fd,
		 log_add_ioctl_req(req, arg));
	rc = file_get(fd, &fp);
	if (rc == 0) {
		rc = file_ioctl(fp, req, arg);
	}
	if (rc < 0) {
		gt_info(-rc, "gt_ioctl(fd=%d, '%s') failed", fd,
			log_add_ioctl_req(req, arg));
	} else {
		gt_info(0, "gt_ioctl(fd=%d, '%s') return 0x%x", fd,
			log_add_ioctl_req(req, arg), rc);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

int
gt_poll(struct pollfd *fds, nfds_t nfds, int timeout_ms)
{
	int rc;
	u64 to;

	if (timeout_ms == -1) {
		to = UINT64_MAX;
	} else {
		to = timeout_ms * GT_NSEC_PER_MSEC;
	}
	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_poll(to=%d, '%s') enter", timeout_ms,
		 log_add_pollfds_events(fds, nfds));
	rc = gt__poll(fds, nfds, to, NULL);
	if (rc < 0) {
		gt_debug(-rc, "gt_poll(to=%d, '%s') failed", timeout_ms,
			 log_add_pollfds_events(fds, nfds));
	} else {
		gt_debug(0, "gt_poll(to=%d, '%s') return %d, '%s'", timeout_ms,
			 log_add_pollfds_events(fds, nfds), rc,
			 log_add_pollfds_revents(fds, nfds));
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

int
gt_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout,
	 const sigset_t *sigmask)
{
	int rc;
	uint64_t to;

	if (timeout == NULL) {
		to = UINT64_MAX;
	} else {
		to = GT_NSEC_PER_SEC * timeout->tv_sec + timeout->tv_nsec;
	}
	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_ppoll(to=%s, '%s')", log_add_ppoll_timeout(timeout),
		 log_add_pollfds_events(fds, nfds));
	rc = gt__poll(fds, nfds, to, sigmask);
	if (rc < 0) {
		gt_debug(-rc, "gt_ppoll(to=%s, '%s') failed",
			 log_add_ppoll_timeout(timeout),
			 log_add_pollfds_events(fds, nfds));
	} else {
		gt_debug(0, "gt_ppoll(to=%s, '%s') return %d, '%s'",
			 log_add_ppoll_timeout(timeout),
			 log_add_pollfds_events(fds, nfds), rc,
			 log_add_pollfds_revents(fds, rc));
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

unsigned int
gt_sleep(unsigned int seconds)
{
	int rc;
	unsigned int left;
	uint64_t start;

	GT_SYSCALL_LOCK;
	start = nanoseconds;
	rc = gt__poll(NULL, 0, seconds * GT_NSEC_PER_SEC, NULL);
	if (rc < 0) {
		left = seconds - (nanoseconds - start) / GT_NSEC_PER_SEC;
	} else {
		left = 0;
	}
	GT_SYSCALL_UNLOCK;
	return left;
}

int
gt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	int rc;

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_sigprocmask('%s') enter", log_add_sigprocmask_how(how));
	rc = service_sigprocmask(how, set, oldset);
	if (rc < 0) {
		gt_warning(-rc, "gt_sigprocmask('%s') failed",
			   log_add_sigprocmask_how(how));
	} else {
		gt_info(0, "gt_sigprocmask('%s') ok",
			log_add_sigprocmask_how(how));
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

int
gt_aio_cancel(int fd)
{
	int rc;
	struct gt_file *fp;

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_aio_cancel(fd=%d) enter", fd);
	rc = gt_so_get(fd, &fp);
	if (rc == 0) {
		file_aio_cancel(&fp->fl_aio);
	}
	if (rc < 0) {
		gt_info(-rc, "gt_aio_cancel(fd=%d) failed", fd);
	} else {
		gt_info(0, "gt_aio_cancel(fd=%d) ok", fd);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

int
gt_aio_set(int fd, gt_aio_f fn)
{
	int rc;
	struct gt_file *fp;

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_aio_set(fd=%d) enter", fd);
	rc = gt_so_get(fd, &fp);
	if (rc == 0) {
		file_aio_add(fp, &fp->fl_aio, fn);
	}
	if (rc < 0) {
		gt_info(-rc, "gt_aio(set(fd=%d) failed", fd);
	} else {
		gt_info(0, "gt_aio_set(fd=%d) ok", fd);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

ssize_t
gt_aio_recvfrom(int fd, struct iovec *iov, int flags, struct sockaddr *addr,
		socklen_t *addrlen)
{
	ssize_t rc;
	struct gt_file *fp;

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_aio_recvfrom(fd=%d) enter", fd);
	rc = gt_so_get(fd, &fp);
	if (rc == 0) {
		rc = gt_so_aio_recvfrom(fp, iov, flags, addr, addrlen);
	}
	if (rc < 0) {
		gt_info(-rc, "gt_aio_recvfrom(fd=%d) failed", fd);
	} else {
		gt_info(0, "gt_aio_recvfrom(fd=%d) return %zd", fd, rc);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

ssize_t
gt_recvdrain(int fd, size_t cnt)
{
	ssize_t rc;
	struct gt_file *fp;

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_aio_recvfrain(fd=%d) enter", fd);
	rc = gt_so_get(fd, &fp);
	if (rc == 0) {
		rc = gt_so_recvdrain(fp, cnt);
	}
	if (rc < 0) {
		gt_info(-rc, "gt_aio_recvdrain(fd=%d) failed", fd);
	} else {
		gt_info(0, "gt_aio_recvdrain(fd=%d) returns %zd", fd, rc);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

#ifdef __linux__
int
gt_clone(int (*fn)(void *), void *child_stack, int flags, void *arg, void *ptid,
	 void *tls, void *ctid)
{
	int rc;

	GT_SYSCALL_LOCK;
	gt_notice(0, "gt_clone('%s') enter", log_add_clone_flags(flags));
	rc = service_clone(fn, child_stack, flags, arg, ptid, tls, ctid);
	if (rc < 0) {
		gt_err(-rc, "gt_clone('%s') failed",
		       log_add_clone_flags(flags));
	} else {
		gt_notice(0, "gt_clone('%s') return pid=%d",
			  log_add_clone_flags(flags), rc);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

int
gt_epoll_create1(int flags)
{
	int rc, fd;

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_epoll_create1() enetr");
	rc = sys_epoll_create1(EPOLL_CLOEXEC);
	if (rc >= 0) {
		fd = rc;
		rc = u_epoll_create(fd);
		if (rc < 0) {
			sys_close(fd);
		}
	}
	if (rc < 0) {
		gt_info(-rc, "gt_epoll_create1() failed");
	} else {
		gt_info(0, "gt_epoll_create1() return ep_fd=%d", rc);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

int
gt_epoll_ctl(int ep_fd, int op, int fd, struct epoll_event *event)
{
	int rc;

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_epoll_ctl(ep_fd=%d, '%s', fd=%d, '%s') enter", ep_fd,
		 log_add_epoll_op(op), fd,
		 log_add_epoll_event_events(event->events));
	rc = u_epoll_ctl(ep_fd, op, fd, event);
	if (rc) {
		gt_info(-rc, "gt_epoll_ctl(ep_fd=%d, '%s', fd=%d, '%s') failed",
			ep_fd, log_add_epoll_op(op), fd,
			log_add_epoll_event_events(event->events));
	} else {
		gt_info(-rc, "gt_epoll_ctl(ep_fd=%d, '%s', fd=%d, '%s') ok",
			ep_fd, log_add_epoll_op(op), fd,
			log_add_epoll_event_events(event->events));
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

int
gt_epoll_pwait(int ep_fd, struct epoll_event *events, int maxevents,
	       int timeout_ms, const sigset_t *sigmask)
{
	int rc;
	uint64_t to;

	if (timeout_ms == -1) {
		to = UINT64_MAX;
	} else {
		to = timeout_ms * GT_NSEC_PER_MSEC;
	}
	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_epoll_pwait(ep_fd=%d) enter", ep_fd);
	rc = u_epoll_pwait(ep_fd, events, maxevents, to, sigmask);
	if (rc < 0) {
		gt_debug(-rc, "gt_epoll_pwait(ep_fd=%d) failed", ep_fd);
	} else {
		gt_debug(0, "gt_epoll_pwait(ep_fd=%d) return %d", ep_fd, rc);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}
#else // __linux__
int
gt_kqueue(void)
{
	int rc, fd;

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_kqueue() enter");
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
		gt_info(-rc, "gt_kqueue() failed");
	} else {
		gt_info(0, "gt_kqueue() return kq_fd=%d", rc);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}

int
gt_kevent(int kq_fd, const struct kevent *changelist, int nchanges,
	  struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
	int rc;

	GT_SYSCALL_LOCK;
	gt_debug(0, "gt_kevent(kq_fd=%d)", kq_fd);
	rc = u_kevent(kq_fd, changelist, nchanges, eventlist, nevents, timeout);
	if (rc < 0) {
		gt_debug(-rc, "gt_kevent(kq_fd=%d) failed", kq_fd);
	} else {
		gt_debug(0, "gt_kevent(kq_fd=%d) return %d", kq_fd, rc);
	}
	GT_SYSCALL_UNLOCK;
	GT_SYSCALL_RETURN(rc);
}
#endif // __linux__

static void
service_in_parent(int pipe_fd[2])
{
	sys_close(pipe_fd[1]);
	// Wait to service_in_child() done
	// NOTE: Unlock to not catch deadlock with controller.
	// See controller_process() scheduler part.
	SERVICE_UNLOCK;
	service_peer_recv(pipe_fd[0]);
	sys_close(pipe_fd[0]);
}

/*static*/ int
service_dup_so(struct gt_file *oldso)
{
	int rc, fd, flags;
	socklen_t addrlen;
	struct sockaddr_in addr;
	struct gt_file *newso;

	fd = file_get_fd(oldso);
	flags = oldso->fl_blocked ? SOCK_NONBLOCK : 0;
	rc = gt_so_socket6(&newso, fd, AF_INET, SOCK_STREAM, flags, 0);
	if (rc < 0) {
		return rc;
	}
	addrlen = sizeof(addr);
	gt_so_getsockname(oldso, (struct sockaddr *)&addr, &addrlen);
	rc = gt_so_bind(newso, &addr);
	if (rc) {
		goto err;
	}
	rc = gt_so_listen(newso, 0);
	if (rc) {
		goto err;
	}
	newso->fl_blocked = oldso->fl_blocked;
	gt_info(0, "service: Duplicate socket, fd=%d", fd);
	return 0;
err:
	gt_warning(-rc, "service: Failed to duplicate socket, fd=%d", fd);
	gt_so_close(newso);
	return rc;
}

//if (so->so_sid == parent_sid &&
//		so->so_ipproto == SO_IPPROTO_TCP &&
//		so->so_state == GT_TCPS_LISTEN) {
//	break;
//}

// Duplicate only listen sockets
struct child_foreach_binded_socket_udata {
	int parent_sid;
	int duplicated;
};

static int
child_foreach_binded_socket(struct gt_file *fp, void *udata_raw)
{
	int rc, proto;
	socklen_t optlen;
	struct tcp_info tcpi;
	struct child_foreach_binded_socket_udata *udata;

	udata = udata_raw;
	if (fp->fl_worker_index != udata->parent_sid) {
		return 0;
	}
	optlen = sizeof(proto);
	rc = gt_so_getsockopt(fp, SOL_SOCKET, SO_PROTOCOL, &proto, &optlen);
	if (rc) {
		return 0;
	}
	if (proto != IPPROTO_TCP) {
		return 0;
	}
	optlen = sizeof(tcpi);
	rc = gt_so_getsockopt(fp, IPPROTO_TCP, TCP_INFO, &tcpi, &optlen);
	if (rc) {
		return 0;
	}
	if (tcpi.tcpi_state != GT_TCPS_LISTEN) {
		return 0;
	}
	if (current->p_sid == udata->parent_sid) {
		return 1;
	}
	rc = service_dup_so(fp);
	if (rc == 0) {
		udata->duplicated++;
	}
	return 0;
}

static void
service_in_child0(void)
{
	int rc;
	struct dev *dev;
	struct child_foreach_binded_socket_udata udata;

	// Close the child's inherited fd/mmap copies of the parent's devs.
	// The dev structs and the p_dev_head list live in shm and still belong
	// to the parent - only the cloexec-style deinit is allowed here.
	GT_DLIST_FOREACH(dev, &current->p_dev_head, dev_list) {
		gt_dev_deinit(dev, true);
	}

	udata.parent_sid = current->p_sid;
	udata.duplicated = 0;
	rc = gt_foreach_binded_socket(child_foreach_binded_socket, &udata);
	service_detach();
	if (!rc) {
		return;
	}

	rc = service_attach();
	if (rc) {
		return;
	}

	gt_foreach_binded_socket(child_foreach_binded_socket, &udata);
	if (!udata.duplicated) {
		service_detach();
	}
}

static void
service_in_child(int pipe_fd[2])
{
	int msg;

	gt_notice(0, "Child process started");
	sys_close(pipe_fd[0]);
	service_in_child0();

	msg = 0;
	gt_send_all(pipe_fd[1], &msg, sizeof(msg), MSG_NOSIGNAL);

	sys_close(pipe_fd[1]);
}

int
gt_worker_fork(void)
{
	int rc, pipe_fd[2];

	gt_notice(0, "service: fork()");
	rc = service_pipe(pipe_fd);
	if (rc) {
		return rc;
	}
	gt_dbg("fork");
	rc = sys_fork();
	if (rc == 0) {
		gt_dbg("in_child");
		service_in_child(pipe_fd);
	} else if (rc > 0) {
		gt_dbg("in_parent");
		service_in_parent(pipe_fd);
	} else {
		sys_close(pipe_fd[0]);
		sys_close(pipe_fd[1]);
	}
	return rc;
}

#ifdef __linux__
static int (*service_clone_fn)(void *);
static int service_clone_pipe_fd[2];

static int
service_clone_in_child(void *arg)
{
	service_in_child(service_clone_pipe_fd);
	// Unlike fork(), this child never returns through the intercepting
	// wrapper, so no trailing GT_SYSCALL_UNLOCK will run: release the lock
	// service_in_child0() took on the new slot and drop the lock count
	// inherited from the cloning thread.
	if (current != NULL) {
		SERVICE_UNLOCK;
	}
	gt_syscall_lock_count = 0;
	return (*service_clone_fn)(arg);
}

// A CLONE_THREAD child shares the address space, so it is its own
// service-thread: each thread gets a distinct `current` and a distinct service
// slot. We attach it up front (best-effort; the thread's first socket call would
// otherwise attach it lazily) and, crucially, detach it when its start routine
// returns so the controller reclaims the slot at thread exit rather than only at
// process exit. fn/arg are passed through the heap (the address space is shared).
struct service_thread_arg {
	int (*fn)(void *);
	void *arg;
};

static int
service_thread_start(void *p)
{
	int rc;
	struct service_thread_arg a;

	a = *(struct service_thread_arg *)p;
	sys_free(p);
	service_attach();
	rc = (*a.fn)(a.arg);
	service_detach();
	return rc;
}

int
service_clone(int (*fn)(void *), void *child_stack, int flags, void *arg,
	      void *ptid, void *tls, void *ctid)
{
	int rc, clone_vm, clone_files, clone_thread;

	clone_vm = flags & CLONE_VM;
	clone_files = flags & CLONE_FILES;
	clone_thread = flags & CLONE_THREAD;
	gt_notice(0, "service: clone('%s')", log_add_clone_flags(flags));
	if (clone_vm) {
		if (clone_files == 0 || clone_thread == 0) {
			return -EINVAL;
		}
	} else {
		if (clone_files || clone_thread) {
			return -EINVAL;
		}
	}

	if (clone_vm) {
		// A thread: make it its own service-thread (attach/detach are
		// per-thread). Pass fn/arg through the shared address space.
		struct service_thread_arg *a;

		a = sys_malloc(sizeof(*a));
		if (a == NULL) {
			return -ENOMEM;
		}
		a->fn = fn;
		a->arg = arg;
		rc = sys_clone(service_thread_start, child_stack, flags, a,
			       ptid, tls, ctid);
		if (rc == -1) {
			rc = -errno;
			sys_free(a);
		}
	} else {
		service_clone_fn = fn;
		rc = service_pipe(service_clone_pipe_fd);
		if (rc) {
			return rc;
		}
		rc = sys_clone(service_clone_in_child, child_stack, flags, arg,
			       ptid, tls, ctid);
		if (rc == -1) {
			rc = -errno;
			sys_close(service_clone_pipe_fd[0]);
			sys_close(service_clone_pipe_fd[1]);
		} else {
			service_in_parent(service_clone_pipe_fd);
		}
	}
	return rc;
}
#endif // __linux__
