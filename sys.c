#include "sys.h"
#include "log.h"
#include "strbuf.h"

#define GT_SYS_LOG_NODE_FOREACH(x) \
	x(mod_deinit) \
	x(fork) \
	x(open) \
	x(socket) \
	x(connect) \
	x(bind) \
	x(listen) \
	x(accept4) \
	x(shutdown) \
	x(close) \
	x(read) \
	x(recvmsg) \
	x(write) \
	x(send) \
	x(sendmsg) \
	x(dup) \
	x(fcntl) \
	x(ioctl) \
	x(getsockopt) \
	x(setsockopt) \
	x(ppoll) \
	x(signal) \
	x(sigaction) \
	x(sigprocmask) \
	x(malloc) \
	x(realloc) \
	x(posix_memalign) \
	x(fopen) \
	x(opendir) \
	x(stat) \
	x(realpath)  \
	x(flock) \
	x(getgrnam) \
	x(chown) \
	x(chmod) \
	x(getifaddrs) \
	x(if_indextoname) \
	x(kill) \
	x(waitpid) \

#ifdef __linux__
#define GT_SYS_LOG_NODE_FOREACH_OS(x) \
	x(clone) \

#else /* __linux__ */
#define GT_SYS_LOG_NODE_FOREACH_OS(x) \
	x(kqueue) \

#endif /* __linux__ */

static struct gt_log_scope this_log;
GT_SYS_LOG_NODE_FOREACH(GT_LOG_NODE_STATIC);
GT_SYS_LOG_NODE_FOREACH_OS(GT_LOG_NODE_STATIC);

gt_open_f gt_sys_open_fn;
gt_socket_f gt_sys_socket_fn;
gt_bind_f gt_sys_bind_fn;
gt_connect_f gt_sys_connect_fn;
gt_listen_f gt_sys_listen_fn;
gt_accept4_f gt_sys_accept4_fn;
gt_flock_f gt_sys_flock_fn;
gt_read_f gt_sys_read_fn;
gt_readv_f gt_sys_readv_fn;
gt_recv_f gt_sys_recv_fn;
gt_recvfrom_f gt_sys_recvfrom_fn;
gt_recvmsg_f gt_sys_recvmsg_fn;
gt_write_f gt_sys_write_fn;
gt_writev_f gt_sys_writev_fn;
gt_send_f gt_sys_send_fn;
gt_sendto_f gt_sys_sendto_fn;
gt_sendmsg_f gt_sys_sendmsg_fn;
gt_sendfile_f gt_sys_sendfile_fn;
gt_shutdown_f gt_sys_shutdown_fn;
gt_close_f gt_sys_close_fn;
gt_dup_f gt_sys_dup_fn;
gt_dup2_f gt_sys_dup2_fn;
gt_fcntl_f gt_sys_fcntl_fn;
gt_ioctl_f gt_sys_ioctl_fn;
gt_ppoll_f gt_sys_ppoll_fn;
gt_fork_f gt_sys_fork_fn;
gt_getsockopt_f gt_sys_getsockopt_fn;
gt_setsockopt_f gt_sys_setsockopt_fn;
gt_getsockname_f gt_sys_getsockname_fn;
gt_getpeername_f gt_sys_getpeername_fn;
gt_signal_f gt_sys_signal_fn;
gt_sigaction_f gt_sys_sigaction_fn;
gt_sigprocmask_f gt_sys_sigprocmask_fn;
#ifdef __linux__
gt_clone_f gt_sys_clone_fn;
gt_epoll_create1_f gt_sys_epoll_create1_fn;
gt_epoll_ctl_f gt_sys_epoll_ctl_fn;
gt_epoll_wait_f gt_sys_epoll_wait_fn;
gt_epoll_pwait_f gt_sys_epoll_pwait_fn;
gt_dup3_f gt_sys_dup3_fn;
#else /* __linux__ */
gt_kqueue_f gt_sys_kqueue_fn;
gt_kevent_f gt_sys_kevent_fn;
#endif /* __linux__ */

int
gt_sys_mod_init()
{
	gt_log_scope_init(&this_log, "sys");
	GT_SYS_LOG_NODE_FOREACH(GT_LOG_NODE_INIT);
	GT_SYS_LOG_NODE_FOREACH_OS(GT_LOG_NODE_INIT);
	return 0;
}

void
gt_sys_mod_deinit(struct gt_log *log)
{
	log = GT_LOG_TRACE(log, mod_deinit);
	gt_log_scope_deinit(log, &this_log);
}

#ifdef __linux__
static void
gt_sys_dlsym_os()
{
	GT_SYS_DLSYM(clone);
	GT_SYS_DLSYM(epoll_create1);
	GT_SYS_DLSYM(epoll_ctl);
	GT_SYS_DLSYM(epoll_wait);
	GT_SYS_DLSYM(epoll_pwait);
}
#else /* __linux__ */
static void
gt_sys_dlsym_os()
{
	GT_SYS_DLSYM(kqueue);
	GT_SYS_DLSYM(kevent);
}
#endif /* __linux__ */

void
gt_sys_mod_dlsym()
{
	GT_SYS_DLSYM(open);
	GT_SYS_DLSYM(socket);
	GT_SYS_DLSYM(bind);
	GT_SYS_DLSYM(connect);
	GT_SYS_DLSYM(listen);
	GT_SYS_DLSYM(accept4);
	GT_SYS_DLSYM(flock);
	GT_SYS_DLSYM(read);
	GT_SYS_DLSYM(readv);
	GT_SYS_DLSYM(recv);
	GT_SYS_DLSYM(recvfrom);
	GT_SYS_DLSYM(recvmsg);
	GT_SYS_DLSYM(write);
	GT_SYS_DLSYM(writev);
	GT_SYS_DLSYM(send);
	GT_SYS_DLSYM(sendto);
	GT_SYS_DLSYM(sendmsg);
	GT_SYS_DLSYM(sendfile);
	GT_SYS_DLSYM(dup);
	GT_SYS_DLSYM(dup2);
	GT_SYS_DLSYM(close);
	GT_SYS_DLSYM(shutdown);
	GT_SYS_DLSYM(fcntl);
	GT_SYS_DLSYM(ioctl);
	GT_SYS_DLSYM(fork);
	GT_SYS_DLSYM(ppoll);
	GT_SYS_DLSYM(setsockopt);
	GT_SYS_DLSYM(getsockopt);
	GT_SYS_DLSYM(getsockname);
	GT_SYS_DLSYM(getpeername);
	GT_SYS_DLSYM(signal);
	GT_SYS_DLSYM(sigaction);
	GT_SYS_DLSYM(sigprocmask);
	gt_sys_dlsym_os();
}

static void
gt_sys_log_addrfn_failed(struct gt_log *log, int eno, int fd,
	const struct sockaddr *addr, socklen_t addrlen)
{
	const struct sockaddr_un *addr_un;
	const struct sockaddr_in *addr_in;

	switch (addr->sa_family) {
	case AF_INET:
		GT_ASSERT(addrlen >= sizeof(*addr_in));
		addr_in = (const struct sockaddr_in *)addr;
		GT_UNUSED(addr_in);
		GT_LOGF(log, LOG_ERR, eno, "failed; fd=%d, sockaddr_in=%s",
		        fd, gt_log_add_sockaddr_in(addr_in));
		break;
	case AF_UNIX:
		GT_ASSERT(addrlen >= sizeof(*addr_un));
		addr_un = (const struct sockaddr_un *)addr;
		GT_UNUSED(addr_un);
		GT_LOGF(log, LOG_ERR, eno, "failed; fd=%d, sun_path='%s'",
		        fd, addr_un->sun_path);
		break;
	default:
		GT_LOGF(log, LOG_ERR, eno, "failed; fd=%d", fd);
		break;
	}
}

int
gt_sys_fork(struct gt_log *log)
{
	int rc;

	rc = (*gt_sys_fork_fn)();
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, fork);
			GT_LOGF(log, LOG_ERR, -rc, "failed");
		}
	}
	return rc;
}

int
gt_sys_open(struct gt_log *log, const char *path, int flags, mode_t mode)
{
	int rc;

restart:
	rc = (*gt_sys_open_fn)(path, flags, mode);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		switch (-rc) {
		case EINTR:
			goto restart;
		default:
			break;
		}
		if  (log != NULL) {
			log = GT_LOG_TRACE(log, open);
			GT_LOGF(log, LOG_ERR, -rc, "failed; path='%s'", path);
		}
	}
	return rc;
}

int
gt_sys_socket(struct gt_log *log, int domain, int type, int protocol)
{
	int rc;

	rc = (*gt_sys_socket_fn)(domain, type, protocol);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc < 0);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, socket);
			GT_LOGF(log, LOG_ERR, -rc,
			        "failed; domain=%s, type=%s",
			        gt_log_add_socket_domain(domain),
			        gt_log_add_socket_type(type));
		}
	}
	return rc;
}

int
gt_sys_connect(struct gt_log *log, int fd, const struct sockaddr *addr,
	socklen_t addrlen)
{
	int rc;

	rc = (*gt_sys_connect_fn)(fd, addr, addrlen);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc < 0);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, connect);
			gt_sys_log_addrfn_failed(log, -rc, fd, addr, addrlen);
		}
		return rc;
	} else {
		return 0;
	}
}

int
gt_sys_bind(struct gt_log *log, int fd, const struct sockaddr *addr,
	socklen_t addrlen)
{
	int rc;

	rc = (*gt_sys_bind_fn)(fd, addr, addrlen);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc < 0);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, bind);
			gt_sys_log_addrfn_failed(log, -rc, fd, addr, addrlen);
		}
		return rc;
	} else {
		return 0;
	}
}

int
gt_sys_listen(struct gt_log *log, int fd, int backlog)
{
	int rc;

	rc = (*gt_sys_listen_fn)(fd, backlog);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc < 0);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, listen);
			GT_LOGF(log, LOG_ERR, -rc,
			        "failed; fd=%d, backlog=%d", fd, backlog);
		}
		return rc;
	} else {
		return 0;
	}
}

int
gt_sys_accept4(struct gt_log *log, int fd, struct sockaddr *addr,
	socklen_t *addrlen, int flags)
{
	int rc;

	rc = (*gt_sys_accept4_fn)(fd, addr, addrlen, flags);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		if (rc != -EAGAIN) {
			if (log != NULL) {
				log = GT_LOG_TRACE(log, accept4);
				GT_LOGF(log, LOG_ERR, -rc,
				        "failed; fd=%d", fd);
			}
		}
	}
	return rc;
}

int
gt_sys_shutdown(struct gt_log *log, int fd, int how)
{
	int rc;

	rc = (*gt_sys_shutdown_fn)(fd, how);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, shutdown);
			GT_LOGF(log, LOG_ERR, -rc,
			        "failed; fd=%d, how=%s",
			        fd, gt_log_add_shutdown_how(how));
		}
	}
	return rc;
}

int
gt_sys_close(struct gt_log *log, int fd)
{
	int rc;

	rc = (*gt_sys_close_fn)(fd);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc < 0);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, close);
			GT_LOGF(log, LOG_ERR, -rc, "failed; fd=%d", fd);
		}
	}
	return rc;
}

ssize_t
gt_sys_read(struct gt_log *log, int fd, void *buf, size_t count)
{
	ssize_t rc;

restart:
	rc = (*gt_sys_read_fn)(fd, buf, count);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		switch (-rc) {
		case EINTR:
			goto restart;
		case EAGAIN:
			break;
		default:
			if (log != NULL) {
				log = GT_LOG_TRACE(log, read);
				GT_LOGF(log, LOG_ERR, -rc,
				        "failed; fd=%d", fd);
			}
			break;
		}
	}
	return rc;
}

ssize_t
gt_sys_recvmsg(struct gt_log *log, int fd, struct msghdr *msg, int flags)
{
	ssize_t rc;

	rc = (*gt_sys_recvmsg_fn)(fd, msg, flags);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		if (rc != -EAGAIN) {
			if (log != NULL) {
				log = GT_LOG_TRACE(log, recvmsg);
				GT_LOGF(log, -rc, LOG_ERR,
				        "failed; fd=%d", fd);
			}
		}
	}
	return rc;
}

ssize_t
gt_sys_write(struct gt_log *log, int fd, const void *buf, size_t count)
{
	ssize_t rc;

restart:
	rc = (*gt_sys_write_fn)(fd, buf, count);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		switch (-rc) {
		case EINTR:
			goto restart;
		case EAGAIN:
			break;
		default:
			if (log != NULL) {
				log = GT_LOG_TRACE(log, write);
				GT_LOGF(log, LOG_ERR, -rc,
				        "failed; fd=%d", fd);
			}
			break;
		}
	}
	return rc;
}

ssize_t
gt_sys_send(struct gt_log *log, int fd, const void *buf, size_t len, int flags)
{
	ssize_t rc;

restart:
	rc = (*gt_sys_send_fn)(fd, buf, len, flags);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		switch (-rc) {
		case EINTR:
			goto restart;
		case EAGAIN:
			break;
		default:
			if (log != NULL) {
				log = GT_LOG_TRACE(log, send);
				GT_LOGF(log, LOG_ERR, -rc,
				        "failed; fd=%d", fd);
			}
			break;
		}
	}
	return rc;
}

ssize_t
gt_sys_sendmsg(struct gt_log *log, int fd, const struct msghdr *msg, int flags)
{
	ssize_t rc;

	rc = (*gt_sys_sendmsg_fn)(fd, msg, flags);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		if (rc != -EPIPE) {
			if (log != NULL) {
				log = GT_LOG_TRACE(log, sendmsg);
				GT_LOGF(log, LOG_ERR, -rc,
				        "failed; fd=%d", fd);
			}
		}
	}
	return rc;
}

int
gt_sys_dup(struct gt_log *log, int fd)
{
	int rc;

	rc = (*gt_sys_dup_fn)(fd);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc < 0);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, dup);
			GT_LOGF(log, LOG_ERR, -rc, "failed; fd=%d", fd);
		}
	}
	return rc;
}

int
gt_sys_fcntl(struct gt_log *log, int fd, int cmd, uintptr_t arg)
{
	int rc;
	rc = (*gt_sys_fcntl_fn)(fd, cmd, arg);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, fcntl);
			GT_LOGF(log, LOG_ERR, -rc,
			        "failed; fd=%d, cmd=%s",
			        fd, gt_log_add_fcntl_cmd(cmd));
		}
	}
	return rc;
}

int
gt_sys_ioctl(struct gt_log *log, int fd, unsigned long request, uintptr_t arg)
{
	int rc;

	rc = (*gt_sys_ioctl_fn)(fd, request, arg);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		switch (request) {
		case SIOCGIFFLAGS:
			if (log != NULL) {
				log = GT_LOG_TRACE(log, ioctl);
				GT_LOGF(log, LOG_ERR, -rc,
				        "failed; fd=%d, req=SIOCGIFFLAGS, ifr_name='%s'",
				        fd, ((struct ifreq *)arg)->ifr_name);
			}
			break;
		default:
			if (log != NULL) {
				log = GT_LOG_TRACE(log, ioctl);
				GT_LOGF(log, LOG_ERR, -rc,
				        "failed; fd=%d, cmd=0x%lx",
				        fd, request);
			}
			break;
		}
	}
	return rc;
}

int
gt_sys_getsockopt(struct gt_log *log, int fd, int level, int optname,
	void *optval, socklen_t *optlen)
{
	int rc;

	rc = (*gt_sys_getsockopt_fn)(fd, level, optname, optval, optlen);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, getsockopt);
			GT_LOGF(log, LOG_ERR, -rc,
			        "failed; fd=%d, level=%s, optname=%s",
			        fd,
			        gt_log_add_sockopt_level(level),
			        gt_log_add_sockopt_optname(level, optname));
		}
	}
	return rc;
}

int
gt_sys_setsockopt(struct gt_log *log, int fd, int level, int optname,
	void *optval, socklen_t optlen)
{
	int rc;

	rc = (*gt_sys_setsockopt_fn)(fd, level, optname, optval, optlen);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, setsockopt);
			GT_LOGF(log, LOG_ERR, -rc,
			       "failed; fd=%d, level=%s, optname=%s",
			       fd,
			       gt_log_add_sockopt_level(level),
			       gt_log_add_sockopt_optname(level, optname));
		}
	}
	return rc;
}

int
gt_sys_ppoll(struct gt_log *log, struct pollfd *fds, nfds_t nfds,
	const struct timespec *to, const sigset_t *sigmask)
{
	int rc;

	rc = (*gt_sys_ppoll_fn)(fds, nfds, to, sigmask);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, ppoll);
			GT_LOGF(log, LOG_ERR, -rc, "failed");
		}
	}
	return rc;
}

void *
gt_sys_signal(struct gt_log *log, int signum, void (*handler)())
{
	int rc;
	void (*res)(int);

	res = (*gt_sys_signal_fn)(signum, handler);
	if (res == SIG_ERR) {
		rc = -errno;
		if (log != NULL) {
			log = GT_LOG_TRACE(log, signal);
			GT_LOGF(log, LOG_ERR, -rc,
			        "failed; signum=%d, sighandler=%s",
			        signum, gt_log_add_sighandler(handler));
		}
	}
	return res;
}

int
gt_sys_sigaction(struct gt_log *log, int signum, const struct sigaction *act,
	struct sigaction *oldact)
{
	int rc;

	rc = (*gt_sys_sigaction_fn)(signum, act, oldact);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, sigaction);
			GT_LOGF(log, LOG_ERR, -rc,
			        "failed; signum=%d", signum);
		}
	}
	return rc;
}

int
gt_sys_sigprocmask(struct gt_log *log, int how, const sigset_t *set,
	sigset_t *oldset)
{
	int rc;

	rc = (*gt_sys_sigprocmask_fn)(how, set, oldset);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, sigprocmask);
			GT_LOGF(log, LOG_ERR, -rc, "failed; how=%s",
			        gt_log_add_sigprocmask_how(how));
		}
	}
	return rc;
}

int
gt_sys_malloc(struct gt_log *log, void **pptr, size_t size)
{
	*pptr = malloc(size);
	if (*pptr == NULL) {
		if (log != NULL) {
			log = GT_LOG_TRACE(log, malloc);
			GT_LOGF(log, LOG_ERR, 0, "failed; size=%zu", size);
		}
		return -ENOMEM;
	}
	return 0;
}

int
gt_sys_realloc(struct gt_log *log, void **pptr, size_t size)
{
	void *new_ptr;

	new_ptr = realloc(*pptr, size);
	if (new_ptr == NULL) {
		if (log != NULL) {
			log = GT_LOG_TRACE(log, realloc);
			GT_LOGF(log, LOG_ERR, 0, "failed; size=%zu", size);
		}
		return -ENOMEM;
	}
	*pptr = new_ptr;
	return 0;
}

int
gt_sys_posix_memalign(struct gt_log *log, void **memptr, size_t alignment,
	size_t size)
{
	int rc;

	rc = posix_memalign(memptr, alignment, size);
	if (rc) {
		if (log != NULL) {
			log = GT_LOG_TRACE(log, posix_memalign);
			GT_LOGF(log, LOG_ERR, 0,
			        "failed; alignment=%zu, size=%zu",
			        alignment, size);
		}
	}
	return -rc;
}

int
gt_sys_fopen(struct gt_log *log, FILE **file, const char *path,
	const char *mode)
{
	int rc;

	*file = fopen(path, mode);
	if (*file == NULL) {
		rc = -errno;
		GT_ASSERT(rc);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, fopen);
			GT_LOGF(log, LOG_ERR, -rc,
			       "failed; path='%s', mode=%s", path, mode);
		}
		return rc;
	}
	return 0;
}

int
gt_sys_opendir(struct gt_log *log, DIR **pdir, const char *name)
{
	int rc;

	*pdir = opendir(name);
	if (*pdir == NULL) {
		rc = -errno;
		GT_ASSERT(rc);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, opendir);
			GT_LOGF(log, LOG_ERR, -rc, "failed; name='%s'", name);
		}
		return rc;
	}
	return 0;
}

int
gt_sys_stat(struct gt_log *log, const char *path, struct stat *buf)
{
	int rc;

restart:
	rc = stat(path, buf);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(errno);
		if (rc == -EINTR) {
			goto restart;
		}
		if (log != NULL) {
			log = GT_LOG_TRACE(log, stat);
			GT_LOGF(log, LOG_ERR, -rc, "failed; path='%s'", path);
		}
	}
	return rc;
}

int
gt_sys_realpath(struct gt_log *log, const char *path, char *resolved_path)
{
	int rc;
	char *res;

	res = realpath(path, resolved_path);
	if (res == NULL) {
		rc = -errno;
		GT_ASSERT(rc);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, realpath);
			GT_LOGF(log, LOG_ERR, -rc, "failed; path='%s'", path);
		}
	} else {
		rc = 0;
	}
	return rc;
}

int
gt_sys_flock(struct gt_log *log, int fd, int operation)
{
	int rc;

restart:
	rc = (*gt_sys_flock_fn)(fd, operation);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		switch (-rc) {
		case EINTR:
			goto restart;
		default:
 			break;
		}
		if (log != NULL) {
			log = GT_LOG_TRACE(log, flock);
			GT_LOGF(log, LOG_ERR, -rc, "failed; fd=%d", fd);
		}
	}
	return rc;
}

int
gt_sys_getgrnam(struct gt_log *log, const char *name, struct group **pgroup)
{
	int rc;

restart:
	rc = 0;
	*pgroup = getgrnam(name);
	if (*pgroup == NULL) {
		rc = -errno;
		GT_ASSERT(rc);
		if (rc == -EINTR) {
			goto restart;
		}
		if (log != NULL) {
			log = GT_LOG_TRACE(log, getgrnam);
			GT_LOGF(log, LOG_ERR, -rc, "failed; name='%s'", name);
		}
	}
	return rc;
}

int
gt_sys_chown(struct gt_log *log, const char *path, uid_t owner, gid_t group)
{
	int rc;

restart:
	rc = chown(path, owner, group);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		switch (-rc) {
		case EINTR:
			goto restart;
		default:
			if (log != NULL) {
				log = GT_LOG_TRACE(log, chown);
				GT_LOGF(log, LOG_ERR, -rc,
				        "failed; uid=%d, gid=%d",
				         owner, group);
			}
			break;
		}
	}
	return rc;
}

int
gt_sys_chmod(struct gt_log *log, const char *path, mode_t mode)
{
	int rc;

restart:
	rc = chmod(path, mode);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		switch (-rc) {
		case EINTR:
			goto restart;
		default:
			if (log != NULL) {
				log = GT_LOG_TRACE(log, chmod);
				GT_LOGF(log, LOG_ERR, -rc,
				        "failed; path='%s', mode=%o",
				        path, mode);
			}
			break;
		}
	}
	return rc;
}

int
gt_sys_getifaddrs(struct gt_log *log, struct ifaddrs **ifap)
{
	int rc;

	rc = getifaddrs(ifap);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, getifaddrs);
			GT_LOGF(log, LOG_ERR, -rc, "failed");
		}
		return rc;
	}
	return 0;
}

int
gt_sys_if_indextoname(struct gt_log *log, int if_idx, char *if_name)
{
	int rc;
	char *s;

	s = if_indextoname(if_idx, if_name);
	if (s == NULL) {
		rc = -errno;
		GT_ASSERT(rc);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, if_indextoname);
			GT_LOGF(log, LOG_ERR, -rc,
			        "failed; if_idx=%d", if_idx);
		}
		return rc;
	}
	GT_ASSERT(s == if_name);
	return 0;
}

int
gt_sys_kill(struct gt_log *log, int pid, int sig)
{
	int rc;

	rc = kill(pid, sig);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, kill);
			GT_LOGF(log, LOG_ERR, -rc,
			        "failed; pid=%d, sig=%d", pid, sig);
		}
	}
	return rc;
}

int
gt_sys_waitpid(struct gt_log *log, pid_t pid, int *status, int options)
{
	int rc;

	rc = waitpid(pid, status, options);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, waitpid);
			GT_LOGF(log, LOG_ERR, -rc,
			        "failed; pid=%d", (int)pid);
		}
	}
	return rc;
}

#ifdef __linux__
int
gt_sys_clone(struct gt_log *log, int (*fn)(void *), void *child_stack,
	int flags, void *arg, void *ptid, void *tls, void *ctid)
{
	int rc;

	rc = (*gt_sys_clone_fn)(fn, child_stack, flags, arg, ptid, tls, ctid);
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, clone);
			GT_LOGF(log, LOG_ERR, -rc, "failed; flags=%s",
			        gt_log_add_clone_flags(flags));
		}
	}
	return rc;
}
#else /* __linux__ */
int
gt_sys_kqueue(struct gt_log *log)
{
	int rc;

	rc = (*gt_sys_kqueue_fn)();
	if (rc == -1) {
		rc = -errno;
		GT_ASSERT(rc);
		if (log != NULL) {
			log = GT_LOG_TRACE(log, kqueue);
			GT_LOGF(log, LOG_ERR, -rc, "failed");
		}
	}
	return rc;
}
#endif /* __linux__ */
