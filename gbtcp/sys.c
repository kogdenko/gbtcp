#include "sys.h"
#include "log.h"
#include "strbuf.h"

#define SYS_LOG_MSG_FOREACH(x) \
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
	x(waitpid) 

#ifdef __linux__
#define SYS_LOG_MSG_FOREACH_OS(x) \
	x(clone)
#else /* __linux__ */
#define SYS_LOG_MSG_FOREACH_OS(x) \
	x(kqueue)
#endif /* __linux__ */

struct sys_mod {
	struct log_scope log_scope;
	SYS_LOG_MSG_FOREACH(LOG_MSG_DECLARE);
	SYS_LOG_MSG_FOREACH_OS(LOG_MSG_DECLARE);
};

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

static struct sys_mod *this_mod;

int
gt_sys_mod_init()
{
	log_scope_init(&this_mod->log_scope, "sys");
	return 0;
}

void
gt_sys_mod_deinit(struct gt_log *log)
{
	LOG_TRACE(log);
	log_scope_deinit(log, &this_mod->log_scope);
}

#ifdef __linux__
static void
gt_sys_dlsym_os()
{
	SYS_DLSYM(clone);
	SYS_DLSYM(epoll_create1);
	SYS_DLSYM(epoll_ctl);
	SYS_DLSYM(epoll_wait);
	SYS_DLSYM(epoll_pwait);
}
#else /* __linux__ */
static void
gt_sys_dlsym_os()
{
	SYS_DLSYM(kqueue);
	SYS_DLSYM(kevent);
}
#endif /* __linux__ */

void
gt_sys_mod_dlsym()
{
	SYS_DLSYM(open);
	SYS_DLSYM(socket);
	SYS_DLSYM(bind);
	SYS_DLSYM(connect);
	SYS_DLSYM(listen);
	SYS_DLSYM(accept4);
	SYS_DLSYM(flock);
	SYS_DLSYM(read);
	SYS_DLSYM(readv);
	SYS_DLSYM(recv);
	SYS_DLSYM(recvfrom);
	SYS_DLSYM(recvmsg);
	SYS_DLSYM(write);
	SYS_DLSYM(writev);
	SYS_DLSYM(send);
	SYS_DLSYM(sendto);
	SYS_DLSYM(sendmsg);
	SYS_DLSYM(sendfile);
	SYS_DLSYM(dup);
	SYS_DLSYM(dup2);
	SYS_DLSYM(close);
	SYS_DLSYM(shutdown);
	SYS_DLSYM(fcntl);
	SYS_DLSYM(ioctl);
	SYS_DLSYM(fork);
	SYS_DLSYM(ppoll);
	SYS_DLSYM(setsockopt);
	SYS_DLSYM(getsockopt);
	SYS_DLSYM(getsockname);
	SYS_DLSYM(getpeername);
	SYS_DLSYM(signal);
	SYS_DLSYM(sigaction);
	SYS_DLSYM(sigprocmask);
	gt_sys_dlsym_os();
}

static void
sys_log_addrfn_failed(struct gt_log *log, int log_msg_level,
	int errnum, int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	const struct sockaddr_un *addr_un;
	const struct sockaddr_in *addr_in;

	switch (addr->sa_family) {
	case AF_INET:
		ASSERT(addrlen >= sizeof(*addr_in));
		addr_in = (const struct sockaddr_in *)addr;
		UNUSED(addr_in);
		LOGF(log, log_msg_level, LOG_ERR, errnum,
		     "failed; fd=%d, sockaddr_in=%s",
		     fd, gt_log_add_sockaddr_in(addr_in));
		break;
	case AF_UNIX:
		ASSERT(addrlen >= sizeof(*addr_un));
		addr_un = (const struct sockaddr_un *)addr;
		UNUSED(addr_un);
		LOGF(log, log_msg_level, LOG_ERR, errnum,
		     "failed; fd=%d, sun_path='%s'",
		     fd, addr_un->sun_path);
		break;
	default:
		LOGF(log, log_msg_level, LOG_ERR, errnum,
		     "failed; fd=%d", fd);
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
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(fork), LOG_ERR, -rc, "failed");
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
		ASSERT(rc);
		switch (-rc) {
		case EINTR:
			goto restart;
		default:
			break;
		}
		if  (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(open), LOG_ERR, -rc,
			     "failed; path='%s'", path);
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
		ASSERT(rc < 0);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(socket), LOG_ERR, -rc,
			     "failed; domain=%s, type=%s",
			     log_add_socket_domain(domain),
			     log_add_socket_type(type));
		}
	}
	return rc;
}

void
sys_log_connect_failed(struct gt_log *log, int errnum, int fd,
	const struct sockaddr *addr, socklen_t addrlen)
{
	sys_log_addrfn_failed(log, LOG_MSG(connect), errnum,
	                      fd, addr, addrlen);
}

int
gt_sys_connect(struct gt_log *log, int fd, const struct sockaddr *addr,
	socklen_t addrlen)
{
	int rc;

	rc = (*gt_sys_connect_fn)(fd, addr, addrlen);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc < 0);
		if (log != NULL) {
			LOG_TRACE(log);
			sys_log_connect_failed(log, -rc, fd, addr, addrlen);
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
		ASSERT(rc < 0);
		if (log != NULL) {
			LOG_TRACE(log);
			sys_log_addrfn_failed(log, LOG_MSG(bind), -rc,
			                      fd, addr, addrlen);
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
		ASSERT(rc < 0);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(listen), LOG_ERR, -rc,
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
		ASSERT(rc);
		if (rc != -EAGAIN) {
			if (log != NULL) {
				LOG_TRACE(log);
				LOGF(log, LOG_MSG(accept4), LOG_ERR, -rc,
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
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(shutdoen), LOG_ERR, -rc,
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
		ASSERT(rc < 0);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(close), LOG_ERR, -rc,
			     "failed; fd=%d", fd);
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
		ASSERT(rc);
		switch (-rc) {
		case EINTR:
			goto restart;
		case EAGAIN:
			break;
		default:
			if (log != NULL) {
				LOG_TRACE(log);
				LOGF(log, LOG_MSG(read), LOG_ERR, -rc,
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
		ASSERT(rc);
		if (rc != -EAGAIN) {
			if (log != NULL) {
				LOG_TRACE(log);
				LOGF(log, LOG_MSG(recvmsg), -rc, LOG_ERR,
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
		ASSERT(rc);
		switch (-rc) {
		case EINTR:
			goto restart;
		case EAGAIN:
			break;
		default:
			if (log != NULL) {
				LOG_TRACE(log);
				LOGF(log, LOG_MSG(write), LOG_ERR, -rc,
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
		ASSERT(rc);
		switch (-rc) {
		case EINTR:
			goto restart;
		case EAGAIN:
			break;
		default:
			if (log != NULL) {
				LOG_TRACE(log);
				LOGF(log, LOG_MSG(send), LOG_ERR, -rc,
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
		ASSERT(rc);
		if (rc != -EPIPE) {
			if (log != NULL) {
				LOG_TRACE(log);
				LOGF(log, LOG_MSG(sendmsg), LOG_ERR, -rc,
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
		ASSERT(rc < 0);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(dup), LOG_ERR, -rc,
			     "failed; fd=%d", fd);
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
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(fcntl), LOG_ERR, -rc,
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
		ASSERT(rc);
		switch (request) {
		case SIOCGIFFLAGS:
			if (log != NULL) {
				LOG_TRACE(log);
				LOGF(log, LOG_MSG(ioctl), LOG_ERR, -rc,
				     "failed; fd=%d, req=SIOCGIFFLAGS, ifr_name='%s'",
				     fd, ((struct ifreq *)arg)->ifr_name);
			}
			break;
		default:
			if (log != NULL) {
				LOG_TRACE(log);
				LOGF(log, LOG_MSG(ioctl), LOG_ERR, -rc,
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
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(getsockopt), LOG_ERR, -rc,
			     "failed; fd=%d, level=%s, optname=%s",
			     fd,
			     log_add_sockopt_level(level),
			     log_add_sockopt_optname(level, optname));
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
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(setsockopt), LOG_ERR, -rc,
			     "failed; fd=%d, level=%s, optname=%s",
			     fd,
			     log_add_sockopt_level(level),
			     log_add_sockopt_optname(level, optname));
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
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(ppoll), LOG_ERR, -rc, "failed");
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
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(signal), LOG_ERR, -rc,
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
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(sigaction), LOG_ERR, -rc,
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
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(sigprocmask), LOG_ERR, -rc,
			     "failed; how=%s", log_add_sigprocmask_how(how));
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
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(malloc), LOG_ERR, 0,
			     "failed; size=%zu", size);
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
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(realloc), LOG_ERR, 0,
			     "failed; size=%zu", size);
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
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(posix_memalign), LOG_ERR, 0,
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
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(fopen), LOG_ERR, -rc,
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
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(opendir), LOG_ERR, -rc,
			     "failed; name='%s'", name);
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
		ASSERT(errno);
		if (rc == -EINTR) {
			goto restart;
		}
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(stat), LOG_ERR, -rc,
			     "failed; path='%s'", path);
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
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(realpath), LOG_ERR,
			     -rc, "failed; path='%s'", path);
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
		ASSERT(rc);
		switch (-rc) {
		case EINTR:
			goto restart;
		default:
 			break;
		}
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, flock, LOG_ERR, -rc, "failed; fd=%d", fd);
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
		ASSERT(rc);
		if (rc == -EINTR) {
			goto restart;
		}
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(getgrnam), LOG_ERR, -rc,
			     "failed; name='%s'", name);
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
		ASSERT(rc);
		switch (-rc) {
		case EINTR:
			goto restart;
		default:
			if (log != NULL) {
				LOG_TRACE(log);
				LOGF(log, LOG_MSG(chown), LOG_ERR, -rc,
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
		ASSERT(rc);
		switch (-rc) {
		case EINTR:
			goto restart;
		default:
			if (log != NULL) {
				LOG_TRACE(log);
				LOGF(log, LOG_MSG(chmod), LOG_ERR, -rc,
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
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(getifaddrs), LOG_ERR, -rc, "failed");
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
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(if_indextoname), LOG_ERR, -rc,
			     "failed; if_idx=%d", if_idx);
		}
		return rc;
	}
	ASSERT(s == if_name);
	return 0;
}

int
gt_sys_kill(struct gt_log *log, int pid, int sig)
{
	int rc;

	rc = kill(pid, sig);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(kill), LOG_ERR, -rc,
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
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(waitpid), LOG_ERR, -rc,
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
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(clone), LOG_ERR, -rc,
			     "failed; flags=%s",
			     log_add_clone_flags(flags));
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
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_MSG(kqueue), LOG_ERR, -rc, "failed");
		}
	}
	return rc;
}
#endif /* __linux__ */
