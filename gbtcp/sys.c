/* GPL2 license */
#include "internals.h"

struct sys_mod {
	struct log_scope log_scope;
};

sys_open_f sys_open_fn;
sys_unlink_f sys_unlink_fn;
sys_pipe_f sys_pipe_fn;
sys_socket_f sys_socket_fn;
sys_bind_f sys_bind_fn;
sys_connect_f sys_connect_fn;
sys_listen_f sys_listen_fn;
sys_accept4_f sys_accept4_fn;
sys_flock_f sys_flock_fn;
sys_read_f sys_read_fn;
sys_readv_f sys_readv_fn;
sys_recv_f sys_recv_fn;
sys_recvfrom_f sys_recvfrom_fn;
sys_recvmsg_f sys_recvmsg_fn;
sys_write_f sys_write_fn;
sys_writev_f sys_writev_fn;
sys_send_f sys_send_fn;
sys_sendto_f sys_sendto_fn;
sys_sendmsg_f sys_sendmsg_fn;
sys_sendfile_f sys_sendfile_fn;
sys_shutdown_f sys_shutdown_fn;
sys_close_f sys_close_fn;
sys_dup_f sys_dup_fn;
sys_dup2_f sys_dup2_fn;
sys_fcntl_f sys_fcntl_fn;
sys_ioctl_f sys_ioctl_fn;
sys_ppoll_f sys_ppoll_fn;
sys_fork_f sys_fork_fn;
sys_getsockopt_f sys_getsockopt_fn;
sys_setsockopt_f sys_setsockopt_fn;
sys_getsockname_f sys_getsockname_fn;
sys_getpeername_f sys_getpeername_fn;
sys_signal_f sys_signal_fn;
sys_sigaction_f sys_sigaction_fn;
sys_sigprocmask_f sys_sigprocmask_fn;
#ifdef __linux__
sys_clone_f sys_clone_fn;
sys_epoll_create1_f sys_epoll_create1_fn;
sys_epoll_ctl_f sys_epoll_ctl_fn;
sys_epoll_wait_f sys_epoll_wait_fn;
sys_epoll_pwait_f sys_epoll_pwait_fn;
sys_dup3_f sys_dup3_fn;
#else /* __linux__ */
sys_kqueue_f sys_kqueue_fn;
sys_kevent_f sys_kevent_fn;
#endif /* __linux__ */

static struct sys_mod *curmod;

int
sys_mod_init(struct log *log, void **pp)
{
	int rc;
	struct sys_mod *mod;

	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (!rc) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "sys");
	}
	return rc;
}

int
sys_mod_attach(struct log *log, void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

void
sys_mod_deinit(struct log *log, void *raw_mod)
{
	struct sys_mod *mod;

	LOG_TRACE(log);
	mod = raw_mod;
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}

void
sys_mod_detach(struct log *log)
{
	curmod = NULL;
}

#ifdef __linux__
static void
dlsym_all_os()
{
	SYS_DLSYM(clone);
	SYS_DLSYM(epoll_create1);
	SYS_DLSYM(epoll_ctl);
	SYS_DLSYM(epoll_wait);
	SYS_DLSYM(epoll_pwait);
}
#else /* __linux__ */
static void
dlsym_all_os()
{
	SYS_DLSYM(kqueue);
	SYS_DLSYM(kevent);
}
#endif /* __linux__ */

void
dlsym_all()
{
	SYS_DLSYM(open);
	SYS_DLSYM(unlink);
	SYS_DLSYM(pipe);
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
	dlsym_all_os();
}

int
sys_fork(struct log *log)
{
	int rc;

	rc = (*sys_fork_fn)();
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed;");
		}
	} else if (rc) {
		LOG_TRACE(log);
		LOGF(log, LOG_NOTICE, 0, "ok; pid=%d", rc);
	}
	return rc;
}

int
sys_open(struct log *log, const char *path, int flags, mode_t mode)
{
	int rc;

restart:
	rc = (*sys_open_fn)(path, flags, mode);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (rc == -EINTR) {
			goto restart;
		} else {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; path='%s'", path);
		}
	}
	return rc;
}

int
sys_symlink(struct log *log, const char *oldpath, const char *newpath)
{
	int rc;

	rc = symlink(oldpath, newpath);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc,
			     "failed; olpath=%s, newpath=%s",
			     oldpath, newpath);
		}
	}
	return rc;
}

int
sys_unlink(struct log *log, const char *path)
{
	int rc, level;

	rc = (*sys_unlink_fn)(path);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		switch (-rc) {
		case ENOENT:
			level = LOG_INFO;
			break;
		default:
			level = LOG_ERR;
			break;
		}
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, level, -rc, "failed; path='%s'", path);
		}
	}
	return rc;
}

int
sys_pipe(struct log *log, int pipefd[2])
{
	int rc;

	rc = (*sys_pipe_fn)(pipefd);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed");
		}
	}
	return rc;
}

int
sys_socket(struct log *log, int domain, int type, int protocol)
{
	int rc;

	rc = (*sys_socket_fn)(domain, type, protocol);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc < 0);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; domain=%s, type=%s",
			     log_add_socket_domain(domain),
			     log_add_socket_type(type));
		}
	}
	return rc;
}

int
sys_connect(struct log *log, int fd, const struct sockaddr *addr,
	socklen_t addrlen)
{
	int rc;

	rc = (*sys_connect_fn)(fd, addr, addrlen);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc < 0);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; fd=%d, addr=%s",
			     fd, log_add_sockaddr(addr, addrlen));
		}
		return rc;
	} else {
		return 0;
	}
}

int
sys_bind(struct log *log, int fd, const struct sockaddr *addr,
	socklen_t addrlen)
{
	int rc;

	rc = (*sys_bind_fn)(fd, addr, addrlen);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc < 0);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; fd=%d, addr=%s",
			     fd, log_add_sockaddr(addr, addrlen));
		}
		return rc;
	} else {
		return 0;
	}
}

int
sys_listen(struct log *log, int fd, int backlog)
{
	int rc;

	rc = (*sys_listen_fn)(fd, backlog);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc < 0);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; fd=%d, backlog=%d",
			     fd, backlog);
		}
		return rc;
	} else {
		return 0;
	}
}

int
sys_accept4(struct log *log, int fd, struct sockaddr *addr,
	socklen_t *addrlen, int flags)
{
	int rc;

	rc = (*sys_accept4_fn)(fd, addr, addrlen, flags);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (rc != -EAGAIN) {
			if (log != NULL) {
				LOG_TRACE(log);
				LOGF(log, LOG_ERR, -rc, "failed; fd=%d", fd);
			}
		}
	}
	return rc;
}

int
sys_shutdown(struct log *log, int fd, int how)
{
	int rc;

	rc = (*sys_shutdown_fn)(fd, how);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; fd=%d, how=%s",
			      fd, log_add_shutdown_how(how));
		}
	}
	return rc;
}

int
sys_close(struct log *log, int fd)
{
	int rc;

	rc = (*sys_close_fn)(fd);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc < 0);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; fd=%d", fd);
		}
	}
	return rc;
}

ssize_t
sys_read(struct log *log, int fd, void *buf, size_t count)
{
	ssize_t rc;

restart:
	rc = (*sys_read_fn)(fd, buf, count);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (rc == -EINTR) {
			goto restart;
		} else if (rc != -EAGAIN && log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; fd=%d", fd);
		}
	}
	return rc;
}

ssize_t
sys_recv(struct log *log, int fd, void *buf, size_t len, int flags)
{
	ssize_t rc;

restart:
	rc = (*sys_recv_fn)(fd, buf, len, flags);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (rc == -EINTR) {
			goto restart;
		} else if (rc != -EAGAIN) {
			LOG_TRACE(log);
			LOGF(log, -rc, LOG_ERR, "failed; fd=%d", fd);
		}
	}
	return rc;
}

ssize_t
sys_recvmsg(struct log *log, int fd, struct msghdr *msg, int flags)
{
	ssize_t rc;

restart:
	rc = (*sys_recvmsg_fn)(fd, msg, flags);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (rc == -EINTR) {
			goto restart;
		} else if (rc != -EAGAIN) {
			LOG_TRACE(log);
			LOGF(log, -rc, LOG_ERR, "failed; fd=%d", fd);
		}
	}
	return rc;
}

ssize_t
sys_write(struct log *log, int fd, const void *buf, size_t count)
{
	ssize_t rc;

restart:
	rc = (*sys_write_fn)(fd, buf, count);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (rc == -EINTR) {
			goto restart;
		} else if (rc == -EAGAIN && log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; fd=%d", fd);
		}
	}
	return rc;
}

ssize_t
sys_send(struct log *log, int fd, const void *buf, size_t len, int flags)
{
	ssize_t rc;

restart:
	rc = (*sys_send_fn)(fd, buf, len, flags);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (rc == -EINTR) {
			goto restart;
		} else  if (rc != -EAGAIN && log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; fd=%d", fd);
		}
	}
	return rc;
}

ssize_t
sys_sendmsg(struct log *log, int fd, const struct msghdr *msg, int flags)
{
	ssize_t rc;

	rc = (*sys_sendmsg_fn)(fd, msg, flags);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (rc != -EPIPE && log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; fd=%d", fd);
		}
	}
	return rc;
}

int
sys_dup(struct log *log, int fd)
{
	int rc;

	rc = (*sys_dup_fn)(fd);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc < 0);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; fd=%d", fd);
		}
	}
	return rc;
}

int
sys_fcntl(struct log *log, int fd, int cmd, uintptr_t arg)
{
	int rc;

	rc = (*sys_fcntl_fn)(fd, cmd, arg);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; fd=%d, cmd=%s",
			     fd, log_add_fcntl_cmd(cmd));
		}
	}
	return rc;
}

int
sys_ioctl(struct log *log, int fd, unsigned long request, uintptr_t arg)
{
	int rc;

	rc = (*sys_ioctl_fn)(fd, request, arg);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		switch (request) {
		case SIOCGIFFLAGS:
			if (log != NULL) {
				LOG_TRACE(log);
				LOGF(log, LOG_ERR, -rc,
				     "failed; fd=%d, req=SIOCGIFFLAGS, ifr_name='%s'",
				     fd, ((struct ifreq *)arg)->ifr_name);
			}
			break;
		default:
			if (log != NULL) {
				LOG_TRACE(log);
				LOGF(log, LOG_ERR, -rc,
				     "failed; fd=%d, cmd=0x%lx",
				     fd, request);
			}
			break;
		}
	}
	return rc;
}

int
sys_getsockopt(struct log *log, int fd, int level, int optname,
	void *optval, socklen_t *optlen)
{
	int rc;

	rc = (*sys_getsockopt_fn)(fd, level, optname, optval, optlen);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc,
			     "failed; fd=%d, level=%s, optname=%s",
			     fd,
			     log_add_sockopt_level(level),
			     log_add_sockopt_optname(level, optname));
		}
	}
	return rc;
}

int
sys_setsockopt(struct log *log, int fd, int level, int optname,
	void *optval, socklen_t optlen)
{
	int rc;

	rc = (*sys_setsockopt_fn)(fd, level, optname, optval, optlen);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			int is_en = log_is_enabled(&curmod->log_scope, LOG_ERR, 1);
			dbg("serscpopt %d", is_en);
			LOGF(log, LOG_ERR, -rc,
			     "failed; fd=%d, level=%s, optname=%s",
			     fd,
			     log_add_sockopt_level(level),
			     log_add_sockopt_optname(level, optname));
		}
	}
	return rc;
}

int
sys_ppoll(struct log *log, struct pollfd *fds, nfds_t nfds,
	const struct timespec *to, const sigset_t *sigmask)
{
	int rc;

	rc = (*sys_ppoll_fn)(fds, nfds, to, sigmask);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed");
		}
	}
	return rc;
}

void *
sys_signal(struct log *log, int signum, void (*handler)())
{
	int rc;
	void (*res)(int);

	res = (*sys_signal_fn)(signum, handler);
	if (res == SIG_ERR) {
		rc = -errno;
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc,
			     "failed; signum=%d, sighandler=%s",
			     signum, log_add_sighandler(handler));
		}
	}
	return res;
}

int
sys_sigaction(struct log *log, int signum, const struct sigaction *act,
	struct sigaction *oldact)
{
	int rc;

	rc = (*sys_sigaction_fn)(signum, act, oldact);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc,
			     "failed; signum=%d", signum);
		}
	}
	return rc;
}

int
sys_sigprocmask(struct log *log, int how, const sigset_t *set,
	sigset_t *oldset)
{
	int rc;

	rc = (*sys_sigprocmask_fn)(how, set, oldset);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc,
			     "failed; how=%s", log_add_sigprocmask_how(how));
		}
	}
	return rc;
}

int
sys_malloc(struct log *log, void **pp, size_t size)
{
	*pp = malloc(size);
	if (*pp == NULL) {
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, 0,
			     "failed; size=%zu", size);
		}
		return -ENOMEM;
	}
	return 0;
}

int
sys_realloc(struct log *log, void **pp, size_t size)
{
	void *new_ptr;

	new_ptr = realloc(*pp, size);
	if (new_ptr == NULL) {
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, 0,
			     "failed; size=%zu", size);
		}
		return -ENOMEM;
	}
	*pp = new_ptr;
	return 0;
}

int
sys_posix_memalign(struct log *log, void **memptr, size_t alignment,
	size_t size)
{
	int rc;

	rc = posix_memalign(memptr, alignment, size);
	if (rc) {
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, 0,
			     "failed; alignment=%zu, size=%zu",
			     alignment, size);
		}
	}
	return -rc;
}

int
sys_fopen(struct log *log, FILE **file, const char *path,
	const char *mode)
{
	int rc;

	*file = fopen(path, mode);
	if (*file == NULL) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; path='%s', mode=%s",
			     path, mode);
		}
		return rc;
	}
	return 0;
}

int
sys_opendir(struct log *log, DIR **pdir, const char *name)
{
	int rc;

	*pdir = opendir(name);
	if (*pdir == NULL) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; name='%s'", name);
		}
		return rc;
	}
	return 0;
}

int
sys_stat(struct log *log, const char *path, struct stat *buf)
{
	int rc;

restart:
	rc = stat(path, buf);
	if (rc == -1) {
		rc = -errno;
		ASSERT(errno);
		if (rc == -EINTR) {
			goto restart;
		} else if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; path='%s'", path);
		}
	}
	return rc;
}

int
sys_realpath(struct log *log, const char *path, char *resolved_path)
{
	int rc;
	char *res;

	res = realpath(path, resolved_path);
	if (res == NULL) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; path='%s'", path);
		}
	} else {
		rc = 0;
	}
	return rc;
}

int
sys_flock(struct log *log, int fd, int operation)
{
	int rc;

restart:
	rc = (*sys_flock_fn)(fd, operation);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (rc == -EINTR) {
			goto restart;
		} else if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; fd=%d", fd);
		}
	}
	return rc;
}

int
sys_getgrnam(struct log *log, const char *name, struct group **pgroup)
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
		} else if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; name='%s'", name);
		}
	}
	return rc;
}

int
sys_chown(struct log *log, const char *path, uid_t owner, gid_t group)
{
	int rc;

restart:
	rc = chown(path, owner, group);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (rc == -EINTR) {
			goto restart;
		} else if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; uid=%d, gid=%d",
			     owner, group);
		}
	}
	return rc;
}

int
sys_chmod(struct log *log, const char *path, mode_t mode)
{
	int rc;

restart:
	rc = chmod(path, mode);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (rc == -EINTR) {
			goto restart;
		} else if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; path='%s', mode=%o",
			     path, mode);
		}
	}
	return rc;
}

int
sys_getifaddrs(struct log *log, struct ifaddrs **ifap)
{
	int rc;

	rc = getifaddrs(ifap);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed");
		}
		return rc;
	}
	return 0;
}

int
sys_if_indextoname(struct log *log, int ifindex, char *ifname)
{
	int rc;
	char *s;

	s = if_indextoname(ifindex, ifname);
	if (s == NULL) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; ifindex=%d", ifindex);
		}
		return rc;
	}
	ASSERT(s == ifname);
	return 0;
}

int
sys_if_nametoindex(struct log *log, const char *ifname)
{
	int rc;

	rc = if_nametoindex(ifname);
	if (rc == 0) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; ifname='%s'", ifname);
		}
	}
	return rc;
}

int
sys_kill(struct log *log, int pid, int sig)
{
	int rc;

	rc = kill(pid, sig);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc,
			     "failed; pid=%d, sig=%d", pid, sig);
		}
	}
	return rc;
}

int
sys_waitpid(struct log *log, pid_t pid, int *status, int options)
{
	int rc;

	rc = waitpid(pid, status, options);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc,
			     "failed; pid=%d", (int)pid);
		}
	}
	return rc;
}

int
sys_daemon(struct log *log, int nochdir, int noclose)
{
	int rc;

	rc = daemon(nochdir, noclose);
	if (rc < 0) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed;");
		}
	} else if (log != NULL) {
		LOG_TRACE(log);
		LOGF(log, LOG_ERR, 0, "ok; pid=%d", getpid());
	}
	return rc;
}

int
sys_inotify_init1(struct log *log, int flags)
{
	int rc;

	rc = inotify_init1(flags);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed;");
		}
	}
	return rc;
}

int
sys_inotify_add_watch(struct log *log, int fd, const char *path, uint32_t mask)
{
	int rc;

	rc = inotify_add_watch(fd, path, mask);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc,
			     "failed; fd=%d, path=%s", fd, path);
		}
	}
	return rc;
}

int
sys_inotify_rm_watch(struct log *log, int fd, int wd)
{
	int rc;

	rc = inotify_rm_watch(fd, wd);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc,
			     "failed; fd=%d, wd=%d", fd, wd);
		}
	}
	return rc;
}

#ifdef __linux__
int
sys_epoll_create1(struct log *log, int flags)
{
	int rc;

	rc = (*sys_epoll_create1_fn)(flags);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed;");	
		}
	}
	return rc;
}

int
sys_epoll_pwait(struct log *log, int epfd, struct epoll_event *events,
	int maxevents, int timeout, const sigset_t *sigmask)
{
	int rc;

restart:
	rc = (*sys_epoll_pwait_fn)(epfd, events, maxevents, timeout, sigmask);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (rc == -EINTR) {
			goto restart;
		} else if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; epfd=%d", epfd);
		}
	}
	return rc;
}

int
sys_clone(struct log *log, int (*fn)(void *), void *child_stack,
	int flags, void *arg, void *ptid, void *tls, void *ctid)
{
	int rc;

	rc = (*sys_clone_fn)(fn, child_stack, flags, arg, ptid, tls, ctid);
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed; flags=%s",
			     log_add_clone_flags(flags));
		}
	}
	return rc;
}
#else /* __linux__ */
int
sys_kqueue(struct log *log)
{
	int rc;

	rc = (*sys_kqueue_fn)();
	if (rc == -1) {
		rc = -errno;
		ASSERT(rc);
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, LOG_ERR, -rc, "failed");
		}
	}
	return rc;
}
#endif /* __linux__ */
