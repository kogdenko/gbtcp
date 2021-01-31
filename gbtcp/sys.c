// GPL v2
#include "internals.h"

#define CURMOD sys

sys_fork_f sys_fork_fn;
sys_open_f sys_open_fn;
//sys_stat_f sys_stat_fn;
//sys_fstat_f sys_fstat_fn;
sys_getgrnam_f sys_getgrnam_fn;
sys_chown_f sys_chown_fn;
sys_fchown_f sys_fchown_fn;
sys_chmod_f sys_chmod_fn;
sys_fchmod_f sys_fchmod_fn;
sys_symlink_f sys_symlink_fn;
sys_unlink_f sys_unlink_fn;
sys_pipe_f sys_pipe_fn;
sys_socket_f sys_socket_fn;
sys_connect_f sys_connect_fn;
sys_bind_f sys_bind_fn;
sys_listen_f sys_listen_fn;
sys_accept4_f sys_accept4_fn;
sys_shutdown_f sys_shutdown_fn;
sys_close_f sys_close_fn;
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
sys_dup_f sys_dup_fn;
sys_dup2_f sys_dup2_fn;
sys_getsockopt_f sys_getsockopt_fn;
sys_setsockopt_f sys_setsockopt_fn;
sys_getpeername_f sys_getpeername_fn;
sys_getsockname_f sys_getsockname_fn;
sys_fcntl_f sys_fcntl_fn;
sys_ioctl_f sys_ioctl_fn;
sys_flock_f sys_flock_fn;
sys_getgrnam_f sys_getgrnam_fn;
sys_chown_f sys_chown_fn;
sys_ppoll_f sys_ppoll_fn;
sys_signal_f sys_signal_fn;
sys_sigaction_f sys_sigaction_fn;
sys_sigprocmask_f sys_sigprocmask_fn;
sys_kill_f sys_kill_fn;
sys_mmap_f sys_mmap_fn;
#ifdef __linux__
sys_clone_f sys_clone_fn;
sys_epoll_create1_f sys_epoll_create1_fn;
sys_epoll_ctl_f sys_epoll_ctl_fn;
sys_epoll_wait_f sys_epoll_wait_fn;
sys_epoll_pwait_f sys_epoll_pwait_fn;
sys_dup3_f sys_dup3_fn;
#else // __linux__
sys_kqueue_f sys_kqueue_fn;
sys_kevent_f sys_kevent_fn;
#endif // __linux__

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
#else // __linux__
static void
dlsym_all_os()
{
	SYS_DLSYM(kqueue);
	SYS_DLSYM(kevent);
}
#endif // __linux__

void
dlsym_all()
{
	SYS_DLSYM(fork);
	SYS_DLSYM(open);
//	SYS_DLSYM(stat);
	//SYS_DLSYM(fstat);
	SYS_DLSYM(getgrnam);
	SYS_DLSYM(chown);
	SYS_DLSYM(fchown);
	SYS_DLSYM(chmod);
	SYS_DLSYM(fchmod);
	SYS_DLSYM(symlink);
	SYS_DLSYM(unlink);
	SYS_DLSYM(pipe);
	SYS_DLSYM(socket);
	SYS_DLSYM(connect);
	SYS_DLSYM(bind);
	SYS_DLSYM(listen);
	SYS_DLSYM(accept4);
	SYS_DLSYM(shutdown);
	SYS_DLSYM(close);
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
	SYS_DLSYM(getsockopt);
	SYS_DLSYM(setsockopt);
	SYS_DLSYM(getpeername);
	SYS_DLSYM(getsockname);
	SYS_DLSYM(fcntl);
	SYS_DLSYM(ioctl);
	SYS_DLSYM(flock);
	SYS_DLSYM(getgrnam);
	SYS_DLSYM(chown);
	SYS_DLSYM(ppoll);
	SYS_DLSYM(signal);
	SYS_DLSYM(sigaction);
	SYS_DLSYM(sigprocmask);
	SYS_DLSYM(kill);
	SYS_DLSYM(mmap);
	dlsym_all_os();
}

int
sys_fork()
{
	int rc;

	rc = (*sys_fork_fn)();
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "fork() failed;");
	} else {
		NOTICE(0, "fork(); pid=%d", rc);
	}
	return rc;
}

int
sys_open(const char *path, int flags, mode_t mode)
{
	int rc;

restart:
	rc = (*sys_open_fn)(path, flags, mode);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		if (rc == -EINTR) {
			goto restart;
		} else {
			ERR(-rc, "open() failed; path='%s'", path);
		}
	} else {
		INFO(0, "open(); path='%s'", path);
	}
	return rc;
}

int
sys_fopen(FILE **file, const char *path, const char *mode)
{
	int rc;

	*file = fopen(path, mode);
	if (*file == NULL) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "fopen() failed; path='%s', mode=%s", path, mode);
	} else {
		rc = 0;
		INFO(0, "fopen(); path='%s', mode=%s", path, mode);
	}
	return rc;
}

char *
sys_fgets(const char *path, char *s, int size, FILE *file)
{
	char *r;

	r = fgets(s, size, file);
	if (r == NULL && errno) {
		ERR(errno, "fgets() failed; path='%s'", path);
	}
	return r;
}

int
sys_opendir(DIR **pdir, const char *name)
{
	int rc;

	*pdir = opendir(name);
	if (*pdir == NULL) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "opendir() failed; name='%s'", name);
	} else {
		rc = 0;
		INFO(0, "opendir(); name='%s'", name);
	}
	return 0;
}

/*int
sys_stat(const char *path, struct stat *buf)
{
	int rc;

	rc = (*sys_stat_fn)(path, buf);
	if (rc == -1) {
		rc = -errno;
		assert(errno);
		ERR(-rc, "stat() failed; path='%s'", path);
	} else {
		INFO(0, "stat(); path='%s'", path);
	}
	return rc;
}*/

int
sys_fstat(int fd, struct stat *buf)
{
	int rc;

	rc = fstat(fd, buf);
	if (rc == -1) {
		rc = -errno;
		assert(errno);
		ERR(-rc, "fstat() failed; fd='%d'", fd);
	} else {
		INFO(0, "fstat(); fd='%d'", fd);
	}
	return rc;
}

int
sys_getgrnam(const char *name, struct group **pgroup)
{
	int rc;

restart:
	rc = 0;
	*pgroup = (*sys_getgrnam_fn)(name);
	if (*pgroup == NULL) {
		rc = -errno;
		assert(rc);
		if (rc == -EINTR) {
			goto restart;
		} else {
			ERR(-rc, "getgrnam() failed; name='%s'", name);
		}
	} else {
		INFO(0, "getgrnam(); name='%s'", name);
	}
	return rc;
}

int
sys_chown(const char *path, uid_t owner, gid_t group)
{
	int rc;

	rc = (*sys_chown_fn)(path, owner, group);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "chown() failed; path='%s', uid=%d, gid=%d",
		    path, owner, group);
	} else {
		INFO(0, "chown(); path='%s', uid=%d, gid=%d",
			path, owner, group);
	}
	return rc;
}

int
sys_fchown(int fd, uid_t owner, gid_t group)
{
	int rc;

	rc = (*sys_fchown_fn)(fd, owner, group);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "fchown() failed; fd=%d, uid=%d, gid=%d",
			fd, owner, group);
	} else {
		INFO(0, "fchown(); fd=%d, uid=%d, gid=%d", fd, owner, group);
	}
	return rc;
}

int
sys_chmod(const char *path, mode_t mode)
{
	int rc;

	rc = (*sys_chmod_fn)(path, mode);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "chmod() failed; path='%s', mode=%o", path, mode);
	} else {
		INFO(0, "chmod(); path='%s', mode=%o", path, mode);
	}
	return rc;
}

int
sys_fchmod(int fd, mode_t mode)
{
	int rc;

	rc = (*sys_fchmod_fn)(fd, mode);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "fchmod() failed; fd=%d, mode=%o", fd, mode);
	} else {
		INFO(0, "fchmod(); fd=%d, mode=%o", fd, mode);
	}
	return rc; 
}

int
sys_ftruncate(int fd, off_t off)
{
	int rc;

restart:
	rc = ftruncate(fd, off);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		if (rc == -EINTR) {
			goto restart;
		} else {
			ERR(-rc, "ftruncate() failed; fd=%d, off=%zu",
				fd, off);
		}
	} else {
		INFO(0, "ftruncate(); fd=%d, off=%zu", fd, off);
	}
	return rc;
}

int
sys_realpath(const char *path, char *resolved_path)
{
	int rc;
	char *res;

	res = realpath(path, resolved_path);
	if (res == NULL) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "realpath() failed; path='%s'", path);
	} else {
		rc = 0;
		INFO(0, "realpath(); path='%s', resolved_path='%s'",
			path, resolved_path);
	}
	return rc;
}

int
sys_symlink(const char *oldpath, const char *newpath)
{
	int rc;

	rc = (*sys_symlink_fn)(oldpath, newpath);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "symlink() failed; olpath='%s', newpath='%s'",
			oldpath, newpath);
	} else {
		INFO(0, "symlink(); oldpath='%s', newpath='%s'",
			oldpath, newpath);
	}
	return rc;
}

int
sys_unlink(const char *path)
{
	int rc;

	rc = (*sys_unlink_fn)(path);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
	}
	if (rc < 0 && rc != -ENOENT) {
		ERR(-rc, "unlink() failed; path='%s'", path);
	} else {
		INFO(-rc, "unlink(); path='%s'", path);
	}
	return rc;
}

int
sys_pipe(int pipefd[2])
{
	int rc;

	rc = (*sys_pipe_fn)(pipefd);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "pipe() failed");
	} else {
		INFO(0, "pipe(); rfd=%d, wfd=%d", pipefd[0], pipefd[1]);
	}
	return rc;
}

int
sys_socket(int domain, int type, int protocol)
{
	int rc;
	
	rc = (*sys_socket_fn)(domain, type, protocol);
	if (rc == -1) {
		rc = -errno;
		assert(rc < 0);
		ERR(-rc, "socket() failed; domain=%s, type=%s, flags=%s",
			log_add_socket_domain(domain),
			log_add_socket_type(SOCK_TYPE_NOFLAGS(type)),
			log_add_socket_flags(SOCK_TYPE_FLAGS(type)));
	} else {
		INFO(0, "socket(); fd=%d, domain=%s, type=%s, flags=%s",
			rc, log_add_socket_domain(domain),
			log_add_socket_type(SOCK_TYPE_NOFLAGS(type)),
			log_add_socket_flags(SOCK_TYPE_FLAGS(type)));
	}
	return rc;
}

int
sys_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;

	rc = (*sys_connect_fn)(fd, addr, addrlen);
	if (rc == -1) {
		rc = -errno;
		assert(rc < 0);
	}
	if (rc < 0 && rc != -EINPROGRESS) {
		ERR(-rc, "connect() failed; fd=%d, addr=%s",
			fd, log_add_sockaddr(addr, addrlen));
	} else {
		INFO(0, "connect(); fd=%d, addr=%s",
			fd, log_add_sockaddr(addr, addrlen));
	}
	return rc;
}

int
sys_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;

	rc = (*sys_bind_fn)(fd, addr, addrlen);
	if (rc == -1) {
		rc = -errno;
		assert(rc < 0);
		ERR(-rc, "bind() failed; fd=%d, addr=%s",
			fd, log_add_sockaddr(addr, addrlen));
	} else {
		INFO(0, "bind(); fd=%d, addr=%s",
			fd, log_add_sockaddr(addr, addrlen));	
	}
	return rc;
}

int
sys_listen(int fd, int backlog)
{
	int rc;

	rc = (*sys_listen_fn)(fd, backlog);
	if (rc == -1) {
		rc = -errno;
		assert(rc < 0);
		ERR(-rc, "listen() failed; fd=%d, backlog=%d", fd, backlog);
	} else {
		INFO(0, "listen(); fd=%d, backlog=%d", fd, backlog);
	}
	return rc;
}

int
sys_accept4(int fd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	int rc;

	rc = (*sys_accept4_fn)(fd, addr, addrlen, flags);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		if (rc != -EAGAIN) {
			ERR(-rc, "accept() failed; fd=%d", fd);
		}
	} else {
		INFO(0, "accept(); fd=%d, newfd=%d", fd, rc);
	}
	return rc;
}

int
sys_shutdown(int fd, int how)
{
	int rc;

	rc = (*sys_shutdown_fn)(fd, how);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "shutdown() failed; fd=%d, how=%s",
			fd, log_add_shutdown_how(how));
	} else {
		INFO(0, "shutdown(); fd=%d, how=%s",
			fd, log_add_shutdown_how(how)); 
	}
	return rc;
}

int
sys_close(int *pfd)
{
	int rc;

	if (*pfd < 0) {
		return 0;
	}
	rc = (*sys_close_fn)(*pfd);
	if (rc == -1) {
		rc = -errno;
		assert(rc < 0);
		ERR(-rc, "close() failed; fd=%d", *pfd);
	} else {
		INFO(0, "close(); fd=%d", *pfd);
	}
	*pfd = -1;
	return rc;
}

ssize_t
sys_read(int fd, void *buf, size_t count)
{
	ssize_t rc;

restart:
	rc = (*sys_read_fn)(fd, buf, count);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		if (rc == -EINTR) {
			goto restart;
		} else if (rc != -EAGAIN) {
			ERR(-rc, "read() failed; fd=%d", fd);
		}
	} else {
		INFO(0, "read(); fd=%d, res=%zd", fd, rc);
	}
	return rc;
}

ssize_t
sys_recv(int fd, void *buf, size_t len, int flags)
{
	ssize_t rc;

restart:
	rc = (*sys_recv_fn)(fd, buf, len, flags);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		if (rc == -EINTR) {
			goto restart;
		} else if (rc != -EAGAIN) {
			ERR(-rc, "recv() failed; fd=%d", fd);
		}
	} else {
		INFO(0, "recv(); fd=%d, res=%zd", fd, rc);
	}
	return rc;
}

#if 0
sys_recvfrom
#endif

ssize_t
sys_recvmsg(int fd, struct msghdr *msg, int flags)
{
	ssize_t rc;

restart:
	rc = (*sys_recvmsg_fn)(fd, msg, flags);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		if (rc == -EINTR) {
			goto restart;
		} else if (rc != -EAGAIN) {
			ERR(-rc, "recvmsg() failed; fd=%d", fd);
		}
	} else {
		INFO(0, "recvmsg(); fd=%d, res=%zd", fd, rc);
	}
	return rc;
}

ssize_t
sys_write(int fd, const void *buf, size_t count)
{
	ssize_t rc;

restart:
	rc = (*sys_write_fn)(fd, buf, count);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		if (rc == -EINTR) {
			goto restart;
		} else if (rc == -EAGAIN) {
			ERR(-rc, "write() failed; fd=%d", fd);
		}
	} else {
		INFO(0, "write(); fd=%d, res=%zd", fd, rc);
	}
	return rc;
}

ssize_t
sys_send(int fd, const void *buf, size_t len, int flags)
{
	ssize_t rc;

restart:
	rc = (*sys_send_fn)(fd, buf, len, flags);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		if (rc == -EINTR) {
			goto restart;
		} else  if (rc != -EAGAIN) {
			ERR(-rc, "send() failed; fd=%d", fd);
		}
	} else {
		INFO(0, "send(); fd=%d, res=%zd", fd, rc);
	}
	return rc;
}

ssize_t
sys_sendmsg(int fd, const struct msghdr *msg, int flags)
{
	ssize_t rc;

restart:
	rc = (*sys_sendmsg_fn)(fd, msg, flags);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
	}
	if (rc < 0 && rc != -EPIPE) {
		if (rc == -EINTR) {
			goto restart;
		}
		ERR(-rc, "sendmsg() failed; fd=%d", fd);
	} else {
		INFO(-rc, "sendmsg(); fd=%d", fd);
	}
	return rc;
}

int
sys_dup(int fd)
{
	int rc;

	rc = (*sys_dup_fn)(fd);
	if (rc == -1) {
		rc = -errno;
		assert(rc < 0);
		ERR(-rc, "dup() failed; fd=%d", fd);
	} else {
		INFO(0, "dup(); fd=%d, newfd=%d", fd, rc);
	}
	return rc;
}

int
sys_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
	int rc;

	rc = (*sys_getsockopt_fn)(fd, level, optname, optval, optlen);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "getsockopt() failed; fd=%d, level=%s, optname=%s",
			fd, log_add_sockopt_level(level),
			log_add_sockopt_optname(level, optname));
	} else {
		INFO(0, "getsockopt(); fd=%d, level=%s, optname=%s",
			fd, log_add_sockopt_level(level),
			log_add_sockopt_optname(level, optname));
	}
	return rc;
}

int
sys_setsockopt(int fd, int level, int optname, void *optval, socklen_t optlen)
{
	int rc;

	rc = (*sys_setsockopt_fn)(fd, level, optname, optval, optlen);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "setsockopt() failed; fd=%d, level=%s, optname=%s",
			fd, log_add_sockopt_level(level),
			log_add_sockopt_optname(level, optname));
	} else {
		INFO(0, "setsockopt(); fd=%d, level=%s, optname=%s",
			fd, log_add_sockopt_level(level),
			log_add_sockopt_optname(level, optname));
	}
	return rc;
}

int
sys_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc;

	assert(addr != NULL);
	assert(addrlen != NULL);
	rc = (*sys_getpeername_fn)(fd, addr, addrlen);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "getpeername() failed; fd=%d", fd);
	} else {
		INFO(0, "getpeername(); fd=%d, addr=%s",
			fd, log_add_sockaddr(addr, *addrlen));
	}
	return rc;
}

int
sys_fcntl(int fd, int cmd, uintptr_t arg)
{
	int rc;

	rc = (*sys_fcntl_fn)(fd, cmd, arg);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "fcntl() failed; fd=%d, cmd=%s",
			fd, log_add_fcntl_cmd(cmd));
	} else {
		INFO(0, "fcntl(); fd=%d, cmd=%s", fd, log_add_fcntl_cmd(cmd));
	}
	return rc;
}

int
sys_ioctl(int fd, u_long req, uintptr_t arg)
{
	int rc;

	rc = (*sys_ioctl_fn)(fd, req, arg);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "ioctl() failed; fd=%d, req=%s",
			fd, log_add_ioctl_req(req, arg));
	} else {
		INFO(0, "ioctl(); fd=%d, req=%s",
			fd, log_add_ioctl_req(req, arg));
	}
	return rc;
}

int
sys_flock(int fd, int operation)
{
	int rc;

restart:
	rc = (*sys_flock_fn)(fd, operation);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		if (rc == -EINTR) {
			goto restart;
		} else {
			ERR(-rc, "flock() failed; fd=%d", fd);
		}
	} else {
		INFO(0, "flock(); fd=%d", fd);
	}
	return rc;
}

int
sys_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *to,
		const sigset_t *sigmask)
{
	int rc;

	rc = (*sys_ppoll_fn)(fds, nfds, to, sigmask);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		if (rc == -EINTR) {
			INFO(-rc, "ppoll() interrupted;");
		} else {
			ERR(-rc, "ppoll() failed;");
		}
	} else {
		DBG(0, "ppoll(); %s", log_add_pollfds_revents(fds, nfds));
	}
	return rc;
}

int
sys_signal(int signum, void **pres, void (*handler)())
{
	int rc;
	void (*res)(int);

	res = (*sys_signal_fn)(signum, handler);
	if (res == SIG_ERR) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "signal() failed; signum=%d, sighandler=%s",
			signum, log_add_sighandler(handler));
	} else {
		rc = 0;
		INFO(0, "signal(); signum=%d", signum);
	}
	if (*pres != NULL) {
		*pres = res;
	}
	return rc;
}

int
sys_sigaction(int signum, const struct sigaction *act,
		struct sigaction *oldact)
{
	int rc;

	rc = (*sys_sigaction_fn)(signum, act, oldact);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "sigaction() failed; signum=%d", signum);
	} else {
		INFO(0, "sigaction(); signum=%d", signum);
	}
	return rc;
}

int
sys_sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	int rc;

	rc = (*sys_sigprocmask_fn)(how, set, oldset);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "sigprocmask() failed; how=%s",
			log_add_sigprocmask_how(how));
	} else {
		INFO(0, "sigprocmask(); how=%s", log_add_sigprocmask_how(how));
	}
	return rc;
}

int
sys_kill(int pid, int sig)
{
	int rc;

	rc = kill(pid, sig);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "kill() failed; pid=%d, sig=%d", pid, sig);
	} else {
		INFO(0, "kill(); pid=%d, sig=%d", pid, sig);
	}
	return rc;
}

int
sys_waitpid(pid_t pid, int *status, int options)
{
	int rc;

	rc = waitpid(pid, status, options);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "waitpid() failed; pid=%d", (int)pid);
	} else {
		INFO(0, "waitpid(); pid=%d", (int)pid);
	}
	return rc;
}

int
sys_daemon(int nochdir, int noclose)
{
	int rc;

	rc = daemon(nochdir, noclose);
	if (rc < 0) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "daemon() failed;");
	} else {
		NOTICE(0, "daemon()");
	}
	return rc;
}

void *
sys_malloc(size_t size)
{
	void *new_ptr;

	new_ptr = malloc(size);
	if (new_ptr == NULL) {
		ERR(0, "malloc() failed; size=%zu", size);
	} else {
		INFO(0, "malloc(); size=%zu, new_ptr=%p", size, new_ptr);
	}
	return new_ptr;
}

void *
sys_realloc(void *old_ptr, size_t size)
{
	void *new_ptr;

	new_ptr = realloc(old_ptr, size);
	if (new_ptr == NULL) {
		ERR(0, "realloc() failed; size=%zu", size);
	} else {
		INFO(0, "realloc(); size=%zu, old_ptr=%p, new_ptr=%p",
		     size, old_ptr, new_ptr);
	}
	return new_ptr;
}

int
sys_posix_memalign(const char *name, void **memptr,
	size_t alignment, size_t size)
{
	int rc;

	rc = posix_memalign(memptr, alignment, size);
	if (rc) {
		ERR(0, "posix_memalign() failed; name='%s', size=%zu",
			name, size);
	} else {
		INFO(0, "posix_memalign(); name='%s', size=%zu, ptr=%p",
			name, size, *memptr);
	}
	return -rc;
}

int
sys_mmap(void **res, void *addr, size_t size, int prot, int flags,
	int fd, off_t offset)
{
	int rc;
	void *ptr;

	ptr = (*sys_mmap_fn)(addr, size, prot, flags, fd, offset);
	if (ptr == MAP_FAILED) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "mmap() failed; fd=%d, size=%zu", fd, size);
	} else {
		rc = 0;
		INFO(0, "mmap(); fd=%d, ptr=%p, size=%zu", fd, ptr, size);
		if (res != NULL) {
			*res = ptr;
		}
	}
	return rc;
}

int
sys_munmap(void *ptr, size_t size)
{
	int rc;

	rc = munmap(ptr, size);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "munmap() failed; ptr=%p, size=%zu", ptr, size);
	} else {
		INFO(0, "munmap(); ptr=%p, size=%zu", ptr, size);
	}
	return rc;
}

int
sys_mprotect(void *ptr, size_t size, int prot)
{
	int rc;

	rc = mprotect(ptr, size, prot);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "mprotect() failed; ptr=%p, size=%zu", ptr, size);
	} else {
		INFO(0, "mprotect(); ptr=%p, size=%zu", ptr, size);
	}
	return rc;
}

int
sys_getifaddrs(struct ifaddrs **ifap)
{
	int rc;

	rc = getifaddrs(ifap);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "getifaddrs() failed;");
		return rc;
	} else {
		INFO(0, "getifaddrs()");
	}
	return 0;
}

int
sys_if_indextoname(int ifindex, char *ifname)
{
	int rc;
	char *s;

	s = if_indextoname(ifindex, ifname);
	if (s == NULL) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "if_indextoname() failed; ifindex=%d", ifindex);
	} else {
		rc = 0;
		assert(s == ifname);
		INFO(0, "if_indextoname(); ifindex=%d, ifname=%s",
			ifindex, ifname);
	}
	return rc;
}

int
sys_if_nametoindex(const char *ifname)
{
	int rc;

	rc = if_nametoindex(ifname);
	if (rc == 0) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "if_nametoindex() failed; ifname='%s'", ifname);
	} else {
		INFO(0, "if_nametoindex(); ifname=%s, ifondex=%d", ifname, rc);
	}
	return rc;
}

#ifdef __linux__
int
sys_epoll_create1(int flags)
{
	int rc;

	rc = (*sys_epoll_create1_fn)(flags);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "epoll_create() failed;");	
	} else {
		INFO(0, "epoll_create(); ep_fd=%d", rc);
	}
	return rc;
}

int
sys_epoll_pwait(int ep_fd, struct epoll_event *events,
	int maxevents, int timeout, const sigset_t *sigmask)
{
	int rc;

restart:
	rc = (*sys_epoll_pwait_fn)(ep_fd, events, maxevents, timeout, sigmask);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		if (rc == -EINTR) {
			goto restart;
		} else {
			ERR(-rc, "epoll_pwait()failed; ep_fd=%d", ep_fd);
		}
	} else {
		DBG(0, "epoll_pwait(); ep_fd=%d", ep_fd);
	}
	return rc;
}

int
sys_epoll_ctl(int ep_fd, int op, int fd, struct epoll_event *event)
{
	int rc;

	rc = (*sys_epoll_ctl_fn)(ep_fd, op, fd, event);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "epoll_ctl() failed; ep_fd=%d, op=%s, fd=%d",
			ep_fd, log_add_epoll_op(op), fd);
	} else {
		INFO(0, "epoll_ctl(); ep_fd=%d, op=%s, fd=%d",
			ep_fd, log_add_epoll_op(op), fd);
	}
	return rc;
}

int
sys_clone(int (*fn)(void *), void *child_stack,
	int flags, void *arg, void *ptid, void *tls, void *ctid)
{
	int rc;

	rc = (*sys_clone_fn)(fn, child_stack, flags, arg, ptid, tls, ctid);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "clone() failed; flags=%s",
			log_add_clone_flags(flags));
	} else {
		INFO(0, "clone(); flags=%s", log_add_clone_flags(flags));
	}
	return rc;
}
#else // __linux__
int
sys_kqueue()
{
	int rc;

	rc = (*sys_kqueue_fn)();
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		ERR(-rc, "kqueue() failed;");
	} else {
		INFO(0, "kqueue(); kq_fd=%d", rc);
	}
	return rc;
}

int
sys_kevent(int kq, const struct kevent *changelist, int nchanges,
		struct kevent *eventlist, int nevents,
		const struct timespec *timeout)
{
	int rc;

	rc = (*sys_kevent_fn)(kq, changelist, nchanges, eventlist, nevents,
		timeout);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		DBG(-rc, "kevent() failed; kq_fd=%d", kq);
	} else {
		DBG(0, "kevent(); kq_fd=%d", kq);
	}
	return rc;
}
#endif // __linux__
