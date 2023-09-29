// SPDX-License-Identifier: LGPL-2.1-only

#include "log.h"
#include "sys.h"

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
sys_sleep_f sys_sleep_fn;
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
dlsym_all_os(void)
{
	SYS_DLSYM(clone);
	SYS_DLSYM(epoll_create1);
	SYS_DLSYM(epoll_ctl);
	SYS_DLSYM(epoll_wait);
	SYS_DLSYM(epoll_pwait);
}
#else // __linux__
static void
dlsym_all_os(void)
{
	SYS_DLSYM(kqueue);
	SYS_DLSYM(kevent);
}
#endif // __linux__

void
dlsym_all(void)
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
	SYS_DLSYM(sleep);
	SYS_DLSYM(signal);
	SYS_DLSYM(sigaction);
	SYS_DLSYM(sigprocmask);
	SYS_DLSYM(kill);
	SYS_DLSYM(mmap);
	dlsym_all_os();
}

int
sys_fork(void)
{
	int rc;

	rc = (*sys_fork_fn)();
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		GT_ERR(SYS, -rc, "fork() failed");
	} else {
		GT_NOTICE(SYS, 0, "fork() return pid=%d", rc);
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
			GT_ERR(SYS, -rc, "open('%s') failed", path);
		}
	} else {
		GT_INFO(SYS, 0, "open('%s') return fd=%d", path, rc);
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
		GT_ERR(SYS, -rc, "fopen('%s', '%s') failed", path, mode);
	} else {
		rc = 0;
		GT_INFO(SYS, 0, "fopen(%s', '%s') return file=%p", path, mode, *file);
	}
	return rc;
}

int
sys_opendir(DIR **pdir, const char *name)
{
	int rc;

	*pdir = opendir(name);
	if (*pdir == NULL) {
		rc = -errno;
		assert(rc);
		GT_ERR(SYS, -rc, "opendir('%s') failed", name);
	} else {
		rc = 0;
		GT_INFO(SYS, 0, "opendir('%s') return dir=%p", name, *pdir);
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
		GT_ERR(SYS, -rc, "failed; path='%s'", path);
	} else {
		GT_INFO(SYS, 0, "ok; path='%s'", path);
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
		GT_ERR(SYS, -rc, "fstat(fd=%d') failed", fd);
	} else {
		GT_INFO(SYS, 0, "fstat(fd='%d') ok", fd);
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
			GT_ERR(SYS, -rc, "getgrnam('%s') failed", name);
		}
	} else {
		GT_INFO(SYS, 0, "getgrnam('%s') ok", name);
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
		GT_ERR(SYS, -rc, "chown('%s', uid=%d, gid=%d) failed",
				path, owner, group);
	} else {
		GT_INFO(SYS, 0, "chown('%s', uid=%d, gid=%d) ok",
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
		GT_ERR(SYS, -rc, "fchown(fd=%d, uid=%d, gid=%d) failed",
				fd, owner, group);
	} else {
		GT_INFO(SYS, 0, "fchown(fd=%d, uid=%d, gid=%d) ok",
				fd, owner, group);
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
		GT_ERR(SYS, -rc, "chmod('%s', '%o') failed", path, mode);
	} else {
		GT_INFO(SYS, 0, "chmod('%s', '%o') ok", path, mode);
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
		GT_ERR(SYS, -rc, "fchmod(fd=%d, '%o') failed", fd, mode);
	} else {
		GT_INFO(SYS, 0, "fchmod(fd=%d, '%o') ok", fd, mode);
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
			GT_ERR(SYS, -rc, "ftruncate(fd=%d, %jd) failed",
					fd, (intmax_t)off);
		}
	} else {
		GT_INFO(SYS, 0, "ftruncate(fd=%d, %jd) ok",
				fd, (intmax_t)off);
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
		GT_ERR(SYS, -rc, "realpath('%s') failed", path);
	} else {
		rc = 0;
		GT_INFO(SYS, 0, "realpath('%s') return '%s'", path, resolved_path);
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
		GT_ERR(SYS, -rc, "symlink('%s', '%s') failed", oldpath, newpath);
	} else {
		GT_INFO(SYS, 0, "symlink('%s', '%s') ok", oldpath, newpath);
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
		GT_ERR(SYS, -rc, "unlink('%s') failed", path);
	} else {
		GT_INFO(SYS, -rc, "unlink('%s') ok", path);
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
		GT_ERR(SYS, -rc, "pipe() failed");
	} else {
		GT_INFO(SYS, 0, "pipe() return rfd=%d, wfd=%d", pipefd[0], pipefd[1]);
	}
	return rc;
}

int
sys_socket(int domain, int type, int protocol)
{
	int rc, type_noflags, flags;
	
	flags = SOCK_TYPE_FLAGS(type);
	type_noflags = SOCK_TYPE_NOFLAGS(type);
	rc = (*sys_socket_fn)(domain, type, protocol);
	if (rc == -1) {
		rc = -errno;
		assert(rc < 0);
		GT_ERR(SYS, -rc, "socket('%s', '%s', '%s') failed",
				log_add_socket_domain(domain),
				log_add_socket_type(type_noflags),
				log_add_socket_flags(flags));
	} else {
		GT_INFO(SYS, 0, "socket('%s', '%s', '%s') return fd=%d",
				log_add_socket_domain(domain),
				log_add_socket_type(type_noflags),
				log_add_socket_flags(flags), rc);
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
		GT_ERR(SYS, -rc, "connect(fd=%d, '%s') failed",
				fd, log_add_sockaddr(addr, addrlen));
	} else {
		GT_INFO(SYS, 0, "connect(fd=%d, '%s') ok",
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
		GT_ERR(SYS, -rc, "bind(fd=%d, '%s') failed",
				fd, log_add_sockaddr(addr, addrlen));
	} else {
		GT_INFO(SYS, 0, "bind(fd=%d, '%s') ok",
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
		GT_ERR(SYS, -rc, "listen(fd=%d, %d) failed", fd, backlog);
	} else {
		GT_INFO(SYS, 0, "listen(fd=%d, %d) ok", fd, backlog);
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
			GT_ERR(SYS, -rc, "accept(fd=%d) failed", fd);
		}
	} else {
		GT_INFO(SYS, 0, "accept(fd=%d) return newfd=%d", fd, rc);
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
		GT_ERR(SYS, -rc, "shutdown(fd=%d, '%s') failed",
				fd, log_add_shutdown_how(how));
	} else {
		GT_INFO(SYS, 0, "shutdown(fd=%d, '%s') ok",
				fd, log_add_shutdown_how(how)); 
	}
	return rc;
}

int
sys_close(int fd)
{
	int rc;

	if (fd < 0) {
		return 0;
	}
	rc = (*sys_close_fn)(fd);
	if (rc == -1) {
		rc = -errno;
		assert(rc < 0);
		GT_ERR(SYS, -rc, "close(fd=%d) failed", fd);
	} else {
		GT_INFO(SYS, 0, "close(fd=%d) ok", fd);
	}
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
			GT_ERR(SYS, -rc, "read(fd=%d) failed", fd);
		}
	} else {
		GT_INFO(SYS, 0, "read(fd=%d) return %zd", fd, rc);
	}
	return rc;
}

#if 0
sys_readv
#endif

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
			GT_ERR(SYS, -rc, "recv(fd=%d) failed", fd);
		}
	} else {
		GT_INFO(SYS, 0, "recv(fd=%d) return %zd", fd, rc);
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
			GT_ERR(SYS, -rc, "recvmsg(fd=%d) failed", fd);
		}
	} else {
		GT_INFO(SYS, 0, "recvmsg(fd=%d) return %zd", fd, rc);
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
			GT_ERR(SYS, -rc, "write(fd=%d) failed", fd);
		}
	} else {
		GT_INFO(SYS, 0, "write(fd=%d) return %zd", fd, rc);
	}
	return rc;
}

#if 0
sys_writev
#endif

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
			GT_ERR(SYS, -rc, "send(fd=%d) failed", fd);
		}
	} else {
		GT_INFO(SYS, 0, "send(fd=%d) return %zd", fd, rc);
	}
	return rc;
}

ssize_t
sys_sendto(int fd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen)
{
	ssize_t rc;

restart:
	rc = (*sys_sendto_fn)(fd, buf, len, flags, dest_addr, addrlen);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		if (rc == -EINTR) {
			goto restart;
		} else if (rc != -EAGAIN) {
			GT_ERR(SYS, -rc, "sendto(fd=%d) failed", fd);
		}
	} else {
		GT_INFO(SYS, 0, "sendto(fd=%d) return %zd", fd, rc);
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
		GT_ERR(SYS, -rc, "sendmsg(fd=%d) failed", fd);
	} else {
		GT_INFO(SYS, -rc, "sendmsg(fd=%d) return %zd", fd, rc);
	}
	return rc;
}

#if 0
sys_sendfile
#endif

int
sys_dup(int fd)
{
	int rc;

	rc = (*sys_dup_fn)(fd);
	if (rc == -1) {
		rc = -errno;
		assert(rc < 0);
		GT_ERR(SYS, -rc, "dup(fd=%d) failed", fd);
	} else {
		GT_INFO(SYS, 0, "dup(fd=%d) return newfd=%d", fd, rc);
	}
	return rc;
}

#if 0
sys_dup2
#endif

int
sys_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
	int rc;

	rc = (*sys_getsockopt_fn)(fd, level, optname, optval, optlen);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		GT_ERR(SYS, -rc, "getsockopt(fd=%d, '%s', '%s') failed",
				fd, log_add_sockopt_level(level),
				log_add_sockopt_optname(level, optname));
	} else {
		GT_INFO(SYS, 0, "getsockopt(fd=%d, '%s', '%s') ok",
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
		GT_ERR(SYS, -rc, "setsockopt(fd=%d, '%s', '%s') failed",
				fd, log_add_sockopt_level(level),
				log_add_sockopt_optname(level, optname));
	} else {
		GT_INFO(SYS, 0, "setsockopt(fd=%d, '%s', '%s') ok",
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
		GT_ERR(SYS, -rc, "getpeername(fd=%d) failed", fd);
	} else {
		GT_INFO(SYS, 0, "getpeername(fd=%d) return '%s'",
				fd, log_add_sockaddr(addr, *addrlen));
	}
	return rc;
}

#if 0
sys_getsockname
#endif

int
sys_fcntl(int fd, int cmd, uintptr_t arg)
{
	int rc;

	rc = (*sys_fcntl_fn)(fd, cmd, arg);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		GT_ERR(SYS, -rc, "fcntl(fd=%d, '%s') failed",
				fd, log_add_fcntl_cmd(cmd));
	} else {
		GT_INFO(SYS, 0, "fcntl(fd=%d, '%s') ok",
				fd, log_add_fcntl_cmd(cmd));
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
		GT_ERR(SYS, -rc, "ioctl(fd=%d, '%s') failed",
				fd, log_add_ioctl_req(req, arg));
	} else {
		GT_INFO(SYS, 0, "ioctl(fd=%d, '%s') ok",
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
			GT_ERR(SYS, -rc, "flock(fd=%d) failed", fd);
		}
	} else {
		GT_INFO(SYS, 0, "flock(fd=%d) ok", fd);
	}
	return rc;
}

int
sys_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *to, const sigset_t *sigmask)
{
	int rc;

	rc = (*sys_ppoll_fn)(fds, nfds, to, sigmask);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		if (rc == -EINTR) {
			GT_INFO(SYS, -rc, "ppoll() interrupted");
		} else {
			GT_ERR(SYS, -rc, "ppoll() failed");
		}
	} else {
		GT_DBG(SYS, 0, "ppoll() return '%s'",
				log_add_pollfds_revents(fds, nfds));
	}
	return rc;
}

int
sys_signal(int signum, void **pres, void (*handler)(int))
{
	int rc;
	void (*res)(int);

	res = (*sys_signal_fn)(signum, handler);
	if (res == SIG_ERR) {
		rc = -errno;
		assert(rc);
		GT_ERR(SYS, -rc, "signal(%d, '%s') failed",	
				signum, log_add_sighandler(handler));
	} else {
		rc = 0;
		GT_INFO(SYS, 0, "signal(%d, '%s') ok",
				signum, log_add_sighandler(handler));
	}
	if (*pres != NULL) {
		*pres = res;
	}
	return rc;
}

int
sys_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
	int rc;

	rc = (*sys_sigaction_fn)(signum, act, oldact);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		GT_ERR(SYS, -rc, "sigaction(%d) failed", signum);
	} else {
		GT_INFO(SYS, 0, "sigaction(%d) ok", signum);
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
		GT_ERR(SYS, -rc, "sigprocmask('%s') failed", log_add_sigprocmask_how(how));
	} else {
		GT_INFO(SYS, 0, "sigprocmask('%s') ok", log_add_sigprocmask_how(how));
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
		GT_ERR(SYS, -rc, "kill(pid=%d, %d) failed", pid, sig);
	} else {
		GT_INFO(SYS, 0, "kill(pid=%d, %d) ok", pid, sig);
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
		GT_ERR(SYS, -rc, "waitpid(pid=%d) failed", (int)pid);
	} else {
		GT_INFO(SYS, 0, "waitpid(pid=%d) ok", (int)pid);
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
		GT_ERR(SYS, -rc, "daemon() failed");
	} else {
		GT_NOTICE(SYS, 0, "daemon() ok");
	}
	return rc;
}

void *
sys_malloc(size_t size)
{
	void *new_ptr;

	new_ptr = malloc(size);
	if (new_ptr == NULL) {
		GT_ERR(SYS, 0, "malloc(%zu) failed", size);
	} else {
		GT_INFO(SYS, 0, "malloc(%zu) return %p", size, new_ptr);
	}
	return new_ptr;
}

void *
sys_realloc(void *old, size_t size)
{
	void *new;
	char oldbuf[GT_PTR_STRLEN + 1];

	// To suppress -Werror=use-after-free 
	snprintf(oldbuf, sizeof(oldbuf), "%p", old);
	GT_UNUSED(oldbuf);

	new = realloc(old, size);
	if (new == NULL) {
		GT_ERR(SYS, 0, "realloc(%p, %zu) failed", old, size);
	} else {
		GT_INFO(SYS, 0, "realloc(%s, %zu) return %p", oldbuf, size, new);
	}
	return new;
}

int
sys_posix_memalign(void **memptr, size_t alignment, size_t size)
{
	int rc;

	rc = posix_memalign(memptr, alignment, size);
	if (rc) {
		GT_ERR(SYS, 0, "posix_memalign(%zu, %zu) failed", alignment, size);
	} else {
		GT_INFO(SYS, 0, "posix_memalign(%zu, %zu) return %p", alignment, size, *memptr);
	}
	return -rc;
}

int
sys_mmap(void **res, void *addr, size_t size, int prot, int flags, int fd, off_t offset)
{
	int rc;
	void *ptr;

	ptr = (*sys_mmap_fn)(addr, size, prot, flags, fd, offset);
	if (ptr == MAP_FAILED) {
		rc = -errno;
		assert(rc);
		GT_ERR(SYS, -rc, "mmap(fd=%d, %zu) failed", fd, size);
	} else {
		rc = 0;
		GT_INFO(SYS, 0, "mmap(fd=%d, %zu) return %p", fd, size, ptr);
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
		GT_ERR(SYS, -rc, "munmap(%p, %zu) failed", ptr, size);
	} else {
		GT_INFO(SYS, 0, "munmap(%p, %zu) ok", ptr, size);
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
		GT_ERR(SYS, -rc, "mprotect(%p, %zu, 0x%x) failed", ptr, size, prot);
	} else {
		GT_INFO(SYS, 0, "mprotect(%p, %zu, 0x%x) ok", ptr, size, prot);
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
		GT_ERR(SYS, -rc, "getifaddrs() failed");
		return rc;
	} else {
		GT_INFO(SYS, 0, "getifaddrs() ok");
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
		GT_ERR(SYS, -rc, "if_indextoname(%d) failed", ifindex);
	} else {
		rc = 0;
		assert(s == ifname);
		GT_INFO(SYS, 0, "if_indextoname(%d) return '%s'", ifindex, ifname);
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
		GT_ERR(SYS, -rc, "if_nametoindex('%s') failed", ifname);
	} else {
		GT_INFO(SYS, 0, "if_nametoindex('%s') return %d", ifname, rc);
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
		GT_ERR(SYS, -rc, "epoll_create1() failed;");
	} else {
		GT_INFO(SYS, 0, "epoll_create1() return ep_fd=%d", rc);
	}
	return rc;
}

int
sys_epoll_pwait(int ep_fd, struct epoll_event *events, int maxevents,
	int timeout, const sigset_t *sigmask)
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
			GT_ERR(SYS, -rc, "epoll_pwait(ep_fd=%d) failed", ep_fd);
		}
	} else {
		GT_DBG(SYS, 0, "epoll_pwait(ep_fd=%d) ok", ep_fd);
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
		GT_ERR(SYS, -rc, "epoll_ctl(ep_fd=%d, 0x%x, fd=%d) failed",
				ep_fd, op, fd);
	} else {
		GT_INFO(SYS, 0, "epoll_ctl(ep_fd=%d, 0x%x, fd=%d) ok",
				ep_fd, op, fd);
	}
	return rc;
}

int
sys_clone(int (*fn)(void *), void *child_stack, int flags, void *arg,
		void *ptid, void *tls, void *ctid)
{
	int rc;

	rc = (*sys_clone_fn)(fn, child_stack, flags, arg, ptid, tls, ctid);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		GT_ERR(SYS, -rc, "clone(%s) failed", log_add_clone_flags(flags));
	} else {
		GT_INFO(SYS, 0, "clone(%s) ok", log_add_clone_flags(flags));
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
		GT_ERR(SYS, -rc, "kqueue() failed");
	} else {
		GT_INFO(SYS, 0, "kqueue() return kq_fd=%d", rc);
	}
	return rc;
}

int
sys_kevent(int kq, const struct kevent *changelist, int nchanges,
		struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
	int rc;

	rc = (*sys_kevent_fn)(kq, changelist, nchanges, eventlist, nevents,
		timeout);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		GT_DBG(SYS, -rc, "kevent(kq_fd=%d) failed", kq);
	} else {
		GT_DBG(SYS, 0, "kevent(kq_fd=%d) ok", kq);
	}
	return rc;
}
#endif // __linux__
