// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/kernel/log.h>
#include <gbtcp/kernel/strbuf.h>
#include <gbtcp/kernel/sys.h>

#define GT_SYS_DECLARATION(name) sys_##name##_f sys_##name##_fn;

GT_SYS_X(GT_SYS_DECLARATION);

struct log_scope *gt_sys_curmod;

#define gt_debug(...) gt_debug3(&gt_main->sys_logger, ##__VA_ARGS__)
#define gt_info(...) gt_info3(&gt_main->sys_logger, ##__VA_ARGS__)
#define gt_notice(...) gt_notice3(&gt_main->sys_logger, ##__VA_ARGS__)
#define gt_err(...) gt_err3(&gt_main->sys_logger, ##__VA_ARGS__)

int
sys_fork(void)
{
	int rc;

	rc = (*sys_fork_fn)();
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		gt_err(-rc, "fork() failed");
	} else {
		gt_notice(0, "fork() return pid:%d", rc);
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
			gt_err(-rc, "open('%s') failed", path);
		}
	} else {
		gt_info(0, "open('%s') return fd=%d", path, rc);
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
		gt_err(-rc, "fopen('%s', '%s') failed", path, mode);
	} else {
		rc = 0;
		gt_info(0, "fopen(%s', '%s') return file:%p", path, mode,
			*file);
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
		gt_err(-rc, "opendir('%s') failed", name);
	} else {
		rc = 0;
		gt_info(0, "opendir('%s') return dir:%p", name, *pdir);
	}
	return rc;
}

/*int
sys_stat(const char *path, struct stat *buf)
{
	int rc;

	rc = (*sys_stat_fn)(path, buf);
	if (rc == -1) {
		rc = -errno;
		assert(errno);
		gt_err(-rc, "failed; path:'%s'", path);
	} else {
		gt_info(0, "ok; path:'%s'", path);
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
		gt_err(-rc, "fstat(fd:%d') failed", fd);
	} else {
		gt_info(0, "fstat(fd:%d) ok", fd);
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
			gt_err(-rc, "getgrnam('%s') failed", name);
		}
	} else {
		gt_info(0, "getgrnam('%s') ok", name);
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
		gt_err(-rc, "chown('%s', uid:%d, gid:%d) failed", path, owner,
		       group);
	} else {
		gt_info(0, "chown('%s', uid:%d, gid:%d) ok", path, owner,
			group);
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
		gt_err(-rc, "fchown(fd:%d, uid:%d, gid:%d) failed", fd, owner,
		       group);
	} else {
		gt_info(0, "fchown(fd:%d, uid:%d, gid:%d) ok", fd, owner,
			group);
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
		gt_err(-rc, "chmod('%s', '%o') failed", path, mode);
	} else {
		gt_info(0, "chmod('%s', '%o') ok", path, mode);
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
		gt_err(-rc, "fchmod(fd:%d, '%o') failed", fd, mode);
	} else {
		gt_info(0, "fchmod(fd:%d, '%o') ok", fd, mode);
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
			gt_err(-rc, "ftruncate(fd:%d, %jd) failed", fd,
			       (intmax_t)off);
		}
	} else {
		gt_info(0, "ftruncate(fd:%d, %jd) ok", fd, (intmax_t)off);
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
		gt_err(-rc, "realpath('%s') failed", path);
	} else {
		rc = 0;
		gt_info(0, "realpath('%s') return '%s'", path, resolved_path);
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
		gt_err(-rc, "symlink('%s', '%s') failed", oldpath, newpath);
	} else {
		gt_info(0, "symlink('%s', '%s') ok", oldpath, newpath);
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
		gt_err(-rc, "unlink('%s') failed", path);
	} else {
		gt_info(-rc, "unlink('%s') ok", path);
	}
	return rc;
}

int
sys_rename(const char *oldpath, const char *newpath)
{
	int rc;

	rc = (*sys_rename_fn)(oldpath, newpath);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		gt_err(-rc, "rename('%s', '%s') failed", oldpath, newpath);
	} else {
		gt_info(0, "rename('%s', '%s') ok", oldpath, newpath);
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
		gt_err(-rc, "pipe() failed");
	} else {
		gt_info(0, "pipe() return rfd:%d, wfd:%d", pipefd[0],
			pipefd[1]);
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
		gt_err(-rc, "socket('%s', '%s', '%s') failed",
		       log_add_socket_domain(domain),
		       log_add_socket_type(type_noflags),
		       log_add_socket_flags(flags));
	} else {
		gt_info(0, "socket('%s', '%s', '%s') return fd:%d",
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
		gt_err(-rc, "connect(fd=%d, '%s') failed", fd,
		       log_add_sockaddr(addr, addrlen));
	} else {
		gt_info(0, "connect(fd=%d, '%s') ok", fd,
			log_add_sockaddr(addr, addrlen));
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
		gt_err(-rc, "bind(fd:%d, '%s') failed", fd,
		       log_add_sockaddr(addr, addrlen));
	} else {
		gt_info(0, "bind(fd:%d, '%s') ok", fd,
			log_add_sockaddr(addr, addrlen));
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
		gt_err(-rc, "listen(fd:%d, %d) failed", fd, backlog);
	} else {
		gt_info(0, "listen(fd:%d, %d) ok", fd, backlog);
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
			gt_err(-rc, "accept(fd:%d) failed", fd);
		}
	} else {
		gt_info(0, "accept(fd:%d) return newfd:%d", fd, rc);
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
		gt_err(-rc, "shutdown(fd:%d, '%s') failed", fd,
		       log_add_shutdown_how(how));
	} else {
		gt_info(0, "shutdown(fd:%d, '%s') ok", fd,
			log_add_shutdown_how(how));
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
		//gt_err(-rc, "close(fd:%d) failed", fd);
	} else {
		//gt_info(0, "close(fd:%d) ok", fd);
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
			gt_err(-rc, "read(fd:%d) failed", fd);
		}
	} else {
		gt_info(0, "read(fd:%d) return %zd", fd, rc);
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
			gt_err(-rc, "recv(fd:%d) failed", fd);
		}
	} else {
		gt_info(0, "recv(fd:%d) return %zd", fd, rc);
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
			gt_err(-rc, "recvmsg(fd:%d) failed", fd);
		}
	} else {
		gt_info(0, "recvmsg(fd:%d) return %zd", fd, rc);
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
			gt_err(-rc, "write(fd:%d) failed", fd);
		}
	} else {
		gt_info(0, "write(fd:%d) return %zd", fd, rc);
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
		} else if (rc != -EAGAIN) {
			gt_err(-rc, "send(fd:%d) failed", fd);
		}
	} else {
		gt_info(0, "send(fd:%d) return %zd", fd, rc);
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
			gt_err(-rc, "sendto(fd:%d) failed", fd);
		}
	} else {
		gt_info(0, "sendto(fd:%d) return %zd", fd, rc);
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
		gt_err(-rc, "sendmsg(fd:%d) failed", fd);
	} else {
		gt_info(-rc, "sendmsg(fd:%d) return %zd", fd, rc);
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
		gt_err(-rc, "dup(fd:%d) failed", fd);
	} else {
		gt_info(0, "dup(fd:%d) return newfd:%d", fd, rc);
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
		gt_err(-rc, "getsockopt(fd:%d, '%s', '%s') failed", fd,
		       log_add_sockopt_level(level),
		       log_add_sockopt_optname(level, optname));
	} else {
		gt_info(0, "getsockopt(fd:%d, '%s', '%s') ok", fd,
			log_add_sockopt_level(level),
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
		gt_err(-rc, "setsockopt(fd:%d, '%s', '%s') failed", fd,
		       log_add_sockopt_level(level),
		       log_add_sockopt_optname(level, optname));
	} else {
		gt_info(0, "setsockopt(fd:%d, '%s', '%s') ok", fd,
			log_add_sockopt_level(level),
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
		gt_err(-rc, "getpeername(fd:%d) failed", fd);
	} else {
		gt_info(0, "getpeername(fd:%d) return '%s'", fd,
			log_add_sockaddr(addr, *addrlen));
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
		gt_err(-rc, "fcntl(fd:%d, '%s') failed", fd,
		       log_add_fcntl_cmd(cmd));
	} else {
		gt_info(0, "fcntl(fd:%d, '%s') ok", fd, log_add_fcntl_cmd(cmd));
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
		gt_err(-rc, "ioctl(fd:%d, '%s') failed", fd,
		       log_add_ioctl_req(req, arg));
	} else {
		gt_info(0, "ioctl(fd:%d, '%s') ok", fd,
			log_add_ioctl_req(req, arg));
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
			gt_err(-rc, "flock(fd:%d) failed", fd);
		}
	} else {
		gt_info(0, "flock(fd:%d) ok", fd);
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
			gt_info(-rc, "ppoll() interrupted");
		} else {
			gt_err(-rc, "ppoll() failed");
		}
	} else {
		if (nfds) {
			gt_debug(0, "ppoll() return '%s'",
				 log_add_pollfds_revents(fds, nfds));
		}
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
		gt_err(-rc, "signal(%d, '%s') failed", signum,
		       log_add_sighandler(handler));
	} else {
		rc = 0;
		gt_info(0, "signal(%d, '%s') ok", signum,
			log_add_sighandler(handler));
	}
	if (pres != NULL) {
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
		gt_err(-rc, "sigaction(%d) failed", signum);
	} else {
		gt_info(0, "sigaction(%d) ok", signum);
	}
	return rc;
}

int
sys_sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	int rc;

	// gt_fmt_sigprocmask_now()

	rc = (*sys_sigprocmask_fn)(how, set, oldset);
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		gt_err(-rc, "sigprocmask('%s') failed",
		       log_add_sigprocmask_how(how));
	} else {
		gt_info(0, "sigprocmask('%s') ok",
			log_add_sigprocmask_how(how));
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
		gt_err(-rc, "kill(pid:%d, %d) failed", pid, sig);
	} else {
		gt_info(0, "kill(pid:%d, %d) ok", pid, sig);
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
		gt_err(-rc, "waitpid(pid:%d) failed", (int)pid);
	} else {
		gt_info(0, "waitpid(pid:%d) ok", (int)pid);
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
		gt_err(-rc, "daemon() failed");
	} else {
		gt_notice(0, "daemon() ok");
	}
	return rc;
}

void *
sys_malloc(size_t size)
{
	int rc;
	void *memptr;

	rc = sys_posix_memalign(&memptr, GT_L1_CACHE_BYTES, size);
	return rc == 0 ? memptr : NULL;
}

char *
sys_strdup(const char *s)
{
	size_t len;
	void *cp;

	len = strlen(s);
	cp = sys_malloc(len + 1);
	if (cp != NULL) {
		memcpy(cp, s, len + 1);
	}

	return cp;
}

char *
sys_strndup(const char *s, size_t n)
{
	size_t len;
	char *cp;

	for (len = 0; len < n; ++len) {
		if (s[len] == '\0') {
			break;
		}
	}

	cp = sys_malloc(len + 1);
	memcpy(cp, s, len);
	cp[len] = '\0';

	return cp;
}

void
sys_free(void *ptr)
{
	free(ptr);
}

/*void *
sys_realloc(void *old, size_t size)
{
	void *new;
	char oldbuf[GT_PTR_STRLEN + 1];

	// To suppress -Werror=use-after-free
	snprintf(oldbuf, sizeof(oldbuf), "%p", old);
	GT_UNUSED(oldbuf);

	new = realloc(old, size);
	if (new == NULL) {
		gt_err(0, "realloc(%p, %zu) failed", old, size);
	} else {
		gt_info(0, "realloc(%s, %zu) return %p", oldbuf, size,
			new);
	}
	return new;
}*/

int
sys_posix_memalign(void **memptr, size_t alignment, size_t size)
{
	int rc;

	assert(alignment >= GT_L1_CACHE_BYTES);
	rc = posix_memalign(memptr, alignment, size);
	if (rc) {
		gt_err(0, "posix_memalign(%zu, %zu) failed", alignment, size);
	} else {
		gt_info(0, "posix_memalign(%zu, %zu) return %p", alignment,
			size, *memptr);
	}
	return -rc;
}

int
sys_mmap(void **res, void *addr, size_t size, int prot, int flags, int fd,
	 off_t offset)
{
	int rc;
	void *ptr;

	ptr = (*sys_mmap_fn)(addr, size, prot, flags, fd, offset);
	if (ptr == MAP_FAILED) {
		rc = -errno;
		assert(rc);
		gt_err(-rc, "mmap(fd:%d, %zu) failed", fd, size);
	} else {
		rc = 0;
		gt_info(0, "mmap(fd:%d, %zu) return %p", fd, size, ptr);
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
		//gt_err(-rc, "munmap(%p, %zu) failed", ptr, size);
	} else {
		//gt_info(0, "munmap(%p, %zu) ok", ptr, size);
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
		gt_err(-rc, "mprotect(%p, %zu, 0x%x) failed", ptr, size, prot);
	} else {
		gt_info(0, "mprotect(%p, %zu, 0x%x) ok", ptr, size, prot);
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
		gt_err(-rc, "getifaddrs() failed");
		return rc;
	} else {
		gt_info(0, "getifaddrs() ok");
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
		gt_err(-rc, "if_indextoname(%d) failed", ifindex);
	} else {
		rc = 0;
		assert(s == ifname);
		gt_info(0, "if_indextoname(%d) return '%s'", ifindex, ifname);
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
		gt_err(-rc, "if_nametoindex('%s') failed", ifname);
	} else {
		gt_info(0, "if_nametoindex('%s') return %d", ifname, rc);
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
		gt_err(-rc, "epoll_create1() failed");
	} else {
		gt_info(0, "epoll_create1() return ep_fd:%d", rc);
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
			gt_err(-rc, "epoll_pwait(ep_fd:%d) failed", ep_fd);
		}
	} else {
		gt_debug(0, "epoll_pwait(ep_fd:%d) ok", ep_fd);
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
		gt_err(-rc, "epoll_ctl(ep_fd:%d, 0x%x, fd=%d) failed", ep_fd,
		       op, fd);
	} else {
		gt_info(0, "epoll_ctl(ep_fd:%d, 0x%x, fd=%d) ok", ep_fd, op,
			fd);
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
		gt_err(-rc, "clone(%s) failed", log_add_clone_flags(flags));
	} else {
		gt_info(0, "clone(%s) ok", log_add_clone_flags(flags));
	}
	return rc;
}
#else // __linux__
int
sys_kqueue(void)
{
	int rc;

	rc = (*sys_kqueue_fn)();
	if (rc == -1) {
		rc = -errno;
		assert(rc);
		gt_err(-rc, "kqueue() failed");
	} else {
		gt_info(0, "kqueue() return kq_fd:%d", rc);
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
		gt_debug(-rc, "kevent(kq_fd:%d) failed", kq);
	} else {
		gt_debug(0, "kevent(kq_fd:%d) ok", kq);
	}
	return rc;
}
#endif // __linux__

void
gt_sys_module_worker_start(void *m)
{
	gt_sys_curmod = m;
}

void
gt_sys_module_worker_stop(void)
{
	// gt_sys_curmod is the shared module object used by every service-thread
	// in this process; clearing it on a per-thread detach would break
	// siblings. It is set idempotently in worker_attach.
}

void
gt_dbg5(const char *file, u_int line, const char *func, int suppressed,
	const char *fmt, ...)
{
	char buf[BUFSIZ];
	va_list ap;
	struct strbuf sb;

	strbuf_init(&sb, buf, sizeof(buf));
	strbuf_addf(&sb, "%-6u:%-6u: %-20s: %-4u: %-20s: ", getpid(),
		    gt_gettid(), file, line, func);
	va_start(ap, fmt);
	strbuf_vaddf(&sb, fmt, ap);
	va_end(ap);
	if (suppressed) {
		strbuf_addf(&sb, " (suppressed %d)", suppressed);
	}
	fprintf(stdout, "%s\n", strbuf_cstr(&sb));
	fflush(stdout);
}

void
gt_dbg_hexdump_ascii5(const char *file, u32 line, const char *func, void *data,
		      size_t count)
{
	char buf[BUFSIZ];
	struct strbuf sb;

	strbuf_init(&sb, buf, sizeof(buf));
	strbuf_addf(&sb, "%-6u:%-6u: %-20s: %-4u: %-20s:\n", getpid(),
		    gt_gettid(), file, line, func);
	strbuf_hexdump_ascii(&sb, data, count);
	fprintf(stdout, "%s", strbuf_cstr(&sb));
	fflush(stdout);
}
