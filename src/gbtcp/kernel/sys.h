// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_SYS_H
#define GBTCP_SYS_H

#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <grp.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>

#ifdef __linux__
#include <linux/ethtool.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#else
#include <sys/event.h>
#endif

#include <gbtcp/config.h>

// clang-format off
#define _GT_SYS_X(_) \
	_(fork) \
	_(open) \
	_(getgrnam) \
	_(chown) \
	_(fchown) \
	_(chmod) \
	_(fchmod) \
	_(symlink) \
	_(unlink) \
	_(rename) \
	_(pipe) \
	_(socket) \
	_(connect) \
	_(bind) \
	_(listen) \
	_(accept4) \
	_(shutdown) \
	_(close) \
	_(read) \
	_(readv) \
	_(recv) \
	_(recvfrom) \
	_(recvmsg) \
	_(write) \
	_(writev) \
	_(send) \
	_(sendto) \
	_(sendmsg) \
	_(sendfile) \
	_(dup) \
	_(dup2) \
	_(getsockopt) \
	_(setsockopt) \
	_(getpeername) \
	_(getsockname) \
	_(fcntl) \
	_(ioctl) \
	_(flock) \
	_(getgrnam) \
	_(chown) \
	_(ppoll) \
	_(sleep) \
	_(signal) \
	_(sigaction) \
	_(sigprocmask) \
	_(kill) \
	_(mmap)

#ifdef __linux__
#define GT_SYS_X(_) \
	_GT_SYS_X(_) \
	_(clone) \
	_(epoll_create1) \
	_(epoll_ctl) \
	_(epoll_wait) \
	_(epoll_pwait)
#else
#define GT_SYS_X(_) \
	_GT_SYS_X(_) \
	_(kqueue) \
	_(kevent)
#endif
// clang-format on

#define GT_SYS_DLSYM(handle, symbol) \
	if (sys_##symbol##_fn == NULL) { \
		sys_##symbol##_fn = dlsym(handle, #symbol); \
		assert(sys_##symbol##_fn != NULL); \
	}

#define GT_SYS_DLSYM_DEFAULT(symbol) GT_SYS_DLSYM(RTLD_DEFAULT, symbol)
#define GT_SYS_DLSYM_NEXT(symbol) GT_SYS_DLSYM(RTLD_NEXT, symbol)

typedef pid_t (*sys_fork_f)(void);
typedef int (*sys_open_f)(const char *, int, mode_t);
typedef struct group *(*sys_getgrnam_f)(const char *);
typedef int (*sys_chown_f)(const char *, uid_t, gid_t);
typedef int (*sys_fchown_f)(int, uid_t, gid_t);
typedef int (*sys_chmod_f)(const char *, mode_t);
typedef int (*sys_fchmod_f)(int, mode_t);
typedef int (*sys_symlink_f)(const char *, const char *);
typedef int (*sys_unlink_f)(const char *);
typedef int (*sys_rename_f)(const char *, const char *);
typedef int (*sys_pipe_f)(int[2]);
typedef int (*sys_socket_f)(int, int, int);
typedef int (*sys_connect_f)(int, const struct sockaddr *, socklen_t);
typedef int (*sys_bind_f)(int, const struct sockaddr *, socklen_t);
typedef int (*sys_listen_f)(int, int);
typedef int (*sys_accept4_f)(int fd, struct sockaddr *, socklen_t *, int);
typedef int (*sys_shutdown_f)(int, int);
typedef int (*sys_close_f)(int);
typedef ssize_t (*sys_read_f)(int, void *, size_t);
typedef ssize_t (*sys_readv_f)(int, const struct iovec *, int);
typedef ssize_t (*sys_recv_f)(int, void *, size_t, int);
typedef ssize_t (*sys_recvfrom_f)(int, void *, size_t, int, struct sockaddr *,
				  socklen_t *);
typedef ssize_t (*sys_recvmsg_f)(int fd, struct msghdr *msg, int);
typedef ssize_t (*sys_write_f)(int, const void *, size_t);
typedef ssize_t (*sys_writev_f)(int, const struct iovec *, int);
typedef ssize_t (*sys_send_f)(int, const void *, size_t, int);
typedef ssize_t (*sys_sendto_f)(int, const void *, size_t, int,
				const struct sockaddr *, socklen_t);
typedef ssize_t (*sys_sendmsg_f)(int, const struct msghdr *, int);
typedef ssize_t (*sys_sendfile_f)(int, int, off_t *, size_t);
typedef int (*sys_dup_f)(int);
typedef int (*sys_dup2_f)(int, int);
typedef int (*sys_getsockopt_f)(int, int, int, void *, socklen_t *);
typedef int (*sys_setsockopt_f)(int, int, int, const void *, socklen_t);
typedef int (*sys_getpeername_f)(int, struct sockaddr *, socklen_t *);
typedef int (*sys_getsockname_f)(int, struct sockaddr *, socklen_t *);
typedef int (*sys_fcntl_f)(int, int, ...);
typedef int (*sys_ioctl_f)(int, unsigned long, ...);
typedef int (*sys_flock_f)(int, int);
typedef int (*sys_ppoll_f)(struct pollfd *, nfds_t, const struct timespec *,
			   const sigset_t *);
typedef unsigned int (*sys_sleep_f)(unsigned int);
typedef void *(*sys_signal_f)(int, void (*)(int));
typedef int (*sys_sigaction_f)(int, const struct sigaction *,
			       struct sigaction *);
typedef int (*sys_sigprocmask_f)(int, const sigset_t *, sigset_t *);
typedef int (*sys_kill_f)(int, int);
typedef void *(*sys_mmap_f)(void *, size_t, int, int, int, off_t);
#ifdef __linux__
typedef int (*sys_clone_f)(int (*)(void *), void *, int, void *, void *, void *,
			   void *);
typedef int (*sys_epoll_create1_f)(int);
typedef int (*sys_epoll_ctl_f)(int, int, int, struct epoll_event *);
typedef int (*sys_epoll_wait_f)(int, struct epoll_event *, int, int);
typedef int (*sys_epoll_pwait_f)(int, struct epoll_event *, int, int,
				 const sigset_t *);
typedef int (*sys_dup3_f)(int, int, int);
#else
typedef int (*sys_kqueue_f)(void);
typedef int (*sys_kevent_f)(int, const struct kevent *, int, struct kevent *,
			    int, const struct timespec *);
#endif

#define GT_SYS_EXTERN(name) extern sys_##name##_f sys_##name##_fn;

GT_SYS_X(GT_SYS_EXTERN);

void dlsym_all(void);

int sys_fork(void);
int sys_open(const char *, int, mode_t);
int sys_fopen(FILE **, const char *, const char *);
int sys_opendir(DIR **, const char *);
#define sys_closedir closedir
int sys_fstat(int, struct stat *);
int sys_getgrnam(const char *, struct group **);
int sys_chown(const char *, uid_t, gid_t);
int sys_fchown(int, uid_t, gid_t);
int sys_chmod(const char *, mode_t);
int sys_fchmod(int, mode_t);
int sys_ftruncate(int, off_t);
int sys_realpath(const char *, char *);
int sys_symlink(const char *, const char *);
int sys_unlink(const char *);
int sys_rename(const char *, const char *);
int sys_pipe(int[2]);
int sys_socket(int, int, int);
int sys_connect(int, const struct sockaddr *, socklen_t);
int sys_bind(int, const struct sockaddr *, socklen_t);
int sys_listen(int, int);
int sys_accept4(int, struct sockaddr *, socklen_t *, int);
int sys_shutdown(int, int);
int sys_close(int);
ssize_t sys_read(int, void *, size_t);
ssize_t sys_recv(int, void *, size_t, int);
ssize_t sys_recvmsg(int, struct msghdr *, int);
ssize_t sys_write(int, const void *, size_t);
ssize_t sys_send(int, const void *, size_t, int);
ssize_t sys_sendto(int, const void *, size_t, int, const struct sockaddr *,
		   socklen_t);
ssize_t sys_sendmsg(int, const struct msghdr *, int);
int sys_dup(int);
int sys_getsockopt(int, int, int, void *, socklen_t *);
int sys_setsockopt(int, int, int, void *, socklen_t);
int sys_getpeername(int, struct sockaddr *, socklen_t *);
int sys_fcntl(int, int, uintptr_t);
int sys_ioctl(int, unsigned long, uintptr_t);
int sys_flock(int, int);
int sys_ppoll(struct pollfd *, nfds_t, const struct timespec *,
	      const sigset_t *);
int sys_signal(int, void **, void (*)(int));
int sys_sigaction(int, const struct sigaction *, struct sigaction *);
int sys_sigprocmask(int, const sigset_t *, sigset_t *);
int sys_kill(int, int);
int sys_waitpid(pid_t, int *, int);
int sys_daemon(int, int);
void *sys_malloc(size_t);
char *sys_strdup(const char *s);
char *sys_strndup(const char *s, size_t n);
void sys_free(void *ptr);
#define gt_sys_free_safe(ptr) \
	({ \
		sys_free(ptr); \
		ptr = NULL; \
	})

void *sys_realloc(void *, size_t);
int sys_posix_memalign(void **, size_t, size_t);
int sys_mmap(void **, void *, size_t, int, int, int, off_t);
int sys_munmap(void *addr, size_t);
int sys_mprotect(void *, size_t, int);
int sys_getifaddrs(struct ifaddrs **);
int sys_if_indextoname(int, char *);
int sys_if_nametoindex(const char *);

#ifdef __linux__
int sys_epoll_create1(int);
int sys_epoll_pwait(int, struct epoll_event *, int, int, const sigset_t *);
int sys_epoll_ctl(int, int, int, struct epoll_event *);
int sys_clone(int (*)(void *), void *, int, void *, void *, void *, void *);
#else // __linux__
int sys_kqueue(void);
int sys_kevent(int, const struct kevent *, int, struct kevent *, int,
	       const struct timespec *);
#endif // __linux__

struct log_scope;
extern struct log_scope *gt_sys_curmod;
void gt_sys_module_worker_start(void *);
void gt_sys_module_worker_stop(void);

#endif // GBTCP_SYS_H
