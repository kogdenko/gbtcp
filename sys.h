// +
#ifndef GBTCP_SYS_H
#define GBTCP_SYS_H

#include "subr.h"

#define GT_SYS_DLSYM(x) \
do { \
	gt_sys_##x##_fn = dlsym(RTLD_NEXT, #x); \
	assert(gt_sys_##x##_fn != NULL); \
} while (0)

typedef pid_t (*gt_fork_f)();

typedef int (*gt_open_f)(const char *path, int flags, mode_t mode);

typedef int (*gt_socket_f)(int domain, int type, int protocol);

typedef int (*gt_connect_f)(int fd, const struct sockaddr *addr,
	socklen_t addrlen);

typedef int (*gt_bind_f)(int fd, const struct sockaddr *addr,
	socklen_t addrlen);

typedef int (*gt_listen_f)(int fd, int backlog);

typedef int (*gt_accept4_f)(int fd, struct sockaddr *addr, socklen_t *addrlen,
	int flags);

typedef int (*gt_shutdown_f)(int fd, int how);

typedef int (*gt_close_f)(int fd);

typedef ssize_t (*gt_read_f)(int fd, void *buf, size_t count);

typedef ssize_t (*gt_readv_f)(int fd, const struct iovec *iov, int iovcnt);

typedef ssize_t (*gt_recv_f)(int fd, void *buf, size_t len, int flags);

typedef ssize_t (*gt_recvfrom_f)(int fd, void *buf, size_t len, int flags,
	struct sockaddr *src_addr, socklen_t *addrlen);

typedef ssize_t (*gt_recvmsg_f)(int fd, struct msghdr *msg, int flags);

typedef ssize_t (*gt_write_f)(int fd, const void *buf, size_t count);

typedef ssize_t (*gt_writev_f)(int fd, const struct iovec *iov, int iovcnt);

typedef ssize_t (*gt_send_f)(int fd, const void *buf, size_t len, int flags);

typedef ssize_t (*gt_sendto_f)(int fd, const void *buf, size_t len, int flags,
	const struct sockaddr *dest_addr, socklen_t addrlen);

typedef ssize_t (*gt_sendmsg_f)(int fd, const struct msghdr *msg, int flags);

typedef ssize_t (*gt_sendfile_f)(int out_fd, int in_fd, off_t *offset,
	size_t count);

typedef int (*gt_dup_f)(int oldfd);

typedef int (*gt_dup2_f)(int oldfd, int newfd);

typedef int (*gt_fcntl_f)(int fd, int cmd, ...);

typedef int (*gt_ioctl_f)(int fd, unsigned long request, ...);

typedef int (*gt_getsockopt_f)(int fd, int level, int optname, void *optval,
	socklen_t *optlen);

typedef int (*gt_setsockopt_f)(int fd, int level, int optname,
	const void *optval, socklen_t optlen);

typedef int (*gt_getpeername_f)(int fd, struct sockaddr *addr,
	socklen_t *addrlen);

typedef int (*gt_getsockname_f)(int fd, struct sockaddr *addr,
	socklen_t *addrlen);

typedef int (*gt_ppoll_f)(struct pollfd *fds, nfds_t nfds,
	const struct timespec *timeout_ts, const sigset_t *sigmask);

typedef void *(*gt_signal_f)(int signum, void (*new_sa_handler)(int));

typedef int (*gt_sigaction_f)(int signum, const struct sigaction *act,
	struct sigaction *oldact);

typedef int (*gt_sigprocmask_f)(int how, const sigset_t *set,
	sigset_t *oldset);

typedef int (*gt_flock_f)(int fd, int operations);

typedef struct group *(*gt_getgrnam_f)(const char *name);

typedef int (*gt_chown_f)(const char *path, uid_t owner, gid_t group);

#ifdef __linux__

typedef int (*gt_clone_f)(int (*fn)(void *), void *child_stack,
	int flags, void *arg, void *ptid, void *tls, void *ctid);

typedef int (*gt_epoll_create1_f)(int flags);

typedef int (*gt_epoll_ctl_f)(int epfd, int op, int fd,
	struct epoll_event *event);

typedef int (*gt_epoll_wait_f)(int epfd, struct epoll_event *events,
	int maxevents, int timeout);

typedef int (*gt_epoll_pwait_f)(int epfd, struct epoll_event *events,
	int maxevents, int timeout, const sigset_t *sigmask);

typedef int (*gt_dup3_f)(int oldfd, int newfd, int flags);

#else /* __linux__ */

typedef int (*gt_kqueue_f)();

typedef int (*gt_kevent_f)(int kq, const struct kevent *changelist,
	int nchanges, struct kevent *eventlist, int nevents,
	const struct timespec *timeout);

#endif /* __linux__ */

extern gt_fork_f gt_sys_fork_fn;
extern gt_open_f gt_sys_open_fn;
extern gt_socket_f gt_sys_socket_fn;
extern gt_connect_f gt_sys_connect_fn;
extern gt_bind_f gt_sys_bind_fn;
extern gt_listen_f gt_sys_listen_fn;
extern gt_accept4_f gt_sys_accept4_fn;
extern gt_shutdown_f gt_sys_shutdown_fn;
extern gt_close_f gt_sys_close_fn;
extern gt_read_f gt_sys_read_fn;
extern gt_readv_f gt_sys_readv_fn;
extern gt_recv_f gt_sys_recv_fn;
extern gt_recvfrom_f gt_sys_recvfrom_fn;
extern gt_recvmsg_f gt_sys_recvmsg_fn;
extern gt_write_f gt_sys_write_fn;
extern gt_writev_f gt_sys_writev_fn;
extern gt_send_f gt_sys_send_fn;
extern gt_sendto_f gt_sys_sendto_fn;
extern gt_sendmsg_f gt_sys_sendmsg_fn;
extern gt_sendfile_f gt_sys_sendfile_fn;
extern gt_fcntl_f gt_sys_fcntl_fn;
extern gt_ioctl_f gt_sys_ioctl_fn;
extern gt_getsockopt_f gt_sys_getsockopt_fn;
extern gt_setsockopt_f gt_sys_setsockopt_fn;
extern gt_getpeername_f gt_sys_getpeername_fn;
extern gt_getsockname_f gt_sys_getsockname_fn;
extern gt_ppoll_f gt_sys_ppoll_fn;
extern gt_signal_f gt_sys_signal_fn;
extern gt_sigaction_f gt_sys_sigaction_fn;
extern gt_sigprocmask_f gt_sys_sigprocmask_fn;
extern gt_flock_f gt_sys_flock_fn;
extern gt_getgrnam_f gt_sys_getgrnam_fn;
extern gt_chown_f gt_sys_chown_fn;
#ifdef __linux__
extern gt_clone_f gt_sys_clone_fn;
extern gt_epoll_create1_f gt_sys_epoll_create1_fn;
extern gt_epoll_ctl_f gt_sys_epoll_ctl_fn;
extern gt_epoll_wait_f gt_sys_epoll_wait_fn;
extern gt_epoll_pwait_f gt_sys_epoll_pwait_fn;
#else /* __linux__ */
extern gt_kqueue_f gt_sys_kqueue_fn;
extern gt_kevent_f gt_sys_kevent_fn;
#endif /* __linux__ */

int gt_sys_mod_init();

void gt_sys_mod_deinit(struct gt_log *log);

void gt_sys_mod_dlsym();

int gt_sys_fork(struct gt_log *log);

int gt_sys_open(struct gt_log *log, const char *path, int flags, mode_t mode);

int gt_sys_socket(struct gt_log *log, int domain, int type, int protocol);

int gt_sys_connect(struct gt_log *log, int fd, const struct sockaddr *addr,
	socklen_t addrlen);

int gt_sys_bind(struct gt_log *log, int fd, const struct sockaddr *addr,
	socklen_t addrlen);

int gt_sys_listen(struct gt_log *log, int fd, int backlog);

int gt_sys_accept4(struct gt_log *log, int fd,
	struct sockaddr *addr, socklen_t *addrlen, int flags);

int gt_sys_shutdown(struct gt_log *log, int fd, int how);

int gt_sys_close(struct gt_log *log, int fd);

ssize_t gt_sys_read(struct gt_log *log, int fd, void *buf, size_t count);

ssize_t gt_sys_recvmsg(struct gt_log *log, int fd, struct msghdr *msg,
	int flags);

ssize_t gt_sys_write(struct gt_log *log, int fd, const void *buf,
	size_t count);

ssize_t gt_sys_send(struct gt_log *log, int fd, const void *buf, size_t len,
	int flags);

ssize_t gt_sys_sendmsg(struct gt_log *log, int fd, const struct msghdr *msg,
	int flags);

int gt_sys_dup(struct gt_log *log, int fd);

int gt_sys_fcntl(struct gt_log *log, int fd, int cmd, uintptr_t arg);

int gt_sys_ioctl(struct gt_log *log, int fd, unsigned long request,
	uintptr_t arg);

int gt_sys_getsockopt(struct gt_log *log, int fd, int level, int opt_name,
	void *opt_val, socklen_t *opt_len);

int gt_sys_setsockopt(struct gt_log *log, int fd, int level, int optname,
	void *optval, socklen_t optlen);

int gt_sys_ppoll(struct gt_log *log, struct pollfd *fds, nfds_t nfds,
	const struct timespec *to, const sigset_t *sigmask);

void *gt_sys_signal(struct gt_log *log, int signum, void (*handler)(int));

int gt_sys_sigaction(struct gt_log *log, int signum, const struct sigaction *act,
	struct sigaction *oldact);

int gt_sys_sigprocmask(struct gt_log *log, int how, const sigset_t *set,
	sigset_t *oldset);

int gt_sys_malloc(struct gt_log *log, void **pptr, size_t size);

int gt_sys_realloc(struct gt_log *log, void **pptr, size_t size);

int gt_sys_posix_memalign(struct gt_log *log, void **memptr, size_t alignment,
	size_t size);

int gt_sys_fopen(struct gt_log *log, FILE **file, const char *path,
	const char *mode);

int gt_sys_opendir(struct gt_log *log, DIR **pdir, const char *name);

int gt_sys_stat(struct gt_log *log, const char *path, struct stat *buf);

int gt_sys_realpath(struct gt_log *log, const char *path, char *resolved_path);

int gt_sys_flock(struct gt_log *log, int fd, int operation);

int gt_sys_getgrnam(struct gt_log *log, const char *name,
	struct group **pgroup);

int gt_sys_chown(struct gt_log *log, const char *path, uid_t owner,
	gid_t group);

int gt_sys_chmod(struct gt_log *log, const char *path, mode_t mode);

int gt_sys_getifaddrs(struct gt_log *log, struct ifaddrs **ifap);

int gt_sys_if_indextoname(struct gt_log *log, int ifindex, char *ifname);

int gt_sys_kill(struct gt_log *log, int pid, int sig);

int gt_sys_waitpid(struct gt_log *log, pid_t pid, int *status, int options);

#ifdef __linux__

int gt_sys_clone(struct gt_log *log, int (*fn)(void *), void *child_stack,
	int flags, void *arg, void *ptid, void *tls, void *ctid);
#else /* __linux__ */
int gt_sys_kqueue();
#endif /* __linux__ */

#endif /* GBTCP_SYS_H */
