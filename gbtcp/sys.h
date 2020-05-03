/* GPL2 license */
#ifndef GBTCP_SYS_H
#define GBTCP_SYS_H

#include "log.h"

#define SYS_DLSYM(x) \
do { \
	sys_##x##_fn = dlsym(RTLD_NEXT, #x); \
	assert(sys_##x##_fn != NULL); \
} while (0)


typedef pid_t (*sys_fork_f)();
typedef int (*sys_open_f)(const char *, int, mode_t);
typedef int (*sys_unlink_f)(const char *);
typedef int (*sys_pipe_f)(int [2]);
typedef int (*sys_socket_f)(int, int, int);
typedef int (*sys_connect_f)(int, const struct sockaddr *, socklen_t);
typedef int (*sys_bind_f)(int, const struct sockaddr *,	socklen_t);
typedef int (*sys_listen_f)(int, int);
typedef int (*sys_accept4_f)(int fd, struct sockaddr *, socklen_t *, int);
typedef int (*sys_shutdown_f)(int, int);
typedef int (*sys_close_f)(int);
typedef ssize_t (*sys_read_f)(int, void *, size_t);
typedef ssize_t (*sys_readv_f)(int, const struct iovec *, int);
typedef ssize_t (*sys_recv_f)(int, void *, size_t, int);
typedef ssize_t (*sys_recvfrom_f)(int, void *, size_t, int,
	struct sockaddr *, socklen_t *);
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
typedef int (*sys_fcntl_f)(int, int, ...);
typedef int (*sys_ioctl_f)(int, unsigned long, ...);
typedef int (*sys_getsockopt_f)(int, int, int, void *, socklen_t *);
typedef int (*sys_setsockopt_f)(int, int, int, const void *, socklen_t);
typedef int (*sys_getpeername_f)(int, struct sockaddr *, socklen_t *);
typedef int (*sys_getsockname_f)(int, struct sockaddr *, socklen_t *);
typedef int (*sys_ppoll_f)(struct pollfd *, nfds_t, const struct timespec *,
	const sigset_t *);
typedef void *(*sys_signal_f)(int, void (*)(int));
typedef int (*sys_sigaction_f)(int, const struct sigaction *,
	struct sigaction *);
typedef int (*sys_sigprocmask_f)(int, const sigset_t *, sigset_t *);
typedef int (*sys_flock_f)(int, int);
typedef struct group *(*sys_getgrnam_f)(const char *);
typedef int (*sys_chown_f)(const char *, uid_t, gid_t);

#ifdef __linux__
typedef int (*sys_clone_f)(int (*)(void *), void *, int, void *,
	void *, void *, void *);
typedef int (*sys_epoll_create1_f)(int);
typedef int (*sys_epoll_ctl_f)(int , int, int, struct epoll_event *);
typedef int (*sys_epoll_wait_f)(int, struct epoll_event *, int, int);
typedef int (*sys_epoll_pwait_f)(int, struct epoll_event *, int, int,
	const sigset_t *);
typedef int (*sys_dup3_f)(int, int, int);
#else /* __linux__ */
typedef int (*sys_kqueue_f)();
typedef int (*sys_kevent_f)(int kq, const struct kevent *, int ,
	struct kevent *, int, const struct timespec *);
#endif /* __linux__ */

extern sys_fork_f sys_fork_fn;
extern sys_open_f sys_open_fn;
extern sys_unlink_f sys_unlink_fn;
extern sys_pipe_f sys_pipe_fn;
extern sys_socket_f sys_socket_fn;
extern sys_connect_f sys_connect_fn;
extern sys_bind_f sys_bind_fn;
extern sys_listen_f sys_listen_fn;
extern sys_accept4_f sys_accept4_fn;
extern sys_shutdown_f sys_shutdown_fn;
extern sys_close_f sys_close_fn;
extern sys_read_f sys_read_fn;
extern sys_readv_f sys_readv_fn;
extern sys_recv_f sys_recv_fn;
extern sys_recvfrom_f sys_recvfrom_fn;
extern sys_recvmsg_f sys_recvmsg_fn;
extern sys_write_f sys_write_fn;
extern sys_writev_f sys_writev_fn;
extern sys_send_f sys_send_fn;
extern sys_sendto_f sys_sendto_fn;
extern sys_sendmsg_f sys_sendmsg_fn;
extern sys_sendfile_f sys_sendfile_fn;
extern sys_fcntl_f sys_fcntl_fn;
extern sys_ioctl_f sys_ioctl_fn;
extern sys_getsockopt_f sys_getsockopt_fn;
extern sys_setsockopt_f sys_setsockopt_fn;
extern sys_getpeername_f sys_getpeername_fn;
extern sys_getsockname_f sys_getsockname_fn;
extern sys_ppoll_f sys_ppoll_fn;
extern sys_signal_f sys_signal_fn;
extern sys_sigaction_f sys_sigaction_fn;
extern sys_sigprocmask_f sys_sigprocmask_fn;
extern sys_flock_f sys_flock_fn;
extern sys_getgrnam_f sys_getgrnam_fn;
extern sys_chown_f sys_chown_fn;
#ifdef __linux__
extern sys_clone_f sys_clone_fn;
extern sys_epoll_create1_f sys_epoll_create1_fn;
extern sys_epoll_ctl_f sys_epoll_ctl_fn;
extern sys_epoll_wait_f sys_epoll_wait_fn;
extern sys_epoll_pwait_f sys_epoll_pwait_fn;
#else /* __linux__ */
extern sys_kqueue_f sys_kqueue_fn;
extern sys_kevent_f sys_kevent_fn;
#endif /* __linux__ */

int sys_mod_init(struct log *, void **);
int sys_mod_attach(struct log *, void *);
void sys_mod_deinit(struct log *, void *);
void sys_mod_detach(struct log *);

void dlsym_all();

int sys_fork(struct log *);
int sys_open(struct log *, const char *, int, mode_t);
int sys_symlink(struct log *, const char *, const char *);
int sys_unlink(struct log *, const char *);
int sys_pipe(struct log *, int [2]);
int sys_socket(struct log *, int, int, int);
int sys_connect(struct log *, int, const struct sockaddr *, socklen_t);
int sys_bind(struct log *, int, const struct sockaddr *, socklen_t);
int sys_listen(struct log *, int, int);
int sys_accept4(struct log *, int, struct sockaddr *, socklen_t *, int);
int sys_shutdown(struct log *, int, int);
int sys_close(struct log *, int);
ssize_t sys_read(struct log *, int, void *, size_t);
ssize_t sys_recvmsg(struct log *, int, struct msghdr *, int);
ssize_t sys_write(struct log *, int, const void *, size_t);
ssize_t sys_send(struct log *, int, const void *, size_t, int);
ssize_t sys_sendmsg(struct log *, int, const struct msghdr *, int);
int sys_dup(struct log *, int);
int sys_fcntl(struct log *, int, int, uintptr_t);
int sys_ioctl(struct log *, int, unsigned long, uintptr_t);
int sys_getsockopt(struct log *, int, int, int, void *, socklen_t *);
int sys_setsockopt(struct log *, int, int, int, void *, socklen_t);
int sys_ppoll(struct log *, struct pollfd *, nfds_t, const struct timespec *,
	const sigset_t *);
void *sys_signal(struct log *, int, void (*)(int));
int sys_sigaction(struct log *, int, const struct sigaction *, struct sigaction *);
int sys_sigprocmask(struct log *, int, const sigset_t *, sigset_t *);
int sys_malloc(struct log *, void **, size_t);
#define sys_free free
int sys_realloc(struct log *, void **, size_t);
int sys_posix_memalign(struct log *, void **, size_t, size_t);
int sys_fopen(struct log *, FILE **, const char *, const char *);
int sys_opendir(struct log *, DIR **, const char *);
int sys_stat(struct log *, const char *, struct stat *);
int sys_realpath(struct log *, const char *, char *);
int sys_flock(struct log *, int, int);
int sys_getgrnam(struct log *, const char *, struct group **);
int sys_chown(struct log *, const char *, uid_t, gid_t);
int sys_chmod(struct log *, const char *, mode_t);
int sys_getifaddrs(struct log *, struct ifaddrs **);
int sys_if_indextoname(struct log *, int, char *);
int sys_kill(struct log *, int, int);
int sys_waitpid(struct log *, pid_t, int *, int);
int sys_daemon(struct log *, int, int);
int sys_inotify_init1(struct log *, int);
int sys_inotify_add_watch(struct log *, int, const char *, uint32_t);
int sys_inotify_rm_watch(struct log *, int, int);

#ifdef __linux__
int sys_epoll_create1(struct log *, int);
int sys_epoll_pwait(struct log *, int, struct epoll_event *, int, int,
	const sigset_t *);
int sys_clone(struct log *, int (*)(void *), void *, int , void *,
	void *, void *, void *);
#else /* __linux__ */
int sys_kqueue();
#endif /* __linux__ */

#endif /* GBTCP_SYS_H */
