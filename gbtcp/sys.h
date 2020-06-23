// gpl2
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
typedef int (*sys_kevent_f)(int, const struct kevent *, int ,
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

int sys_mod_init(void **);
int sys_mod_attach(void *);
void sys_mod_deinit(void *);
void sys_mod_detach();

void dlsym_all();

int sys_fork();
int sys_open(const char *, int, mode_t);
int sys_symlink(const char *, const char *);
int sys_unlink(const char *);
int sys_pipe(int [2]);
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
ssize_t sys_sendmsg(int, const struct msghdr *, int);
int sys_dup(int);
int sys_fcntl(int, int, uintptr_t);
int sys_ioctl(int, unsigned long, uintptr_t);
int sys_getsockopt(int, int, int, void *, socklen_t *);
int sys_setsockopt(int, int, int, void *, socklen_t);
int sys_getpeername(int, struct sockaddr *, socklen_t *);
int sys_ppoll(struct pollfd *, nfds_t, const struct timespec *,
	const sigset_t *);
void *sys_signal(int, void (*)(int));
int sys_sigaction(int, const struct sigaction *, struct sigaction *);
int sys_sigprocmask(int, const sigset_t *, sigset_t *);
void *sys_malloc(size_t);
#define sys_free free
void *sys_realloc(void *, size_t);
int sys_posix_memalign(const char *, void **, size_t, size_t);
int sys_mmap(void **, void *, size_t, int, int, int, off_t);
int sys_munmap(void *addr, size_t);
int sys_mprotect(void *, size_t, int);
int sys_fopen(FILE **, const char *, const char *);
int sys_opendir(DIR **, const char *);
#define sys_closedir closedir
int sys_stat(const char *, struct stat *);
int sys_fstat(int, struct stat *);
int sys_ftruncate(int, off_t);
int sys_realpath(const char *, char *);
int sys_flock(int, int);
int sys_getgrnam(const char *, struct group **);
int sys_chown(const char *, uid_t, gid_t);
int sys_fchown(int, uid_t, gid_t);
int sys_chmod(const char *, mode_t);
int sys_getifaddrs(struct ifaddrs **);
int sys_if_indextoname(int, char *);
int sys_if_nametoindex(const char *);
int sys_kill(int, int);
int sys_waitpid(pid_t, int *, int);
int sys_daemon(int, int);
int sys_inotify_init1(int);
int sys_inotify_add_watch(int, const char *, uint32_t);
int sys_inotify_rm_watch(int, int);
int sys_shm_open(const char *, int, mode_t);

#ifdef __linux__
int sys_epoll_create1(int);
int sys_epoll_pwait(int, struct epoll_event *, int, int, const sigset_t *);
int sys_epoll_ctl(int, int, int, struct epoll_event *);
int sys_clone(int (*)(void *), void *, int , void *, void *, void *, void *);
#else // __linux__
int sys_kqueue();
#endif // __linux__

#endif // GBTCP_SYS_H
