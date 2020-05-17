// GPL2 license
#ifndef GBTCP_H
#define GBTCP_H

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifdef __linux__
#include <sys/epoll.h>
#else // __linux__
#include <sys/event.h>
#include <sys/time.h>
#endif // __linux__

#define GT_TCP_S_CLOSED 0
#define GT_TCP_S_LISTEN 1
#define GT_TCP_S_SYN_SENT 2
#define GT_TCP_S_SYN_RCVD 3
#define GT_TCP_S_ESTABLISHED 4
#define GT_TCP_S_CLOSE_WAIT 5
#define GT_TCP_S_FIN_WAIT_1 6
#define GT_TCP_S_CLOSING 7
#define GT_TCP_S_LAST_ACK 8
#define GT_TCP_S_FIN_WAIT_2 9
#define GT_TCP_S_TIME_WAIT 10
#define GT_TCP_NSTATES 11

#define GT_SYSCTL_BUFSIZ 4096
#define GT_RSS_NQ_MAX 32
#define GT_SERVICE_COUNT_MAX 128
#define GT_GROUP_NAME "gbtcp"

#define GT_TCP_STAT(x) \
	x(sndtotal) \
	x(sndpack) \
	x(sndbyte) \
	x(sndrexmitpack) \
	x(sndrexmitbyte) \
	x(sndacks) \
	x(delack) \
	x(sndurg) \
	x(sndprobe) \
	x(sndwinup) \
	x(sndctrl) \
	x(rcvtotal) \
	x(rcvackpack) \
	x(rcvackbyte) \
	x(rcvdupack) \
	x(rcvacktoomuch) \
	x(rcvpack) \
	x(rcvbyte) \
	x(rcvduppack) \
	x(rcvdupbyte) \
	x(pawsdrop) \
	x(rcvpartduppack) \
	x(rcvpartdupbyte) \
	x(rcvpackafterwin) \
	x(rcvbyteafterwin) \
	x(rcvwinprobe) \
	x(rcvwinupd) \
	x(rcvbadsum) \
	x(rcvbadoff) \
	x(rcvshort) \
	x(rcvoopack) \
	x(rcvoobyte) \
	x(rcvafterclose) \
	x(rcvmemdrop) \
	x(connattempt) \
	x(accepts) \
	x(badsyn) \
	x(listendrop) \
	x(connects) \
	x(closed) \
	x(drops) \
	x(conndrops) \
	x(rttupdated) \
	x(segstimed) \
	x(rexmttimeo) \
	x(timeoutdrop) \
	x(persisttimeo) \
	x(keeptimeo) \
	x(keepprobe) \
	x(keepdrops) \
	x(predack) \
	x(preddat) \

#define GT_UDP_STAT(x) \
	x(ipackets) \
	x(hdrops) \
	x(badlen) \
	x(badsum) \
	x(nosum) \
	x(noport) \
	x(fullsock) \
	x(opackets) \

#define GT_IP_STAT(x) \
	x(total) \
	x(badsum) \
	x(toosmall) \
	x(tooshort) \
	x(toolong) \
	x(badhlen) \
	x(badlen) \
	x(badvers) \
	x(fragments) \
	x(fragdropped) \
	x(delivered) \
	x(noproto) \
	x(localout) \
	x(noroute) \
	x(fragmented) \
	x(cantfrag) \

#define GT_ICMP_STAT(x) \
	x(badcode) \
	x(tooshort) \
	x(checksum) \
	x(badlen) \
	x(reflect) \

#define GT_ARP_STAT(x) \
	x(txrequests) \
	x(txreplies) \
	x(txrepliesdropped) \
	x(rxrequests) \
	x(rxreplies) \
	x(received) \
	x(dropped) \
	x(bypassed) \
	x(filtered) \
	x(timeouts) \
	x(dupips) \
	x(toosmall) \
	x(badhrd) \
	x(badpro) \
	x(badhlen) \
	x(badplen) \
	x(badaddr) \
	x(badop)

//#ifdef __linux__
typedef void (*gt_sighandler_t)(int);
//#else /* __linux__ */
//typedef __sighandler_t gt_sighandler_t;
//#endif /* __linux__ */

extern __thread int gbtcp_errno;

pid_t gbtcp_fork();

pid_t gbtcp_vfork();

int gbtcp_socket(int domain, int type, int protocol);

int gbtcp_connect(int fd, const struct sockaddr *addr, socklen_t addrlen);

int gbtcp_bind(int fd, const struct sockaddr *addr, socklen_t addrlen);

int gbtcp_listen(int fd, int backlog);

int gbtcp_accept4(int lfd, struct sockaddr *addr, socklen_t *addrlen,
	int flags);

int gbtcp_shutdown(int fd, int how);

int gbtcp_close(int fd);

ssize_t gbtcp_read(int fd, void *buf, size_t count);

ssize_t gbtcp_readv(int fd, const struct iovec *iov, int iovcnt);

ssize_t gbtcp_recv(int fd, void *buf, size_t len, int flags);

ssize_t gbtcp_recvfrom(int fd, void *buf, size_t len, int flags,
	struct sockaddr *src_addr, socklen_t *addrlen);

ssize_t gbtcp_recvmsg(int fd, struct msghdr *msg, int flags);

ssize_t gbtcp_write(int fd, const void *buf, size_t count);

ssize_t gbtcp_writev(int fd, const struct iovec *iov, int iovcnt);

ssize_t gbtcp_send(int fd, const void *buf, size_t len, int flags);

ssize_t gbtcp_sendto(int fd, const void *buf, size_t len, int flags,
	const struct sockaddr *dest_addr, socklen_t addrlen);

ssize_t gbtcp_sendmsg(int fd, const struct msghdr *msg, int flags);

ssize_t gbtcp_sendfile(int out_fd, int in_fd, off_t *offset, size_t count);

int gbtcp_fcntl(int fd, int cmd, uintptr_t arg);

int gbtcp_ioctl(int fd, unsigned long request, uintptr_t arg);

int gbtcp_getsockopt(int fd, int level, int optname,
	void *optval, socklen_t *optlen);

int gbtcp_setsockopt(int fd, int level, int optname,
	const void *optval, socklen_t optlen);

int gbtcp_getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen);

int gbtcp_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen);

int gbtcp_poll(struct pollfd *fds, nfds_t nfds, int timeout);

int gbtcp_ppoll(struct pollfd *fds, nfds_t nfds,
	const struct timespec *timeout_ts, const sigset_t *sigmask);

int gt_sysctl(const char *, char *, const char *);

int gt_first_fd();

gt_sighandler_t gbtcp_signal(int signum, gt_sighandler_t new_sa_handler);

int gbtcp_sigaction(int signum, const struct sigaction *act,
	struct sigaction *oldact);

#ifdef __linux__

int gbtcp_clone(int (*fn)(void *), void *child_stack,
	int flags, void *arg, void *ptid, void *tls, void *ctid);

int gbtcp_epoll_create1(int);

int gbtcp_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

int gbtcp_epoll_pwait(int epfd, struct epoll_event *events,
	int maxevents, int timeout, const sigset_t *sigmask);

#else /* __linux__ */

int gbtcp_kqueue();

int gbtcp_kevent(int, const struct kevent *, int, struct kevent *, int,
	const struct timespec *);

#endif /* __linux__ */

#ifndef gt_dbg
#define gt_dbg(f, ...) \
do { \
	printf("%-6d: %-20s: %-4d: %-20s: ", \
	       getpid(), __FILE__, __LINE__, __func__); \
	printf(f, ##__VA_ARGS__); \
	printf("\n"); \
} while (0)
#endif // gt_dbg

#endif // GBTCP_H
