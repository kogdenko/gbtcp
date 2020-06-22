// gpl2
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
#include <syslog.h>
#ifdef __linux__
#include <sys/epoll.h>
#else // __linux__
#include <sys/event.h>
#include <sys/time.h>
#endif // __linux__

#define GT_TCPS_CLOSED 0
#define GT_TCPS_LISTEN 1
#define GT_TCPS_SYN_SENT 2
#define GT_TCPS_SYN_RCVD 3
#define GT_TCPS_ESTABLISHED 4
#define GT_TCPS_CLOSE_WAIT 5
#define GT_TCPS_FIN_WAIT_1 6
#define GT_TCPS_CLOSING 7
#define GT_TCPS_LAST_ACK 8
#define GT_TCPS_FIN_WAIT_2 9
#define GT_TCPS_TIME_WAIT 10
#define GT_TCP_NSTATES 11

#define GT_SYSCTL_BUFSIZ 4096
#define GT_RSS_NQ_MAX 32
#define GT_SERVICES_MAX 128
#define GT_FIRST_FD (FD_SETSIZE >> 1)
#define GT_GROUP_NAME "gbtcp"

#define GT_SYSCTL_FILE_NOFILE "file.nofile"
#define GT_SYSCTL_ROUTE "route"
#define GT_SYSCTL_ROUTE_RSS_QID "route.rss.qid"
#define GT_SYSCTL_ROUTE_IF_LIST "route.if.list"
#define GT_SYSCTL_ROUTE_IF_ADD "route.if.add"
#define GT_SYSCTL_ROUTE_IF_DEL "route.if.del"
#define GT_SYSCTL_ROUTE_ADDR_LIST "route.addr.list"
#define GT_SYSCTL_ROUTE_ROUTE_LIST "route.route.list"
#define GT_SYSCTL_TCP "tcp"
#define GT_SYSCTL_TCP_FIN_TIMEOUT "tcp.fin_timeout"
#define GT_SYSCTL_SOCKET "socket"
#define GT_SYSCTL_SOCKET_ATTACHED_LIST "socket.attached.list"
#define GT_SYSCTL_SOCKET_ATTACHED_SIZE "socket.attached.size"
#define GT_SYSCTL_SOCKET_BINDED_LIST "socket.binded.list"
#define GT_SYSCTL_ARP_ADD "arp.add"
#define GT_SYSCTL_ARP_DEL "arp.del"
#define GT_SYSCTL_ARP_LIST "arp.list"
#define GT_SYSCTL_SCHED_SERVICE_LIST "sched.service.list"
#define GT_SYSCTL_INET_CKSUM_OFFLOAD_RX "inet.cksum.offload.rx"
#define GT_SYSCTL_INET_CKSUM_OFFLOAD_TX "inet.cksum.offload.tx"

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
	x(bypassed) \
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

extern __thread int gt_errno;
extern int gt_preload_passthru;

pid_t gt_fork();
int gt_socket(int, int, int);
int gt_connect(int, const struct sockaddr *, socklen_t);
int gt_bind(int, const struct sockaddr *, socklen_t);
int gt_listen(int, int);
int gt_accept4(int, struct sockaddr *, socklen_t *, int);
int gt_shutdown(int, int);
int gt_close(int);
ssize_t gt_read(int, void *, size_t);
ssize_t gt_readv(int, const struct iovec *, int);
ssize_t gt_recv(int, void *, size_t, int);
ssize_t gt_recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
ssize_t gt_recvmsg(int, struct msghdr *, int);
ssize_t gt_write(int, const void *, size_t);
ssize_t gt_writev(int, const struct iovec *, int);
ssize_t gt_send(int, const void *, size_t, int);
ssize_t gt_sendto(int, const void *, size_t, int,
	const struct sockaddr *, socklen_t);
ssize_t gt_sendmsg(int, const struct msghdr *, int);
int gt_fcntl(int, int, uintptr_t);
int gt_ioctl(int, unsigned long, uintptr_t);
int gt_getsockopt(int, int, int, void *, socklen_t *);
int gt_setsockopt(int, int, int, const void *, socklen_t);
int gt_getpeername(int, struct sockaddr *, socklen_t *);
int gt_poll(struct pollfd *, nfds_t, int);
int gt_ppoll(struct pollfd *, nfds_t, const struct timespec *,
	const sigset_t *);
int gt_sysctl(const char *, char *, const char *);
void gt_init(const char *, int);
int gt_sigaction(int, const struct sigaction *,	struct sigaction *);

#ifdef __linux__
int gt_clone(int (*)(void *), void *, int, void *, void *, void *, void *);
int gt_epoll_create1(int);
int gt_epoll_ctl(int, int, int, struct epoll_event *);
int gt_epoll_pwait(int, struct epoll_event *, int, int, const sigset_t *);
#else /* __linux__ */
int gt_kqueue();
int gt_kevent(int, const struct kevent *, int, struct kevent *, int,
	const struct timespec *);
#endif /* __linux__ */

void gt_dbg5(const char *, u_int, const char *, int, const char *, ...)
	__attribute__((format(printf, 5, 6)));

#define gt_dbg(fmt, ...) \
	gt_dbg5(__FILE__, __LINE__, __func__, 0, fmt, ##__VA_ARGS__)

#endif // GBTCP_H
