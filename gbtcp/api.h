// +
#ifndef GBTCP_API_H
#define GBTCP_API_H

#include "subr.h"

int gt_api_mod_init();

void gt_api_mod_deinit(struct gt_log *log);

int gt_api_socket(struct gt_log *log, int fd, int domain, int type, int proto);

int gt_api_bind(struct gt_log *log, int fd, const struct sockaddr *addr,
	socklen_t addrlen);

int gt_api_listen(struct gt_log *log, int fd, int backlog);

int gt_api_accept4(int lfd, struct sockaddr *addr, socklen_t *addrlen,
	int flags);

int gt_api_shutdown(int fd, int how);

int gt_api_close(int fd);

ssize_t gt_api_recvfrom(int fd, const struct iovec *iov, int iovcnt,
	int flags, struct sockaddr *addr, socklen_t *addrlen);

int gt_api_send(int fd, const struct iovec *iov, int iovcnt, int flags,
	be32_t faddr, be16_t fport);

int gt_api_fcntl(int fd, int cmd, uintptr_t arg);

int gt_api_fcntl(int fd, int cmd, uintptr_t arg);

int gt_api_getsockopt(int fd, int level, int optname, void *optval,
	socklen_t *optlen);

int gt_api_setsockopt(int fd, int level, int optname, const void *optval,
	socklen_t optlen);

int gt_api_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen);

#endif /* GBTCP_API_H */
