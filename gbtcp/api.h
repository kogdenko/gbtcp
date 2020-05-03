// GPL2 license
#ifndef GBTCP_API_H
#define GBTCP_API_H

#include "log.h"

#define API_RETURN(rc) \
do { \
	if (rc < 0) { \
		gbtcp_errno = -rc; \
		return -1; \
	} else { \
		return rc; \
	} \
} while (0)

int api_mod_init(struct log *, void **);
int api_mod_attach(struct log *, void *);
void api_mod_deinit(struct log *, void *);
void api_mod_detach(struct log *);

int api_socket(struct log *, int, int, int, int);
int api_bind(struct log *, int, const struct sockaddr *, socklen_t);
int api_listen(struct log *, int, int);
int api_accept4(int, struct sockaddr *, socklen_t *, int);
int api_shutdown(int, int);
int api_close(int);
ssize_t api_recvfrom(int, const struct iovec *, int, int,
	struct sockaddr *, socklen_t *);
int api_send(int fd, const struct iovec *iov, int iovcnt, int flags,
	be32_t faddr, be16_t fport);
int api_fcntl(int fd, int cmd, uintptr_t arg);
int api_fcntl(int fd, int cmd, uintptr_t arg);
int api_getsockopt(int fd, int level, int optname, void *optval,
	socklen_t *optlen);
int api_setsockopt(int fd, int level, int optname, const void *optval,
	socklen_t optlen);
int api_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen);

#endif // GBTCP_API_H
