// GPL2 license
#ifndef GBTCP_API_H
#define GBTCP_API_H

#include "subr.h"

#define API_RETURN(rc) \
	if (rc < 0) { \
		gt_errno = -rc; \
		return -1; \
	} else { \
		return rc; \
	} \

int api_mod_init(void **);
int api_mod_attach(void *);
void api_mod_deinit();
void api_mod_detach();

int api_socket(int, int, int);
int api_bind(int, const struct sockaddr *, socklen_t);
int api_listen(int, int);
int api_accept4(int, struct sockaddr *, socklen_t *, int);
int api_shutdown(int, int);
int api_close(int);
ssize_t api_recvfrom(int, const struct iovec *, int, int,
	struct sockaddr *, socklen_t *);
int api_send(int, const struct iovec *, int, int, be32_t, be16_t);
int api_fcntl(int, int, uintptr_t);
int api_fcntl(int, int, uintptr_t);
int api_getsockopt(int, int, int, void *, socklen_t *);
int api_setsockopt(int, int, int, const void *,	socklen_t);
int api_getpeername(int, struct sockaddr *, socklen_t *);

#endif // GBTCP_API_H
