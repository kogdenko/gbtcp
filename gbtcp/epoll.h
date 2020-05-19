// GPL2 license
#ifndef GBTCP_EPOLL_H
#define GBTCP_EPOLL_H

#include "subr.h"

#ifdef __linux__
typedef struct epoll_event epoll_event_t;
#else /* __linux__ */
typedef struct kevent epoll_event_t;
#endif /* __linux__ */

int epoll_mod_init(struct log *, void **);
int epoll_mod_attach(struct log *, void *);
void epoll_mod_deinit(struct log *, void *);
void epoll_mod_detach(struct log *);

int u_epoll_create(int);
int u_epoll_close(struct file *);
int u_epoll_pwait(int, epoll_event_t *, int, uint64_t, const sigset_t *);

#ifdef __linux__
int u_epoll_ctl(int, int, int, struct epoll_event *);
#else /* __linux__ */
int u_kevent(int, const struct kevent *, int,
	struct kevent *, int, const struct timespec *);
#endif /* __linux__ */

#endif // GBTCP_EPOLL_H
