/* GPL2 license */
#ifndef GBTCP_EPOLL_H
#define GBTCP_EPOLL_H

#include "subr.h"

struct file;

#ifdef __linux__
typedef struct epoll_event gt_epoll_event_t;
#else /* __linux__ */
typedef struct kevent gt_epoll_event_t;
#endif /* __linux__ */

int epoll_mod_init(struct log *, void **);
int epoll_mod_attach(struct log *, void *);
void epoll_mod_deinit(struct log *, void *);
void epoll_mod_detach(struct log *);

int gt_epoll_create(int);
int gt_epoll_close(struct file *);
int gt_epoll_pwait(int, gt_epoll_event_t *, int,
	gt_time_t, const sigset_t *);

#ifdef __linux__
int gt_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
#else /* __linux__ */
int gt_epoll_kevent(int kq, const struct kevent *changelist, int nchanges,
	struct kevent *eventlist, int nevents,
	const struct timespec *timeout);
#endif /* __linux__ */

#endif /* GBTCP_EPOLL_H */
