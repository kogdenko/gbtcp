#ifndef GBTCP_EPOLL_H
#define GBTCP_EPOLL_H

#include "subr.h"

struct gt_file;

#ifdef __linux__
typedef struct epoll_event gt_epoll_event_t;
#else /* __linux__ */
typedef struct kevent gt_epoll_event_t;
#endif /* __linux__ */

int gt_epoll_mod_init();

void gt_epoll_mod_deinit(struct gt_log *log);

int gt_epoll_create(int ep_fd);

int gt_epoll_close(struct gt_file *fp);

int gt_epoll_pwait(int ep_fd, gt_epoll_event_t *buf, int cnt,
	gt_time_t to, const sigset_t *sigmask);

#ifdef __linux__
int gt_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
#else /* __linux__ */
int gt_epoll_kevent(int kq, const struct kevent *changelist, int nchanges,
	struct kevent *eventlist, int nevents,
	const struct timespec *timeout);
#endif /* __linux__ */

#endif /* GBTCP_EPOLL_H */
