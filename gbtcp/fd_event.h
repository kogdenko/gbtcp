// GPL v2
#ifndef GBTCP_FD_EVENT_H
#define GBTCP_FD_EVENT_H

#include "subr.h"
#include "list.h"

typedef int (*fd_event_f)(void *, short);

struct fd_thread;

struct fd_event {
	short fde_fd;
	short fde_ref_cnt;
	short fde_events;
	short fde_id;
	fd_event_f fde_fn;
	void *fde_udata;
	struct fd_thread *fde_thread;
};

struct fd_thread {
	uint64_t fdt_drain_time;
	uint64_t fdt_timeout;
	int fdt_n_used;
	int fdt_is_waiting;
	struct fd_event *fdt_used[FD_SETSIZE];
	struct fd_event fdt_buf[FD_SETSIZE];
};

#define FD_EVENT_TIMEOUT_MIN (20 * NSEC_USEC)


static inline void
fd_thread_init(struct fd_thread *t)
{
	t->fdt_timeout = FD_EVENT_TIMEOUT_MIN;
}

struct fd_poll {
	uint64_t fdp_to;
	int fdp_n_events;
	int fdp_n_added;
	int fdp_throttled; // for repeted `rxtx` call
	struct pollfd fdp_pfds[FD_SETSIZE];
	struct fd_event *fdp_events[FD_SETSIZE];
};

void fd_thread_wait3(struct fd_thread *, int, uint64_t);
#define fd_thread_check(t) fd_thread_wait3(t, 0, 0)
#define fd_thread_wait(t) fd_thread_wait3(t, 1, TIMER_TIMEOUT)

struct fd_event *fd_event_add(struct fd_thread *, int, void *, fd_event_f);
void fd_event_del(struct fd_event *);
void fd_event_set(struct fd_event *, short);
void fd_event_clear(struct fd_event *, short);
int fd_event_is_set(struct fd_event *, short);

void fd_poll_init(struct fd_poll *);
int fd_poll_add3(struct fd_poll *, int, short); 
#define fd_poll_add(p, pfd) \
	fd_poll_add3(p, (pfd)->fd, (pfd)->events)
int fd_poll_wait(struct fd_poll *, const sigset_t *);

#endif // GBTCP_FD_EVENT_H
