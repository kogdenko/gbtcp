// gpl2 license
#ifndef GBTCP_FD_EVENT_H
#define GBTCP_FD_EVENT_H

#include "subr.h"
#include "list.h"

typedef int (*fd_event_f)(void *, short);

struct fd_event {
	short fde_fd;
	short fde_ref_cnt;
	short fde_events;
	short fde_id;
	fd_event_f fde_fn;
	void *fde_udata;
};

struct fd_poll {
	uint64_t fdp_to;
	uint64_t fdp_time;
	struct timespec fdp_to_ts;
	int fdp_n_events;
	int fdp_n_added;
	int fdp_throttled; // For repeted `rxtx` call
	struct pollfd fdp_pfds[FD_SETSIZE];
	struct fd_event *fdp_events[FD_SETSIZE];
};

extern int fd_poll_epoch;

void clean_fd_events();
void wait_for_fd_events2(int, uint64_t);
#define check_fd_events() wait_for_fd_events2(0, 0)
#define wait_for_fd_events() wait_for_fd_events2(1, TIMER_TIMEOUT)

int fd_event_add(struct fd_event **, int, const char *, void *, fd_event_f);
void fd_event_del(struct fd_event *);
void fd_event_set(struct fd_event *, short);
void fd_event_clear(struct fd_event *, short);
int fd_event_is_set(struct fd_event *, short);

void fd_poll_init(struct fd_poll *);
void fd_poll_add_fd_events(struct fd_poll *);
int fd_poll_add(struct fd_poll *, struct pollfd *); 
int fd_poll_call(struct fd_poll *, struct pollfd *);

#endif // GBTCP_FD_EVENT_H
