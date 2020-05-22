#ifndef GBTCP_FD_EVENT_H
#define GBTCP_FD_EVENT_H

#include "subr.h"
#include "list.h"

#define FD_EVENTS_MAX FD_SETSIZE

// System should RX netmap devices every 20 microseconds
// or packets would be lost
#define FD_EVENT_TIMEOUT 20000ull

typedef int (*fd_event_f)(void *, short revents);

struct fd_event {
	int fde_fd;
	int fde_ref_cnt;
	short fde_events;
	short fde_id;
	fd_event_f fde_fn;
	void *fde_udata;
	char fde_name[64];
};

struct gt_fd_event_set {
	uint64_t fdes_to;
	uint64_t fdes_time;
	struct timespec fdes_ts;
	int fdes_nr_used;
	int fdes_again; // For repeted `rxtx` call
	struct fd_event *fdes_used[FD_EVENTS_MAX];
};

extern uint64_t gt_fd_event_epoch;

int fd_event_mod_init(void **);
int fd_event_mod_attach(void *);
void fd_event_mod_deinit(void *);
void fd_event_mod_detach();

void check_fd_events();
void wait_for_fd_events();

void gt_fd_event_ctl_init(struct fd_event *e);

int gt_fd_event_new(struct fd_event **pe, int fd,
	const char *name, fd_event_f fn, void *udata);

void gt_fd_event_del(struct fd_event *e);

void gt_fd_event_set(struct fd_event *e, short events);

void gt_fd_event_clear(struct fd_event *e, short events);

int gt_fd_event_is_set(struct fd_event *e, short events);

void gt_fd_event_set_init(struct gt_fd_event_set *set, struct pollfd *pfds);

int gt_fd_event_set_call(struct gt_fd_event_set *set, struct pollfd *pfds);

#endif /* GBTCP_FD_EVENT_H */
