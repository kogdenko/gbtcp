// gpl2 license
#ifndef GBTCP_FD_EVENT_H
#define GBTCP_FD_EVENT_H

#include "subr.h"
#include "list.h"

#define FD_EVENTS_MAX FD_SETSIZE

typedef int (*fd_event_f)(void *, short);

struct fd_event {
	int fde_fd;
	int fde_ref_cnt;
	short fde_events;
	short fde_id;
	fd_event_f fde_fn;
	void *fde_udata;
	char fde_name[64];
};

struct fd_poll {
	uint64_t fdes_to;
	uint64_t fdes_time;
	struct timespec fdes_ts;
	int fdes_nr_used;
	int fdes_first;
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

int fd_event_add(struct fd_event **, int, const char *, void *, fd_event_f);
void fd_event_del(struct fd_event *);
void fd_event_set(struct fd_event *, short);
void fd_event_clear(struct fd_event *, short);
int fd_event_is_set(struct fd_event *, short);

void fd_poll_init(struct fd_poll *);
void fd_poll_set(struct fd_poll *, struct pollfd *);
int fd_poll_call(struct fd_poll *, struct pollfd *);

#endif // GBTCP_FD_EVENT_H
