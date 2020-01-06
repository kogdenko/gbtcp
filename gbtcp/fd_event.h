#ifndef GBTCP_FD_EVENT_H
#define GBTCP_FD_EVENT_H

#include "subr.h"
#include "list.h"

#define GT_FD_EVENTS_MAX FD_SETSIZE

// System should RX netmap devices every 20 microseconds
// or packets would be lost
#define GT_FD_EVENT_TIMEOUT 20000ull

typedef int (*gt_fd_event_f)(void *, short revents);

struct gt_fd_event {
	int fde_fd;
	int fde_ref_cnt;
	short fde_events;
	short fde_id;
	gt_fd_event_f fde_fn;
	void *fde_udata;
	int fde_has_cnt;
	uint64_t fde_cnt_POLLIN;
	uint64_t fde_cnt_POLLOUT;
	uint64_t fde_cnt_POLLERR;
	uint64_t fde_cnt_POLLHUP;
	uint64_t fde_cnt_POLLNVAL;
	uint64_t fde_cnt_UNKNOWN;
	uint64_t fde_cnt_set_POLLIN;
	uint64_t fde_cnt_set_POLLOUT;
	char fde_name[PATH_MAX];
};

struct gt_fd_event_set {
	gt_time_t fdes_to;
	gt_time_t fdes_time;
	struct timespec fdes_ts;
	int fdes_nr_used;
	int fdes_again; // For repeted `rxtx` call
	int fdes_epoch;
	struct gt_fd_event *fdes_used[GT_FD_EVENTS_MAX];
};

extern uint64_t gt_fd_event_epoch;

int gt_fd_event_mod_init();

void gt_fd_event_mod_deinit(struct gt_log *log);

void gt_fd_event_mod_check();

void gt_fd_event_mod_try_check();

void gt_fd_event_mod_trylock_check();

int gt_fd_event_mod_wait();

void gt_fd_event_ctl_init(struct gt_log *log, struct gt_fd_event *e);

int gt_fd_event_new(struct gt_log *log, struct gt_fd_event **pe, int fd,
	const char *name, gt_fd_event_f fn, void *udata);

void gt_fd_event_del(struct gt_fd_event *e);

void gt_fd_event_set(struct gt_fd_event *e, short events);

void gt_fd_event_clear(struct gt_fd_event *e, short events);

int gt_fd_event_is_set(struct gt_fd_event *e, short events);

void gt_fd_event_set_init(struct gt_fd_event_set *set, struct pollfd *pfds);

int gt_fd_event_set_call(struct gt_fd_event_set *set, struct pollfd *pfds);

#endif /* GBTCP_FD_EVENT_H */
