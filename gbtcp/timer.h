#ifndef GBTCP_TIMER_H
#define GBTCP_TIMER_H

#include "subr.h"
#include "list.h"

#define GT_TIMER_RING_SIZE 4096llu
#define GT_TIMER_RING_MASK (GT_TIMER_RING_SIZE - 1llu)
#define GT_TIMER_TIMEOUT (32 * GT_MSEC)
#define GT_TIMER_RING_ID_SHIFT 3
#define GT_TIMER_EXPIRE_MAX (5 * 60 * 60 * GT_SEC) // 5 Hours

struct gt_timer {
	struct dllist tm_list;
	uintptr_t tm_data;
};

typedef void (*gt_timer_f)(struct gt_timer *);

int gt_timer_mod_init();

void gt_timer_mod_deinit(struct gt_log *log);

void gt_timer_mod_check();

void gt_timer_init(struct gt_timer *timer);

int gt_timer_is_running(struct gt_timer *timer);

gt_time_t gt_timer_timeout(struct gt_timer *timer);

void gt_timer_set(struct gt_timer *timer, gt_time_t expire, gt_timer_f fn);

void gt_timer_del(struct gt_timer *timer);

#endif /* GBTCP_TIMER_H */
