// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_TIMER_H
#define GBTCP_TIMER_H

#include <gbtcp/kernel/htable.h>
#include <gbtcp/kernel/mod.h>
#include <gbtcp/kernel/subr.h>

#define GT_TIMER_RING_MAX 16
#define GT_TIMER_RING_SHIFT 12
#define GT_TIMER_RING_SIZE (1llu << GT_TIMER_RING_SHIFT) // 4096
#define GT_TIMER_RING_MASK (GT_TIMER_RING_SIZE - 1llu)
#define GT_TIMER_SEG_SIZE_MIN (1llu << 24) // ~16 ms in ns
#define GT_TIMER_EXPIRE_MIN GT_TIMER_SEG_SIZE_MIN
#define GT_TIMER_EXPIRE_MAX (48 * GT_SEC_PER_HOUR * GT_NSEC_PER_SEC)

struct gt_timer {
	struct gt_dlist tm_link;
	u8 tm_ring_id;
	// The single-arg handler this timer fires, resolved by
	// GT_WORKER_FUNC_EXEC(). See gt_timer_set_fn().
	struct gt_worker_func tm_fn;
};

struct gt_timer_ring {
	u64 tmr_seg_shift;
	u64 tmr_pos;
	int tmr_n_timers;
	struct gt_dlist tmr_seg[GT_TIMER_RING_SIZE];
};

struct gt_timer_wheel {
	u64 tmw_last_time;
	int tmw_n_rings;
	struct gt_timer_ring *tmw_ring;
	struct gt_dlist tmw_zero_timer_head;
};

int gt_timer_wheel_init(struct gt_timer_wheel *);
void gt_timer_wheel_deinit(struct gt_timer_wheel *);
int gt_timer_wheel_is_empty(struct gt_timer_wheel *);
void gt_timer_wheel_run(struct gt_timer_wheel *);
void gt_timer_wheel_call_zero_timers(struct gt_timer_wheel *);
void gt_timer_wheel_migrate(struct gt_timer_wheel *, struct gt_timer_wheel *,
			    u8);

void gt_timer_init(struct gt_timer *timer);
int gt_timer_is_running(struct gt_timer *timer);

// Arm a timer with a directly-registered, single-arg handler (e.g. one of
// gt_so_main's so_timer_*_fn), resolved via GT_WORKER_FUNC_EXEC()
// when it fires.
void gt__timer_set_fn(struct gt_timer_wheel *tmw, struct gt_timer *timer,
		      u64 to, struct gt_worker_func fn);
#define gt_timer_set_fn(timer, to, fn) \
	gt__timer_set_fn(&current->wrk_timer_wheel, timer, to, fn)

void gt__timer_cancel(struct gt_timer_wheel *tw, struct gt_timer *t);
#define gt_timer_cancel(t) gt__timer_cancel(&current->wrk_timer_wheel, t)

#endif // GBTCP_TIMER_H
