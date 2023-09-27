// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_TIMER_H
#define GBTCP_TIMER_H

#include "subr.h"
#include "htable.h"

#define TIMER_RING_SHIFT 12
#define TIMER_RING_SIZE (1llu << TIMER_RING_SHIFT) // 4096
#define TIMER_RING_MASK (TIMER_RING_SIZE - 1llu)
#define TIMER_RING0_SEG_SHIFT 24
#define TIMER_RING0_SEG (1llu << TIMER_RING0_SEG_SHIFT) // ~16 msec
#define TIMER_RING1_SEG_SHIFT (TIMER_RING0_SEG_SHIFT + TIMER_RING_SHIFT - 2)
#define TIMER_RING1_SEG (1llu << TIMER_RING1_SEG_SHIFT) // ~17 sec
#define TIMER_TIMEOUT TIMER_RING0_SEG

#define TIMER_EXPIRE_MIN (2*TIMER_RING0_SEG) // ~32 msec
#define TIMER_EXPIRE_MAX (TIMER_RING1_SEG*TIMER_RING_SIZE - 1) // ~ 19 hours
#define TIMER_N_RINGS 2

struct service;

struct timer {
	struct gt_dlist tm_list;
	u_char tm_sid;
	u_char tm_ring_id;
	u_short tm_seg_id;
	u_char tm_module_id;
	u_char tm_fn_id;
};

typedef struct htable_bucket timer_seg_t;

struct timer_ring {
	uint64_t tmr_seg_shift;
	uint64_t tmr_cur;
	timer_seg_t tmr_segs[TIMER_RING_SIZE];
};

int init_timers(struct service *);
void deinit_timers(struct service *);
void run_timers(void);
void migrate_timers(struct service *, struct service *);

void timer_init(struct timer *);
int timer_is_running(struct timer *);
uint64_t timer_timeout(struct timer *);
void timer_set(struct timer *, uint64_t, u_char, u_char);
void timer_cancel(struct timer *);

#endif // GBTCP_TIMER_H
