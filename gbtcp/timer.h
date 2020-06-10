// gpl2 license
#ifndef GBTCP_TIMER_H
#define GBTCP_TIMER_H

#include "subr.h"
#include "list.h"

#define TIMER_RING_SIZE 4096llu
#define TIMER_RING_MASK (TIMER_RING_SIZE - 1llu)
#define TIMER_TIMEOUT (32 * NANOSECONDS_MILLISECOND)
#define TIMER_EXPIRE_MAX (5 * NANOSECONDS_HOUR)
#define TIMER_RINGS_MAX 4

struct timer {
	struct dlist tm_list;
	u_char tm_sid;
	u_char tm_ring_id;
	u_char tm_mod_id;
	u_char tm_fn_id;
};

struct timer_ring {
	uint64_t tmr_seg_shift;
	uint64_t tmr_cur;
	int tmr_n_timers;
	struct dlist tmr_segs[TIMER_RING_SIZE];
};

int timer_mod_init();
int timer_mod_service_init(struct service *);
void timer_mod_deinit();
void timer_mod_service_deinit(struct service *);

void check_timers();

void timer_init(struct timer *);
int timer_is_running(struct timer *);
uint64_t timer_timeout(struct timer *);
void timer_set4(struct timer *, uint64_t, u_char, u_char);
#define timer_set(timer, expire, fn_id) \
	timer_set4(timer, expire, CAT2(MOD_, CURMOD), fn_id)
void timer_del(struct timer *);

#endif // GBTCP_TIMER_H
