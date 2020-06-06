// gpl2 license
#ifndef GBTCP_TIMER_H
#define GBTCP_TIMER_H

#include "subr.h"
#include "list.h"

#define TIMER_RING_SIZE 4096llu
#define TIMER_RING_MASK (TIMER_RING_SIZE - 1llu)
#define TIMER_TIMEOUT (32 * NANOSECONDS_MILLISECOND)
#define TIMER_RING_ID_SHIFT 3
#define TIMER_EXPIRE_MAX (5 * NANOSECONDS_HOUR)
#define TIMER_NRINGS_MAX (1 << TIMER_RING_ID_SHIFT) 

struct timer {
	struct dlist tm_list;
	uintptr_t tm_data;
};

struct timer_ring {
	uint64_t r_seg_shift;
	uint64_t r_cur;
	int r_ntimers;
	struct dlist r_segs[TIMER_RING_SIZE];
};

typedef void (*timer_f)(struct timer *);

int timer_mod_init();
int timer_mod_service_init(struct service *);
void timer_mod_deinit();
void timer_mod_service_deinit(struct service *);

void check_timers();

void timer_init(struct timer *);
int timer_is_running(struct timer *);
uint64_t timer_timeout(struct timer *);
void timer_set(struct timer *, uint64_t, timer_f);
void timer_del(struct timer *);

#endif // GBTCP_TIMER_H
