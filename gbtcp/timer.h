/* GPL2 license */
#ifndef GBTCP_TIMER_H
#define GBTCP_TIMER_H

#include "subr.h"
#include "list.h"

#define TIMER_RING_SIZE 4096llu
#define TIMER_RING_MASK (TIMER_RING_SIZE - 1llu)
#define TIMER_TIMO (32 * GT_MSEC)
#define TIMER_RING_ID_SHIFT 3
#define TIMER_EXPIRE_MAX (5 * 60 * 60 * GT_SEC) // 5 Hours

struct gt_timer {
	struct dlist tm_list;
	uintptr_t tm_data;
};

typedef void (*gt_timer_f)(struct gt_timer *);

int timer_mod_init(struct log *, void **);
int timer_mod_attach(struct log *, void *);
void timer_mod_deinit(struct log *, void *);
void timer_mod_detach(struct log *);

void gt_timer_mod_check();

void gt_timer_init(struct gt_timer *timer);

int gt_timer_is_running(struct gt_timer *timer);

uint64_t gt_timer_timeout(struct gt_timer *timer);

void gt_timer_set(struct gt_timer *timer, uint64_t expire, gt_timer_f fn);

void gt_timer_del(struct gt_timer *timer);

#endif /* GBTCP_TIMER_H */
