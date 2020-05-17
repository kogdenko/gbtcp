// GPL2 license
#ifndef GBTCP_TIMER_H
#define GBTCP_TIMER_H

#include "subr.h"
#include "list.h"

#define TIMER_RING_SIZE 4096llu
#define TIMER_RING_MASK (TIMER_RING_SIZE - 1llu)
#define TIMER_TIMO (32 * NANOSECONDS_MILLISECOND)
#define TIMER_RING_ID_SHIFT 3
#define TIMER_EXPIRE_MAX (5 * NANOSECONDS_HOUR)

struct timer {
	struct dlist tm_list;
	uintptr_t tm_data;
};

typedef void (*timer_f)(struct timer *);

int timer_mod_init(struct log *, void **);
int timer_mod_attach(struct log *, void *);
void timer_mod_deinit(struct log *, void *);
void timer_mod_detach(struct log *);

void timer_mod_check();

void timer_init(struct timer *);
int timer_is_running(struct timer *);
uint64_t timer_timeout(struct timer *);
void timer_set(struct timer *, uint64_t, timer_f);
void timer_del(struct timer *);

#endif // GBTCP_TIMER_H
