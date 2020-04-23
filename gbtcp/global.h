/* GPL2 license */
#ifndef GBTCP_INIT_H
#define GBTCP_INIT_H

#include "subr.h"

extern int gt_global_epoch;
extern int service_inited;
extern struct spinlock gt_global_lock;

#define GT_GLOBAL_LOCK spinlock_lock(&gt_global_lock) 

#define GT_GLOBAL_UNLOCK spinlock_unlock(&gt_global_lock)

int gt_global_mod_init();

void gt_global_mod_deinit(struct log *log);

int service_init();
int controller_init();

void service_deinit(struct log *log);

gt_time_t gt_global_get_time();

void gt_global_set_time();

#endif /* GBTCP_INIT_H */
