#ifndef GBTCP_GLOBAL_H
#define GBTCP_GLOBAL_H

#include "subr.h"

extern int gt_global_epoch;
extern int gt_global_inited;
extern struct gt_spinlock gt_global_lock;

#define GT_GLOBAL_LOCK gt_spinlock_lock(&gt_global_lock) 

#define GT_GLOBAL_UNLOCK gt_spinlock_unlock(&gt_global_lock)

int gt_global_mod_init();

void gt_global_mod_deinit(struct gt_log *log);

int gt_global_init();

void gt_global_deinit(struct gt_log *log);

gt_time_t gt_global_get_time();

void gt_global_set_time();

#endif /* GBTCP_GLOBAL_H */
