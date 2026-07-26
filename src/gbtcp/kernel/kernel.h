// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_KERNEL_H
#define GBTCP_KERNEL_H

#include <gbtcp/kernel/subr.h>

struct gt_timer;

int gt_kernel_module_init(u8 module_id, void **puser);
int gt_kernel_module_postinit(void *mod);
void gt_kernel_module_worker_start(void *);
void gt_kernel_module_worker_stop(void);
void gt_kernel_module_timer(struct gt_timer *);
void gt_kernel_module_tx(void);

#endif // GBTCP_KERNEL_H
