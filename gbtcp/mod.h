// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_MOD_H
#define GBTCP_MOD_H

#include "global.h"
//#include "subr.h"
//#include "service.h"

struct timer;

struct mod {
	int (*mod_init)(void);
	void (*mod_deinit)(void);
	void (*mod_timer)(struct timer *, u_char);
};

extern struct mod mods[MODS_MAX];

const char *gt_module_id2name(int);
void *gt_module_get(int);
void *gt_module_get_safe(int);
int gt_module_init(int, size_t);
void gt_module_deinit(int);

#endif // GBTCP_MOD_H
