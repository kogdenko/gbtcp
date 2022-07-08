// gpl2
#ifndef GBTCP_MOD_H
#define GBTCP_MOD_H

#include "subr.h"
#include "service.h"

struct mod {
	int (*mod_init)(void);
	void (*mod_deinit)(void);
	void (*mod_timer)(struct timer *, u_char);
};

extern struct mod mods[MODS_MAX];

#define mod_get(id) \
	(shared == NULL ? NULL : shared->shm_mods[id])

#define curmod ((struct GT_CAT2(CURMOD, _mod) *) \
	(shared->shm_mods[GT_CAT2(MOD_, CURMOD)]))

#define curmod_init() \
	mod_init2(GT_CAT2(MOD_, CURMOD), sizeof(struct GT_CAT2(CURMOD, _mod)))

#define curmod_deinit() \
	mod_deinit1(GT_CAT2(MOD_, CURMOD))

const char *mod_name(int);
int mod_init2(int, size_t);
void mod_deinit1(int);

#endif // GBTCP_MOD_H
