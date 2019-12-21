// gpl2
#ifndef GBTCP_MOD_H
#define GBTCP_MOD_H

#include "subr.h"
#include "service.h"

struct mod {
	int (*mod_init)();
	void (*mod_deinit)();
	void (*mod_timer)(struct timer *, u_char);
};

extern struct mod mods[MODS_MAX];

#define mod_get(id) \
	(shared == NULL ? NULL : shared->shm_mods[id])

#define curmod ((struct CAT2(CURMOD, _mod) *) \
	(shared->shm_mods[CAT2(MOD_, CURMOD)]))

#define curmod_init() \
	mod_init2(CAT2(MOD_, CURMOD), sizeof(struct CAT2(CURMOD, _mod)))

#define curmod_deinit() \
	mod_deinit1(CAT2(MOD_, CURMOD))

const char *mod_name(int);
int mod_init2(int, size_t);
void mod_deinit1();

#endif // GBTCP_MOD_H
