// gpl2 license
#ifndef GBTCP_MOD_H
#define GBTCP_MOD_H

#include "subr.h"
#include "service.h"

struct mod {
	int (*mod_init)();
	int (*mod_service_init)(struct service *);
	void (*mod_deinit)();
	void (*mod_service_deinit)(struct service *);
	void (*mod_timer_handler)(struct timer *, u_char);
};

extern struct mod mods[MODS_NUM];

#define mod_get(id) \
	(shm_ih == NULL ? NULL : shm_ih->ih_mods[id])

#define curmod ((struct CAT2(CURMOD, _mod) *) \
	(shm_ih->ih_mods[CAT2(MOD_, CURMOD)]))

#define curmod_init() \
	mod_init2(CAT2(MOD_, CURMOD), sizeof(struct CAT2(CURMOD, _mod)))

#define curmod_deinit() \
	mod_deinit1(CAT2(MOD_, CURMOD))

const char *mod_name(int);
int mod_init2(int, size_t);
void mod_deinit1();

#endif // GBTCP_MOD_H
