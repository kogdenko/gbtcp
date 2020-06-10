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

#if 0
#define curmod3(_, X, x) ((struct x *)(shm_ih->ih_mods[X]))
#define curmod_cat(X, x, name) curmod3(~, X##name, name##x)
#define curmod_med(X, x, name) curmod_cat(X, x, name)
#define curmod curmod_med(MOD_, _mod, CURMOD)
#else
#define curmod ((struct CAT2(CURMOD, _mod) *) \
	(shm_ih->ih_mods[CAT2(MOD_, CURMOD)]))
#endif

#define curmod_init() \
	mod_init2(CAT2(MOD_, CURMOD), sizeof(struct CAT2(CURMOD, _mod)))

#define curmod_deinit() \
	mod_deinit1(CAT2(MOD_, CURMOD))

const char *mod_name(int);
int mod_init2(int, size_t);
void mod_deinit1();
void mod_timer_handler(struct timer *, u_char, u_char);

int mods_init();
int mods_service_init(struct service *);
void mods_deinit();
void mods_service_deinit(struct service *);

#endif // GBTCP_MOD_H
