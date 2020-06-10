#include "internals.h"

struct mod mods[MODS_NUM] = {
	[MOD_log] = {
		.mod_init = log_mod_init,
		.mod_deinit = log_mod_deinit,
	},
	[MOD_mbuf] = {
		.mod_service_init = mbuf_mod_service_init,
	},
	[MOD_timer] = {
		.mod_service_init = timer_mod_service_init,
		.mod_service_deinit = timer_mod_service_deinit,
	},
	[MOD_route] = {
		.mod_init = route_mod_init,
		.mod_deinit = route_mod_deinit,
	},
	[MOD_arp] = {
		.mod_init = arp_mod_init,
		.mod_service_init = arp_mod_service_init,
		.mod_deinit = arp_mod_deinit,
		.mod_service_deinit = arp_mod_service_deinit,
		.mod_timer_handler = arp_mod_timer_handler,
	},
	[MOD_file] = {
		.mod_init = file_mod_init,
		.mod_service_init = file_mod_service_init,
		.mod_deinit = file_mod_deinit,
		.mod_service_deinit = file_mod_service_deinit,
	},
	[MOD_inet] = {
		.mod_init = inet_mod_init,
		.mod_deinit = inet_mod_deinit,
	},
	[MOD_tcp] = {
		.mod_init = tcp_mod_init,
		.mod_service_init = tcp_mod_service_init,
		.mod_deinit = tcp_mod_deinit,
		.mod_service_deinit = tcp_mod_service_deinit,
		.mod_timer_handler = tcp_mod_timer_handler,
	},
};

const char *
mod_name(int mod_id)
{
#define MOD_ID2NAME(name) case MOD_##name: return #name;
	switch (mod_id) {
	MOD_FOREACH(MOD_ID2NAME)
	default:
		assert(!"bad mod_id");
		return NULL;
	}
#undef MOD_ID2NAME
}

int
mod_init2(int mod_id, size_t size)
{
	int rc;
	struct log_scope *scope;

	assert(shm_ih->ih_mods[mod_id] == NULL);
	assert(size >= sizeof(*scope));
	rc = shm_malloc((void **)&scope, size);
	if (rc == 0) {
		memset(scope, 0, size);
		log_scope_init(scope, mod_name(mod_id));
		shm_ih->ih_mods[mod_id] = scope;
	}
	return rc;
}

void
mod_deinit1(int mod_id)
{
	struct log_scope *scope;

	scope = shm_ih->ih_mods[mod_id];
	log_scope_deinit(scope);
	shm_free(scope);
}

void
mod_timer_handler(struct timer *timer, u_char mod_id, u_char fn_id)
{
	assert(mod_id < MODS_NUM);
	assert(mods[mod_id].mod_timer_handler != NULL);
	(*mods[mod_id].mod_timer_handler)(timer, fn_id);
}

int
mods_init()
{
	int i, rc;

	rc = 0;
	for (i = 1; i < MODS_NUM; ++i) {
		if (mods[i].mod_init == NULL) {
			rc = mod_init2(i, sizeof(struct log_scope));
		} else {
			rc = (*mods[i].mod_init)();
		}
		if (rc) {
			break;
		}
	}
	return rc;
}

int
mods_service_init(struct service *s)
{
	int i, rc;

	rc = 0;
	for (i = 1; i < MODS_NUM; ++i) {
		if (mods[i].mod_service_init != NULL) {
			rc = (*mods[i].mod_service_init)(s);
			if (rc) {
				break;
			}
		}
	}
	return 0;
}

void
mods_deinit()
{
	int i;

	for (i = MODS_NUM - 1; i > 0; --i) {
		if (shm_ih->ih_mods[i] != NULL) {
			if (mods[i].mod_deinit == NULL) {
				mod_deinit1(i);
			} else {
				(*mods[i].mod_deinit)();
			}
			shm_ih->ih_mods[i] = NULL;
		}
	}
}

void
mods_service_deinit(struct service *s)
{
	int i;

	for (i = MODS_NUM - 1; i > 0; --i) {
		if (mods[i].mod_service_deinit != NULL) {
			(*mods[i].mod_service_deinit)(s);
		}
	}
}
