// gpl2
#include "internals.h"

struct mod mods[MODS_MAX] = {
	[MOD_log] = {
		.mod_init = log_mod_init,
	},
	[MOD_shm] = {
		.mod_init = shm_mod_init,
	},
	[MOD_route] = {
		.mod_init = route_mod_init,
		.mod_deinit = route_mod_deinit,
	},
	[MOD_arp] = {
		.mod_init = arp_mod_init,
		.mod_deinit = arp_mod_deinit,
		.mod_timer = arp_mod_timer,
	},
	[MOD_file] = {
		.mod_init = file_mod_init,
	},
	[MOD_inet] = {
		.mod_init = inet_mod_init,
	},
	[MOD_tcp] = {
		.mod_init = tcp_mod_init,
		.mod_deinit = tcp_mod_deinit,
		.mod_timer = tcp_mod_timer,
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
	rc = shm_malloc(mod_name(mod_id), (void **)&scope, size);
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

	sysctl_del(mod_name(mod_id));
	scope = shm_ih->ih_mods[mod_id];
	log_scope_deinit(scope);
	shm_free(scope);
}
