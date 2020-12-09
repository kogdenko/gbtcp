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
	struct log_scope *scope;

	assert(shared->shm_mods[mod_id] == NULL);
	assert(size >= sizeof(*scope));
	scope = shm_malloc(size);
	if (scope == NULL) {
		return -ENOMEM;
	} else {
		memset(scope, 0, size);
		log_scope_init(scope, mod_name(mod_id));
		shared->shm_mods[mod_id] = scope;
		return 0;
	}
}

void
mod_deinit1(int mod_id)
{
	struct log_scope *scope;

	sysctl_del(mod_name(mod_id));
	scope = shared->shm_mods[mod_id];
	log_scope_deinit(scope);
	shm_free(scope);
}

int
init_modules()
{
	int i, rc;

	for (i = MOD_FIRST; i < MODS_MAX; ++i) {
		if (mods[i].mod_init == NULL) {
			rc = mod_init2(i, sizeof(struct log_scope));
		} else {
			rc = (*mods[i].mod_init)();
		}
		if (rc) {
			return rc;
		}
	}	
	return 0;
}
