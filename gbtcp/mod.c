// SPDX-License-Identifier: LGPL-2.1-only

#include "file.h"
#include "gbtcp/socket.h"
#include "global.h"
#include "log.h"
#include "mod.h"
#include "shm.h"

struct mod mods[MODS_MAX] = {
	[GT_MODULE_LOG] = {
		.mod_init = log_mod_init,
	},
	[GT_MODULE_SHM] = {
		.mod_init = shm_mod_init,
	},
	[GT_MODULE_DEV] = {
		.mod_init = dev_mod_init,
	},
	[GT_MODULE_ROUTE] = {
		.mod_init = route_mod_init,
		.mod_deinit = route_mod_deinit,
	},
	[GT_MODULE_ARP] = {
		.mod_init = arp_mod_init,
		.mod_deinit = arp_mod_deinit,
		.mod_timer = arp_mod_timer,
	},
	[GT_MODULE_FILE] = {
		.mod_init = file_mod_init,
	},
	[GT_MODULE_INET] = {
		.mod_init = inet_mod_init,
	},
	[GT_MODULE_SOCKET] = {
		.mod_init = socket_mod_init,
		.mod_deinit = socket_mod_deinit,
		.mod_timer = socket_mod_timer,
	},
//	[MOD_bsd] = {
//		.mod_init = bsd_mod_init,
//		.mod_deinit = bsd_mod_deinit,
//		.mod_timer = bsd_mod_timer,
//	},
};

const char *
gt_module_id2name(int module_id)
{
#define MODULE_ID2NAME(name) case GT_MODULE_##name: return #name;
	switch (module_id) {
	MOD_FOREACH(MODULE_ID2NAME)
	default:
		GT_DIE(0, "Bad module id: %d", module_id);
		return NULL;
	}
#undef MODULE_ID2NAME
}

void*
gt_module_get(int module_id)
{
	return shared->shm_mods[module_id];
}

void*
gt_module_get_safe(int module_id)
{
	if (shared == NULL) {
		return NULL;
	}
	return gt_module_get(module_id);
}

int
gt_module_init(int module_id, size_t size)
{
	struct log_scope *scope;

	assert(shared->shm_mods[module_id] == NULL);
	assert(size >= sizeof(*scope));
	scope = shm_malloc(size);
	if (scope == NULL) {
		return -ENOMEM;
	} else {
		memset(scope, 0, size);
		log_scope_init(scope, gt_module_id2name(module_id));
		shared->shm_mods[module_id] = scope;
		return 0;
	}
}

void
gt_module_deinit(int module_id)
{
	struct log_scope *scope;

	sysctl_del(gt_module_id2name(module_id));
	scope = shared->shm_mods[module_id];
	log_scope_deinit(scope);
	shm_free(scope);
}
