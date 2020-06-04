#include "internals.h"

struct mod {
	int (*mod_init)(void **);
	int (*mod_attach)(void *);
	int (*mod_service_init)(struct service *);
	void (*mod_deinit)();
	void (*mod_detach)();
	void (*mod_service_deinit)(struct service *);
};

#define MOD4(name) { \
	.mod_init = name##_mod_init, \
	.mod_attach = name##_mod_attach, \
	.mod_deinit = name##_mod_deinit, \
	.mod_detach = name##_mod_detach, \
},

#define MOD6(name) { \
	.mod_init = name##_mod_init, \
	.mod_attach = name##_mod_attach, \
	.mod_deinit = name##_mod_deinit, \
	.mod_detach = name##_mod_detach, \
	.mod_service_init = name##_mod_service_init, \
	.mod_service_deinit = name##_mod_service_deinit, \
},

struct mod mods[MODS_MAX] = {
	{
		.mod_init = sysctl_mod_init,
		.mod_attach = sysctl_mod_attach,
		.mod_deinit = sysctl_mod_deinit,
		.mod_detach = sysctl_mod_detach,
	},
	MOD4(log)
	MOD4(sys)
	MOD4(subr)
	MOD4(pid)
	MOD4(poll)
	MOD4(epoll)
	MOD4(mbuf)
	MOD4(htable)
	MOD4(timer)
	MOD4(fd_event)
	MOD4(signal)
	MOD4(dev)
	MOD4(api)
	MOD4(lptree)
	MOD4(route)
	MOD6(arp)
	MOD6(file)
	MOD4(inet)
	MOD4(sockbuf)
	MOD6(tcp)
	MOD4(service)
	MOD4(controller)
};

#define FOREACH_MOD(i, mod) \
	for (i = 0, mod = mods; \
	     i < ARRAY_SIZE(mods) && mod->mod_init != NULL; \
	     ++i, ++mod)

int
foreach_mod_init(struct init_hdr *ih)
{
	int i, rc;
	struct mod *mod;

	rc = 0;
	FOREACH_MOD(i, mod) {
		rc = (*mod->mod_init)(ih->ih_mods + i);
		if (rc) {
			return rc;
		}
	}
	return 0;
}

int
foreach_mod_attach(struct init_hdr *ih)
{
	int i, rc;
	struct mod *mod;

	rc = 0;
	FOREACH_MOD(i, mod) {
		rc = (*mod->mod_attach)(ih->ih_mods[i]);
		if (rc) {
			return rc;
		}
	}
	return 0;
}

int
foreach_mod_service_init(struct service *s)
{
	int i, rc;
	struct mod *mod;

	rc = 0;
	FOREACH_MOD(i, mod) {
		if (mod->mod_service_init != NULL) {
			rc = (*mod->mod_service_init)(s);
			if (rc) {
				return rc;
			}
		}
	}
	return 0;
}

void
foreach_mod_deinit(struct init_hdr *ih)
{
	int i;
	struct mod *mod;

	if (ih != NULL) {
		FOREACH_MOD(i, mod) {
			(*mod->mod_deinit)();
		}
	}
}

void
foreach_mod_detach()
{
	int i;
	struct mod *mod;

	FOREACH_MOD(i, mod) {
		(*mod->mod_detach)();
	}
}

void
foreach_mod_service_deinit(struct service *s)
{
	int i;
	struct mod *mod;

	FOREACH_MOD(i, mod) {
		if (mod->mod_service_deinit != NULL) {
			(*mod->mod_service_deinit)(s);
		}
	}
}
