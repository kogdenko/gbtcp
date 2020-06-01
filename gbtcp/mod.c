#include "internals.h"

struct mod {
	int (*m_init)(void **);
	int (*m_attach)(void *);
	int (*m_service_init)(struct service *);
	void (*m_deinit)();
	void (*m_detach)();
	void (*m_service_deinit)(struct service *);
};

#define MOD4(name) { \
	.m_init = name##_mod_init, \
	.m_attach = name##_mod_attach, \
	.m_deinit = name##_mod_deinit, \
	.m_detach = name##_mod_detach, \
},

#define MOD6(name) { \
	.m_init = name##_mod_init, \
	.m_attach = name##_mod_attach, \
	.m_deinit = name##_mod_deinit, \
	.m_detach = name##_mod_detach, \
	.m_service_init = name##_mod_service_init, \
	.m_service_deinit = name##_mod_service_deinit, \
},

struct mod mods[MODS_MAX] = {
	MOD4(sysctl)
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
	     i < ARRAY_SIZE(mods) && mod->m_init != NULL; \
	     ++i, ++mod)

int
foreach_mod_init(struct init_hdr *ih)
{
	int i, rc;
	struct mod *mod;

	rc = 0;
	FOREACH_MOD(i, mod) {
		rc = (*mod->m_init)(ih->ih_mods + i);
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
		rc = (*mod->m_attach)(ih->ih_mods[i]);
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
		if (mod->m_service_init != NULL) {
			rc = (*mod->m_service_init)(s);
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
			(*mod->m_deinit)();
		}
	}
}

void
foreach_mod_detach()
{
	int i;
	struct mod *mod;

	FOREACH_MOD(i, mod) {
		(*mod->m_detach)();
	}
}

void
foreach_mod_service_deinit(struct service *s)
{
	int i;
	struct mod *mod;

	FOREACH_MOD(i, mod) {
		if (mod->m_service_deinit != NULL) {
			(*mod->m_service_deinit)(s);
		}
	}
}
