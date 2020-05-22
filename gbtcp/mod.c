#include "internals.h"

struct mod {
	int (*m_init)(struct log *, void **);
	int (*m_attach)(struct log *, void *);
	int (*m_service_init)(struct log *, struct service *);
	void (*m_deinit)(struct log *, void *);
	void (*m_detach)(struct log *);
	void (*m_service_deinit)(struct log *, struct service *);
};

#define MOD_BASE(name) \
	.m_init = name##_mod_init, \
	.m_attach = name##_mod_attach, \
	.m_deinit = name##_mod_deinit, \
	.m_detach = name##_mod_detach, \

#define MOD_SERVICE(name) \
	.m_service_init = name##_mod_service_init, \
	.m_service_deinit = name##_mod_service_deinit,


struct mod mods[MOD_COUNT_MAX] = {
	{
		MOD_BASE(sysctl)
	},
	{
		MOD_BASE(log)
	},
	{
		MOD_BASE(subr)
	},
	{
		MOD_BASE(pid)
	},
	{
		MOD_BASE(poll)
	},
	{
		MOD_BASE(epoll)
	},
	{
		MOD_BASE(sys)
	},
	{
		MOD_BASE(mbuf)
	},
	{
		MOD_BASE(htable)
	},
	{
		MOD_BASE(timer)
	},
	{
		MOD_BASE(fd_event)
	},
	{
		MOD_BASE(signal)
	},
	{
		MOD_BASE(dev)
	},
	{
		MOD_BASE(api)
	},
	{
		MOD_BASE(lptree)
	},
	{
		MOD_BASE(route)
	},
	{
		MOD_BASE(arp)
		MOD_SERVICE(arp)
	},
	{
		MOD_BASE(file)
		MOD_SERVICE(file)
	},
	{
		MOD_BASE(inet)
	},
	{
		MOD_BASE(sockbuf)
	},
	{
		MOD_BASE(tcp)
		MOD_SERVICE(tcp)
	},
	{
		MOD_BASE(service)
	},
	{
		MOD_BASE(controller)
	}
};

#define MOD_FOREACH2(i, mod) \
	for (i = 0, mod = mods; \
	     i < ARRAY_SIZE(mods) && mod->m_init != NULL; \
	     ++i, ++mod)

int
mod_foreach_mod_init(struct log *log, struct init_hdr *ih)
{
	int i, rc;
	struct mod *mod;

	rc = 0;
	MOD_FOREACH2(i, mod) {
		rc = (*mod->m_init)(log, ih->ih_mods + i);
		if (rc) {
			return rc;
		}
	}
	return 0;
}

int
mod_foreach_mod_attach(struct log *log, struct init_hdr *ih)
{
	int i, rc;
	struct mod *mod;

	ASSERT(current != NULL);
	rc = 0;
	MOD_FOREACH2(i, mod) {
		rc = (*mod->m_attach)(log, ih->ih_mods[i]);
		if (rc) {
			return rc;
		}
	}
	return 0;
}

int
mod_foreach_mod_service_init(struct log *log, struct service *s)
{
	int i, rc;
	struct mod *mod;

	rc = 0;
	MOD_FOREACH2(i, mod) {
		if (mod->m_service_init != NULL) {
			rc = (*mod->m_service_init)(log, s);
			if (rc) {
				return rc;
			}
		}
	}
	return 0;
}

void
mod_foreach_mod_deinit(struct log *log, struct init_hdr *ih)
{
	int i;
	struct mod *mod;

	if (ih != NULL) {
		MOD_FOREACH2(i, mod) {
			(*mod->m_deinit)(log, ih->ih_mods[i]);
		}
	}
}

void
mod_foreach_mod_detach(struct log *log)
{
	int i;
	struct mod *mod;

	MOD_FOREACH2(i, mod) {
		(*mod->m_detach)(log);
	}
}

void
mod_foreach_mod_service_deinit(struct log *log, struct service *s)
{
	int i;
	struct mod *mod;

	MOD_FOREACH2(i, mod) {
		if (mod->m_service_deinit != NULL) {
			(*mod->m_service_deinit)(log, s);
		}
	}
}
