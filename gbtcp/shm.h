// gpl2
#ifndef GBTCP_SHM_H
#define GBTCP_SHM_H

#include "service.h"
#include "mbuf.h"

struct shm_hdr {

	struct spinlock msb_lock;
	uintptr_t msb_begin;
	uintptr_t msb_end;
	struct dlist msb_buddy_area[BUDDY_ORDER_MAX - BUDDY_ORDER_MIN + 1];
	struct dlist msb_garbage[GT_SERVICES_MAX];

	uint64_t shm_ns;
	uint64_t shm_hz;
	void *shm_mods[MODS_MAX];
	struct service shm_cpus[N_CPUS];

	struct dlist shm_proc_head;

};

int shm_mod_init();

int shm_init();
int shm_attach();
void shm_deinit();
void shm_detach();

#define shared_ns() READ_ONCE(shared->shm_ns)

#endif // GBTCP_SHM_H
