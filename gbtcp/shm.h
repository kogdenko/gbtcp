// gpl2
#ifndef GBTCP_SHM_H
#define GBTCP_SHM_H

#include "service.h"
#include "mbuf.h"



struct shm_hdr {

	struct spinlock msb_global_lock;

	struct mem_buddy msb_global_buddy;


	struct spinlock msb_percpu_lock;

	struct mem_buddy msb_percpu_buddy[PERCPU_BUF_NUM];


	struct dlist msb_garbage[CPU_NUM];

	uintptr_t msb_addr;
	size_t msb_size;


	u64 msb_nanosecond;
	u64 msb_mhz;


	void *shm_mods[MODS_MAX];
	struct cpu msb_cpus[CPU_NUM];

	struct dlist shm_proc_head;

};

static inline struct cpu *
cpu_get(int i)
{
	assert(i < CPU_NUM);
	return shared->msb_cpus + i;
}

#define CPU_FOREACH(cpu) \
	for (cpu = shared->msb_cpus; cpu < shared->msb_cpus + N_CPUS; ++cpu)


int shm_mod_init();

int shm_init();
int shm_attach();
void shm_deinit();
void shm_detach();

#define nanosecond READ_ONCE(shared->msb_nanosecond)

#endif // GBTCP_SHM_H
