// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_SHM_H
#define GBTCP_SHM_H

#include "service.h"

#define shared_ns() READ_ONCE(shared->shm_ns)

#define SERVICE_FOREACH(s) \
	for ((s) = shared->shm_services; \
	     (s) != shared->shm_services + ARRAY_SIZE(shared->shm_services); \
	     (s)++)

struct shm_hdr {
	uintptr_t shm_base_addr;
	struct spinlock shm_lock;
	struct dlist shm_heap;
	size_t shm_size;
	int shm_n_sb_pages;
	int shm_n_pages;
	uint64_t shm_ns;
	uint64_t shm_hz;
	int shm_rss_table_size;
	void *shm_mods[MODS_MAX];
	struct service shm_services[GT_SERVICES_MAX];
	int shm_rss_table[GT_RSS_NQ_MAX];
	struct dlist shm_garbage_head[GT_SERVICES_MAX];
	bitset_word_t *shm_pages;
};

int shm_mod_init(void);

int shm_init(void);
int shm_attach(void);
void shm_deinit(void);
void shm_detach(void);

void shm_lock(void);
void shm_unlock(void);

void shm_garbage_push(struct service *);
void shm_garbage_pop(struct dlist *, u_char);

void *shm_malloc(size_t);
void *shm_realloc(void *, size_t);
void shm_free(void *);
int shm_alloc_pages(void **, size_t, size_t);
void shm_free_pages(void *, size_t);

#endif // GBTCP_SHM_H
