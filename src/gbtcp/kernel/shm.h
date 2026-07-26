// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_SHM_H
#define GBTCP_SHM_H

#include <gbtcp/kernel/worker.h>

#define shared_ns() READ_ONCE(shared->shm_ns)

#define GT_WORKER_FOREACH(wrk) \
	for ((wrk) = shared->shm_services; \
	     (wrk) != \
	     shared->shm_services + GT_ARRAY_SIZE(shared->shm_services); \
	     (wrk)++)

struct shm_hdr {
	// Single shared heap; per-service caches (service.p_mm_cache) allocate
	// from it. Must be the FIRST field: gt_mheap_create()/attach() place
	// the heap at offset 0 of the mapping, so the mapping base is both the
	// heap and this header. The mapping identity (base address, size) lives
	// inside the heap itself.
	struct gt_mheap_hdr shm_heap;

	// Guards service-slot claim/release (service_claim_slot()); shared by
	// every process attached to the heap.
	struct spinlock shm_lock;

	uint64_t shm_ns;
	uint64_t shm_hz;
	int shm_rss_table_size;
	struct gt_main_module shm_mods[GT_MODULE_MAX];
	// Loaded main modules, in load order; see struct gt_main_module.mmod_list.
	struct gt_dlist module_head;
	struct service shm_services[GT_SERVICES_MAX];
	int shm_rss_table[GT_RSS_NQ_MAX];

	char *module_directory;
};

int shm_init(void);
int shm_attach(void);
void shm_deinit(void);
void shm_detach(void);

void shm_lock(void);
void shm_unlock(void);

// Active cache: the running worker's cache, or the controller cache before a
// worker is attached. Allocate with gt_malloc(shm_cache(), ...).
struct gt_mcache *shm_cache(void);

// Kernel (shared-memory) allocation, for code that only ever runs attached
// to a service — e.g. the CLI command tree, built once by the controller.
// Unlike gt_get_allocator() (which also serves unattached utility tools via
// sys_malloc), these always go through shm_cache(), so a caller that isn't
// actually attached asserts instead of silently falling back to the system
// heap.
void *gt_kmalloc(unsigned long size, u8 flags);
void *gt_kmalloc_align(unsigned long size, unsigned long align, u8 flags);
void *gt_kmemdup(const void *ptr, size_t size);
char *gt_kstrdup(const char *s);
char *gt_kstrndup(const char *s, size_t n);
void gt_kfree_internal(void *ptr);
#define gt_kfree(p) \
	({ \
		gt_kfree_internal(p); \
		p = NULL; \
	})

// The attached service's allocator, for passing to the generic gt_vec_*
// macros (vector.h) from code that — like gt_kmalloc() et al above — only
// ever runs attached. Asserts instead of silently falling back to
// sys_malloc, unlike gt_get_allocator().
struct gt_allocator *gt_get_kallocator(void);

#define gt_kvec_add(v, e) gt_vec_add(v, gt_get_kallocator(), e)
#define gt_kvec_free(v) gt_vec_free(v, gt_get_kallocator())

#endif // GBTCP_SHM_H
