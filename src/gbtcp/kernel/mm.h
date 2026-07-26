// SPDX-License-Identifier: GPL-2.0

#ifndef GBTCP_MM_H
#define GBTCP_MM_H

#include <gbtcp/kernel/list.h>
#include <gbtcp/kernel/subr.h>

#define GT_SLAB_ORDER_LOW 6
#define GT_SLAB_SIZE_LOW (1Ul << GT_SLAB_ORDER_LOW)

#define GT_PAGE_ORDER 21 // 2Mb
#define GT_PAGE_SIZE (1Ul << GT_PAGE_ORDER)

#define GT_SLAB_ORDER_HIGH GT_PAGE_ORDER
#define GT_SLAB_SIZE_HIGH GT_PAGE_SIZE

#define GT_MHEAP_N_PAGES_MAX 4096 // 8Gb

#define GT_MF_ZERO (1 << 0)
#define GT_MF_NOFAIL (1 << 1)

#define GT_N_MCACHES_MAX_ORDER 14
#define GT_N_MCACHES_MAX ((1 << GT_N_MCACHES_MAX_ORDER) - 1)
#define GT_MCACHE_ID_INVALID GT_N_MCACHES_MAX

struct gt_page {
	u16 pg_cache_id : GT_N_MCACHES_MAX_ORDER;
	u8 pg_allocated : 1;
	u8 pg_last : 1;
};

_Static_assert(sizeof(struct gt_page) == sizeof(u16),
	       "page struct must be 2 bytes");

struct gt_mheap_hdr {
	u8 *mhh_base_addr;
	unsigned long mhh_size;

	struct spinlock mhh_lock;
	int mhh_n_pages;
	int mhh_free_pages;
	u16 mhh_n_caches;
	u8 *mhh_mem;

	// Unused gap between the header and the first page-aligned page
	u8 *mhh_gap;

	struct gt_page mhh_pages[GT_MHEAP_N_PAGES_MAX];

	u64 mhh_cnt_oom;
};

struct gt_mheap {
	struct gt_mheap_hdr *mhp_hdr;
	int mhp_fd;
};

struct gt_mcache {
	struct gt_mheap_hdr *mch_heap;
	u16 mch_id;
	struct gt_dlist mch_available[GT_SLAB_ORDER_HIGH + 1];
	u32 mch_available_size[GT_SLAB_ORDER_HIGH + 1];
	u32 mch_n_slab_pages;

	unsigned long mch_usage;
	unsigned long mch_n_mbufs;

	unsigned int mch_n_pages;
};

struct gt_mbuf_header {
	u16 mbh_magic;
	u8 mbh_status;
	u8 mbh_order;
	u8 mbh_root_order;
	u8 mbh_pad;
	u16 mbh_cache_id;
};

_Static_assert(sizeof(struct gt_mbuf_header) == sizeof(u64),
	       "mbuf header must be 8 bytes");

typedef int (*gt_mbuf_f)(struct gt_mbuf_header *mh, void *udata);

int gt_mbuf_foreach(void *ptr, u8 order, gt_mbuf_f fn, void *udata);

int gt_mheap_create(struct gt_mheap *heap, const char *path, unsigned long size,
		    unsigned long hdr_size, u16 n_caches);

int gt_mheap_attach(struct gt_mheap *heap, const char *path);

void gt_mheap_detach(struct gt_mheap *heap);

void gt_mheap_free_cache(struct gt_mheap_hdr *heap, u16 cache_id);

void gt_mcache_init(struct gt_mcache *cache, struct gt_mheap_hdr *heap, u16 id);
void gt_mcache_deinit(struct gt_mcache *cache);

void *gt_malloc(struct gt_mcache *cache, unsigned long size, u8 flags);
void *gt_malloc_align(struct gt_mcache *cache, unsigned long size,
		      unsigned long align, u8 flags);
void *gt_realloc(struct gt_mcache *cache, void *ptr, unsigned long size,
		 u8 flags);
void gt_free_internal(struct gt_mcache *cache, void *ptr);
#define gt_free(cache, p) \
	({ \
		gt_free_internal(cache, p); \
		p = NULL; \
	})

// Allocation front-end for code shared between service-threads and utility
// tools (api, cli, protobuf): a worker allocates from its shared-heap cache,
// a utility tool (which does not touch shared memory at all) from the system
// heap. Pure vtable: which backend is behind it is fixed at init time (see
// gt_kallocator_init()/gt_uallocator below), not re-decided on every call.
struct gt_allocator {
	void *(*alc_malloc)(struct gt_allocator *alc, unsigned long size,
			    u8 flags);
	void *(*alc_malloc_align)(struct gt_allocator *alc, unsigned long size,
				  unsigned long align, u8 flags);
	void (*alc_free)(struct gt_allocator *alc, void *ptr);
};

// The mcache-backed allocator: a gt_allocator whose ops dispatch into
// alc_mm_cache. Thread-local (gt_thread.trd_kallocator), bound to the
// attached service's cache in service_attach() — not shm-resident, since its
// function pointers are only valid in the process that set them (see the
// comment on gt_thread.trd_kallocator).
struct gt_kallocator {
	struct gt_allocator alc;
	struct gt_mcache *alc_mm_cache;
};

void gt_kallocator_init(struct gt_kallocator *kalc, struct gt_mcache *cache);

// The process-wide sys_malloc()/sys_free()-backed allocator, used while
// current == NULL (utility tools never attach to a service).
extern struct gt_allocator gt_uallocator;

// The calling thread's allocator: the attached service's cache-backed one
// (gt_current_thread.trd_kallocator.alc), or gt_uallocator while
// current == NULL.
struct gt_allocator *gt_get_allocator(void);

void *gt_a_malloc(struct gt_allocator *alc, unsigned long size, u8 flags);
void *gt_a_malloc_align(struct gt_allocator *alc, unsigned long size,
			unsigned long align, u8 flags);
void gt_a_free_internal(struct gt_allocator *alc, void *ptr);
#define gt_a_free(alc, p) \
	({ \
		gt_a_free_internal(alc, p); \
		p = NULL; \
	})

#endif // GBTCP_MM_H
