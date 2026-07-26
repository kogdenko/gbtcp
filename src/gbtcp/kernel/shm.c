// SPDX-License-Identifier: LGPL-2.1-only

#include <stddef.h>

#include <gbtcp/kernel/shm.h>

#define SHM_PATH "/var/run/gbtcp.shm"

#define SHM_SIZE (256 * 1024 * 1024) // 256Mb

struct shm_hdr *shared;

// Process-local heap state (fd); the shared allocator state is
// shared->shm_heap.
static struct gt_mheap shm_heap = { .mhp_fd = -1 };

// gt_mheap_create()/attach() return the mapping base as the heap header; it
// doubles as the shm header only if the heap header sits at its very
// beginning.
_Static_assert(offsetof(struct shm_hdr, shm_heap) == 0,
	       "shm_heap must be the first field of shm_hdr");

struct gt_mcache *
shm_cache(void)
{
	// Every service thread claims its slot before its first allocation:
	// workers in service_attach(), the controller by attaching right
	// after shm_init().
	assert(current != NULL);
	return &current->p_mm_cache;
}

void *
gt_kmalloc(unsigned long size, u8 flags)
{
	return gt_malloc(shm_cache(), size, flags);
}

void *
gt_kmalloc_align(unsigned long size, unsigned long align, u8 flags)
{
	return gt_malloc_align(shm_cache(), size, align, flags);
}

void *
gt_kmemdup(const void *ptr, size_t size)
{
	void *cp;

	// gt_malloc() only guarantees 4-byte alignment; duplicated structs
	// need natural alignment (see gt_memdup(), subr.c).
	cp = gt_kmalloc_align(size, sizeof(void *), 0);
	if (cp != NULL) {
		memcpy(cp, ptr, size);
	}
	return cp;
}

char *
gt_kstrdup(const char *s)
{
	return gt_kmemdup(s, strlen(s) + 1);
}

char *
gt_kstrndup(const char *s, size_t n)
{
	size_t len;
	char *cp;

	len = strnlen(s, n);
	cp = gt_kmalloc_align(len + 1, sizeof(void *), 0);
	if (cp != NULL) {
		memcpy(cp, s, len);
		cp[len] = '\0';
	}
	return cp;
}

void
gt_kfree_internal(void *ptr)
{
	gt_free_internal(shm_cache(), ptr);
}

struct gt_allocator *
gt_get_kallocator(void)
{
	// Mirrors shm_cache()'s assert: callers only ever run attached.
	assert(current != NULL);
	return &gt_current_thread.trd_kallocator.alc;
}

// The calling thread's allocator: the attached service's cache-backed one
// (gt_current_thread.trd_kallocator, bound to current->p_mm_cache in
// service_attach()), or gt_uallocator (mm.c) — utility tools (gbtcpctl,
// gbtcp-netstat) never attach and never touch shared memory, so their
// api/cli/protobuf allocations come from the system heap.
struct gt_allocator *
gt_get_allocator(void)
{
	if (current != NULL) {
		return &gt_current_thread.trd_kallocator.alc;
	}
	return &gt_uallocator;
}

int
shm_init(void)
{
	int i, rc;

	// The heap is published (rename) only fully initialized, so a failed
	// create leaves no file behind and attachers never see a partial heap.
	rc = gt_mheap_create(&shm_heap, SHM_PATH, SHM_SIZE, sizeof(*shared),
			     GT_SERVICES_MAX);
	if (rc) {
		return rc;
	}
	shared = (struct shm_hdr *)shm_heap.mhp_hdr;

	spinlock_init(&shared->shm_lock);
	shared->shm_ns = nanoseconds;
	gt_dlist_init(&shared->module_head);

	// One cache per service; each attaching thread binds its own
	// thread-local allocator to it in service_attach().
	for (i = 0; i < GT_SERVICES_MAX; ++i) {
		gt_mcache_init(&shared->shm_services[i].p_mm_cache,
			       &shared->shm_heap, i);
	}

	return 0;
}

int
shm_attach(void)
{
	int rc;

	// Already created or attached in this process (e.g. the controller's
	// own service thread attaching after shm_init()).
	if (shared != NULL) {
		return 0;
	}

	rc = gt_mheap_attach(&shm_heap, SHM_PATH);
	if (rc == 0) {
		shared = (struct shm_hdr *)shm_heap.mhp_hdr;
	}
	return rc;
}

void
shm_detach(void)
{
	shared = NULL;
	gt_mheap_detach(&shm_heap);
}

void
shm_deinit(void)
{
	shm_detach();
	sys_unlink(SHM_PATH);
}

void
shm_lock(void)
{
	spinlock_lock(&shared->shm_lock);
}

void
shm_unlock(void)
{
	spinlock_unlock(&shared->shm_lock);
}
