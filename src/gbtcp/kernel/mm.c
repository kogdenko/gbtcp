// SPDX-License-Identifier: GPL-2.0

#include <gbtcp/kernel/mm.h>
#include <gbtcp/kernel/log.h>
#include <gbtcp/kernel/sys.h>

#define GT_MBUF_MAGIC 0xfeed

#define GT_MBUF_AVAILABLE 0
#define GT_MBUF_ALLOCATED 1
// Duplicate header for allocating aligned memory
#define GT_MBUF_PADDING 2

// Mapping-address hint for the file-backed heap.
#ifdef __linux__
#ifdef __i386__
// On x86 32-bit systems, allocate shared memory outside the area where the
// process stores its heap/stack, to avoid shared memory attach failures.
#define GT_MHEAP_HINT ((void *)0x80000000)
#else // __i386__
#define GT_MHEAP_HINT NULL
#endif // __i386__
#else // __linux__
#define GT_MHEAP_HINT NULL
#endif // __linux__

#define GT_IS_PAGE_ALIGNED(ptr) \
	GT_IS_ALIGNED((unsigned long)(ptr), GT_PAGE_SIZE)

#define GT_MHEAP_LOCK spinlock_lock(&heap->mhh_lock)
#define GT_MHEAP_UNLOCK spinlock_unlock(&heap->mhh_lock)

struct gt_mbuf {
	struct gt_mbuf_header mb_hdr;
	struct gt_dlist mb_list;
};

static int gt_mheap_free(struct gt_mheap_hdr *heap, void *ptr);

static inline struct gt_mbuf *
gt_mbuf_get(void *ptr)
{
	u32 size;
	struct gt_mbuf_header *mh;
	struct gt_mbuf *m;

	mh = (struct gt_mbuf_header *)((u8 *)ptr - sizeof(*mh));
	assert(mh->mbh_magic == GT_MBUF_MAGIC);

	size = GT_POW2(mh->mbh_order);
	m = (struct gt_mbuf *)GT_PTR_ALIGN_DOWN(mh, size);
	assert(&m->mb_hdr == mh || mh->mbh_status == GT_MBUF_PADDING);
	assert(m->mb_hdr.mbh_magic == GT_MBUF_MAGIC);
	assert(m->mb_hdr.mbh_order == mh->mbh_order);
	assert(m->mb_hdr.mbh_status == GT_MBUF_ALLOCATED);
	return m;
}

static void
gt_mbuf_init(struct gt_mbuf *m, int order, int root_order, u16 cache_id)
{
	assert(order <= root_order);
	m->mb_hdr.mbh_magic = GT_MBUF_MAGIC;
	m->mb_hdr.mbh_order = order;
	m->mb_hdr.mbh_root_order = root_order;
	m->mb_hdr.mbh_status = GT_MBUF_ALLOCATED;
	m->mb_hdr.mbh_cache_id = cache_id;
}

static void
gt_mbuf_free(struct gt_mcache *cache, struct gt_mbuf *m)
{
	assert(m->mb_hdr.mbh_status == GT_MBUF_ALLOCATED);
	GT_DLIST_INSERT_HEAD(cache->mch_available + m->mb_hdr.mbh_order, m,
			     mb_list);
	cache->mch_available_size[m->mb_hdr.mbh_order]++;
	m->mb_hdr.mbh_status = GT_MBUF_AVAILABLE;
}

static void
gt_mbuf_alloc(struct gt_mcache *cache, struct gt_mbuf *m)
{
	assert(m->mb_hdr.mbh_status == GT_MBUF_AVAILABLE);
	assert(cache->mch_available_size[m->mb_hdr.mbh_order] > 0);

	GT_DLIST_REMOVE(m, mb_list);
	cache->mch_available_size[m->mb_hdr.mbh_order]--;
	m->mb_hdr.mbh_status = GT_MBUF_ALLOCATED;
}

int
gt_mbuf_foreach(void *ptr, u8 order, gt_mbuf_f fn, void *udata)
{
	int i, rc, size;
	struct gt_mbuf_header *mh;

	if (order < GT_SLAB_ORDER_LOW) {
		return 0;
	}

	mh = ptr;
	if (mh->mbh_magic != GT_MBUF_MAGIC) {
		return 0;
	}

	if (mh->mbh_order == order) {
		if (mh->mbh_status == GT_MBUF_ALLOCATED) {
			rc = (*fn)(mh, udata);
			return rc;
		}
	} else if (mh->mbh_order < order) {
		size = GT_POW2(order - 1);
		for (i = 0; i < 2; ++i) {
			rc = gt_mbuf_foreach((u8 *)ptr + i * size, order - 1,
					     fn, udata);
			if (rc) {
				return rc;
			}
		}
	}

	return 0;
}

// Buddy allocator
// When a buddy allocator starts, its entire memory is aligned to a large power-of-two address.
// Every split creates smaller blocks whose addresses remain aligned to their size
static void *
gt_buddy_split(struct gt_mcache *cache, struct gt_mbuf *chunk, int order)
{
	u32 size;
	struct gt_mbuf *m, *buddy;

	assert(chunk->mb_hdr.mbh_order >= order);

	m = chunk;

	while (m->mb_hdr.mbh_order > order) {
		m->mb_hdr.mbh_order--;
		size = GT_POW2(m->mb_hdr.mbh_order);

		buddy = (struct gt_mbuf *)((u8 *)m + size);
		gt_mbuf_init(buddy, m->mb_hdr.mbh_order,
			     m->mb_hdr.mbh_root_order, m->mb_hdr.mbh_cache_id);
		gt_mbuf_free(cache, buddy);
	}

	return (void *)((u8 *)m + sizeof(struct gt_mbuf_header));
}

static void
gt_buddy_merge(struct gt_mcache *cache, struct gt_mbuf *m)
{
	u32 size;
	struct gt_mbuf *buddy;

	while (m->mb_hdr.mbh_order < m->mb_hdr.mbh_root_order) {
		size = GT_POW2(m->mb_hdr.mbh_order);

		// left buddy when it is aligned to the parent
		if (GT_IS_ALIGNED((uintptr_t)m, size << 1)) {
			buddy = (struct gt_mbuf *)((u8 *)m + size);
		} else {
			buddy = (struct gt_mbuf *)((u8 *)m - size);
		}

		assert(buddy->mb_hdr.mbh_magic == GT_MBUF_MAGIC);

		if (buddy->mb_hdr.mbh_status == GT_MBUF_AVAILABLE &&
		    buddy->mb_hdr.mbh_order == m->mb_hdr.mbh_order) {
			gt_mbuf_alloc(cache, buddy);
		} else {
			break;
		}

		if (m > buddy) {
			m = buddy;
		}
		m->mb_hdr.mbh_order++;
	}

	// A fully-merged page is unused. Release it back to the global heap, but
	// keep one page cached to avoid frequent global page (de)allocation.
	if (m->mb_hdr.mbh_order == GT_SLAB_ORDER_HIGH &&
	    cache->mch_available_size[GT_SLAB_ORDER_HIGH] >= 1) {
		cache->mch_n_slab_pages--;
		gt_mheap_free(cache->mch_heap, m);
	} else {
		gt_mbuf_free(cache, m);
	}
}

static void *
gt_slab_cache_alloc(struct gt_mcache *cache, int order)
{
	int i;
	struct gt_dlist *head;
	struct gt_mbuf *m;

	for (i = order; i <= GT_SLAB_ORDER_HIGH; ++i) {
		head = cache->mch_available + i;
		if (!gt_dlist_is_empty(head)) {
			m = GT_DLIST_FIRST(head, struct gt_mbuf, mb_list);
			gt_mbuf_alloc(cache, m);
			return gt_buddy_split(cache, m, order);
		}
	}

	return NULL;
}

static void
gt_mheap_set_free_pages(struct gt_mheap_hdr *heap, int free_pages)
{
	assert(free_pages >= 0);
	assert(free_pages <= heap->mhh_n_pages);

	heap->mhh_free_pages = free_pages;
}

static int
gt_mheap_get_pageindex(struct gt_mheap_hdr *heap, void *ptr)
{
	int pageindex;

	pageindex = ((u8 *)ptr - heap->mhh_mem) >> GT_PAGE_ORDER;
	assert(pageindex >= 0 && pageindex < heap->mhh_n_pages);
	return pageindex;
}

static void
gt_mheap_init(struct gt_mheap_hdr *heap, void *mem, int n_pages, u16 n_caches)
{
	int i;

	assert(n_pages <= GT_MHEAP_N_PAGES_MAX);
	assert(n_caches <= GT_N_MCACHES_MAX);
	assert(GT_IS_PAGE_ALIGNED(mem));

	spinlock_init(&heap->mhh_lock);

	heap->mhh_mem = mem;
	heap->mhh_n_pages = n_pages;
	heap->mhh_n_caches = n_caches;
	heap->mhh_cnt_oom = 0;

	gt_mheap_set_free_pages(heap, n_pages);

	memset(heap->mhh_pages, 0, sizeof(heap->mhh_pages));
	for (i = 0; i < n_pages; ++i) {
		heap->mhh_pages[i].pg_cache_id = GT_MCACHE_ID_INVALID;
	}
}

static void *
gt_mheap_alloc_pages(struct gt_mheap_hdr *heap, int n, u16 owner, u8 flags)
{
	int i, j, m, I, N;
	void *ptr;
	struct gt_page *page;

	N = INT_MAX;

	GT_MHEAP_LOCK;

	for (i = 0; i < heap->mhh_n_pages - n; i += m + 1) {
		for (j = i; j < heap->mhh_n_pages; ++j) {
			if (heap->mhh_pages[j].pg_allocated) {
				break;
			}
		}

		m = j - i;

		if (m >= n && m < N) {
			N = m;
			I = i;
			if (m == n) {
				break;
			}
		}
	}

	if (N == INT_MAX) {
		heap->mhh_cnt_oom++;
		GT_MHEAP_UNLOCK;
		if (GT_FLAG_ISSET(flags, GT_MF_NOFAIL)) {
			GT_DIE_NOMEM;
		}
		return NULL;
	}

	for (i = I; i < I + n; ++i) {
		page = heap->mhh_pages + i;

		page->pg_cache_id = owner;
		page->pg_allocated = 1;
		page->pg_last = (i == I + n - 1);
	}

	gt_mheap_set_free_pages(heap, heap->mhh_free_pages - n);

	GT_MHEAP_UNLOCK;

	ptr = heap->mhh_mem + (I << GT_PAGE_ORDER);
	return ptr;
}

static int
gt_mheap_free(struct gt_mheap_hdr *heap, void *ptr)
{
	int i, n, pageindex, eof;
	struct gt_page *page;

	pageindex = gt_mheap_get_pageindex(heap, ptr);

	GT_MHEAP_LOCK;

	n = 0;
	eof = 0;
	for (i = pageindex; i < heap->mhh_n_pages; ++i) {
		assert(heap->mhh_pages[i].pg_allocated);
		eof = heap->mhh_pages[i].pg_last;
		page = heap->mhh_pages + i;
		page->pg_allocated = 0;
		page->pg_last = 0;
		page->pg_cache_id = GT_MCACHE_ID_INVALID;
		n++;
		if (eof) {
			break;
		}
	}

	gt_mheap_set_free_pages(heap, heap->mhh_free_pages + n);

	GT_MHEAP_UNLOCK;

	assert(eof);

	return n;
}

int
gt_mheap_create(struct gt_mheap *heap, const char *path, unsigned long size,
		unsigned long hdr_size, u16 n_caches)
{
	int rc, fd, n_pages;
	u8 *base, *mem, *end;
	char tmp_path[PATH_MAX];
	struct gt_mheap_hdr *hdr;

	assert(hdr_size >= sizeof(struct gt_mheap_hdr));

	heap->mhp_hdr = NULL;
	heap->mhp_fd = -1;

	// Build under a temporary name and rename() into place once the heap
	// is fully initialized, so attachers never observe a half-built heap:
	// they see either no file or a valid one.
	rc = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
	if (rc < 0 || rc >= (int)sizeof(tmp_path)) {
		return -ENAMETOOLONG;
	}

	size = GT_ROUND_UP(size, GT_SYS_PAGE_SIZE);

	rc = sys_open(tmp_path, O_CREAT | O_RDWR, 0666);
	if (rc < 0) {
		return rc;
	}
	fd = rc;

	rc = sys_ftruncate(fd, size);
	if (rc) {
		goto err;
	}
	rc = sys_mmap((void **)&hdr, GT_MHEAP_HINT, size,
		      PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (rc) {
		goto err;
	}

	base = (u8 *)hdr;
	mem = (u8 *)GT_ROUND_UP((unsigned long)base + hdr_size, GT_PAGE_SIZE);
	end = base + size;
	assert(end > mem);
	n_pages = (end - mem) / GT_PAGE_SIZE;

	memset(hdr, 0, hdr_size);

	gt_mheap_init(hdr, (void *)mem, n_pages, n_caches);
	hdr->mhh_base_addr = base;
	hdr->mhh_size = size;
	hdr->mhh_gap = (u8 *)(base + hdr_size);

	rc = sys_rename(tmp_path, path);
	if (rc < 0) {
		sys_munmap(hdr, size);
		goto err;
	}

	heap->mhp_hdr = hdr;
	heap->mhp_fd = fd;
	return 0;

err:
	sys_close(fd);
	sys_unlink(tmp_path);
	return rc;
}

int
gt_mheap_attach(struct gt_mheap *heap, const char *path)
{
	int rc, fd;
	unsigned long size;
	void *addr, *tmp;
	struct gt_mheap_hdr *hdr;

	heap->mhp_hdr = NULL;
	heap->mhp_fd = -1;

	rc = sys_open(path, O_RDWR, 0666);
	if (rc < 0) {
		return rc;
	}
	fd = rc;

	// Bootstrap: map just the heap header to learn where the full mapping
	// must live, then remap the whole heap at that address.
	rc = sys_mmap(&tmp, NULL, sizeof(*hdr), PROT_READ, MAP_SHARED, fd, 0);
	if (rc) {
		goto err;
	}
	hdr = tmp;
	addr = hdr->mhh_base_addr;
	size = hdr->mhh_size;
	sys_munmap(tmp, sizeof(*hdr));

	rc = sys_mmap(&tmp, addr, size, PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_FIXED, fd, 0);
	if (rc) {
		goto err;
	}
	assert(tmp == addr);

	heap->mhp_hdr = tmp;
	heap->mhp_fd = fd;
	return 0;
err:
	sys_close(fd);
	return rc;
}

void
gt_mheap_detach(struct gt_mheap *heap)
{
	struct gt_mheap_hdr *hdr;

	hdr = heap->mhp_hdr;
	if (hdr != NULL) {
		assert((u8 *)hdr == hdr->mhh_base_addr);
		heap->mhp_hdr = NULL;
		sys_munmap(hdr->mhh_base_addr, hdr->mhh_size);
	}

	if (heap->mhp_fd >= 0) {
		sys_close(heap->mhp_fd);
		heap->mhp_fd = -1;
	}
}

void
gt_mheap_free_cache(struct gt_mheap_hdr *heap, u16 cache_id)
{
	int i, freed;

	freed = 0;

	GT_MHEAP_LOCK;

	for (i = 0; i < heap->mhh_n_pages; ++i) {
		if (heap->mhh_pages[i].pg_allocated &&
		    heap->mhh_pages[i].pg_cache_id == cache_id) {
			heap->mhh_pages[i].pg_allocated = 0;
			heap->mhh_pages[i].pg_last = 0;
			heap->mhh_pages[i].pg_cache_id = GT_MCACHE_ID_INVALID;
			freed++;
		}
	}

	gt_mheap_set_free_pages(heap, heap->mhh_free_pages + freed);

	GT_MHEAP_UNLOCK;
}

void
gt_mcache_init(struct gt_mcache *cache, struct gt_mheap_hdr *heap, u16 id)
{
	int i, order;
	unsigned long a, e;
	struct gt_mbuf *m;

	assert(heap != NULL);
	assert(id < heap->mhh_n_caches);

	cache->mch_n_slab_pages = 0;
	cache->mch_n_mbufs = 0;
	cache->mch_usage = 0;
	cache->mch_n_pages = 0;
	cache->mch_heap = heap;
	cache->mch_id = id;

	for (i = 0; i < GT_ARRAY_SIZE(cache->mch_available); ++i) {
		gt_dlist_init(cache->mch_available + i);
		cache->mch_available_size[i] = 0;
	}

	// Give the gap to cache 0
	if (id != 0) {
		return;
	}

	a = GT_ROUND_UP((unsigned long)heap->mhh_gap, GT_SLAB_SIZE_LOW);
	e = (unsigned long)heap->mhh_mem;

	while (a < e) {
		order = GT_SLAB_ORDER_LOW;
		while (order + 1 < GT_SLAB_ORDER_HIGH &&
		       GT_IS_ALIGNED(a, GT_POW2(order + 1)) &&
		       a + GT_POW2(order + 1) <= e) {
			order++;
		}

		m = (struct gt_mbuf *)a;
		gt_mbuf_init(m, order, order, cache->mch_id);
		gt_mbuf_free(cache, m);

		a += GT_POW2(order);
	}
}

void
gt_mcache_deinit(struct gt_mcache *cache)
{
	int head_size;
	struct gt_dlist *head;
	struct gt_mbuf *m;

	// Memory leak detection
	assert(cache->mch_n_mbufs == 0);
	assert(cache->mch_usage == 0);
	assert(cache->mch_n_pages == 0);

	head = cache->mch_available + GT_SLAB_ORDER_HIGH;
	head_size = gt_dlist_size(head);
	assert(cache->mch_n_slab_pages == head_size);

	while (!gt_dlist_is_empty(head)) {
		m = GT_DLIST_FIRST(head, struct gt_mbuf, mb_list);
		gt_mbuf_alloc(cache, m);
		gt_mheap_free(cache->mch_heap, m);
	}
}

static void *
gt_slab_alloc(struct gt_mcache *cache, unsigned long mb_size, u8 flags)
{
	u8 heap_alloc_flags;
	int order;
	void *ptr;
	struct gt_mbuf *m;

	assert(mb_size < GT_PAGE_SIZE);

	order = ffs(mb_size) - 1;
	if (order < GT_SLAB_ORDER_LOW) {
		order = GT_SLAB_ORDER_LOW;
	}

	ptr = gt_slab_cache_alloc(cache, order);
	if (ptr != NULL) {
		return ptr;
	}

	heap_alloc_flags = 0;
	if (GT_FLAG_ISSET(flags, GT_MF_NOFAIL)) {
		heap_alloc_flags |= GT_MF_NOFAIL;
	}
	m = gt_mheap_alloc_pages(cache->mch_heap, 1, cache->mch_id,
				 heap_alloc_flags);
	if (m == NULL) {
		return NULL;
	}

	cache->mch_n_slab_pages++;
	gt_mbuf_init(m, GT_SLAB_ORDER_HIGH, GT_SLAB_ORDER_HIGH, cache->mch_id);

	ptr = gt_buddy_split(cache, m, order);

	return ptr;
}

static void
gt_slab_free(struct gt_mcache *cache, struct gt_mbuf *m)
{
	assert(m->mb_hdr.mbh_status == GT_MBUF_ALLOCATED);

	gt_buddy_merge(cache, m);
}

void *
gt_malloc(struct gt_mcache *cache, unsigned long size, u8 flags)
{
	return gt_malloc_align(cache, size, sizeof(struct gt_mbuf_header),
			       flags);
}

void *
gt_malloc_align(struct gt_mcache *cache, unsigned long size,
		unsigned long align, u8 flags)
{
	int n;
	unsigned long mb_size;
	void *ptr;
	struct gt_mbuf *mb;
	struct gt_mbuf_header *pad;

	assert(align >= sizeof(struct gt_mbuf_header));
	assert(align == 0 || GT_IS_POW2(align));
	assert(align <= GT_PAGE_SIZE);

	if (size == 0) {
		return NULL;
	}

	mb_size = gt_roundup_pow2_64(size + align);

	if (mb_size >= GT_PAGE_SIZE) {
		n = GT_DIV_ROUND_UP(size, GT_PAGE_SIZE);
		ptr = gt_mheap_alloc_pages(cache->mch_heap, n, cache->mch_id,
					   flags);
		if (ptr != NULL) {
			cache->mch_n_pages += n;
		}
	} else {
		ptr = gt_slab_alloc(cache, mb_size, flags);
		if (ptr == NULL) {
			return NULL;
		}
		mb = gt_mbuf_get(ptr);
		mb_size = GT_POW2(mb->mb_hdr.mbh_order);

		cache->mch_usage += mb_size;
		cache->mch_n_mbufs++;

		if (align == sizeof(struct gt_mbuf_header)) {
			ptr = (struct gt_mbuf_header *)mb + 1;
		} else {
			ptr = (u8 *)mb + align;
			assert(GT_IS_ALIGNED((unsigned long)ptr, align));
			assert((u8 *)ptr + size <= (u8 *)mb + mb_size);

			pad = (struct gt_mbuf_header *)ptr - 1;

			pad->mbh_magic = GT_MBUF_MAGIC;
			pad->mbh_order = mb->mb_hdr.mbh_order;
			pad->mbh_root_order = mb->mb_hdr.mbh_root_order;
			pad->mbh_status = GT_MBUF_PADDING;
			pad->mbh_cache_id = mb->mb_hdr.mbh_cache_id;
		}
	}

	if (ptr != NULL) {
		if (GT_FLAG_ISSET(flags, GT_MF_ZERO)) {
			memset(ptr, 0, size);
		}
	}

	return ptr;
}

// TODO: Implement realloc more efficiently. Current implementation always
// allocates a new block, copies, and frees the old one. Instead we could:
// - Try to expand the current block using adjacent free mbufs
// - Merge with the buddy block if free
// - Only allocate new + copy when expansion is impossible
void *
gt_realloc(struct gt_mcache *cache, void *ptr, unsigned long size, u8 flags)
{
	int i, n, pageindex;
	unsigned long tmp, hdr_size, old_size;
	void *new_ptr;
	struct gt_mheap_hdr *heap;
	struct gt_mbuf *m;

	if (ptr == NULL) {
		return gt_malloc(cache, size, flags);
	}

	heap = cache->mch_heap;

	if (GT_IS_PAGE_ALIGNED(ptr)) {
		n = 0;
		GT_MHEAP_LOCK;
		pageindex = gt_mheap_get_pageindex(heap, ptr);
		for (i = pageindex; i < heap->mhh_n_pages; ++i) {
			n++;
			if (heap->mhh_pages[i].pg_last) {
				break;
			}
		}
		GT_MHEAP_UNLOCK;
		old_size = n * GT_PAGE_SIZE;
	} else {
		m = gt_mbuf_get(ptr);
		hdr_size = (u8 *)ptr - (u8 *)m;
		tmp = GT_POW2(m->mb_hdr.mbh_order);
		old_size = tmp - hdr_size;
	}

	new_ptr = gt_malloc(cache, size, flags);
	if (new_ptr != NULL) {
		tmp = GT_MIN(old_size, size);
		memcpy(new_ptr, ptr, tmp);
		gt_free_internal(cache, ptr);
	}

	return new_ptr;
}

void
gt_free_internal(struct gt_mcache *cache, void *ptr)
{
	int pageindex;
	unsigned long n, size;
	u16 owner;
	struct gt_mheap_hdr *heap;
	struct gt_mbuf *m;

	if (ptr == NULL) {
		return;
	}

	heap = cache->mch_heap;

	if (GT_IS_PAGE_ALIGNED(ptr)) {
		pageindex = gt_mheap_get_pageindex(heap, ptr);
		owner = heap->mhh_pages[pageindex].pg_cache_id;
	} else {
		m = gt_mbuf_get(ptr);
		owner = m->mb_hdr.mbh_cache_id;
	}

	if (owner != cache->mch_id) {
		// The object belongs to another cache.
		// This only happens while the owning (dead) cache is being
		// torn down, whose pages gt_mheap_free_cache() reclaims
		return;
	}

	if (GT_IS_PAGE_ALIGNED(ptr)) {
		n = gt_mheap_free(cache->mch_heap, ptr);
		assert(cache->mch_n_pages >= n);
		cache->mch_n_pages -= n;
	} else {
		assert(cache->mch_n_mbufs > 0);

		m = gt_mbuf_get(ptr);
		size = GT_POW2(m->mb_hdr.mbh_order);

		assert(cache->mch_usage >= size);
		cache->mch_usage -= size;
		cache->mch_n_mbufs--;

		gt_slab_free(cache, m);
	}
}

void *
gt_a_malloc(struct gt_allocator *alc, unsigned long size, u8 flags)
{
	return (*alc->alc_malloc)(alc, size, flags);
}

void *
gt_a_malloc_align(struct gt_allocator *alc, unsigned long size,
		  unsigned long align, u8 flags)
{
	return (*alc->alc_malloc_align)(alc, size, align, flags);
}

void
gt_a_free_internal(struct gt_allocator *alc, void *ptr)
{
	(*alc->alc_free)(alc, ptr);
}

static void *
gt_kallocator_malloc(struct gt_allocator *alc, unsigned long size, u8 flags)
{
	struct gt_kallocator *a;

	a = container_of(alc, struct gt_kallocator, alc);
	return gt_malloc(a->alc_mm_cache, size, flags);
}

static void *
gt_kallocator_malloc_align(struct gt_allocator *alc, unsigned long size,
			   unsigned long align, u8 flags)
{
	struct gt_kallocator *a;

	a = container_of(alc, struct gt_kallocator, alc);
	return gt_malloc_align(a->alc_mm_cache, size, align, flags);
}

static void
gt_kallocator_free(struct gt_allocator *alc, void *ptr)
{
	struct gt_kallocator *a;

	a = container_of(alc, struct gt_kallocator, alc);
	gt_free_internal(a->alc_mm_cache, ptr);
}

void
gt_kallocator_init(struct gt_kallocator *kalc, struct gt_mcache *cache)
{
	kalc->alc.alc_malloc = gt_kallocator_malloc;
	kalc->alc.alc_malloc_align = gt_kallocator_malloc_align;
	kalc->alc.alc_free = gt_kallocator_free;
	kalc->alc_mm_cache = cache;
}

static void *
gt_uallocator_malloc_align(struct gt_allocator *alc, unsigned long size,
			   unsigned long align, u8 flags)
{
	int rc;
	void *ptr;

	GT_UNUSED(alc);

	if (size == 0) {
		return NULL;
	}

	// Never below GT_L1_CACHE_BYTES, like sys_malloc(): gt_pbc_free()
	// discriminates allocator-owned pointers from gt_vec-built message
	// fields by that alignment, and a gt_vec data pointer sits
	// sizeof(struct gt_vec_header) past the allocation, so it can only
	// stay unaligned if the allocation itself is aligned.
	rc = sys_posix_memalign(&ptr, GT_MAX(align, GT_L1_CACHE_BYTES), size);
	if (rc) {
		return NULL;
	}
	if (GT_FLAG_ISSET(flags, GT_MF_ZERO)) {
		memset(ptr, 0, size);
	}
	return ptr;
}

static void *
gt_uallocator_malloc(struct gt_allocator *alc, unsigned long size, u8 flags)
{
	return gt_uallocator_malloc_align(alc, size, GT_L1_CACHE_BYTES, flags);
}

static void
gt_uallocator_free(struct gt_allocator *alc, void *ptr)
{
	GT_UNUSED(alc);

	sys_free(ptr);
}

struct gt_allocator gt_uallocator = {
	.alc_malloc = gt_uallocator_malloc,
	.alc_malloc_align = gt_uallocator_malloc_align,
	.alc_free = gt_uallocator_free,
};
