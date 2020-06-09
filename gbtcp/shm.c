#include "internals.h"

#define CURMOD shm

#define SHM_NAME "gbtcp"
#define SHM_SIZE (1024*1024*1204) // 1 Gb
#define SHM_ADDR (void *)(0x7fffffffffff - 8llu * 1024 * 1024 * 1024)

typedef uint32_t bitset_word_t;

#define BITSET_WORD_SIZE 32
#define BITSET_WORD_MASK (BITSET_WORD_SIZE - 1)
#define BITSET_WORD_SHIFT 5
#define BITSET_WORD_ARRAY_SIZE(n) \
	(ROUND_UP(n, BITSET_WORD_SIZE) >> BITSET_WORD_SHIFT)
#define BITSET_MASK(i) ((bitset_word_t)1 << (i & BITSET_WORD_MASK))
#define BITSET_WORD(i) (i >> BITSET_WORD_SHIFT)

static void
bitset_set(bitset_word_t *bitset_words, int i)
{
	bitset_words[BITSET_WORD(i)] |= BITSET_MASK(i);
}

static void
bitset_clr(bitset_word_t *bitset_words, int i)
{
	bitset_words[BITSET_WORD(i)] &= ~BITSET_MASK(i);
}

static int
bitset_get(const bitset_word_t *bitset_words, int i)
{
	return (bitset_words[BITSET_WORD(i)] & BITSET_MASK(i)) != 0;
}

struct shm_hdr {
	uintptr_t shm_base_addr;
	struct spinlock shm_lock;
	struct dlist shm_heap;
	int shm_npages;
	int shm_hdr_size;
	size_t shm_size;
	struct dlist shm_mbuf_free_indirect_head[GT_SERVICES_MAX];
	bitset_word_t *shm_pages;
};

struct shm_region {
	struct dlist r_list;
	size_t r_size;
};

static int shm_fd = -1;
static struct shm_hdr *shm = MAP_FAILED;

#define IS_SHM_ADDR(p) \
	(((uintptr_t)(p) - shm->shm_base_addr) < shm->shm_size)

static void
shm_page_alloc(u_int page)
{
	assert(page < shm->shm_npages);
	bitset_set(shm->shm_pages, page);
}

static void
shm_page_free(u_int page)
{
	assert(page < shm->shm_npages);
	bitset_clr(shm->shm_pages, page);
}

static int
shm_page_is_allocated(u_int page)
{
	int flag;

	assert(page < shm->shm_npages);
	flag = bitset_get(shm->shm_pages, page);
	return flag;	
}

static uintptr_t
shm_page_to_virt(u_int page)
{
	assert(page < shm->shm_npages);
	return shm->shm_base_addr + (page << PAGE_SHIFT);
}

static int
shm_virt_to_page(uintptr_t addr)
{
	int page;
	uintptr_t base_addr;

	base_addr = ROUND_DOWN(addr, PAGE_SIZE);
	page = (base_addr - shm->shm_base_addr) >> PAGE_SHIFT;
	assert(page < shm->shm_npages);
	return page;
}

static void
shm_lock()
{
	spinlock_lock(&shm->shm_lock);
}

static void
shm_unlock()
{
	int i, n;
	struct dlist *dst, *src, tofree;
	struct mbuf *m;

	if (current != NULL && current->p_mbuf_free_indirect_n) {
		current->p_mbuf_free_indirect_n = 0;
		n =  ARRAY_SIZE(current->p_mbuf_free_indirect_head);
		for (i = 0; i < n; ++i) {
			src = current->p_mbuf_free_indirect_head + i;
			if (!dlist_is_empty(src)) {
				assert(i != current->p_sid);
				dst = shm->shm_mbuf_free_indirect_head + i;
				dlist_splice_tail_init(dst, src);
			}
		}
	}
	if (current == NULL) {
		dlist_init(&tofree);
	} else {
		src = shm->shm_mbuf_free_indirect_head + current->p_sid;
		dlist_replace_init(&tofree, src);
	}
	spinlock_unlock(&shm->shm_lock);
	while (!dlist_is_empty(&tofree)) {
		m = DLIST_FIRST(&tofree, struct mbuf, mb_list);
		DLIST_REMOVE(m, mb_list);
		mbuf_free_direct(m);
	}
}

int
shm_init(void **pinit, int init_size)
{
	int i, rc, npages, hdr_size, superblock_size, superblock_npages;
	size_t size;

	size = ROUND_UP(SHM_SIZE, PAGE_SIZE);
	npages = size >> PAGE_SHIFT;
	rc = sys_shm_open(SHM_NAME, O_CREAT|O_RDWR, 0666);
	if (rc < 0) {
		goto err;
	}
	shm_fd = rc;
	sys_ftruncate(shm_fd, size);
	rc = sys_mmap((void **)&shm, SHM_ADDR, size, PROT_READ|PROT_WRITE,
	              MAP_SHARED, shm_fd, 0);
	if (rc) {
		goto err;
	}
	assert(!(((uintptr_t)shm) & PAGE_MASK));
	hdr_size = sizeof(*shm);
	hdr_size += BITSET_WORD_ARRAY_SIZE(npages) * sizeof(bitset_word_t);
	superblock_size = ROUND_UP((hdr_size + init_size), PAGE_SIZE);
	memset(shm, 0, superblock_size);
	shm->shm_base_addr = (uintptr_t)shm;
	spinlock_init(&shm->shm_lock);
	dlist_init(&shm->shm_heap);
	shm->shm_npages = npages;
	shm->shm_hdr_size = hdr_size;
	shm->shm_size = size;
	shm->shm_pages = (bitset_word_t *)(shm + 1);
	for (i = 0; i < ARRAY_SIZE(shm->shm_mbuf_free_indirect_head); ++i) {
		dlist_init(shm->shm_mbuf_free_indirect_head + i);
	}
	superblock_npages = superblock_size >> PAGE_SHIFT;
	for (i = 0; i < superblock_npages; ++i) {
		shm_page_alloc(i);
	}
	if (pinit != NULL) {
		*pinit  = (void *)(shm->shm_base_addr + shm->shm_hdr_size);
	}
	NOTICE(0, "ok; addr=%"PRIxPTR, shm->shm_base_addr);
	return 0;
err:
	shm_deinit();
	return rc;
}

int
shm_attach(void **pinit)
{
	int rc;
	size_t size;
	void *addr;

	rc = sys_shm_open(SHM_NAME, O_RDWR, 0666);
	if (rc < 0) {
		goto err;
	}
	shm_fd = rc;
	rc = sys_mmap((void **)&shm, NULL, sizeof(*shm), PROT_READ,
	              MAP_SHARED, shm_fd, 0);
	if (rc) {
		goto err;
	}
	size = shm->shm_size;
	addr = (void *)shm->shm_base_addr;
	sys_munmap(shm, sizeof(*shm));
	shm = MAP_FAILED;
	NOTICE(0, "hit; addr=%p", addr);
	rc = sys_mmap((void **)&shm, addr, size, PROT_READ|PROT_WRITE,
	              MAP_SHARED|MAP_FIXED, shm_fd, 0);
	if (rc) {
		goto err;
	}
	if (pinit != NULL) {
		*pinit = (void *)(shm->shm_base_addr + shm->shm_hdr_size);
	}
	NOTICE(0, "ok; addr=%"PRIxPTR, shm->shm_base_addr);
	return 0;
err:
	shm_detach();
	return rc;
}

void
shm_detach()
{
	if (shm != MAP_FAILED) {
		sys_munmap(shm, shm->shm_size);
		shm = MAP_FAILED;
	}
	sys_close(shm_fd);
	shm_fd = -1;
}

void
shm_deinit()
{
	shm_detach();
	shm_unlink(SHM_NAME);
}

static int
shm_alloc_pages_locked(void **pp, size_t alignment, size_t size)
{
	int i, j, n, rc, alignment_n, size_n;
	uintptr_t addr;

	alignment_n = alignment >> PAGE_SHIFT;
	size_n = size >> PAGE_SHIFT;
	assert(size_n);
	addr = ROUND_UP(shm->shm_base_addr, alignment);
	i = shm_virt_to_page(addr);
	n = shm->shm_npages - size_n;
	for (; i < n; i += alignment_n) {
		rc = 0;
		for (j = i; j < i + size_n; ++j) {
			rc = shm_page_is_allocated(j);
			if (rc) {
				break;
			}
		}
		if (rc == 0) {
			for (j = i; j < i + size_n; ++j) {
				shm_page_alloc(j);
			}
			*pp = (void *)shm_page_to_virt(i);
			return 0;
		}
	}
	return -ENOMEM;
}

static void
shm_free_pages_locked(uintptr_t addr, size_t size)
{
	int i, size_n;

	size_n = size >> PAGE_SHIFT;
	i = shm_virt_to_page(addr);
	for (; i < size_n; ++i) {
		if (!shm_page_is_allocated(i)) {
			die(0, "double free; addr=%"PRIxPTR,
			    shm_page_to_virt(i));
		}
		shm_page_free(i);
	}
}

static int
shm_region_merge(struct shm_region *left, struct shm_region *right)
{
	uintptr_t left_addr, right_addr;

	left_addr = (uintptr_t)left;
	right_addr = (uintptr_t)right;
	assert(left_addr <= right_addr);
	if (left_addr + left->r_size > right_addr) {
		die(0, "memory corrupted; left=(%p, %zu), right=(%p, %zu)",
		    left, left->r_size, right, right->r_size);
	}
	if (left_addr + left->r_size == right_addr) {
		left->r_size += right->r_size;
		return 1;
	} else {
		return 0;
	}
}

static void
shm_free_locked(void *tofree_ptr)
{
	int rc;
	uintptr_t tofree_addr; 
	struct shm_region *r, *tofree_r;

	tofree_r = ((struct shm_region *)tofree_ptr) - 1;
	tofree_addr = (uintptr_t)tofree_r;
	DLIST_FOREACH(r, &shm->shm_heap, r_list) {
		if ((uintptr_t)r < tofree_addr) {
			rc = shm_region_merge(r, tofree_r);
			if (rc) {
				break;
			}
		} else {
			DLIST_INSERT_BEFORE(tofree_r, r, r_list);
			rc = shm_region_merge(tofree_r, r);
			if (rc) {
				DLIST_REMOVE(r, r_list);
			}
			break;
		}
	}
}

static int
shm_malloc_locked(void **pp, size_t size)
{
	int rc, r_bf_size;
	struct shm_region *r, *r_bf;

	// Best fit
	r_bf = NULL;
	r_bf_size = 0;
	DLIST_FOREACH(r, &shm->shm_heap, r_list) {
		if (r->r_size >= size + sizeof(*r)) {
			if (r_bf_size == 0 || r_bf_size > r->r_size) {
				r_bf = r;
				r_bf_size = r->r_size;
			}
		}
	}
	if (r_bf_size != 0) {
		DLIST_REMOVE(r_bf, r_list);
	} else {
		r_bf_size = ROUND_UP(size + sizeof(*r), PAGE_SIZE);
		rc = shm_alloc_pages_locked((void **)&r_bf,
		                            PAGE_SIZE, r_bf_size);
		if (rc) {
			return rc;
		}
	}
	if (r_bf_size - (size + sizeof(*r)) > 128) {
		r_bf->r_size = size + sizeof(*r);
		r = (struct shm_region *)(((u_char *)r_bf) + r_bf->r_size);
		r->r_size = r_bf_size - r_bf->r_size;
		shm_free_locked(r + 1);
	}
	*pp = r_bf + 1;
	return 0;
}

int
shm_malloc(void **pp, size_t size)
{
	int rc;

	shm_lock();
	rc = shm_malloc_locked(pp, size);
	shm_unlock();
	return rc;
}

int
shm_realloc(void **pp, size_t size)
{
	int rc;
	size_t old_size;
	struct shm_region *r;
	void *new;

	if (*pp == NULL) {
		old_size = 0;
	} else {
		r = ((struct shm_region *)*pp) - 1;
		old_size = r->r_size;
	}
	rc = shm_malloc(&new, size);
	if (rc) {
		return rc;
	}
	memcpy(new, *pp, old_size);
	*pp = new;
	return 0;
}

void
shm_free(void *ptr)
{
	shm_lock();
	shm_free_locked(ptr);
	shm_unlock();
}

int
shm_alloc_pages(void **pp, size_t alignment, size_t size)
{
	int rc;

	if (alignment & PAGE_MASK) {
		return -EINVAL;
	}
	if (size & PAGE_MASK) {
		return -EINVAL;
	}
	shm_lock();
	rc = shm_alloc_pages_locked(pp, alignment, size);
	shm_unlock();
	return rc;
}

void
shm_free_pages(void *ptr, size_t size)
{
	uintptr_t addr;

	addr = (uintptr_t)ptr;
	assert((addr & PAGE_MASK) == 0);
	assert((size & PAGE_MASK) == 0);
	shm_lock();
	shm_free_pages_locked(addr, size);
	shm_unlock();
}
