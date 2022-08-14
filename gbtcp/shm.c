// gpl2
#include "internals.h"

#define CURMOD shm

#define SHM_MAGIC 0xb9d1
#define SHM_PATH GT_PREFIX"/shm"

#define SHM_SIZE (256*1024*1024) // 256Mb
#ifdef __linux__
  #ifdef __i386__
    #define SHM_HINT ((void *)0x80000000)
  #else // __i386__
    #define SHM_HINT NULL
  #endif // __i386__
#else // __linux__
  #define SHM_HINT NULL
#endif // __linux__

struct shm_mod {
	struct log_scope log_scope;
	int shm_n_allocated_pages;
};

static int shm_fd = -1;
static int shm_early = 1;
static int shm_early_n_allocated_pages;

struct shm_hdr *shared;

#define IS_SHM_ADDR(p) \
	(((uintptr_t)(p) - shared->shm_base_addr) < shared->shm_size)

#if 0
static void
check_heap(const char *msg)
{
	int n;
	struct mbuf *m;

	n = 0;
	dbg("heap> %s", msg);
	DLIST_FOREACH(m, &shared->shm_heap, mb_list) {
		if (!IS_SHM_ADDR(m)) {
			dbg("not shm %p", m);
			assert(0);
		}
		if (!IS_SHM_ADDR(m->mb_list.dls_prev)) {
			dbg("not shm prev %p", m->mb_list.dls_prev);
			assert(0);
		}
		if (m->mb_magic != SHM_MAGIC) {
			dbg("memory corrupted at %p, %d", m, n);
			assert(0);
		}
		dbg("%p, %u", m, m->mb_size);
		n++;
	}
	dbg("<");
}
#endif

int
shm_mod_init(void)
{
	int rc;

	rc = curmod_init();
	if (rc) {
		return rc;
	}
	sysctl_add_int("shm.n_allocated_pages", SYSCTL_RD, &curmod->shm_n_allocated_pages, 0, 0);
	return 0;
}

static int
shm_page_is_allocated(u_int page)
{
	int flag;

	assert(page < shared->shm_n_pages);
	flag = bitset_get(shared->shm_pages, page);
	return flag;	
}

static void
shm_page_alloc(u_int page)
{
	assert(!shm_page_is_allocated(page));
	bitset_set(shared->shm_pages, page);
	if (shm_early) {
		shm_early_n_allocated_pages++;
	} else {
		curmod->shm_n_allocated_pages++;
	}
}

static void
shm_page_free(u_int page)
{
	assert(page < shared->shm_n_pages);
	assert(page >= shared->shm_n_sb_pages);
	bitset_clr(shared->shm_pages, page);
	if (shm_early) {
		shm_early_n_allocated_pages--;
	} else {
		curmod->shm_n_allocated_pages--;
	}
}

static uintptr_t
shm_page_to_virt(u_int page)
{
	assert(page < shared->shm_n_pages);
	return shared->shm_base_addr + (page << PAGE_SHIFT);
}

static int
shm_virt_to_page(uintptr_t addr)
{
	int page;
	uintptr_t base_addr;

	base_addr = ROUND_DOWN(addr, PAGE_SIZE);
	page = (base_addr - shared->shm_base_addr) >> PAGE_SHIFT;
	assert(page < shared->shm_n_pages);
	return page;
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

static void
shm_unlock_and_free_garbage(void)
{
	struct dlist head;

	dlist_init(&head);
	if (current != NULL) {
		shm_garbage_push(current);
		shm_garbage_pop(&head, current->p_sid);
	}
	shm_unlock();
	mbuf_free_direct_list(&head);
}

void
shm_garbage_push(struct service *s)
{
	int i;
	struct dlist *dst, *src;

	for (i = 0; i < s->p_mbuf_garbage_max; ++i) {
		src = s->p_mbuf_garbage_head + i;
		if (!dlist_is_empty(src)) {
			assert(i != s->p_sid);
			dst = shared->shm_garbage_head + i;
			dlist_splice_tail_init(dst, src);
		}
	}
	s->p_mbuf_garbage_max = 0;
}

void
shm_garbage_pop(struct dlist *dst, u_char sid)
{
	struct dlist *src;

	src = shared->shm_garbage_head + sid;
	if (!dlist_is_empty(src)) {
		dlist_splice_tail_init(dst, src);
	}
}

int
shm_init(void)
{
	int i, rc, n_pages, sb_size;
	size_t size;
	//struct stat buf;

	assert(shm_early);
	size = ROUND_UP(SHM_SIZE, PAGE_SIZE);
	n_pages = size >> PAGE_SHIFT;
	rc = sys_open(SHM_PATH, O_CREAT|O_RDWR, 0666);
	if (rc < 0) {
		goto err;
	}
	shm_fd = rc;
	//fchgrp(shm_fd, &buf, GT_GROUP_NAME);
	rc = sys_ftruncate(shm_fd, size);
	if (rc) {
		goto err;
	}
	rc = sys_mmap((void **)&shared, SHM_HINT, size, PROT_READ|PROT_WRITE, MAP_SHARED,
			shm_fd, 0);
	if (rc) {
		goto err;
	}
	assert(!(((uintptr_t)shared) & PAGE_MASK));
	sb_size = sizeof(*shared);
	sb_size += BITSET_WORD_ARRAY_SIZE(n_pages) * sizeof(bitset_word_t);
	sb_size = ROUND_UP(sb_size, PAGE_SIZE);
	memset(shared, 0, sb_size);
	shared->shm_ns = nanoseconds;
	shared->shm_base_addr = (uintptr_t)shared;
	spinlock_init(&shared->shm_lock);
	dlist_init(&shared->shm_heap);
	shared->shm_n_pages = n_pages;
	shared->shm_size = size;
	shared->shm_pages = (bitset_word_t *)(shared + 1);
	for (i = 0; i < GT_SERVICES_MAX; ++i) {
		dlist_init(shared->shm_garbage_head + i);
	}
	shared->shm_n_sb_pages = sb_size >> PAGE_SHIFT;
	for (i = 0; i < shared->shm_n_sb_pages; ++i) {
		shm_page_alloc(i);
	}
	for (i = MOD_FIRST; i < MODS_MAX; ++i) {
		if (mods[i].mod_init == NULL) {
			rc = mod_init2(i, sizeof(struct log_scope));
		} else {
			rc = (*mods[i].mod_init)();
		}
		if (rc) {
			goto err;
		}
	}	
	shm_early = 0;
	curmod->shm_n_allocated_pages += shm_early_n_allocated_pages;
	shm_early_n_allocated_pages = 0;
	NOTICE(0, "Shared memory initialized at address %p", (void *)shared->shm_base_addr);
	return 0;
err:
	ERR(-rc, "Failed to initialize shared memory");
	shm_deinit();
	return rc;
}

int
shm_attach(void)
{
	int rc;
	size_t size;
	void *addr, *tmp;

	rc = sys_open(SHM_PATH, O_RDWR, 0666);
	if (rc < 0) {
		goto err;
	}
	shm_fd = rc;
	rc = sys_mmap((void **)&shared, NULL, sizeof(*shared), PROT_READ, MAP_SHARED, shm_fd, 0);
	if (rc) {
		goto err;
	}
	size = shared->shm_size;
	addr = (void *)shared->shm_base_addr;
	tmp = shared;
	shared = NULL;
	sys_munmap(tmp, sizeof(*shared));
	rc = sys_mmap((void **)&shared, addr, size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED,
			shm_fd, 0);
	if (rc) {
		goto err;
	}
	assert(shared == addr);
	shm_early = 0;
	NOTICE(0, "Shared memory mapped to address: %p", shared);
	return 0;
err:
	ERR(-rc, "Failed to map shared memory");
	shm_detach();
	return rc;
}

void
shm_detach(void)
{
	void *tmp;
	size_t size;

	if (shared != NULL) {
		tmp = shared;
		size = shared->shm_size;
		shared = NULL;
		sys_munmap(tmp, size);
	}
	sys_close(shm_fd);
	shm_fd = -1;
	shm_early = 1;
	NOTICE(0, "Shared memory detached");
}

void
shm_deinit(void)
{
	int i;

	if (shared != NULL) {
		for (i = MODS_MAX - 1; i >= MOD_FIRST; --i) {
			if (shared->shm_mods[i] != NULL) {
				if (mods[i].mod_deinit == NULL) {
					mod_deinit1(i);
				} else {
					(*mods[i].mod_deinit)();
				}
				shared->shm_mods[i] = NULL;
			}
		}
	}
	shm_detach();
	sys_unlink(SHM_PATH);
}

static int
shm_alloc_pages_locked(void **pp, size_t alignment, size_t size)
{
	int i, n, rc, page, alignment_n, size_n;
	uintptr_t addr;

	alignment_n = alignment >> PAGE_SHIFT;
	size_n = size >> PAGE_SHIFT;
	assert(size_n);
	addr = ROUND_UP(shared->shm_base_addr, alignment);
	page = shm_virt_to_page(addr);
	n = shared->shm_n_pages - size_n;
	for (; page < n; page += alignment_n) {
		rc = 0;
		for (i = 0; i < size_n; ++i) {
			rc = shm_page_is_allocated(page + i);
			if (rc) {
				break;
			}
		}
		if (rc == 0) {
			for (i = 0; i < size_n; ++i) {
				shm_page_alloc(page + i);
			}
			*pp = (void *)shm_page_to_virt(page);
			INFO(0, "Allocated %d pages (%zu bytes) in shared memory at %p",
				size_n, size, *pp);
			return 0;
		}
	}
	WARN(ENOMEM, "Failed to allocate %d pages (%zu bytes) in shared memory",
		size_n, size);
	return -ENOMEM;
}

static void
shm_free_pages_locked(uintptr_t addr, size_t size)
{
	int i, page, size_n;

	size_n = size >> PAGE_SHIFT;
	page = shm_virt_to_page(addr);
	for (i = 0; i < size_n; ++i) {
		if (!shm_page_is_allocated(page + i)) {
			gtl_die(0, "Double free page at %p", (void *)shm_page_to_virt(page + i));
		}
		shm_page_free(page + i);
	}
	INFO(0, "Free %d pages (%zu bytes) in shared memory", size_n, size);
}

#define IS_ADJACENT(l, r) \
	((uintptr_t)(l) + (l)->mb_size == (uintptr_t)(r))

static void
shm_merge(struct mbuf *middle)
{
	struct mbuf *m, *x;

	m = middle;
	if (m != DLIST_FIRST(&shared->shm_heap, struct mbuf, mb_list)) {
		x = DLIST_PREV(m, mb_list);
		if (IS_ADJACENT(x, m)) {
			x->mb_size += m->mb_size;
			DLIST_REMOVE(m, mb_list);
			m = x;
		}
	}
	if (m != DLIST_LAST(&shared->shm_heap, struct mbuf, mb_list)) {
		x = DLIST_NEXT(m, mb_list);
		if (IS_ADJACENT(m, x)) {
			m->mb_size += x->mb_size;
			DLIST_REMOVE(x, mb_list);
		}
	}
}

static void
shm_free_locked(void *tofree_ptr)
{
	struct mbuf *m, *tofree_m;

	if (tofree_ptr == NULL) {
		return;
	}
	tofree_m = ((struct mbuf *)tofree_ptr) - 1;
	assert(tofree_m->mb_magic == SHM_MAGIC);
	assert(tofree_m->mb_freed == 0);
	tofree_m->mb_freed = 1;
	DLIST_FOREACH(m, &shared->shm_heap, mb_list) {
		assert(m->mb_magic == SHM_MAGIC);
		if ((uintptr_t)tofree_m < (uintptr_t)m) {
			DLIST_INSERT_BEFORE(tofree_m, m, mb_list);
			shm_merge(tofree_m);
			return;
		}
	}
	DLIST_INSERT_TAIL(&shared->shm_heap, tofree_m, mb_list);
	shm_merge(tofree_m);
}

static void *
shm_malloc_locked(size_t mem_size)
{
	int rc;
	size_t size, new_size;
	struct mbuf *m, *b;

	size = sizeof(struct mbuf) + mem_size;
	assert(size < INT_MAX);
	b = NULL;
	DLIST_FOREACH(m, &shared->shm_heap, mb_list) {
		if (m->mb_size >= size) {
			if (b == NULL || b->mb_size > m->mb_size) {
				b = m;
			}
		}
	}
	if (b == NULL) {
		new_size = ROUND_UP(size, PAGE_SIZE);
		rc = shm_alloc_pages_locked((void **)&b, PAGE_SIZE, new_size);
		if (rc) {
			return NULL;
		}
		b->mb_magic = SHM_MAGIC;
		b->mb_size = new_size;
	} else {
		assert(b->mb_freed == 1);
		DLIST_REMOVE(b, mb_list);
	}
	b->mb_freed = 0;
	if (b->mb_size > size + 128) {
		m = (struct mbuf *)(((u_char *)b) + size);
		m->mb_magic = SHM_MAGIC;
		m->mb_size = b->mb_size - size;
		m->mb_freed = 0;
		b->mb_size = size;
		shm_free_locked(m + 1);
	}
	return b + 1;
}

void *
shm_malloc(size_t size)
{
	void *new_ptr;

	shm_lock();
	new_ptr = shm_malloc_locked(size);
	if (new_ptr != NULL) {
		INFO(0, "Allocated %zu bytes of shared memory at %p", size, new_ptr);
	} else {
		WARN(ENOMEM, "Failed to allocate %zu bytes in shared memory", size);
	}
	shm_unlock_and_free_garbage();
	return new_ptr;
}

void *
shm_realloc(void *old_ptr, size_t size)
{
	size_t old_size;
	struct mbuf *m;
	void *new_ptr;

	if (old_ptr == NULL) {
		old_size = 0;
	} else {
		m = ((struct mbuf *)old_ptr) - 1;
		old_size = m->mb_size - sizeof(*m);
	}
	new_ptr = shm_malloc(size);
	if (new_ptr != NULL) {
		memcpy(new_ptr, old_ptr, old_size);
		shm_free(old_ptr);
	}
	return new_ptr;
}

void
shm_free(void *ptr)
{
	shm_lock();
	shm_free_locked(ptr);
	// TODO: ??? change to real number of bytes
	INFO(0, "Free ??? bytes shared memory at %p", ptr);
	shm_unlock_and_free_garbage();
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
	shm_unlock_and_free_garbage();
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
	shm_unlock_and_free_garbage();
}
