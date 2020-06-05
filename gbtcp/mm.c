#include "internals.h"

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
	bitset_word_t *shm_pages;
};

struct shm_region {
	struct dlist r_list;
	int r_size;
};

static void *curmod;
static int shm_fd = -1;
static __thread int shm_locked;
static struct shm_hdr *shm = MAP_FAILED;
static int shm_sigsegv_handler_is_set;
static struct sigaction shm_sigsegv_old;

#define IS_SHM_ADDR(p) \
	(((uintptr_t)(p) - shm->shm_base_addr) < shm->shm_size)

static void
shm_page_set_used(u_int page)
{
	ASSERT(page < shm->shm_npages);
	bitset_set(shm->shm_pages, page);
}

static int
shm_page_is_used(u_int page)
{
	int flag;

	ASSERT(page < shm->shm_npages);
	flag = bitset_get(shm->shm_pages, page);
	return flag;	
}

static uintptr_t
shm_page_to_virt(u_int page)
{
	ASSERT(page < shm->shm_npages);
	return shm->shm_base_addr + (page << PAGE_SHIFT);
}

static int
shm_virt_to_page(uintptr_t addr)
{
	int page;
	uintptr_t base_addr;

	base_addr = ROUND_DOWN(addr, PAGE_SIZE);
	page = (base_addr - shm->shm_base_addr) >> PAGE_SHIFT;
	ASSERT(page < shm->shm_npages);
	return page;
}

static void
shm_lock()
{
	ASSERT(shm_locked == 0);
	WRITE_ONCE(shm_locked, 1);
	spinlock_lock(&shm->shm_lock);
}

static void
shm_unlock()
{
	ASSERT(shm_locked == 1);
	spinlock_unlock(&shm->shm_lock);
	WRITE_ONCE(shm_locked, 0);
}

static int
shm_mprotect(uintptr_t addr, size_t size, int retry)
{
	int rc;

	rc = sys_mprotect((void *)addr, size, PROT_READ|PROT_WRITE);
	if (rc) {
		if (retry) {
			// TODO: drain and retry
		}
	}
	return rc;
}

static void
shm_sigsegv_handler_restore()
{
	ASSERT(shm_sigsegv_handler_is_set);
	shm_sigsegv_handler_is_set = 0;
	sys_sigaction(SIGSEGV, &shm_sigsegv_old, NULL);
}

static void
shm_sigsegv_handler(int signum, siginfo_t *info, void *udata)
{
	int rc, page, is_used;
	uintptr_t addr;

	if (!READ_ONCE(shm_locked)) {
		addr = ROUND_DOWN((uintptr_t)info->si_addr, PAGE_SIZE);
		if (addr - shm->shm_base_addr <= shm->shm_size) {
			shm_lock();
			page = shm_virt_to_page(addr);
			is_used = shm_page_is_used(page);
			shm_unlock();
			if (is_used) {
				rc = shm_mprotect(addr, PAGE_SIZE, 1);
				if (rc == 0) {
					return;
				}
			}
		}
	}
	shm_sigsegv_handler_restore();
}

static int
shm_sigsegv_handler_set()
{
	int rc;
	struct sigaction sigsegv;

	ASSERT(shm_sigsegv_handler_is_set == 0);
	memset(&sigsegv, 0, sizeof(sigsegv));
	sigsegv.sa_sigaction = shm_sigsegv_handler;
	sigsegv.sa_flags = SA_SIGINFO;
	rc = sys_sigaction(SIGSEGV, &sigsegv, &shm_sigsegv_old);
	if (rc == 0) {
		shm_sigsegv_handler_is_set = 1;
	}
	return rc;
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
	rc = sys_mmap((void **)&shm, SHM_ADDR, size, PROT_NONE,
	              MAP_SHARED, shm_fd, 0);
	if (rc) {
		goto err;
	}
	ASSERT(!(((uintptr_t)shm) & PAGE_MASK));
	hdr_size = sizeof(*shm);
	hdr_size += BITSET_WORD_ARRAY_SIZE(npages) * sizeof(bitset_word_t);
	superblock_size = ROUND_UP((hdr_size + init_size), PAGE_SIZE);
	rc = shm_mprotect((uintptr_t )shm, superblock_size, 0);
	if (rc) {
		sys_munmap(shm, size);
		shm = MAP_FAILED;
		goto err;
	}
	memset(shm, 0, hdr_size);
	shm->shm_base_addr = (uintptr_t)shm;
	spinlock_init(&shm->shm_lock);
	dlist_init(&shm->shm_heap);
	shm->shm_npages = npages;
	shm->shm_hdr_size = hdr_size;
	shm->shm_size = size;
	shm->shm_pages = (bitset_word_t *)(shm + 1);
	superblock_npages = superblock_size >> PAGE_SHIFT;
	for (i = 0; i < superblock_npages; ++i) {
		shm_page_set_used(i);
	}
	rc = shm_sigsegv_handler_set();
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
	rc = sys_mmap((void **)&shm, addr, size, PROT_NONE,
	              MAP_SHARED|MAP_FIXED, shm_fd, 0);
	if (rc) {
		goto err;
	}
	rc = shm_sigsegv_handler_set();
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
	if (shm_sigsegv_handler_is_set) {
		shm_sigsegv_handler_restore();
	}
}

void
shm_deinit()
{
	shm_detach();
	shm_unlink(SHM_NAME);
}

static int
shm_alloc_pages_locked(void **pp, int alignment, int size)
{
	int i, j, n, rc, alignment_n, size_n;
	uintptr_t addr;

	alignment_n = alignment >> PAGE_SHIFT;
	size_n = size >> PAGE_SHIFT;
	ASSERT(size_n);
	addr = ROUND_UP(shm->shm_base_addr, alignment);
	i = shm_virt_to_page(addr);
	n = shm->shm_npages - size_n;
	for (; i < n; i += alignment_n) {
		rc = 0;
		for (j = i; j < i + size_n; ++j) {
			rc = shm_page_is_used(j);
			if (rc) {
				break;
			}
		}
		if (rc == 0) {
			addr = shm_page_to_virt(i);
			rc = shm_mprotect(addr, size, 0);
			if (rc) {
				break;
			}
			for (j = i; j < i + size_n; ++j) {
				shm_page_set_used(j);
			}
			*pp = (void *)addr;
			return 0;
		}
	}
	return -ENOMEM;
}

int
shm_malloc_locked(void **pp, size_t size)
{
	int rc, rem, size2, size3;
	struct shm_region *r, *r2;

	r2 = NULL;
	size2 = size + sizeof(*r2);
	DLIST_FOREACH(r, &shm->shm_heap, r_list) {
		if (r->r_size >= size2) {
			if (r2 == NULL || r2->r_size > r->r_size) {
				r2 = r;
			}
		}
	}
	if (r2 != NULL) {
		r = r2;
		DLIST_REMOVE(r, r_list);
		goto out;
	}
	size3 = ROUND_UP(size2, PAGE_SIZE);
	rc = shm_alloc_pages_locked((void **)&r, PAGE_SIZE, size3);



	if (rc) {
		return rc;
	}
	r->r_size = size3;

out:
	rem = r->r_size - size2;
	if (rem > 128) {
		r->r_size = size2;
		r2 = (struct shm_region *)(((u_char *)r) + r->r_size);
		r2->r_size = rem;
		ASSERT(IS_SHM_ADDR(r2));
		DLIST_INSERT_HEAD(&shm->shm_heap, r2, r_list);
	}
	*pp = r + 1;
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
shm_realloc(void **pp, int size)
{
	int rc, old_size;
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
shm_free(void *p)
{
}

int
shm_alloc_pages(void **pp, int alignment, int size)
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
shm_free_pages(void *ptr, int size)
{
	uintptr_t addr;

	addr = (uintptr_t)ptr;
	if (addr & PAGE_MASK) {
		return -EINVAL;
	}
	if (size & PAGE_MASK) {
		return -EINVAL;
	}
	shm_free_pages_locked(addr, size);
}
