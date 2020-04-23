#include "internals.h"

#define NAME "gbtcp"

struct shm_hdr {
	uintptr_t shm_addr;
	struct spinlock shm_lock;
	struct dlist shm_free_region_head;
	int shm_npages;
	u_char *shm_pageset;
};

struct shm_region {
	struct dlist shmr_list;
	int shmr_size;
};

static struct shm_hdr *shm;

static int
roundup_page(int size)
{
	int ret;
	ret = size & ~(PAGE_SIZE - 1);
	if (size & (PAGE_SIZE - 1)) {
		ret += PAGE_SIZE;
	}
	assert(ret >= size);
	return ret;
}

int
shm_init(void **pp, int size)
{
	int i, n, rc, fd, npages;
	void *ptr;
	npages = 256000;
	rc = shm_open(NAME, O_CREAT|O_RDWR, 0666);
	if (rc == -1) {
		return -errno;
	}
	fd = rc;
	ftruncate(fd, npages * PAGE_SIZE);
	ptr = mmap(0, npages * PAGE_SIZE, PROT_READ|PROT_WRITE,
	           MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		sys_close(NULL, fd);
		return -errno;
	}
	assert(!(((uintptr_t)ptr) & (PAGE_SIZE - 1)));
	shm = ptr;
	shm->shm_addr = (uintptr_t)ptr;
	printf("INIT1 %p %p\n", ptr, (void *)shm->shm_addr);
	spinlock_init(&shm->shm_lock);
	dlist_init(&shm->shm_free_region_head);
	shm->shm_npages = npages;
	shm->shm_pageset = (u_char *)(shm + 1);
	memset(shm->shm_pageset, 0, npages);
	n = roundup_page(sizeof(*shm) + npages + size) >> PAGE_SHIFT;
	for (i = 0; i < n; ++i) {
		shm->shm_pageset[i] = 1;
	}
	*pp  = ((u_char *)shm) + sizeof(*shm) + npages;
	memset(*pp, 0, size);
	printf("INIT2 %d\n", n);
	return 0;
}

int
shm_attach(void **pp)
{
	int rc, fd, size;
	void *ptr, *addr;
	rc = shm_open(NAME, O_RDWR, 0666);
	if (rc == -1) {
		printf("== 1\n");
		return -errno;
	}
	fd = rc;
	ptr = mmap(0, sizeof(*shm), PROT_READ|PROT_WRITE,
	           MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		sys_close(NULL, fd);
		printf("== 2\n");
		return -errno;
	}
	shm = ptr;
	printf("ATTACH %p, %p\n", shm, (void *)shm->shm_addr);
	size = shm->shm_npages * PAGE_SIZE;
	addr = (void *)shm->shm_addr;
	munmap(ptr, sizeof(*shm));
	ptr = mmap(addr, size, PROT_READ|PROT_WRITE,
	           MAP_SHARED|MAP_FIXED, fd, 0);
	if (ptr == MAP_FAILED) {
		rc = -errno;
		printf("== 3 %p %s\n", addr, strerror(-rc));
		sys_close(NULL, fd);
		return rc;
	}
	shm = ptr;
	*pp = ((u_char *)shm) + sizeof(*shm) + shm->shm_npages;
	return 0;
}

int
shm_alloc_page_locked(struct log *log, void **pp, int alignment, int size)
{
	int i, j, alignment_n, size_n;
	uintptr_t addr;
	if (alignment & (PAGE_SIZE - 1)) {
		return -EINVAL;
	}
	if (size & (PAGE_SIZE - 1)) {
		return -EINVAL;
	}
	alignment_n = alignment >> PAGE_SHIFT;
	size_n = size >> PAGE_SHIFT;
	addr = shm->shm_addr & ~(alignment - 1);
	if (addr < shm->shm_addr) {
		addr += alignment;
		assert(addr > shm->shm_addr);
	}
	for (i = (addr - shm->shm_addr) >> PAGE_SHIFT;
	     i <= shm->shm_npages - size_n; i += alignment_n) {
		for (j = i; j < i + size_n; ++j) {
			if (shm->shm_pageset[j]) {
				break;
			}
		}
		if (j == i + size_n) {
			for (j = i; j < i + size_n; ++j) {
				shm->shm_pageset[j] = 1;
			}
			*pp = (void *)(shm->shm_addr + (i << PAGE_SHIFT));
			return 0;
		}
	}
	return -ENOMEM;
}

int
shm_alloc_locked(struct log *log, void **pp, int size)
{
	int rc, rem, size2, size3;
	struct shm_region *r, *r2;
	r2 = NULL;
	size2 = size + sizeof(*r2);
	DLIST_FOREACH(r, &shm->shm_free_region_head, shmr_list) {
		if (r->shmr_size >= size2) {
			if (r2 == NULL || r2->shmr_size > r->shmr_size) {
				r2 = r;
			}
		}
	}
	if (r2 != NULL) {
		r = r2;
		DLIST_REMOVE(r, shmr_list);
		goto out;
	}
	size3 = roundup_page(size2);
	rc = shm_alloc_page_locked(log, (void **)&r, PAGE_SIZE, size3);
	if (rc) {
		return rc;
	}
	r->shmr_size = size3;
out:
	rem = r->shmr_size - size2;
	if (rem > 128) {
		r->shmr_size = size2;
		r2 = (struct shm_region *)(((u_char *)r) + r->shmr_size);
		r2->shmr_size = rem;
		DLIST_INSERT_HEAD(&shm->shm_free_region_head, r2, shmr_list);
	}
	*pp = r + 1;
	return 0;
}
#define SHM_LOCK  spinlock_lock(&shm->shm_lock)
#define SHM_UNLOCK spinlock_unlock(&shm->shm_lock);
 

int
shm_alloc(struct log *log, void **pp, int size)
{
	int rc;
	SHM_LOCK;
	rc = shm_alloc_locked(log, pp, size);
	SHM_UNLOCK;
	if (rc) {
		printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	} else {
//		printf("A %p %d\n", *pp, size);
		memset(*pp, 0, size);
	}

//	if (log != NULL rc < 0) {
//		LOG_TRACE(log);
//		LOGF(
//	}
	return rc;
}
int
shm_realloc(struct log *log, void **pp, int size)
{
	int rc, old_size;
	struct shm_region *r;
	void *new;
	if (*pp == NULL) {
		old_size = 0;
	} else {
		r = *pp;
		r--;
		old_size = r->shmr_size;
	}
	rc = shm_alloc(log, &new, size);
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
shm_alloc_page(struct log *log, void **pp, int alignment, int size)
{
	int rc;
	//return -posix_memalign(pp, alignment, size);
	SHM_LOCK;
	rc = shm_alloc_page_locked(log, pp, alignment, size);
	SHM_UNLOCK;
	if (rc) {
		printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	} else {
//		printf("A %p %d\n", *pp, size);
	}
	return rc;
}

void
shm_free_page(void *ptr, int size)
{
}
