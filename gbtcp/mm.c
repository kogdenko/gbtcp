#include "internals.h"

#define NAME "gbtcp"

struct mm_bootstrap {
	void *mbt_addr;
	struct spinlock mbt_lock;
	struct dlist mbt_head;
	int mbt_npages;
	u_char *mbt_pages;
};

struct mm_region {
	struct dlist mr_list;
	int mr_size;
};

struct mm_bootstrap *mbt;

int
mm_create()
{
	int i, n, rc, fd, npages;
	void *ptr;
	npages = 2056;
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
	mbt = ptr;
	mbt->mbt_addr = ptr;
	spinlock_init(&mbt->mbt_lock);
	dlist_init(&mbt->mbt_head);
	mbt->mbt_npages = npages;
	mbt->mbt_pages = (u_char *)(mbt + 1);
	memset(mbt->mbt_pages, 0, npages);
	n = (sizeof(*mbt) + npages) >> PAGE_SHIFT;
	if (n == 0)
		n = 1;
	for (i = 0; i < n; ++i) {
		mbt->mbt_pages[i] = 1;
	}
	printf("busy %d\n", n);
	return 0;
}

int
mm_open()
{
#if 0
	return 0;
#else
	int rc, fd, size;
	void *ptr, *addr;
	rc = shm_open(NAME, O_RDWR, 0666);
	if (rc == -1) {
		return -errno;
	}
	fd = rc;
	ptr = mmap(0, sizeof(*mbt), PROT_READ|PROT_WRITE,
	           MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		sys_close(NULL, fd);
		return -errno;
	}
	mbt = ptr;
	size = mbt->mbt_npages * PAGE_SIZE;
	addr = mbt->mbt_addr;
	munmap(ptr, sizeof(*mbt));
	ptr = mmap(addr, size, PROT_READ|PROT_WRITE,
	           MAP_SHARED|MAP_FIXED, fd, 0);
	if (ptr == MAP_FAILED) {
		sys_close(NULL, fd);
		return -errno;
	}
	mbt = ptr;
	return 0;
#endif
}

int
vmalloc_locked(void **pp, int size)
{
	int n, i, s, rem;
	struct mm_region *r, *r2;
	r2 = NULL;
	DLIST_FOREACH(r, &mbt->mbt_head, mr_list) {
		if (r->mr_size >= size + sizeof(*r)) {
			if (r2 == NULL || r2->mr_size > r->mr_size) {
				r2 = r;
			}
		}
	}
	printf("r2=%p\n", r2);
	if (r2 != NULL) {
		r = r2;
		DLIST_REMOVE(r, mr_list);
		goto out;
	}
	n = (size + sizeof(*r)) >> PAGE_SHIFT;
	if (!n) {
		n = 1;
	}
	s = 0;
	printf("npages=%d, n=%d\n", mbt->mbt_npages, n);
	for (i = 0; i < mbt->mbt_npages; ++i) {
		if (mbt->mbt_pages[i]) {
			s = i + 1;
		} else if (i - s == n) {
			goto _1;			
		}
	}
	printf("NOMEM\n");
	return -ENOMEM;
_1:
	printf("1 %d\n", s);
	for (i = s; i < s + n; ++i) {
		mbt->mbt_pages[i] = 1;
	}
	printf("2\n");
	r = (struct mm_region *)(((u_char *)mbt) + s * PAGE_SIZE);
	r->mr_size = n * PAGE_SIZE;
out:
	rem = r->mr_size - (size + sizeof(*r));
	if (rem > 128) {
		r->mr_size = size + sizeof(*r);
		r2 = (struct mm_region *)(((u_char *)r) + r->mr_size);
		r2->mr_size = rem;
		DLIST_INSERT_HEAD(&mbt->mbt_head, r2, mr_list);
	}
	*pp = r + 1;
	return 0;
}
int
mm_alloc(struct log *log, void **pp, int size)
{
	int rc;
	spinlock_lock(&mbt->mbt_lock);
	rc = vmalloc_locked(pp, size);
	printf("vmalloc %d\n", rc);
	spinlock_unlock(&mbt->mbt_lock);
	printf("alloc %d\n", rc);
	return rc;
}
void
mm_free(void *p)
{
}
