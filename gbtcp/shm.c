// gpl2
#include "internals.h"

#define CURMOD shm

#define SHM_MAGIC 0xb9d1
#define SHM_PATH GT_PREFIX"/shm"
#define SHM_SIZE (1024*1024*1204) // 1 Gb

struct shm_mod {
	struct log_scope log_scope;
	int shm_n_allocated_pages;
};

static int shm_fd = -1;

struct shm_hdr *shared;

void mem_buddy_init();

int
shm_init()
{
	int i, rc;
	size_t size;
	struct stat buf;

	NOTICE(0, "hit;");
	size = SHM_SIZE;
	rc = sys_open(SHM_PATH, O_CREAT|O_RDWR, 0666);
	if (rc < 0) {
		goto err;
	}
	shm_fd = rc;
	fchgrp(shm_fd, &buf, GT_GROUP_NAME);
	rc = sys_ftruncate(shm_fd, size);
	if (rc) {
		goto err;
	}
	rc = sys_mmap((void **)&shared, NULL, size, PROT_READ|PROT_WRITE,
		MAP_SHARED, shm_fd, 0);
	if (rc) {
		goto err;
	}
	memset(shared, 0, sizeof(*shared));
	shared->shm_ns = nanoseconds;
	shared->msb_begin = (uintptr_t)shared;
	spinlock_init(&shared->msb_lock);
	shared->msb_end = shared->msb_begin + size;
	for (i = 0; i < ARRAY_SIZE(shared->msb_garbage); ++i) {
		dlist_init(shared->msb_garbage + i);
	}
	for (i = 0; i < ARRAY_SIZE(shared->msb_buddy_area); ++i) {
		dlist_init(&shared->msb_buddy_area[i]);
	}
	mem_buddy_init();
	dlist_init(&shared->shm_proc_head);
	NOTICE(0, "ok; addr=%p", (void *)shared->msb_begin);
	return 0;
err:
	ERR(-rc, "failed;");
	shm_deinit();
	return rc;
}

int
shm_attach()
{
	int rc;
	size_t size;
	void *addr;
	struct shm_hdr *tmp;

	rc = sys_open(SHM_PATH, O_RDWR, 0666);
	if (rc < 0) {
		return rc;
	}
	shm_fd = rc;
	rc = sys_mmap((void **)&tmp, NULL, sizeof(*tmp), PROT_READ,
		MAP_SHARED, shm_fd, 0);
	if (rc) {
		sys_close(&shm_fd);
		return rc;
	}
	size = tmp->msb_end - tmp->msb_begin;
	addr = (void *)tmp->msb_begin;
	sys_munmap(tmp, sizeof(*tmp));
	rc = sys_mmap((void **)&shared, addr, size, PROT_READ|PROT_WRITE,
		MAP_SHARED|MAP_FIXED, shm_fd, 0);
	if (rc) {
		sys_close(&shm_fd);
	}
	return rc;
}

void
shm_detach()
{
	size_t size;

	if (shared != NULL) {
		size = shared->msb_end - shared->msb_begin;
		sys_munmap(shared, size);
		shared = NULL;
	}
	sys_close(&shm_fd);
}

void
shm_deinit()
{
	int i;

	NOTICE(0, "hit;");
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
