// gpl2
#ifndef GBTCP_SHM_H
#define GBTCP_SHM_H

#include "subr.h"

int shm_mod_init();

int shm_init();
int shm_attach();
void shm_deinit();
void shm_detach();

void shm_lock();
void shm_unlock();

void shm_garbage_push(struct service *);
void shm_garbage_pop(struct dlist *, u_char);

uint64_t shm_get_nanoseconds();
void shm_set_nanoseconds(uint64_t);

#define shm_ns shm_get_nanoseconds()

void *shm_malloc(size_t);
void *shm_realloc(void *, size_t);
void shm_free(void *);
int shm_alloc_pages(void **, size_t, size_t);
void shm_free_pages(void *, size_t);

#endif // GBTCP_SHM_H
