// gpl2 license
#ifndef GBTCP_SHM_H
#define GBTCP_SHM_H

#include "subr.h"

int shm_init(void **, int);
int shm_attach(void **);
void shm_deinit();
void shm_detach();

int shm_malloc(void **, size_t);
int shm_realloc(void **, size_t);
void shm_free(void *);
int shm_alloc_pages(void **, size_t, size_t);
void shm_free_pages(void *, size_t);

#endif // GBTCP_SHM_H
