// GPL2 license
#ifndef GBTCP_SHM_H
#define GBTCP_SHM_H

#include "subr.h"

int shm_init(void **, int);
int shm_attach(void **);
void shm_deinit();
void shm_detach();
int shm_malloc(void **, size_t);
int shm_realloc(void **, int);
void shm_free(void *);
int shm_alloc_page(void **, int, int);
void shm_free_page(void *, int);

#endif // GBTCP_SHM_H
