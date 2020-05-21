// GPL2 license
#ifndef GBTCP_SHM_H
#define GBTCP_SHM_H

#include "subr.h"

int shm_init(struct log *, void **, int);
int shm_attach(struct log *, void **);
void shm_deinit(struct log *);
void shm_detach(struct log *);
int shm_malloc(struct log *, void **, size_t);
int shm_realloc(struct log *, void **, int);
void shm_free(void *);
int shm_alloc_page(struct log *, void **, int, int);
void shm_free_page(void *, int);

#endif // GBTCP_SHM_H
