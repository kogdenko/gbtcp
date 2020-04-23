/* GPL2 license */
#ifndef GBTCP_SHM_H
#define GBTCP_SHM_H

struct log;

int shm_init(void **, int);
int shm_attach(void **);
int shm_alloc(struct log *, void **, int);
void shm_free(void *);
int shm_alloc_page(struct log *, void **, int, int);
void shm_free_page(void *, int);

#endif /* GBTCP_SHM_H */
