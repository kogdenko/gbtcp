/* GPL2 license */
#ifndef GBTCP_MM_H
#define GBTCP_MM_H

struct log;

int mm_create();
int mm_open();
int mm_alloc(struct log *, void **, int);
void mm_free(void *);

#endif /* GBTCP_MM_H */
