#ifndef GBTCP_SOCKBUF_H
#define GBTCP_SOCKBUF_H

#include "list.h"

struct sockbuf {
	int sob_max;
	int sob_len;
	struct dlist sob_head;
};

int sockbuf_mod_init(struct log *, void **);
int sockbuf_mod_attach(struct log *, void *);
void sockbuf_mod_deinit(struct log *, void *);
void sockbuf_mod_detach(struct log *);

void sockbuf_init(struct sockbuf *, int);
void sockbuf_free(struct sockbuf *);
int sockbuf_full(struct sockbuf *);
void sockbuf_set_max(struct sockbuf *, int);
int sockbuf_add(struct sockbuf *, const void *, int, int);
int sockbuf_readv(struct sockbuf *, const struct iovec *, int, int, int);
int sockbuf_readv4(struct sockbuf *, const struct iovec *, int, int);
int sockbuf_recv(struct sockbuf *, void *, int, int);
int sockbuf_drop(struct sockbuf *, int);
void sockbuf_copy(struct sockbuf *, int, u_char *, int);
int sockbuf_rewrite(struct sockbuf *, const void *, int);

#endif // GBTCP_SOCKBUF_H
