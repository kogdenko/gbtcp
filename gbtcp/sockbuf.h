// gpl2 license
#ifndef GBTCP_SOCKBUF_H
#define GBTCP_SOCKBUF_H

#include "list.h"

#define SOCKBUF_CHUNK_SIZE 2048

struct sockbuf {
	int sob_max;
	int sob_len;
	struct dlist sob_head;
};

int sockbuf_mod_init(void **);
int sockbuf_mod_attach(void *);
void sockbuf_mod_deinit();
void sockbuf_mod_detach();

void sockbuf_init(struct sockbuf *, int);
void sockbuf_free(struct sockbuf *);
int sockbuf_full(struct sockbuf *);
void sockbuf_set_max(struct sockbuf *, int);
int sockbuf_space(struct sockbuf *);
int sockbuf_add(struct mbuf_pool *, struct sockbuf *, const void *, int);
int sockbuf_readv(struct sockbuf *, const struct iovec *, int, int, int);
int sockbuf_readv4(struct sockbuf *, const struct iovec *, int, int);
int sockbuf_read(struct sockbuf *, void *, int, int);
int sockbuf_read_zerocopy(struct sockbuf *, void **);

int sockbuf_drain(struct sockbuf *, int);
void sockbuf_copy(struct sockbuf *, int, u_char *, int);
int sockbuf_rewrite(struct sockbuf *, const void *, int);

#endif // GBTCP_SOCKBUF_H
