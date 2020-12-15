// gpl2
#ifndef GBTCP_SOCKBUF_H
#define GBTCP_SOCKBUF_H

#include "list.h"

struct sock_buf {
	int sob_max;
	int sob_len;
	struct dlist sob_head;
};

void sockbuf_init(struct sock_buf *, int);
void sockbuf_free(struct sock_buf *);
int sockbuf_full(struct sock_buf *);
void sockbuf_set_max(struct sock_buf *, int);
int sockbuf_space(struct sock_buf *);
int sockbuf_add(struct sock_buf *, const void *, int);
int sockbuf_readv(struct sock_buf *, const struct iovec *, int, int, int);
int sockbuf_readv4(struct sock_buf *, const struct iovec *, int, int);
int sockbuf_read(struct sock_buf *, void *, int, int);
int sockbuf_read_zerocopy(struct sock_buf *, void **);

int sockbuf_drain(struct sock_buf *, int);
void sockbuf_copy(struct sock_buf *, int, u_char *, int);
int sockbuf_rewrite(struct sock_buf *, const void *, int);

#endif // GBTCP_SOCKBUF_H
