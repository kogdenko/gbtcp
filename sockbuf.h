#ifndef GBTCP_SOCKBUF_H
#define GBTCP_SOCKBUF_H

#include "list.h"

struct gt_sockbuf {
	int sob_max;
	int sob_len;
	struct gt_list_head sob_head;
};

int gt_sockbuf_mod_init();

void gt_sockbuf_mod_deinit(struct gt_log *err);

void gt_sockbuf_init(struct gt_sockbuf *b, int max);

void gt_sockbuf_free(struct gt_sockbuf *b);

int gt_sockbuf_full(struct gt_sockbuf *b);

void gt_sockbuf_set_max(struct gt_sockbuf *b, int max);

int gt_sockbuf_add(struct gt_sockbuf *b, const void *buf, int cnt, int atomic);

int gt_sockbuf_readv(struct gt_sockbuf *b,
	const struct iovec *iov, int iovcnt, int cnt, int peek);

int gt_sockbuf_readv4(struct gt_sockbuf *b,
	const struct iovec *iov, int iovcnt, int peek);

int gt_sockbuf_recv(struct gt_sockbuf *b, void *dst, int cnt, int peek);

int gt_sockbuf_pop(struct gt_sockbuf *b, int cnt);

void gt_sockbuf_send(struct gt_sockbuf *b, int off, void *dst, int cnt);

int gt_sockbuf_rewrite(struct gt_sockbuf *b, const void *dst, int cnt);

#endif /* GBTCP_SOCKBUF_H */
