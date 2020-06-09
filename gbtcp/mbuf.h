// GPL2 license
#ifndef GBTCP_MBUF_H
#define GBTCP_MBUF_H

#include "subr.h"
#include "list.h"

#define MBUF_CHUNKS_MAX 2048

struct mbuf {
	struct dlist mb_list;
	uint16_t mb_magic;
	u_char mb_sid;
	u_int mb_used : 1;
	u_int mb_allocated : 1;
};

struct mbuf_pool {
	int mbp_mbuf_size;
	int mbp_mbufs_per_chunk;
	u_char mbp_id;
	u_char mbp_sid;
	struct dlist mbp_avail_chunkq;
	struct dlist mbp_empty_chunkq;
	struct mbuf_chunk *mbp_chunks[MBUF_CHUNKS_MAX]; // FIXME: allocate exact size
	int mbp_nr_chunks;
};

#define MBUF_FOREACH_SAFE(m, p, tmp_id) \
	for (m = mbuf_next(p, 0); \
	     m != NULL && ((tmp_id = mbuf_get_id(m) + 1), 1); \
	     m = mbuf_next(p, tmp_id))

int mbuf_mod_init(void **);
int mbuf_mod_attach(void *);
int mbuf_mod_service_init(struct service *);
void mbuf_mod_deinit();
void mbuf_mod_detach();

void mbuf_pool_init(struct mbuf_pool *, u_char, int);
void mbuf_pool_deinit(struct mbuf_pool *);
int mbuf_pool_is_empty(struct mbuf_pool *);

int mbuf_alloc(struct mbuf_pool *, struct mbuf **);
int mbuf_alloc3(struct mbuf_pool *, uint32_t, struct mbuf **);
void mbuf_init(struct mbuf *);
void mbuf_free(struct mbuf *);
void mbuf_free_direct(struct mbuf *m);
void mbuf_free_rcu(struct mbuf *);
struct mbuf *mbuf_get(struct mbuf_pool *, uint32_t);
struct mbuf *mbuf_next(struct mbuf_pool *, uint32_t);
int mbuf_get_id(struct mbuf *);
struct mbuf_pool *mbuf_get_pool(struct mbuf *m);

#endif // GBTCP_MBUF_H
