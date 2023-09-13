// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_MBUF_H
#define GBTCP_MBUF_H

#include "list.h"

enum mbuf_area {
	MBUF_AREA_NONE,
	MBUF_AREA_POOL,
	MBUF_AREA_HEAP,
};

#define MBUF_NO_ID 0

struct mbuf {
	struct dlist mb_list;
	struct mbuf_chunk *mb_chunk;
	uint32_t mb_size;
	uint16_t mb_magic;
	u_char mb_freed;
	u_char mb_area;
};

struct mbuf_chunk {
	struct dlist mbc_list;
	struct dlist mbc_mbuf_head;
	struct mbuf_pool *mbc_pool;
	int mbc_n_mbufs;
	short mbc_id;
};

struct mbuf_pool {
	int mbp_mbuf_size;
	int mbp_chunk_size;
	int mbp_mbufs_per_chunk;
	int mbp_chunk_map_size;
	int mbp_n_allocated_chunks;
	u_char mbp_sid;
	u_char mbp_referenced;
	struct dlist mbp_avail_chunk_head;
	struct dlist mbp_not_avail_chunk_head;
	struct mbuf_chunk **mbp_chunk_map;
};

#define MBUF_FOREACH_SAFE(m, p, tmp_id) \
	for (m = mbuf_next(p, 0); \
	     m != NULL && ((tmp_id = mbuf_get_id(m) + 1), 1); \
	     m = mbuf_next(p, tmp_id))

int mbuf_mod_init(void **);
void mbuf_mod_deinit(void);

int mbuf_pool_alloc(struct mbuf_pool **, u_char, int, int, int);
void mbuf_pool_free(struct mbuf_pool *);

int mbuf_alloc(struct mbuf_pool *, struct mbuf **);
int mbuf_alloc3(struct mbuf_pool *, uint32_t, struct mbuf **);
void mbuf_init(struct mbuf *, u_char);
void mbuf_free(struct mbuf *);
void mbuf_free_direct(struct mbuf *);
void mbuf_free_direct_list(struct dlist *);
void mbuf_free_rcu(struct mbuf *);
struct mbuf *mbuf_get(struct mbuf_pool *, uint32_t);
struct mbuf *mbuf_next(struct mbuf_pool *, uint32_t);
int mbuf_get_id(struct mbuf *);
#define mbuf_get_pool(m) \
	((m)->mb_chunk == NULL ? NULL : (m)->mb_chunk->mbc_pool)

#endif // GBTCP_MBUF_H
