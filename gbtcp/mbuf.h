// gpl2 license
#ifndef GBTCP_MBUF_H
#define GBTCP_MBUF_H

#include "list.h"

enum mbuf_area {
	MBUF_AREA_NONE,
	MBUF_AREA_POOL,
	MBUF_AREA_HEAP,
};

struct mbuf {
	struct dlist mb_list;
	uint32_t mb_size;
	uint16_t mb_magic;
	u_char mb_freed;
	u_char mb_area;
};

struct mbuf_pool {
	int mbp_mbuf_size;
	int mbp_mbufs_per_chunk;
	u_char mbp_sid;
	u_char mbp_referenced;
	struct dlist mbp_avail_chunk_head;
	struct dlist mbp_not_avail_chunk_head;
	struct mbuf_chunk **mbp_chunk_map;
	int mbp_chunk_map_size;
	int mbp_n_allocated_chunks;
	const char *mbp_name;
};

#define MBUF_FOREACH_SAFE(m, p, tmp_id) \
	for (m = mbuf_next(p, 0); \
	     m != NULL && ((tmp_id = mbuf_get_id(m) + 1), 1); \
	     m = mbuf_next(p, tmp_id))

int mbuf_mod_init(void **);
int mbuf_mod_service_init(struct service *);
void mbuf_mod_deinit();
void mbuf_mod_service_deinit(struct service *);

int mbuf_pool_alloc(struct mbuf_pool **, u_char, const char *, int, int);
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
struct mbuf_pool *mbuf_get_pool(struct mbuf *m);

#endif // GBTCP_MBUF_H
