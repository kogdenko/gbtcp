/* GPL2 license */
#ifndef GBTCP_MBUF_H
#define GBTCP_MBUF_H

#include "subr.h"
#include "list.h"

#define MBUF_CHUNKS_MAX 2048

struct mbuf {
	struct dlist mb_list;
	union {
		uint32_t mb_flags;
		struct {
			uint16_t mb_magic;
			uint8_t mb_used;
			uint8_t mb_pool_id;
		};
	};
};

struct mbuf_pool {
	int mbp_mbuf_size;
	int mbp_mbufs_per_chunk;
	uint8_t mbp_id;
	struct dlist mbp_avail_chunkq;
	struct dlist mbp_empty_chunkq;
	struct mchunk *mbp_chunks[MBUF_CHUNKS_MAX];
	int mbp_nr_chunks;
};

#define MBUF_FOREACH_SAFE(m, p, tmp_id) \
	for (m = mbuf_next(p, 0); \
	     m != NULL && ((tmp_id = mbuf_get_id(p, m) + 1), 1); \
	     m = mbuf_next(p, tmp_id))

int mbuf_mod_init(struct log *, void **);
int mbuf_mod_attach(struct log *, void *);
void mbuf_mod_deinit(struct log *, void *);
void mbuf_mod_detach(struct log *);

int mbuf_pool_alloc(struct log *, struct mbuf_pool **, int);
int mbuf_pool_is_empty(struct mbuf_pool *);
void mbuf_pool_free(struct mbuf_pool *);

int mbuf_alloc(struct log *, struct mbuf_pool *, struct mbuf **);
int mbuf_alloc4(struct log *, struct mbuf_pool *, uint32_t, struct mbuf **);
void mbuf_init(struct mbuf *);
void mbuf_free(struct mbuf *);
struct mbuf *mbuf_get(struct mbuf_pool *, uint32_t);
struct mbuf *mbuf_next(struct mbuf_pool *, uint32_t);
int mbuf_get_id(struct mbuf_pool *, struct mbuf *);

#endif /* GBTCP_MBUF_H */
