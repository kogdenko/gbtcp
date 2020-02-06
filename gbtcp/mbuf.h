#ifndef GBTCP_MBUF_H
#define GBTCP_MBUF_H

#include "subr.h"
#include "list.h"

#define GT_MBUF_CHUNKS_MAX 2048

struct gt_mbuf {
	struct gt_list_head mb_list;
	union {
		uint32_t mb_flags;
		struct {
			uint16_t mb_magic;
			uint8_t mb_used;
			uint8_t mb_pool_id;
		};
	};
};

struct gt_mbuf_pool {
	int mbp_mbuf_size;
	int mbp_mbufs_per_chunk;
	uint8_t mbp_id;
	struct gt_list_head mbp_avail_chunkq;
	struct gt_list_head mbp_empty_chunkq;
	struct gt_mbuf_chunk *mbp_chunks[GT_MBUF_CHUNKS_MAX];
	int mbp_nr_chunks;
};

#define GT_MBUF_FOREACH_SAFE(m, p, tmp_id) \
	for (m = gt_mbuf_next(p, 0); \
	     m != NULL && ((tmp_id = gt_mbuf_get_id(p, m) + 1), 1); \
	     m = gt_mbuf_next(p, tmp_id))

int gt_mbuf_mod_init();

void gt_mbuf_mod_deinit(struct gt_log *log);

int gt_mbuf_pool_new(struct gt_log *log, struct gt_mbuf_pool **pp,
	int mbuf_size);

int gt_mbuf_pool_is_empty(struct gt_mbuf_pool *p);

void gt_mbuf_pool_del(struct gt_mbuf_pool *p);

int gt_mbuf_alloc(struct gt_log *log, struct gt_mbuf_pool *p,
	struct gt_mbuf **mp);
#define mballoc gt_mbuf_alloc

int gt_mbuf_alloc4(struct gt_log *log, struct gt_mbuf_pool *p, uint32_t m_id,
	struct gt_mbuf **mp);

void gt_mbuf_init(struct gt_mbuf *m);

void gt_mbuf_free(struct gt_mbuf *m);
#define mbfree gt_mbuf_free

struct gt_mbuf *gt_mbuf_get(struct gt_mbuf_pool *p, uint32_t m_id);

struct gt_mbuf *gt_mbuf_next(struct gt_mbuf_pool *p, uint32_t m_id);

int gt_mbuf_get_id(struct gt_mbuf_pool *p, struct gt_mbuf *m);

#endif /* GBTCP_MBUF_H */
