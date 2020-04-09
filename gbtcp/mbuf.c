#include "log.h"
#include "sys.h"
#include "subr.h"
#include "mbuf.h"

#define GT_MBUF_MAGIC 0xcafe

#define GT_MBUF_CHUNK_SIZE (2 * 1024 * 1024)
#define GT_MBUF_CHUNK_DATA_SIZE \
	(GT_MBUF_CHUNK_SIZE - sizeof(struct gt_mbuf_chunk))

#define MBUF_LOG_MSG_FOREACH(x) \
	x(mod_deinit) \
	x(pool_new) \
	x(alloc) \
	x(chunk_alloc) \

struct mbuf_mod {
	struct log_scope log_scope;
	MBUF_LOG_MSG_FOREACH(LOG_MSG_DECLARE);
};

struct gt_mbuf_chunk {
	struct dllist c_list;
	struct dllist c_freeq;
	int c_freeq_size;
	short c_id;
};

static struct mbuf_mod *this_mod;

static struct gt_mbuf_pool *gt_mbuf_pools[256];

static struct gt_mbuf_chunk *gt_mbuf_get_chunk(struct gt_mbuf *m);

static void gt_mbuf_chunk_pop_freeq(struct gt_mbuf_pool *p,
	struct gt_mbuf_chunk *chunk, struct gt_mbuf *m);

static int gt_mbuf_chunk_alloc(struct gt_log *log, struct gt_mbuf_pool *p,
	struct gt_mbuf_chunk **pchunk);

static int gt_mbuf_chunk_is_empty(struct gt_mbuf_pool *p,
	struct gt_mbuf_chunk *chunk);

static void gt_mbuf_chunk_free(struct gt_mbuf_pool *p,
	struct gt_mbuf_chunk *chunk);

#define GT_MBUF_GET(p, chunk, i) \
	(struct gt_mbuf *)(((uint8_t *)(chunk + 1)) + i * p->mbp_mbuf_size);

int
gt_mbuf_mod_init()
{
	log_scope_init(&this_mod->log_scope, "mbuf");
	return 0;
}

void
gt_mbuf_mod_deinit(struct gt_log *log)
{
	LOG_TRACE(log);
	log_scope_deinit(log, &this_mod->log_scope);
}

int
gt_mbuf_pool_new(struct gt_log *log, struct gt_mbuf_pool **pp, int mbuf_size)
{
	int i, rc, id;
	struct gt_mbuf_pool *p;

	ASSERT(mbuf_size >= sizeof(struct gt_mbuf));
	LOG_TRACE(log);
	mbuf_size = GT_ROUND_UP(mbuf_size, GT_CACHE_LINE_SIZE);
	id = -1;
	for (i = 0; i < GT_ARRAY_SIZE(gt_mbuf_pools); ++i) {
		if (gt_mbuf_pools[i] == NULL) {
			id = i;
			break;
		}
	}
	if (id == -1) {
		LOGF(log, pool_new, LOG_ERR, 0, "no pool slots");
		return -ENFILE;
	}
	p = gt_mbuf_pools[id];
	if (p != NULL) {
		goto out;
	}
	rc = gt_sys_malloc(log, (void **)&p, sizeof(*p));
	if (rc) {
		return rc;
	}
	memset(p, 0, sizeof(*p));
	p->mbp_id = id;
	p->mbp_mbuf_size = mbuf_size;
	p->mbp_mbufs_per_chunk = GT_MBUF_CHUNK_DATA_SIZE / mbuf_size;
	dllist_init(&p->mbp_avail_chunkq);
	dllist_init(&p->mbp_empty_chunkq);
	p->mbp_nr_chunks = GT_ARRAY_SIZE(p->mbp_chunks);
	gt_mbuf_pools[p->mbp_id] = p;
out:
	if (pp != NULL) {
		*pp = p;
	}
	return 0;
}

int
gt_mbuf_pool_is_empty(struct gt_mbuf_pool *p)
{
	int rc;
	struct gt_mbuf_chunk *chunk;

	rc = dllist_isempty(&p->mbp_empty_chunkq);
	if (rc == 0) {
		return 0;
	}
	DLLIST_FOREACH(chunk, &p->mbp_avail_chunkq, c_list) {
		rc = gt_mbuf_chunk_is_empty(p, chunk);
		if (rc == 0) {
			return 0;
		}
	}
	return 1;
}

void
gt_mbuf_pool_del(struct gt_mbuf_pool *p)
{
	struct gt_mbuf_chunk *chunk;

	ASSERT(dllist_isempty(&p->mbp_empty_chunkq));
	while (!dllist_isempty(&p->mbp_avail_chunkq)) {
		chunk = DLLIST_FIRST(&p->mbp_avail_chunkq,
		                     struct gt_mbuf_chunk,
		                     c_list);
		gt_mbuf_chunk_free(p, chunk);
	}
	gt_mbuf_pools[p->mbp_id] = NULL;
	free(p);
}

int
gt_mbuf_alloc(struct gt_log *log, struct gt_mbuf_pool *p, struct gt_mbuf **mp)
{
	int i, rc;
	struct gt_mbuf *m;
	struct gt_mbuf_chunk *chunk;

	*mp = NULL;
	if (dllist_isempty(&p->mbp_avail_chunkq)) {
		LOG_TRACE(log);
		rc = gt_mbuf_chunk_alloc(log, p, &chunk);
		if (rc) {
			return rc;
		}
		for (i = 0; i < GT_ARRAY_SIZE(p->mbp_chunks); ++i) {
			if (p->mbp_chunks[i] == NULL) {
				chunk->c_id = i;
				p->mbp_chunks[i] = chunk;
				break;
			}
		}
		ASSERT(i < GT_ARRAY_SIZE(p->mbp_chunks));
	}
	ASSERT(!dllist_isempty(&p->mbp_avail_chunkq));
	chunk = DLLIST_FIRST(&p->mbp_avail_chunkq,
	                      struct gt_mbuf_chunk, c_list);
	ASSERT(chunk->c_freeq_size);
	m = DLLIST_FIRST(&chunk->c_freeq, struct gt_mbuf, mb_list);
	gt_mbuf_chunk_pop_freeq(p, chunk, m);
	*mp = m;
	return 0;
}

int
gt_mbuf_alloc4(struct gt_log *log, struct gt_mbuf_pool *p, uint32_t m_id,
	struct gt_mbuf **mp)
{
	int i, rc, chunk_id;
	struct gt_mbuf *m;
	struct gt_mbuf_chunk *chunk;

	LOG_TRACE(log);
	*mp = NULL;
	chunk_id = m_id / p->mbp_mbufs_per_chunk;
	if (chunk_id >= GT_ARRAY_SIZE(p->mbp_chunks)) {
		LOGF(log, alloc, LOG_ERR, 0, "too big id; m_id=%u", m_id);
		return -ENFILE;
	}
	chunk = p->mbp_chunks[chunk_id];
	if (chunk == NULL) {
		rc = gt_mbuf_chunk_alloc(log, p, &chunk);
		if (rc) {
			return rc;
		}
		p->mbp_chunks[chunk_id] = chunk;
		chunk->c_id = chunk_id;
	}
	i = m_id % p->mbp_mbufs_per_chunk;
	m = GT_MBUF_GET(p, chunk, i);
	if (m->mb_used) {
		LOGF(log, alloc, LOG_ERR, 0, "already allocated; m_id=%d", m_id);
		return -EBUSY;
	} else {
		gt_mbuf_chunk_pop_freeq(p, chunk, m);
		*mp = m;
		return 0;
	}
}

void
gt_mbuf_init(struct gt_mbuf *m)
{
	m->mb_magic = GT_MBUF_MAGIC;
	m->mb_used = 1;
	m->mb_pool_id = UINT8_MAX;
}

void
gt_mbuf_free(struct gt_mbuf *m)
{
	struct gt_mbuf_chunk *chunk;
	struct gt_mbuf_pool *p;

	if (m == NULL) {
		return;
	}
	ASSERT(m->mb_magic == GT_MBUF_MAGIC);
	ASSERT(m->mb_used == 1);
	ASSERT(m->mb_pool_id < GT_ARRAY_SIZE(gt_mbuf_pools));
	p = gt_mbuf_pools[m->mb_pool_id];
	m->mb_used = 0;
	chunk = gt_mbuf_get_chunk(m);
	DLLIST_INSERT_HEAD(&chunk->c_freeq, m, mb_list);
	ASSERT(chunk->c_freeq_size < p->mbp_mbufs_per_chunk);
	if (chunk->c_freeq_size == 0) {
		DLLIST_REMOVE(chunk, c_list);
		DLLIST_INSERT_TAIL(&p->mbp_avail_chunkq, chunk, c_list);
	}
	chunk->c_freeq_size++;
}

struct gt_mbuf *
gt_mbuf_get(struct gt_mbuf_pool *p, uint32_t m_id)
{
	int chunk_id, i;
	struct gt_mbuf *m;
	struct gt_mbuf_chunk *chunk;

	chunk_id = m_id / p->mbp_mbufs_per_chunk;
	if (chunk_id >= GT_ARRAY_SIZE(p->mbp_chunks)) {
		return NULL;
	}
	chunk = p->mbp_chunks[chunk_id];
	if (chunk == NULL) {
		return NULL;
	}
	i = m_id % p->mbp_mbufs_per_chunk;
	m = GT_MBUF_GET(p, chunk, i);
	if (m->mb_used) {
		return m;
	} else {
		return NULL;
	}
}

struct gt_mbuf *
gt_mbuf_next(struct gt_mbuf_pool *p, uint32_t m_id)
{
	int i, chunk_id;
	struct gt_mbuf_chunk *chunk;
	struct gt_mbuf *m;

	chunk_id = m_id / p->mbp_mbufs_per_chunk;
	i = m_id % p->mbp_mbufs_per_chunk;
	for (; chunk_id < GT_ARRAY_SIZE(p->mbp_chunks); ++chunk_id) {
		chunk = p->mbp_chunks[chunk_id];
		if (chunk != NULL) {
			for (; i < p->mbp_mbufs_per_chunk; ++i) {
				m = GT_MBUF_GET(p, chunk, i);
				if (m->mb_used) {
					return m;
				}
			}
			i = 0;
		}
	}
	return NULL;
}

int
gt_mbuf_get_id(struct gt_mbuf_pool *p, struct gt_mbuf *m)
{
	int i, m_id;
	struct gt_mbuf_chunk *chunk;

	ASSERT(m->mb_magic == GT_MBUF_MAGIC);
	chunk = gt_mbuf_get_chunk(m);
	i = ((uint8_t *)m - (uint8_t *)(chunk + 1)) / p->mbp_mbuf_size;
	m_id = chunk->c_id * p->mbp_mbufs_per_chunk + i;
	return m_id;
}

static struct gt_mbuf_chunk *
gt_mbuf_get_chunk(struct gt_mbuf *m)
{
	uintptr_t x;

	x = GT_ROUND_DOWN(((uintptr_t)m), GT_MBUF_CHUNK_SIZE);
	return (struct gt_mbuf_chunk *)x;
}

static void
gt_mbuf_chunk_pop_freeq(struct gt_mbuf_pool *p, struct gt_mbuf_chunk *chunk,
	struct gt_mbuf *m)
{
	ASSERT(m->mb_used == 0);
	DLLIST_REMOVE(m, mb_list);
	chunk->c_freeq_size--;
	if (chunk->c_freeq_size == 0) {
		DLLIST_REMOVE(chunk, c_list);
		DLLIST_INSERT_HEAD(&p->mbp_empty_chunkq, chunk, c_list);
	}
	m->mb_used = 1;
}

static int
gt_mbuf_chunk_alloc(struct gt_log *log, struct gt_mbuf_pool *p,
	struct gt_mbuf_chunk **pchunk)
{
	int i, rc;
	struct gt_mbuf_chunk *chunk;
	struct gt_mbuf *m;

	LOG_TRACE(log);
	if (p->mbp_nr_chunks == 0) {
		LOGF(log, chunk_alloc, LOG_ERR, 0, "no chunk slots"); 
		return -ENOMEM;
	}
	rc = gt_sys_posix_memalign(log, (void **)pchunk,
	                           GT_MBUF_CHUNK_SIZE, GT_MBUF_CHUNK_SIZE);
	if (rc) {
		return rc;
	}
	p->mbp_nr_chunks--;
	chunk = *pchunk;
	dllist_init(&chunk->c_freeq);
	chunk->c_freeq_size = p->mbp_mbufs_per_chunk;
	for (i = 0; i < chunk->c_freeq_size; ++i) {
		m = GT_MBUF_GET(p, chunk, i);
		m->mb_magic = GT_MBUF_MAGIC;
		m->mb_used = 0;
		m->mb_pool_id = p->mbp_id;
		DLLIST_INSERT_TAIL(&chunk->c_freeq, m, mb_list);
	}
	DLLIST_INSERT_TAIL(&p->mbp_avail_chunkq, chunk, c_list);
	return 0;
}

static int
gt_mbuf_chunk_is_empty(struct gt_mbuf_pool *p, struct gt_mbuf_chunk *chunk)
{
	return chunk->c_freeq_size == p->mbp_mbufs_per_chunk;
}

static void
gt_mbuf_chunk_free(struct gt_mbuf_pool *p, struct gt_mbuf_chunk *chunk)
{
	DLLIST_REMOVE(chunk, c_list);
	free(chunk);
}
