#include "internals.h"

#define MBUF_MAGIC 0xcafe

#define MBUF_CHUNK_SIZE (2 * 1024 * 1024)
#define MBUF_CHUNK_DATA_SIZE \
	(MBUF_CHUNK_SIZE - sizeof(struct mbuf_chunk))

#define MBUF_LOG_MSG_FOREACH(x) \
	x(alloc) \
	x(chunk_alloc) \

struct mbuf_mod {
	struct log_scope log_scope;
	MBUF_LOG_MSG_FOREACH(LOG_MSG_DECLARE);
	struct mbuf_pool *mbuf_pools[UINT8_MAX]; // FIXME: move to proc

};

struct mbuf_chunk {
	struct dlist c_list;
	struct dlist c_freeq;
	int c_freeq_size;
	short c_id;
};

static struct mbuf_mod *current_mod;

#define MBUF_GET(p, chunk, i) \
	(struct mbuf *)(((u_char *)(chunk + 1)) + i * p->mbp_mbuf_size);

int
mbuf_mod_init(struct log *log, void **pp)
{
	int rc;
	struct mbuf_mod *mod;
	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (!rc) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "mbuf");
		memset(mod->mbuf_pools, 0, sizeof(mod->mbuf_pools));
	}
	return rc;
}
int
mbuf_mod_attach(struct log *log, void *raw_mod)
{
	current_mod = raw_mod;
	return 0;
}
void
mbuf_mod_deinit(struct log *log, void *raw_mod)
{
	struct mbuf_mod *mod;
	mod = raw_mod;
	LOG_TRACE(log);
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}
void
mbuf_mod_detach(struct log *log)
{
	current_mod = NULL;
}
static struct mbuf_chunk *
mbuf_get_chunk(struct mbuf *m)
{
	uintptr_t p;
	p = ROUND_DOWN(((uintptr_t)m), MBUF_CHUNK_SIZE);
	return (struct mbuf_chunk *)p;
}
static void
mbuf_chunk_pop_freeq(struct mbuf_pool *p, struct mbuf_chunk *chunk,
	struct mbuf *m)
{
	ASSERT(m->mb_used == 0);
	DLIST_REMOVE(m, mb_list);
	chunk->c_freeq_size--;
	if (chunk->c_freeq_size == 0) {
		DLIST_REMOVE(chunk, c_list);
		DLIST_INSERT_HEAD(&p->mbp_empty_chunkq, chunk, c_list);
	}
	m->mb_used = 1;
}
static int
mbuf_chunk_alloc(struct log *log, struct mbuf_pool *p,
	struct mbuf_chunk **pchunk)
{
	int i, rc;
	struct mbuf_chunk *chunk;
	struct mbuf *m;
	LOG_TRACE(log);
	if (p->mbp_nr_chunks == 0) {
		LOGF(log, LOG_MSG(chunk_alloc), LOG_ERR, 0, "no chunk slots");
		return -ENOMEM;
	}
	rc = shm_alloc_page(log, (void **)pchunk,
	                    MBUF_CHUNK_SIZE, MBUF_CHUNK_SIZE);
	if (rc) {
		return rc;
	}
	p->mbp_nr_chunks--;
	chunk = *pchunk;
	dlist_init(&chunk->c_freeq);
	chunk->c_freeq_size = p->mbp_mbufs_per_chunk;
	for (i = 0; i < chunk->c_freeq_size; ++i) {
		m = MBUF_GET(p, chunk, i);
		m->mb_magic = MBUF_MAGIC;
		m->mb_used = 0;
		m->mb_pool_id = p->mbp_id;
		DLIST_INSERT_TAIL(&chunk->c_freeq, m, mb_list);
	}
	DLIST_INSERT_TAIL(&p->mbp_avail_chunkq, chunk, c_list);
	return 0;
}
static int
mbuf_chunk_is_empty(struct mbuf_pool *p, struct mbuf_chunk *chunk)
{
	return chunk->c_freeq_size == p->mbp_mbufs_per_chunk;
}
static void
mbuf_chunk_free(struct mbuf_pool *p, struct mbuf_chunk *chunk)
{
	DLIST_REMOVE(chunk, c_list);
	shm_free_page(chunk, MBUF_CHUNK_SIZE);
}
int
mbuf_pool_alloc(struct log *log, struct mbuf_pool **pp, int mbuf_size)
{
	int i, rc;
	struct mbuf_pool *p;
	ASSERT(mbuf_size >= sizeof(struct mbuf));
	LOG_TRACE(log);
	mbuf_size = ROUND_UP(mbuf_size, CACHE_LINE_SIZE);
	for (i = 0; i < ARRAY_SIZE(current_mod->mbuf_pools); ++i) {
		if (current_mod->mbuf_pools[i] == NULL) {
			goto found;
		}
	}
	LOGF(log, 7, LOG_ERR, 0, "no pool slots");
	return -ENFILE;
found:
	p = current_mod->mbuf_pools[i];
	rc = shm_alloc(log, (void **)&p, sizeof(*p));
	if (!rc) {
		memset(p, 0, sizeof(*p));
		p->mbp_id = i;
		p->mbp_mbuf_size = mbuf_size;
		p->mbp_mbufs_per_chunk = MBUF_CHUNK_DATA_SIZE / mbuf_size;
		dlist_init(&p->mbp_avail_chunkq);
		dlist_init(&p->mbp_empty_chunkq);
		p->mbp_nr_chunks = ARRAY_SIZE(p->mbp_chunks);
		current_mod->mbuf_pools[p->mbp_id] = p;
		*pp = p;
	}
	return rc;
}
int
mbuf_pool_is_empty(struct mbuf_pool *p)
{
	int rc;
	struct mbuf_chunk *chunk;
	rc = dlist_is_empty(&p->mbp_empty_chunkq);
	if (rc == 0) {
		return 0;
	}
	DLIST_FOREACH(chunk, &p->mbp_avail_chunkq, c_list) {
		rc = mbuf_chunk_is_empty(p, chunk);
		if (rc == 0) {
			return 0;
		}
	}
	return 1;
}
void
mbuf_pool_free(struct mbuf_pool *p)
{
	struct mbuf_chunk *chunk;
	ASSERT(dlist_is_empty(&p->mbp_empty_chunkq));
	while (!dlist_is_empty(&p->mbp_avail_chunkq)) {
		chunk = DLIST_FIRST(&p->mbp_avail_chunkq,
		                    struct mbuf_chunk,
		                    c_list);
		mbuf_chunk_free(p, chunk);
	}
	current_mod->mbuf_pools[p->mbp_id] = NULL;
	shm_free(p);
}
int
mbuf_alloc(struct log *log, struct mbuf_pool *p, struct mbuf **mp)
{
	int i, rc;
	struct mbuf *m;
	struct mbuf_chunk *chunk;
	*mp = NULL;
	if (dlist_is_empty(&p->mbp_avail_chunkq)) {
		LOG_TRACE(log);
		rc = mbuf_chunk_alloc(log, p, &chunk);
		if (rc) {
			return rc;
		}
		for (i = 0; i < ARRAY_SIZE(p->mbp_chunks); ++i) {
			if (p->mbp_chunks[i] == NULL) {
				chunk->c_id = i;
				p->mbp_chunks[i] = chunk;
				break;
			}
		}
		ASSERT(i < ARRAY_SIZE(p->mbp_chunks));
	}
	ASSERT(!dlist_is_empty(&p->mbp_avail_chunkq));
	chunk = DLIST_FIRST(&p->mbp_avail_chunkq,
	                    struct mbuf_chunk, c_list);
	ASSERT(chunk->c_freeq_size);
	m = DLIST_FIRST(&chunk->c_freeq, struct mbuf, mb_list);
	mbuf_chunk_pop_freeq(p, chunk, m);
	*mp = m;
	return 0;
}
int
mbuf_alloc4(struct log *log, struct mbuf_pool *p, uint32_t m_id,
	struct mbuf **mp)
{
	int i, rc, chunk_id;
	struct mbuf *m;
	struct mbuf_chunk *chunk;
	LOG_TRACE(log);
	*mp = NULL;
	chunk_id = m_id / p->mbp_mbufs_per_chunk;
	if (chunk_id >= ARRAY_SIZE(p->mbp_chunks)) {
		LOGF(log, LOG_MSG(alloc), LOG_ERR, 0,
		     "too big id; m_id=%u", m_id);
		return -ENFILE;
	}
	chunk = p->mbp_chunks[chunk_id];
	if (chunk == NULL) {
		rc = mbuf_chunk_alloc(log, p, &chunk);
		if (rc) {
			return rc;
		}
		p->mbp_chunks[chunk_id] = chunk;
		chunk->c_id = chunk_id;
	}
	i = m_id % p->mbp_mbufs_per_chunk;
	m = MBUF_GET(p, chunk, i);
	if (m->mb_used) {
		LOGF(log, LOG_MSG(alloc), LOG_ERR, 0,
		     "already allocated; m_id=%d", m_id);
		return -EBUSY;
	} else {
		mbuf_chunk_pop_freeq(p, chunk, m);
		*mp = m;
		return 0;
	}
}
void
mbuf_init(struct mbuf *m)
{
	m->mb_magic = MBUF_MAGIC;
	m->mb_used = 1;
	m->mb_pool_id = UINT8_MAX;
}
void
mbuf_free(struct mbuf *m)
{
	struct mbuf_chunk *chunk;
	struct mbuf_pool *p;
	if (m == NULL) {
		return;
	}
	ASSERT(m->mb_magic == MBUF_MAGIC);
	ASSERT(m->mb_used == 1);
	ASSERT(m->mb_pool_id < ARRAY_SIZE(current_mod->mbuf_pools));
	p = current_mod->mbuf_pools[m->mb_pool_id];
	m->mb_used = 0;
	chunk = mbuf_get_chunk(m);
	DLIST_INSERT_HEAD(&chunk->c_freeq, m, mb_list);
	ASSERT(chunk->c_freeq_size < p->mbp_mbufs_per_chunk);
	if (chunk->c_freeq_size == 0) {
		DLIST_REMOVE(chunk, c_list);
		DLIST_INSERT_TAIL(&p->mbp_avail_chunkq, chunk, c_list);
	}
	chunk->c_freeq_size++;
}
struct mbuf *
mbuf_get(struct mbuf_pool *p, uint32_t m_id)
{
	int chunk_id, i;
	struct mbuf *m;
	struct mbuf_chunk *chunk;
	chunk_id = m_id / p->mbp_mbufs_per_chunk;
	if (chunk_id >= ARRAY_SIZE(p->mbp_chunks)) {
		return NULL;
	}
	chunk = p->mbp_chunks[chunk_id];
	if (chunk == NULL) {
		return NULL;
	}
	i = m_id % p->mbp_mbufs_per_chunk;
	m = MBUF_GET(p, chunk, i);
	if (m->mb_used) {
		return m;
	} else {
		return NULL;
	}
}
struct mbuf *
mbuf_next(struct mbuf_pool *p, uint32_t m_id)
{
	int i, chunk_id;
	struct mbuf_chunk *chunk;
	struct mbuf *m;
	chunk_id = m_id / p->mbp_mbufs_per_chunk;
	i = m_id % p->mbp_mbufs_per_chunk;
	for (; chunk_id < ARRAY_SIZE(p->mbp_chunks); ++chunk_id) {
		chunk = p->mbp_chunks[chunk_id];
		if (chunk != NULL) {
			for (; i < p->mbp_mbufs_per_chunk; ++i) {
				m = MBUF_GET(p, chunk, i);
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
mbuf_get_id(struct mbuf_pool *p, struct mbuf *m)
{
	int i, m_id;
	struct mbuf_chunk *chunk;
	ASSERT(m->mb_magic == MBUF_MAGIC);
	chunk = mbuf_get_chunk(m);
	i = ((u_char *)m - (uint8_t *)(chunk + 1)) / p->mbp_mbuf_size;
	m_id = chunk->c_id * p->mbp_mbufs_per_chunk + i;
	return m_id;
}
