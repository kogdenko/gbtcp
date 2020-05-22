#include "internals.h"

#define MBUF_MAGIC 0xcafe

#define MBUF_CHUNK_SIZE (2 * 1024 * 1024)
#define MBUF_CHUNK_DATA_SIZE  (MBUF_CHUNK_SIZE - sizeof(struct mbuf_chunk))

struct mbuf_mod {
	struct log_scope log_scope;
};

struct mbuf_chunk {
	struct dlist c_list;
	struct dlist c_freeq;
	struct mbuf_pool *c_pool;
	int c_freeq_size;
	short c_id;
};

static struct mbuf_mod *curmod;

#define MBUF_GET(p, chunk, i) \
	(struct mbuf *)(((u_char *)(chunk + 1)) + i * p->mbp_mbuf_size);

int
mbuf_mod_init(void **pp)
{
	int rc;
	struct mbuf_mod *mod;

	rc = shm_malloc(pp, sizeof(*mod));
	if (!rc) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "mbuf");
	}
	return rc;
}

int
mbuf_mod_attach(void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

void
mbuf_mod_deinit(void *raw_mod)
{
	struct mbuf_mod *mod;

	mod = raw_mod;
	log_scope_deinit(&mod->log_scope);
	shm_free(mod);
}

void
mbuf_mod_detach()
{
	curmod = NULL;
}

static struct mbuf_chunk *
mbuf_get_chunk(struct mbuf *m)
{
	uintptr_t p;

	p = ROUND_DOWN(((uintptr_t)m), MBUF_CHUNK_SIZE);
	return (struct mbuf_chunk *)p;
}

static int
mbuf_chunk_alloc(struct mbuf_pool *p, struct mbuf_chunk **pchunk)
{
	int i, rc;
	struct mbuf_chunk *chunk;
	struct mbuf *m;

	if (p->mbp_nr_chunks == 0) {
		ERR(0, "no chunk slots;");
		return -ENOMEM;
	}
	rc = shm_alloc_page((void **)pchunk,
	                    MBUF_CHUNK_SIZE, MBUF_CHUNK_SIZE);
	if (rc) {
		return rc;
	}
	p->mbp_nr_chunks--;
	chunk = *pchunk;
	chunk->c_pool = p;
	dlist_init(&chunk->c_freeq);
	chunk->c_freeq_size = p->mbp_mbufs_per_chunk;
	for (i = 0; i < chunk->c_freeq_size; ++i) {
		m = MBUF_GET(p, chunk, i);
		m->mb_magic = MBUF_MAGIC;
		m->mb_used = 0;
		m->mb_allocated = 1;
		m->mb_service_id = p->mbp_service_id;
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

void
mbuf_pool_init(struct mbuf_pool *p, u_char service_id, int mbuf_size)
{
	memset(p, 0, sizeof(*p));
	p->mbp_service_id = service_id;
	p->mbp_mbuf_size = mbuf_size;
	p->mbp_mbufs_per_chunk = MBUF_CHUNK_DATA_SIZE / mbuf_size;
	dlist_init(&p->mbp_avail_chunkq);
	dlist_init(&p->mbp_empty_chunkq);
	p->mbp_nr_chunks = ARRAY_SIZE(p->mbp_chunks);
}

void
mbuf_pool_deinit(struct mbuf_pool *p)
{
	struct mbuf_chunk *chunk;

	ASSERT(dlist_is_empty(&p->mbp_empty_chunkq));
	while (!dlist_is_empty(&p->mbp_avail_chunkq)) {
		chunk = DLIST_FIRST(&p->mbp_avail_chunkq,
		                    struct mbuf_chunk,
		                    c_list);
		mbuf_chunk_free(p, chunk);
	}
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

int
mbuf_alloc(struct mbuf_pool *p, struct mbuf **mp)
{
	int i, rc;
	struct mbuf *m;
	struct mbuf_chunk *chunk;

	ASSERT(current->p_id == p->mbp_service_id);
	*mp = NULL;
	if (dlist_is_empty(&p->mbp_avail_chunkq)) {
		rc = mbuf_chunk_alloc(p, &chunk);
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
	ASSERT(m->mb_used == 0);
	DLIST_REMOVE(m, mb_list);
	chunk->c_freeq_size--;
	if (chunk->c_freeq_size == 0) {
		DLIST_REMOVE(chunk, c_list);
		DLIST_INSERT_HEAD(&p->mbp_empty_chunkq, chunk, c_list);
	}
	m->mb_used = 1;
	m->mb_allocated = 1;
	*mp = m;
	return 0;
}

void
mbuf_init(struct mbuf *m)
{
	m->mb_magic = MBUF_MAGIC;
	m->mb_used = 1;
	m->mb_allocated = 0;
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
	ASSERT(m->mb_service_id == current->p_id); // TODO
	m->mb_used = 0;
	chunk = mbuf_get_chunk(m);
	p = chunk->c_pool;
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

	ASSERT(p->mbp_service_id == current->p_id);
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

	ASSERT(p->mbp_service_id == current->p_id);
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
mbuf_get_id(struct mbuf *m)
{
	int i, m_id;
	struct mbuf_chunk *chunk;
	struct mbuf_pool *p;

	ASSERT(m->mb_magic == MBUF_MAGIC);
	chunk = mbuf_get_chunk(m);
	p = chunk->c_pool;
	i = ((u_char *)m - (uint8_t *)(chunk + 1)) / p->mbp_mbuf_size;
	m_id = chunk->c_id * p->mbp_mbufs_per_chunk + i;
	return m_id;
}

struct mbuf_pool *
mbuf_get_pool(struct mbuf *m)
{
	struct mbuf_chunk *chunk;

	if (m->mb_allocated) {
		chunk = mbuf_get_chunk(m);
		return chunk->c_pool;
	} else {
		return NULL;
	}
}
