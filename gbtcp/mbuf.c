#include "internals.h"

#define CURMOD mbuf

#define MBUF_MAGIC 0xcafe

#define MBUF_CHUNK_SIZE (2 * 1024 * 1024)
#define MBUF_CHUNK_DATA_SIZE  (MBUF_CHUNK_SIZE - sizeof(struct mbuf_chunk))

struct mbuf_chunk {
	struct dlist mbc_list;
	struct dlist mbc_freeq;
	struct mbuf_pool *mbc_pool;
	int mbc_freeq_size;
	short mbc_id;
};

#define MBUF_GET(p, chunk, i) \
	(struct mbuf *)(((u_char *)(chunk + 1)) + i * p->mbp_mbuf_size);

int
mbuf_mod_service_init(struct service *s)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(s->p_mbuf_free_indirect_head); ++i) {
		dlist_init(s->p_mbuf_free_indirect_head + i);
	}
	return 0;
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
		return -ENOMEM;
	}
	rc = shm_alloc_pages((void **)pchunk,
	                     MBUF_CHUNK_SIZE, MBUF_CHUNK_SIZE);
	if (rc) {
		return rc;
	}
	p->mbp_nr_chunks--;
	chunk = *pchunk;
	chunk->mbc_pool = p;
	dlist_init(&chunk->mbc_freeq);
	chunk->mbc_freeq_size = p->mbp_mbufs_per_chunk;
	for (i = 0; i < chunk->mbc_freeq_size; ++i) {
		m = MBUF_GET(p, chunk, i);
		m->mb_magic = MBUF_MAGIC;
		m->mb_used = 0;
		m->mb_allocated = 1;
		m->mb_service_id = p->mbp_service_id;
		DLIST_INSERT_TAIL(&chunk->mbc_freeq, m, mb_list);
	}
	DLIST_INSERT_TAIL(&p->mbp_avail_chunkq, chunk, mbc_list);
	return 0;
}

static int
mbuf_chunk_is_empty(struct mbuf_pool *p, struct mbuf_chunk *chunk)
{
	return chunk->mbc_freeq_size == p->mbp_mbufs_per_chunk;
}

static void
mbuf_chunk_free(struct mbuf_pool *p, struct mbuf_chunk *chunk)
{
	DLIST_REMOVE(chunk, mbc_list);
	shm_free_pages(chunk, MBUF_CHUNK_SIZE);
}

void
mbuf_pool_init(struct mbuf_pool *p, u_char service_id, int mbuf_size)
{
	assert(mbuf_size >= sizeof(struct mbuf));
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

	assert(dlist_is_empty(&p->mbp_empty_chunkq));
	while (!dlist_is_empty(&p->mbp_avail_chunkq)) {
		chunk = DLIST_FIRST(&p->mbp_avail_chunkq,
		                    struct mbuf_chunk,
		                    mbc_list);
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
	DLIST_FOREACH(chunk, &p->mbp_avail_chunkq, mbc_list) {
		rc = mbuf_chunk_is_empty(p, chunk);
		if (rc == 0) {
			return 0;
		}
	}
	return 1;
}

static void
mbuf_alloc2(struct mbuf *m, struct mbuf_chunk *chunk)
{
	struct mbuf_pool *p;

	assert(m->mb_used == 0);
	DLIST_REMOVE(m, mb_list);
	p = chunk->mbc_pool;
	chunk->mbc_freeq_size--;
	if (chunk->mbc_freeq_size == 0) {
		DLIST_REMOVE(chunk, mbc_list);
		DLIST_INSERT_HEAD(&p->mbp_empty_chunkq, chunk, mbc_list);
	}
	m->mb_used = 1;
	m->mb_allocated = 1;
}

int
mbuf_alloc(struct mbuf_pool *p, struct mbuf **mp)
{
	int i, rc;
	struct mbuf *m;
	struct mbuf_chunk *chunk;

	assert(current->p_id == p->mbp_service_id);
	*mp = NULL;
	if (dlist_is_empty(&p->mbp_avail_chunkq)) {
		rc = mbuf_chunk_alloc(p, &chunk);
		if (rc) {
			return rc;
		}
		for (i = 0; i < ARRAY_SIZE(p->mbp_chunks); ++i) {
			if (p->mbp_chunks[i] == NULL) {
				chunk->mbc_id = i;
				p->mbp_chunks[i] = chunk;
				break;
			}
		}
		assert(i < ARRAY_SIZE(p->mbp_chunks));
	}
	assert(!dlist_is_empty(&p->mbp_avail_chunkq));
	chunk = DLIST_FIRST(&p->mbp_avail_chunkq,
	                    struct mbuf_chunk, mbc_list);
	assert(chunk->mbc_freeq_size);
	m = DLIST_FIRST(&chunk->mbc_freeq, struct mbuf, mb_list);
	mbuf_alloc2(m, chunk);
	*mp = m;
	return 0;
}

int
mbuf_alloc3(struct mbuf_pool *p, uint32_t m_id, struct mbuf **mp)
{
	int i, rc, chunk_id;
	struct mbuf *m;
	struct mbuf_chunk *chunk;

	assert(current->p_id == p->mbp_service_id);
	*mp = NULL;
	chunk_id = m_id / p->mbp_mbufs_per_chunk;
	if (chunk_id >= ARRAY_SIZE(p->mbp_chunks)) {
		return -ENFILE;
	}
	chunk = p->mbp_chunks[chunk_id];
	if (chunk == NULL) {
		rc = mbuf_chunk_alloc(p, &chunk);
		if (rc) {
			return rc;
		}
		p->mbp_chunks[chunk_id] = chunk;
		chunk->mbc_id = chunk_id;
	}
	i = m_id % p->mbp_mbufs_per_chunk;
	m = MBUF_GET(p, chunk, i);
	if (m->mb_used) {
		return -EBUSY;
	} else {
		mbuf_alloc2(m, chunk);
		*mp = m;
		return 0;
	}
}

void
mbuf_init(struct mbuf *m)
{
	m->mb_magic = MBUF_MAGIC;
	m->mb_used = 1;
	m->mb_allocated = 0;
}

static void
mbuf_free_indirect(struct mbuf *m)
{
	struct dlist *head;

	current->p_mbuf_free_indirect_n++;
	head = current->p_mbuf_free_indirect_head + m->mb_service_id;
	DLIST_INSERT_TAIL(head, m, mb_list);
}

void
mbuf_free_direct(struct mbuf *m)
{
	struct mbuf_chunk *chunk;
	struct mbuf_pool *p;

	assert(m->mb_magic == MBUF_MAGIC);
	chunk = mbuf_get_chunk(m);
	p = chunk->mbc_pool;
	DLIST_INSERT_HEAD(&chunk->mbc_freeq, m, mb_list);
	assert(chunk->mbc_freeq_size < p->mbp_mbufs_per_chunk);
	if (chunk->mbc_freeq_size == 0) {
		DLIST_REMOVE(chunk, mbc_list);
		DLIST_INSERT_TAIL(&p->mbp_avail_chunkq, chunk, mbc_list);
	}
	chunk->mbc_freeq_size++;
}

void
mbuf_free(struct mbuf *m)
{
	if (m == NULL) {
		return;
	}
	assert(m->mb_magic == MBUF_MAGIC);
	assert(m->mb_used == 1);
	if (!m->mb_allocated) {
		return;
	}
	m->mb_used = 0;
	if (m->mb_service_id != current->p_id) {
		mbuf_free_indirect(m);
	} else {
		mbuf_free_direct(m);
	}
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
mbuf_get_id(struct mbuf *m)
{
	int i, m_id;
	struct mbuf_chunk *chunk;
	struct mbuf_pool *p;

	assert(m->mb_magic == MBUF_MAGIC);
	chunk = mbuf_get_chunk(m);
	p = chunk->mbc_pool;
	i = ((u_char *)m - (uint8_t *)(chunk + 1)) / p->mbp_mbuf_size;
	m_id = chunk->mbc_id * p->mbp_mbufs_per_chunk + i;
	return m_id;
}

struct mbuf_pool *
mbuf_get_pool(struct mbuf *m)
{
	struct mbuf_chunk *chunk;

	if (m->mb_allocated) {
		chunk = mbuf_get_chunk(m);
		return chunk->mbc_pool;
	} else {
		return NULL;
	}
}
