#include "internals.h"

#define CURMOD mbuf

#define MBUF_MAGIC 0xcafe

#define MBUF_CHUNK_SIZE (2 * 1024 * 1024)
#define MBUF_CHUNK_DATA_SIZE  (MBUF_CHUNK_SIZE - sizeof(struct mbuf_chunk))

struct mbuf_chunk {
	struct dlist mbc_list;
	struct dlist mbc_mbuf_head;
	struct mbuf_pool *mbc_pool;
	int mbc_n_mbufs;
	short mbc_id;
};

#define MBUF_GET(p, chunk, i) \
	(struct mbuf *)(((u_char *)(chunk + 1)) + (i) * (p)->mbp_mbuf_size)

int
mbuf_mod_service_init(struct service *s)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(s->p_mbuf_free_indirect_head); ++i) {
		dlist_init(s->p_mbuf_free_indirect_head + i);
	}
	return 0;
}

void
mbuf_mod_service_deinit(struct service *s)
{
	shm_lock();
	shm_unlock(s); // clean mbuf_free_indirect
	assert(s->p_mbuf_free_indirect_n == 0);
}

static struct mbuf_chunk *
mbuf_get_chunk(struct mbuf *m)
{
	uintptr_t base;

	base = ROUND_DOWN(((uintptr_t)m), MBUF_CHUNK_SIZE);
	return (struct mbuf_chunk *)base;
}

void
mbuf_init(struct mbuf *m, u_char area)
{
	m->mb_size = 0;
	m->mb_magic = MBUF_MAGIC;
	m->mb_freed = 0;
	m->mb_area = area;
}

static int
mbuf_chunk_alloc(struct mbuf_pool *p, struct mbuf_chunk **pchunk)
{
	int i, rc;
	struct mbuf_chunk *chunk;
	struct mbuf *m;

	if (p->mbp_chunk_map_size != 0 &&
	    p->mbp_n_allocated_chunks == p->mbp_chunk_map_size) {
		return -ENOMEM;
	}
	rc = shm_alloc_pages((void **)pchunk,
	                     MBUF_CHUNK_SIZE, MBUF_CHUNK_SIZE);
	if (rc) {
		return rc;
	}
	p->mbp_n_allocated_chunks++;
	chunk = *pchunk;
	chunk->mbc_pool = p;
	chunk->mbc_id = -1;
	dlist_init(&chunk->mbc_mbuf_head);
	chunk->mbc_n_mbufs = p->mbp_mbufs_per_chunk;
	for (i = 0; i < chunk->mbc_n_mbufs; ++i) {
		m = MBUF_GET(p, chunk, i);
		mbuf_init(m, MBUF_AREA_POOL);
		m->mb_freed = 1;
		DLIST_INSERT_TAIL(&chunk->mbc_mbuf_head, m, mb_list);
	}
	DLIST_INSERT_TAIL(&p->mbp_avail_chunk_head, chunk, mbc_list);
	return 0;
}

/*static int
mbuf_chunk_is_empty(struct mbuf_pool *p, struct mbuf_chunk *chunk)
{
	return chunk->mbc_n_avail_mbufs == p->mbp_mbufs_per_chunk;
}*/

static int
mbuf_chunk_free(struct mbuf_pool *p, struct mbuf_chunk *chunk)
{
	assert(chunk->mbc_n_mbufs == p->mbp_mbufs_per_chunk);
	if (p->mbp_referenced == 0) {
		if (chunk->mbc_id >= 0) {
			assert(p->mbp_chunk_map[chunk->mbc_id] == chunk);
			p->mbp_chunk_map[chunk->mbc_id] = NULL;
		}
		DLIST_REMOVE(chunk, mbc_list);
		shm_free_pages(chunk, MBUF_CHUNK_SIZE);
		p->mbp_n_allocated_chunks--;
		if (p->mbp_n_allocated_chunks == 0) {
			shm_free(p);
			return -EINVAL;
		}
	}
	return 0;
}

int
mbuf_pool_alloc(struct mbuf_pool **pp, u_char sid, int mbuf_size,
	int n_mbufs_max)
{
	int rc, size, mbuf_size_align, mbufs_per_chunk, chunk_map_size;
	struct mbuf_pool *p;

	assert(mbuf_size >= sizeof(struct mbuf));
	mbuf_size_align = ALIGN_PTR(mbuf_size);
	assert(mbuf_size_align >= mbuf_size);
	mbufs_per_chunk = MBUF_CHUNK_DATA_SIZE / mbuf_size_align;
	chunk_map_size = n_mbufs_max / mbufs_per_chunk;
	if (n_mbufs_max % mbufs_per_chunk) {
		chunk_map_size++;
	}
	size = sizeof(*p) + chunk_map_size * sizeof(struct mbuf_chunk *);
	rc = shm_malloc((void **)pp, size);
	if (rc) {
		return rc;
	}
	p = *pp;
	memset(p, 0, size);
	p->mbp_sid = sid;
	p->mbp_referenced = 1;
	p->mbp_mbuf_size = mbuf_size_align;
	p->mbp_mbufs_per_chunk = mbufs_per_chunk;
	dlist_init(&p->mbp_avail_chunk_head);
	dlist_init(&p->mbp_not_avail_chunk_head);
	p->mbp_chunk_map_size = chunk_map_size;
	if (p->mbp_chunk_map_size) {
		p->mbp_chunk_map = (struct mbuf_chunk **)(p + 1);
	}
	return 0;
}

void
mbuf_pool_free(struct mbuf_pool *p)
{
	int rc;
	struct mbuf_chunk *chunk, *tmp;

	if (p == NULL) {
		return;
	}
	p->mbp_referenced = 0;
	DLIST_FOREACH_SAFE(chunk, &p->mbp_avail_chunk_head, mbc_list, tmp) {
		if (chunk->mbc_n_mbufs == p->mbp_mbufs_per_chunk) {
			rc = mbuf_chunk_free(p, chunk);
			if (rc) {
				break;
			}
		}
	}
}

static void
mbuf_alloc2(struct mbuf *m, struct mbuf_chunk *chunk)
{
	struct mbuf_pool *p;

	assert(m->mb_freed == 1);
	assert(chunk->mbc_n_mbufs > 0);
	DLIST_REMOVE(m, mb_list);
	p = chunk->mbc_pool;
	chunk->mbc_n_mbufs--;
	if (chunk->mbc_n_mbufs == 0) {
		DLIST_REMOVE(chunk, mbc_list);
		DLIST_INSERT_HEAD(&p->mbp_not_avail_chunk_head, chunk, mbc_list);
	}
	WRITE_ONCE(m->mb_freed, 0);
	DBG(0, "ok; m=%p, c=%p, n=%d", m, chunk, chunk->mbc_n_mbufs);
}

int
mbuf_alloc(struct mbuf_pool *p, struct mbuf **mp)
{
	int i, rc;
	struct mbuf *m;
	struct mbuf_chunk *chunk;

	assert(current->p_sid == p->mbp_sid);
	*mp = NULL;
	if (dlist_is_empty(&p->mbp_avail_chunk_head)) {
		rc = mbuf_chunk_alloc(p, &chunk);
		if (rc) {
			return rc;
		}
		for (i = 0; i < p->mbp_chunk_map_size; ++i) {
			if (p->mbp_chunk_map[i] == NULL) {
				chunk->mbc_id = i;
				p->mbp_chunk_map[i] = chunk;
				break;
			}
		}
		assert(i == 0 || i < p->mbp_chunk_map_size);
	}
	assert(!dlist_is_empty(&p->mbp_avail_chunk_head));
	chunk = DLIST_FIRST(&p->mbp_avail_chunk_head,
	                    struct mbuf_chunk, mbc_list);
	assert(chunk->mbc_n_mbufs);
	assert(!dlist_is_empty(&chunk->mbc_mbuf_head));
	m = DLIST_FIRST(&chunk->mbc_mbuf_head, struct mbuf, mb_list);
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

	assert(current->p_sid == p->mbp_sid);
	*mp = NULL;
	chunk_id = m_id / p->mbp_mbufs_per_chunk;
	if (chunk_id >= p->mbp_chunk_map_size) {
		return -ENFILE;
	}
	chunk = p->mbp_chunk_map[chunk_id];
	if (chunk == NULL) {
		rc = mbuf_chunk_alloc(p, &chunk);
		if (rc) {
			return rc;
		}
		p->mbp_chunk_map[chunk_id] = chunk;
		chunk->mbc_id = chunk_id;
	}
	i = m_id % p->mbp_mbufs_per_chunk;
	m = MBUF_GET(p, chunk, i);
	if (READ_ONCE(m->mb_freed)) {
		mbuf_alloc2(m, chunk);
		*mp = m;
		return 0;
	} else {
		return -EBUSY;
	}
}

static void
mbuf_free_indirect(struct mbuf *m)
{
	struct dlist *head;
	struct mbuf_pool *p;

	p = mbuf_get_pool(m);
	DBG(0, "hit; m=%p, sid=%d->%d", m, current->p_sid, p->mbp_sid);
	current->p_mbuf_free_indirect_n++;
	assert(p->mbp_sid < GT_SERVICES_MAX);
	head = current->p_mbuf_free_indirect_head + p->mbp_sid;
	DLIST_INSERT_TAIL(head, m, mb_list);
}

void
mbuf_free_direct(struct mbuf *m)
{
	struct mbuf_chunk *chunk;
	struct mbuf_pool *p;

	chunk = mbuf_get_chunk(m);
	DBG(0, "hit; m=%p, c=%p, n=%d", m, chunk, chunk->mbc_n_mbufs);
	p = chunk->mbc_pool;
	assert(chunk->mbc_n_mbufs < p->mbp_mbufs_per_chunk);
	DLIST_INSERT_HEAD(&chunk->mbc_mbuf_head, m, mb_list);
	if (chunk->mbc_n_mbufs == 0) {
		DLIST_REMOVE(chunk, mbc_list);
		DLIST_INSERT_TAIL(&p->mbp_avail_chunk_head, chunk, mbc_list);
	}
	chunk->mbc_n_mbufs++;
	if (chunk->mbc_n_mbufs == p->mbp_mbufs_per_chunk) {
		mbuf_chunk_free(p, chunk);
	}
}

void
mbuf_free(struct mbuf *m)
{
	struct mbuf_chunk *chunk;

	if (m == NULL) {
		return;
	}
	DBG(0, "hit, m=%p", m);
	assert(m->mb_freed == 0);
	WRITE_ONCE(m->mb_freed, 1);
	switch (m->mb_area) {
	case MBUF_AREA_NONE:
		break;
	case MBUF_AREA_HEAP:
		break;
	case MBUF_AREA_POOL:
		chunk = mbuf_get_chunk(m); 
		if (chunk->mbc_pool->mbp_sid == current->p_sid) {
			mbuf_free_direct(m);
		} else {
			mbuf_free_indirect(m);
		}
		break;
	default:
		BUG("bad area");
	}
}

struct mbuf *
mbuf_get(struct mbuf_pool *p, uint32_t m_id)
{
	int chunk_id, i;
	struct mbuf *m;
	struct mbuf_chunk *chunk;

	chunk_id = m_id / p->mbp_mbufs_per_chunk;
	if (chunk_id >= p->mbp_chunk_map_size) {
		return NULL;
	}
	chunk = p->mbp_chunk_map[chunk_id];
	if (chunk == NULL) {
		return NULL;
	}
	i = m_id % p->mbp_mbufs_per_chunk;
	m = MBUF_GET(p, chunk, i);
	if (READ_ONCE(m->mb_freed)) {
		return NULL;
	} else {
		return m;
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
	for (; chunk_id < p->mbp_chunk_map_size; ++chunk_id) {
		chunk = p->mbp_chunk_map[chunk_id];
		if (chunk != NULL) {
			assert(chunk->mbc_id >= 0);
			for (; i < p->mbp_mbufs_per_chunk; ++i) {
				m = MBUF_GET(p, chunk, i);
				if (!READ_ONCE(m->mb_freed)) {
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

	assert(m->mb_area == MBUF_AREA_POOL);
	chunk = mbuf_get_chunk(m);
	assert(chunk->mbc_id >= 0);
	p = chunk->mbc_pool;
	i = ((u_char *)m - (u_char *)(chunk + 1)) / p->mbp_mbuf_size;
	m_id = chunk->mbc_id * p->mbp_mbufs_per_chunk + i;
	return m_id;
}

struct mbuf_pool *
mbuf_get_pool(struct mbuf *m)
{
	struct mbuf_chunk *chunk;

	assert(m->mb_area == MBUF_AREA_POOL);
	chunk = mbuf_get_chunk(m);
	return chunk->mbc_pool;
}
