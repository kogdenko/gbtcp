// gpl2
#include "internals.h"

#define CURMOD mbuf

#define MBUF_MAGIC 0xcafe

#define MBUF_GET(p, chunk, i) \
	(struct mbuf *)(((u_char *)(chunk + 1)) + (i) * (p)->mbp_mbuf_size)

void
mbuf_init(struct mbuf *m, u_char area)
{
	m->mb_chunk = NULL;
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
		dbg("y");
		return -ENOMEM;
	}
	rc = shm_alloc_pages((void **)pchunk,
		p->mbp_chunk_size, p->mbp_chunk_size);
	if (rc) {
		dbg("z %u", p->mbp_chunk_size);
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
		m->mb_chunk = chunk;
		DLIST_INSERT_TAIL(&chunk->mbc_mbuf_head, m, mb_list);
	}
	DLIST_INSERT_TAIL(&p->mbp_avail_chunk_head, chunk, mbc_list);
	return 0;
}

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
		shm_free_pages(chunk, p->mbp_chunk_size);
		p->mbp_n_allocated_chunks--;
		if (p->mbp_n_allocated_chunks == 0) {
			mbuf_pool_free(p);
			return -EINVAL;
		}
	}
	return 0;
}

int
mbuf_pool_alloc(struct mbuf_pool **pp, u_char sid,
	int chunk_size, int mbuf_size, int n_mbufs_max)
{
	int size, mbuf_size_align, mbufs_per_chunk, chunk_map_size;
	struct mbuf_pool *p;

	assert(mbuf_size >= sizeof(struct mbuf));
	assert(chunk_size >= PAGE_SIZE);
	assert((chunk_size & PAGE_MASK) == 0);
	mbuf_size_align = ALIGN_PTR(mbuf_size);
	assert(mbuf_size_align >= mbuf_size);
	mbufs_per_chunk = (chunk_size - sizeof(struct mbuf_chunk)) /
		mbuf_size_align;
	chunk_map_size = n_mbufs_max / mbufs_per_chunk;
	if (n_mbufs_max % mbufs_per_chunk) {
		chunk_map_size++;
	}
	size = sizeof(*p) + chunk_map_size * sizeof(struct mbuf_chunk *);
	p = shm_malloc(size);
	if (p == NULL) {
		return -ENOMEM;
	}
	*pp = p;
	memset(p, 0, size);
	p->mbp_sid = sid;
	p->mbp_referenced = 1;
	p->mbp_chunk_size = chunk_size;
	p->mbp_mbuf_size = mbuf_size_align;
	p->mbp_mbufs_per_chunk = mbufs_per_chunk;
	dlist_init(&p->mbp_avail_chunk_head);
	dlist_init(&p->mbp_not_avail_chunk_head);
	p->mbp_chunk_map_size = chunk_map_size;
	if (p->mbp_chunk_map_size) {
		p->mbp_chunk_map = (struct mbuf_chunk **)(p + 1);
	}
	INFO(0, "ok; pool=%p", p);
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
	if (p->mbp_n_allocated_chunks == 0) {
		INFO(0, "ok; pool=%p", p);
		shm_free(p);
		return;
	}
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
		DLIST_INSERT_HEAD(&p->mbp_not_avail_chunk_head,
		                  chunk, mbc_list);
	}
	WRITE_ONCE(m->mb_freed, 0);
	DBG(0, "ok; m=%p, c=%p, pool=%p, n=%d",
	    m, chunk, p, chunk->mbc_n_mbufs);
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
	//printf("alloc mbuf=%p\n", m);
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
mbuf_free_garbage(struct mbuf *m)
{
	struct dlist *head;
	struct mbuf_pool *p;

	p = m->mb_chunk->mbc_pool;
	DBG(0, "hit; m=%p, pool=%p, sid=%d->%d",
	    m, p, current->p_sid, p->mbp_sid);
	assert(p->mbp_sid < GT_SERVICES_MAX);
	if (current->p_mbuf_garbage_max < p->mbp_sid + 1) {
		current->p_mbuf_garbage_max = p->mbp_sid + 1;
	}
	head = current->p_mbuf_garbage_head + p->mbp_sid;
	DLIST_INSERT_TAIL(head, m, mb_list);
}

void
mbuf_free_direct(struct mbuf *m)
{
	struct mbuf_chunk *chunk;
	struct mbuf_pool *p;

	chunk = m->mb_chunk;
	p = chunk->mbc_pool;
	DBG(0, "hit; m=%p, c=%p, pool=%p, n=%d",
	    m, chunk, p, chunk->mbc_n_mbufs);
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
mbuf_free_direct_list(struct dlist *head)
{
	struct mbuf *m;

	while (!dlist_is_empty(head)) {
		m = DLIST_FIRST(head, struct mbuf, mb_list);
		DLIST_REMOVE(m, mb_list);
		mbuf_free_direct(m);
	}
}

void
mbuf_free(struct mbuf *m)
{
	struct mbuf_chunk *chunk;

	if (m == NULL) {
		return;
	}
	DBG(0, "hit; m=%p", m);
	assert(m->mb_freed == 0);
	WRITE_ONCE(m->mb_freed, 1);
	switch (m->mb_area) {
	case MBUF_AREA_NONE:
		break;
	case MBUF_AREA_HEAP:
		break;
	case MBUF_AREA_POOL:
		chunk = m->mb_chunk;
		if (chunk->mbc_pool->mbp_sid == current->p_sid) {
			mbuf_free_direct(m);
		} else {
			mbuf_free_garbage(m);
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
	chunk = m->mb_chunk;
	p = chunk->mbc_pool;
	assert(p->mbp_chunk_map_size);
	assert(chunk->mbc_id >= 0);
	i = ((u_char *)m - (u_char *)(chunk + 1)) / p->mbp_mbuf_size;
	m_id = chunk->mbc_id * p->mbp_mbufs_per_chunk + i;
	return m_id;
}
