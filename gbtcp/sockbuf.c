#include "log.h"
#include "mbuf.h"
#include "sockbuf.h"

#define GT_SOCKBUF_CHUNK_SIZE 2048
#define GT_SOCKBUF_CHUNK_DATA_SIZE \
	(GT_SOCKBUF_CHUNK_SIZE - sizeof(struct sbchunk))

#define GT_SOCKBUF_LOG_NODE_FOREACH(x) \
	x(mod_init) \
	x(mod_deinit) \
	x(chunk_alloc)

struct gt_uio {
	struct iovec *uio_iov;
	int uio_iovcnt;
	size_t uio_off; /* must be typeof of iov_len */
};

struct sbchunk {
	struct gt_mbuf ch_mbuf;
#define ch_list ch_mbuf.mb_list
	int ch_len;
	int ch_off;
};

static struct gt_mbuf_pool *gt_sockbuf_chunk_pool;
static struct gt_log_scope this_log;
GT_SOCKBUF_LOG_NODE_FOREACH(GT_LOG_NODE_STATIC);

static int
gt_uio_copyin(struct gt_uio *uio, void *buf, int cnt)
{
	int off;
	size_t n;
	uint8_t *dst;

	for (off = 0; uio->uio_iovcnt && off < cnt; off += n) {
		GT_ASSERT(uio->uio_iov->iov_len >= uio->uio_off);
		n = uio->uio_iov->iov_len - uio->uio_off;
		dst = (uint8_t *)uio->uio_iov->iov_base + uio->uio_off;
		if (n > cnt - off) {
			n = cnt - off;
		}
		uio->uio_off += n;
		if (uio->uio_off == uio->uio_iov->iov_len) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
			uio->uio_off = 0;
		}
		memcpy(dst, (uint8_t *)buf + off, n);
	}
	return off;
}

static int
gt_sockbuf_chunk_space(struct sbchunk *chunk)
{
	GT_ASSERT(chunk->ch_off + chunk->ch_len <= GT_SOCKBUF_CHUNK_DATA_SIZE);
	return GT_SOCKBUF_CHUNK_DATA_SIZE - (chunk->ch_off + chunk->ch_len);
}

static void *
gt_sockbuf_chunk_data(struct sbchunk *chunk)
{
	return ((uint8_t *)chunk) + sizeof(*chunk);
}

static struct sbchunk *
gt_sockbuf_chunk_alloc(struct gt_sockbuf *b)
{
	int rc;
	struct gt_log *log;
	struct sbchunk *chunk;

	log = GT_LOG_TRACE1(chunk_alloc);
	rc = gt_mbuf_alloc(log, gt_sockbuf_chunk_pool,
	                   (struct gt_mbuf **)&chunk);
	if (rc == 0) {
		chunk->ch_len = 0;
		chunk->ch_off = 0;
		DLLIST_INSERT_TAIL(&b->sob_head, chunk, ch_list);
	}
	return chunk;
}

void
gt_sockbuf_init(struct gt_sockbuf *b, int max)
{
	b->sob_len = 0;
	b->sob_max = max;
	dllist_init(&b->sob_head);
}

int
gt_sockbuf_full(struct gt_sockbuf *b)
{
	return b->sob_len >= b->sob_max;
}

void
gt_sockbuf_free(struct gt_sockbuf *b)
{
	struct sbchunk *chunk;

	b->sob_len = 0;
	while (!dllist_isempty(&b->sob_head)) {
		chunk = DLLIST_FIRST(&b->sob_head, struct sbchunk, ch_list);
		DLLIST_REMOVE(chunk, ch_list);
		gt_mbuf_free(&chunk->ch_mbuf);
	}
}

void
gt_sockbuf_set_max(struct gt_sockbuf *b, int max)
{
	b->sob_max = max;
}

static void
gt_sockbuf_free_n(struct gt_sockbuf *b, int nr_chunks)
{
	int i;
	struct sbchunk *chunk;

	for (i = 0; i < nr_chunks; ++i) {
		GT_ASSERT(!dllist_isempty(&b->sob_head));
		chunk = DLLIST_LAST(&b->sob_head, struct sbchunk, ch_list);
		DLLIST_REMOVE(chunk, ch_list);
		gt_mbuf_free(&chunk->ch_mbuf);
	}
}

static int
gt_sockbuf_space(struct gt_sockbuf *b)
{
	return b->sob_max < b->sob_len ? 0 : b->sob_max - b->sob_len;
}

static void
gt_sockbuf_write(struct gt_sockbuf *b, struct sbchunk *pos,
	const void *src, int cnt)
{
	int n, rem, space;
	uint8_t *data;
	const uint8_t *ptr;

	ptr = src;
	rem = cnt;
	DLLIST_FOREACH_CONTINUE(pos, &b->sob_head, ch_list) {
		GT_ASSERT(rem > 0);
		space = gt_sockbuf_chunk_space(pos);
		n = MIN(rem, space);
		data = gt_sockbuf_chunk_data(pos);
		memcpy(data + pos->ch_off + pos->ch_len, ptr, n);
		b->sob_len += n;
		pos->ch_len += n;
		ptr += n;
		rem -= n;
	}
	GT_ASSERT(rem == 0);
}

int
gt_sockbuf_add(struct gt_sockbuf *b, const void *buf, int cnt, int atomic)
{
	int n, rem, space, added;
	struct sbchunk *chunk, *pos;

	GT_ASSERT(cnt >= 0);
	GT_ASSERT(cnt <= UINT16_MAX);
	space = gt_sockbuf_space(b);
	added = MIN(cnt, space);
	if (added <= 0) {
		return 0;
	}
	if (atomic) {
		if (added < cnt) {
			return 0;
		}
	}
	n = 0;
	if (dllist_isempty(&b->sob_head)) {
		chunk = gt_sockbuf_chunk_alloc(b);
		if (chunk == NULL) {
			return -ENOMEM;
		}
		n++;
	} else {
		chunk = DLLIST_LAST(&b->sob_head, struct sbchunk, ch_list);
	}
	pos = chunk;
	rem = added;
	while (1) {
		rem -= gt_sockbuf_chunk_space(chunk);
		if (rem <= 0) {
			break;
		}
		chunk = gt_sockbuf_chunk_alloc(b);
		if (chunk == NULL) {
			gt_sockbuf_free_n(b, n);
			return -ENOMEM;
		}
		n++;
	}
	gt_sockbuf_write(b, pos, buf, added);
	return added;
}

static void
gt_sockbuf_send_direct(struct gt_sockbuf *b, int off, uint8_t *dst, int cnt)
{
	uint8_t *data;
	size_t n;
	struct sbchunk *chunk;

	DLLIST_FOREACH(chunk, &b->sob_head, ch_list) {
		GT_ASSERT(chunk->ch_len);
		if (off < chunk->ch_len) {
			break;
		}
		off -= chunk->ch_len;
	}
	for (; cnt != 0; chunk = DLLIST_NEXT(chunk, ch_list)) {
		GT_ASSERT(&chunk->ch_list != &b->sob_head);
		n = MIN(cnt, chunk->ch_len - off);
		data = gt_sockbuf_chunk_data(chunk);
		memcpy(dst, data + chunk->ch_off + off, n);
		off = 0;
		cnt -= n;
		dst += n;
	}
}

static void
gt_sockbuf_send_reverse(struct gt_sockbuf *b, int off, void *dst, int cnt)
{
	// TODO:
	GT_BUG;
}

void
gt_sockbuf_send(struct gt_sockbuf *b, int off, void *dst, int cnt)
{
	GT_ASSERT(off + cnt <= b->sob_len);

	if (off > (b->sob_len << 1)) {
		// Near to end
		gt_sockbuf_send_reverse(b, off, dst, cnt);
	} else {
		// Near to begin
		gt_sockbuf_send_direct(b, off, dst, cnt);
	}
}

int
gt_sockbuf_readv(struct gt_sockbuf *b,
	const struct iovec *iov, int iovcnt, int cnt, int peek)
{
	int n, off;
	uint8_t *ptr;
	struct gt_uio uio;
	struct sbchunk *pos, *tmp;

	uio.uio_iov = (struct iovec *)iov;
	uio.uio_iovcnt = iovcnt;
	uio.uio_off = 0;
	off = 0;
	DLLIST_FOREACH_SAFE(pos, &b->sob_head, ch_list, tmp) {
		GT_ASSERT(pos->ch_len);
		GT_ASSERT(b->sob_len >= pos->ch_len);
		ptr = gt_sockbuf_chunk_data(pos);
		n = pos->ch_len;
		if (n > cnt - off) {
			n = cnt - off;
			if (n == 0) {
				break;
			}
		}
		n = gt_uio_copyin(&uio, ptr + pos->ch_off, n);
		if (n == 0) {
			break;
		}
		if (peek == 0) {
			b->sob_len -= n;
			if (pos->ch_len == n) {
				DLLIST_REMOVE(pos, ch_list);
				gt_mbuf_free(&pos->ch_mbuf);
			} else {
				pos->ch_len -= n;
				pos->ch_off += n;
			}
		}
		off += n;
	}
	return off;
}

int
gt_sockbuf_readv4(struct gt_sockbuf *b,
	const struct iovec *iov, int iovcnt, int peek)
{
	int rc;

	rc = gt_sockbuf_readv(b, iov, iovcnt, INT_MAX, peek);
	return rc;
}

int
gt_sockbuf_recv(struct gt_sockbuf *b, void *buf, int cnt, int peek)
{
	int rc;
	struct iovec iov;

	iov.iov_base = buf;
	iov.iov_len = cnt;
	rc = gt_sockbuf_readv(b, &iov, 1, cnt, peek);
	return rc;
}

int
gt_sockbuf_pop(struct gt_sockbuf *b, int cnt)
{
	int n, off;
	struct sbchunk *pos, *tmp;

	off = 0;
	DLLIST_FOREACH_SAFE(pos, &b->sob_head, ch_list, tmp) {
		GT_ASSERT(pos->ch_len);
		GT_ASSERT(b->sob_len >= pos->ch_len);
		n = pos->ch_len;
		if (n > cnt - off) {
			n = cnt - off;
		}
		b->sob_len -= n;
		pos->ch_off += n;
		pos->ch_len -= n;
		if (pos->ch_len == 0) {
			DLLIST_REMOVE(pos, ch_list);
			gt_mbuf_free(&pos->ch_mbuf);
		}
		off += n;
		if (off == cnt) {
			break;
		}
	}
	return off;
}

int
gt_sockbuf_rewrite(struct gt_sockbuf *b, const void *dst, int cnt)
{
	uint8_t *data;
	int n, pos;
	struct sbchunk *chunk;

	pos = 0;
	DLLIST_FOREACH(chunk, &b->sob_head, ch_list) {
		GT_ASSERT(chunk->ch_len);
		GT_ASSERT(b->sob_len <= chunk->ch_len);
		n = MIN(cnt - pos, chunk->ch_len);
		data = gt_sockbuf_chunk_data(chunk);
		memcpy(data + chunk->ch_off, (uint8_t *)dst + pos, n);
		pos += n;
		if (pos == cnt) {
			break;
		}
	}
	return pos;
}

int
gt_sockbuf_mod_init()
{
	int rc;
	struct gt_log *log;

	gt_log_scope_init(&this_log, "sockbuf");
	GT_SOCKBUF_LOG_NODE_FOREACH(GT_LOG_NODE_INIT);
	log = GT_LOG_TRACE1(mod_init);
	rc = gt_mbuf_pool_new(log, &gt_sockbuf_chunk_pool,
	                      GT_SOCKBUF_CHUNK_SIZE);
	return rc;
}

void
gt_sockbuf_mod_deinit(struct gt_log *log)
{
	log = GT_LOG_TRACE(log, mod_deinit);
	// TODO:
	//GT_ASSERT(gt_mbuf_pool_is_empty(gt_sockbuf_chunk_pool));
	gt_mbuf_pool_del(gt_sockbuf_chunk_pool);
	gt_log_scope_deinit(log, &this_log);
}
