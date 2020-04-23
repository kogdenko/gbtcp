#include "log.h"
#include "mm.h"
#include "mbuf.h"
#include "sockbuf.h"

#define GT_SOCKBUF_CHUNK_SIZE 2048
#define GT_SOCKBUF_CHUNK_DATA_SIZE \
	(GT_SOCKBUF_CHUNK_SIZE - sizeof(struct sbchunk))

struct sockbuf_mod {
	struct log_scope log_scope;
};

struct gt_uio {
	struct iovec *uio_iov;
	int uio_iovcnt;
	size_t uio_off; /* must be typeof of iov_len */
};

struct sbchunk {
	struct mbuf ch_mbuf;
#define ch_list ch_mbuf.mb_list
	int ch_len;
	int ch_off;
};

static struct mbuf_pool *sockbuf_chunk_pool;
static struct sockbuf_mod *current_mod;

static int
uio_copyin(struct gt_uio *uio, void *buf, int cnt)
{
	int off;
	size_t n;
	uint8_t *dst;

	for (off = 0; uio->uio_iovcnt && off < cnt; off += n) {
		ASSERT(uio->uio_iov->iov_len >= uio->uio_off);
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
	ASSERT(chunk->ch_off + chunk->ch_len <= GT_SOCKBUF_CHUNK_DATA_SIZE);
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
	struct log *log;
	struct sbchunk *chunk;

	log = log_trace0();
	rc = mbuf_alloc(log, sockbuf_chunk_pool, (struct mbuf **)&chunk);
	if (rc == 0) {
		chunk->ch_len = 0;
		chunk->ch_off = 0;
		DLIST_INSERT_TAIL(&b->sob_head, chunk, ch_list);
	}
	return chunk;
}

void
gt_sockbuf_init(struct gt_sockbuf *b, int max)
{
	b->sob_len = 0;
	b->sob_max = max;
	dlist_init(&b->sob_head);
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
	while (!dlist_is_empty(&b->sob_head)) {
		chunk = DLIST_FIRST(&b->sob_head, struct sbchunk, ch_list);
		DLIST_REMOVE(chunk, ch_list);
		mbuf_free(&chunk->ch_mbuf);
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
		ASSERT(!dlist_is_empty(&b->sob_head));
		chunk = DLIST_LAST(&b->sob_head, struct sbchunk, ch_list);
		DLIST_REMOVE(chunk, ch_list);
		mbuf_free(&chunk->ch_mbuf);
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
	DLIST_FOREACH_CONTINUE(pos, &b->sob_head, ch_list) {
		ASSERT(rem > 0);
		space = gt_sockbuf_chunk_space(pos);
		n = MIN(rem, space);
		data = gt_sockbuf_chunk_data(pos);
		memcpy(data + pos->ch_off + pos->ch_len, ptr, n);
		b->sob_len += n;
		pos->ch_len += n;
		ptr += n;
		rem -= n;
	}
	ASSERT(rem == 0);
}

int
gt_sockbuf_add(struct gt_sockbuf *b, const void *buf, int cnt, int atomic)
{
	int n, rem, space, added;
	struct sbchunk *chunk, *pos;

	ASSERT(cnt >= 0);
	ASSERT(cnt <= UINT16_MAX);
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
	if (dlist_is_empty(&b->sob_head)) {
		chunk = gt_sockbuf_chunk_alloc(b);
		if (chunk == NULL) {
			return -ENOMEM;
		}
		n++;
	} else {
		chunk = DLIST_LAST(&b->sob_head, struct sbchunk, ch_list);
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

	DLIST_FOREACH(chunk, &b->sob_head, ch_list) {
		ASSERT(chunk->ch_len);
		if (off < chunk->ch_len) {
			break;
		}
		off -= chunk->ch_len;
	}
	for (; cnt != 0; chunk = DLIST_NEXT(chunk, ch_list)) {
		ASSERT(&chunk->ch_list != &b->sob_head);
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
	BUG;
}

void
gt_sockbuf_send(struct gt_sockbuf *b, int off, void *dst, int cnt)
{
	ASSERT(off + cnt <= b->sob_len);

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
	DLIST_FOREACH_SAFE(pos, &b->sob_head, ch_list, tmp) {
		ASSERT(pos->ch_len);
		ASSERT(b->sob_len >= pos->ch_len);
		ptr = gt_sockbuf_chunk_data(pos);
		n = pos->ch_len;
		if (n > cnt - off) {
			n = cnt - off;
			if (n == 0) {
				break;
			}
		}
		n = uio_copyin(&uio, ptr + pos->ch_off, n);
		if (n == 0) {
			break;
		}
		if (peek == 0) {
			b->sob_len -= n;
			if (pos->ch_len == n) {
				DLIST_REMOVE(pos, ch_list);
				mbuf_free(&pos->ch_mbuf);
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
	DLIST_FOREACH_SAFE(pos, &b->sob_head, ch_list, tmp) {
		ASSERT(pos->ch_len);
		ASSERT(b->sob_len >= pos->ch_len);
		n = pos->ch_len;
		if (n > cnt - off) {
			n = cnt - off;
		}
		b->sob_len -= n;
		pos->ch_off += n;
		pos->ch_len -= n;
		if (pos->ch_len == 0) {
			DLIST_REMOVE(pos, ch_list);
			mbuf_free(&pos->ch_mbuf);
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
	DLIST_FOREACH(chunk, &b->sob_head, ch_list) {
		ASSERT(chunk->ch_len);
		ASSERT(b->sob_len <= chunk->ch_len);
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
sockbuf_mod_init(struct log *log, void **pp)
{
	int rc;
	struct sockbuf_mod *mod;
	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (rc) {
		return rc;
	}
	mod = *pp;
	log_scope_init(&mod->log_scope, "sockbuf");
	return rc;
}

int
sockbuf_mod_attach(struct log *log, void *raw_mod)
{
	int rc;
	LOG_TRACE(log);
	current_mod = raw_mod;
	rc = mbuf_pool_alloc(log, &sockbuf_chunk_pool,
	                     GT_SOCKBUF_CHUNK_SIZE);
	return rc;
}

void
sockbuf_mod_deinit(struct log *log, void *raw_mod)
{
	struct sockbuf_mod *mod;
	LOG_TRACE(log);
	mod = raw_mod;
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}

void
sockbuf_mod_detach(struct log *log)
{
	// TODO:
	//ASSERT(mbuf_pool_is_empty(sockbuf_chunk_pool));
	mbuf_pool_free(sockbuf_chunk_pool);
	current_mod = NULL;
}
