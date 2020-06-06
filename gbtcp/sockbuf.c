#include "internals.h"

#define CURMOD sockbuf

#define SOCKBUF_CHUNK_DATA_SIZE \
	(SOCKBUF_CHUNK_SIZE - sizeof(struct sbchunk))

struct uio {
	struct iovec *uio_iov;
	int uio_iovcnt;
	size_t uio_off; // must be typeof(iov_len)
};

struct sbchunk {
	struct mbuf ch_mbuf;
#define ch_list ch_mbuf.mb_list
	int ch_len;
	int ch_off;
};

static int
uio_copyin(struct uio *uio, void *buf, int cnt)
{
	int off;
	size_t n;
	u_char *dst;

	for (off = 0; uio->uio_iovcnt && off < cnt; off += n) {
		assert(uio->uio_iov->iov_len >= uio->uio_off);
		n = uio->uio_iov->iov_len - uio->uio_off;
		dst = (u_char *)uio->uio_iov->iov_base + uio->uio_off;
		if (n > cnt - off) {
			n = cnt - off;
		}
		uio->uio_off += n;
		if (uio->uio_off == uio->uio_iov->iov_len) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
			uio->uio_off = 0;
		}
		memcpy(dst, (u_char *)buf + off, n);
	}
	return off;
}

static int
sockbuf_chunk_space(struct sbchunk *chunk)
{
	assert(chunk->ch_off + chunk->ch_len <= SOCKBUF_CHUNK_DATA_SIZE);
	return SOCKBUF_CHUNK_DATA_SIZE - (chunk->ch_off + chunk->ch_len);
}

static void *
sockbuf_chunk_data(struct sbchunk *chunk)
{
	return ((u_char *)chunk) + sizeof(*chunk);
}

static struct sbchunk *
sockbuf_chunk_alloc(struct mbuf_pool *p, struct sockbuf *b)
{
	int rc;
	struct sbchunk *chunk;

	rc = mbuf_alloc(p, (struct mbuf **)&chunk);
	if (rc == 0) {
		chunk->ch_len = 0;
		chunk->ch_off = 0;
		DLIST_INSERT_TAIL(&b->sob_head, chunk, ch_list);
	}
	return chunk;
}

void
sockbuf_init(struct sockbuf *b, int max)
{
	b->sob_len = 0;
	b->sob_max = max;
	dlist_init(&b->sob_head);
}

int
sockbuf_full(struct sockbuf *b)
{
	return b->sob_len >= b->sob_max;
}

void
sockbuf_free(struct sockbuf *b)
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
sockbuf_set_max(struct sockbuf *b, int max)
{
	b->sob_max = max;
}

static void
sockbuf_free_n(struct sockbuf *b, int nr_chunks)
{
	int i;
	struct sbchunk *chunk;

	for (i = 0; i < nr_chunks; ++i) {
		assert(!dlist_is_empty(&b->sob_head));
		chunk = DLIST_LAST(&b->sob_head, struct sbchunk, ch_list);
		DLIST_REMOVE(chunk, ch_list);
		mbuf_free(&chunk->ch_mbuf);
	}
}

int
sockbuf_space(struct sockbuf *b)
{
	return b->sob_max < b->sob_len ? 0 : b->sob_max - b->sob_len;
}

static void
sockbuf_write(struct sockbuf *b, struct sbchunk *pos,
	const void *src, int cnt)
{
	int n, rem, space;
	u_char *data;
	const u_char *ptr;

	ptr = src;
	rem = cnt;
	DLIST_FOREACH_CONTINUE(pos, &b->sob_head, ch_list) {
		assert(rem > 0);
		space = sockbuf_chunk_space(pos);
		n = MIN(rem, space);
		data = sockbuf_chunk_data(pos);
		memcpy(data + pos->ch_off + pos->ch_len, ptr, n);
		b->sob_len += n;
		pos->ch_len += n;
		ptr += n;
		rem -= n;
	}
	assert(rem == 0);
}

int
sockbuf_add(struct mbuf_pool *p, struct sockbuf *b, const void *buf, int cnt)
{
	int n, rem, space, added;
	struct sbchunk *chunk, *pos;

	assert(cnt >= 0);
	assert(cnt <= UINT16_MAX);
	space = sockbuf_space(b);
	added = MIN(cnt, space);
	if (added <= 0) {
		return 0;
	}
	n = 0;
	if (dlist_is_empty(&b->sob_head)) {
		chunk = sockbuf_chunk_alloc(p, b);
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
		rem -= sockbuf_chunk_space(chunk);
		if (rem <= 0) {
			break;
		}
		chunk = sockbuf_chunk_alloc(p, b);
		if (chunk == NULL) {
			sockbuf_free_n(b, n);
			return -ENOMEM;
		}
		n++;
	}
	sockbuf_write(b, pos, buf, added);
	return added;
}

void
sockbuf_copy(struct sockbuf *b, int off, u_char *dst, int cnt)
{
	u_char *data;
	size_t n;
	struct sbchunk *chunk;

	DLIST_FOREACH(chunk, &b->sob_head, ch_list) {
		assert(chunk->ch_len);
		if (off < chunk->ch_len) {
			break;
		}
		off -= chunk->ch_len;
	}
	for (; cnt != 0; chunk = DLIST_NEXT(chunk, ch_list)) {
		assert(&chunk->ch_list != &b->sob_head);
		n = MIN(cnt, chunk->ch_len - off);
		data = sockbuf_chunk_data(chunk);
		memcpy(dst, data + chunk->ch_off + off, n);
		off = 0;
		cnt -= n;
		dst += n;
	}
}

int
sockbuf_readv(struct sockbuf *b, const struct iovec *iov, int iovcnt,
	int accum_len_max, int peek)
{
	int n, off;
	u_char *ptr;
	struct uio uio;
	struct sbchunk *pos, *tmp;

	uio.uio_iov = (struct iovec *)iov;
	uio.uio_iovcnt = iovcnt;
	uio.uio_off = 0;
	off = 0;
	DLIST_FOREACH_SAFE(pos, &b->sob_head, ch_list, tmp) {
		assert(pos->ch_len);
		assert(b->sob_len >= pos->ch_len);
		ptr = sockbuf_chunk_data(pos);
		n = pos->ch_len;
		if (n > accum_len_max - off) {
			n = accum_len_max - off;
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
sockbuf_read_zerocopy(struct sockbuf *b, void **pbuf)
{
	struct sbchunk *c;

	if (dlist_is_empty(&b->sob_head)) {
		return 0;
	}
	c = DLIST_FIRST(&b->sob_head, struct sbchunk, ch_list);
	assert(c->ch_len);
	*pbuf = sockbuf_chunk_data(c);
	return c->ch_len;
}

int
sockbuf_readv4(struct sockbuf *b, const struct iovec *iov, int iovcnt, int peek)
{
	int rc;

	rc = sockbuf_readv(b, iov, iovcnt, INT_MAX, peek);
	return rc;
}

int
sockbuf_read(struct sockbuf *b, void *buf, int cnt, int peek)
{
	int rc;
	struct iovec iov;

	iov.iov_base = buf;
	iov.iov_len = cnt;
	rc = sockbuf_readv(b, &iov, 1, cnt, peek);
	return rc;
}

int
sockbuf_drain(struct sockbuf *b, int cnt)
{
	int n, off;
	struct sbchunk *pos, *tmp;

	off = 0;
	DLIST_FOREACH_SAFE(pos, &b->sob_head, ch_list, tmp) {
		assert(pos->ch_len);
		assert(b->sob_len >= pos->ch_len);
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
sockbuf_rewrite(struct sockbuf *b, const void *dst, int cnt)
{
	u_char *data;
	int n, pos;
	struct sbchunk *chunk;

	pos = 0;
	DLIST_FOREACH(chunk, &b->sob_head, ch_list) {
		assert(chunk->ch_len);
		assert(b->sob_len <= chunk->ch_len);
		n = MIN(cnt - pos, chunk->ch_len);
		data = sockbuf_chunk_data(chunk);
		memcpy(data + chunk->ch_off, (u_char *)dst + pos, n);
		pos += n;
		if (pos == cnt) {
			break;
		}
	}
	return pos;
}
