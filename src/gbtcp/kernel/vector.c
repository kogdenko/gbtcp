// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/kernel/mm.h>
#include <gbtcp/kernel/shm.h>
#include <gbtcp/kernel/vector.h>

void *
gt__vec_reserve(void *v, struct gt_allocator *alc, size_t szof, size_t new_cap)
{
	size_t size, cap, max_cap;
	void *v2;
	struct gt_vec_header *vh2;

	size = gt_vec_size(v);
	cap = gt_vec_capacity(v);

	if (new_cap <= cap) {
		return v;
	}

	max_cap = GT_MAX(new_cap, 3 * cap / 2);

	vh2 = gt_a_malloc(alc, sizeof(*vh2) + max_cap * szof, 0);
	if (vh2 == NULL) {
		return NULL;
	}

	vh2->vh_size = size;
	vh2->vh_capacity = max_cap;
	v2 = vh2 + 1;

	memcpy(v2, v, size * szof);

	gt__vec_free(v, alc);

	return v2;
}

void *
gt__vec_resize(void *v, struct gt_allocator *alc, size_t szof, size_t new_size,
	       u8 flags)
{
	void *v2;
	size_t size;
	struct gt_vec_header *vh;

	size = gt_vec_size(v);

	v2 = gt__vec_reserve(v, alc, szof, new_size);
	if (v2 == NULL) {
		return NULL;
	}

	if (new_size > size && GT_FLAG_ISSET(flags, GT_MF_ZERO)) {
		memset((u8 *)v2 + size * szof, 0, (new_size - size) * szof);
	}

	vh = gt_vec_get_header(v2);
	if (vh != NULL) {
		vh->vh_size = new_size;
	}

	return v2;
}

void
gt__vec_pop_front(void *v, struct gt_allocator *alc, size_t n, size_t szof)
{
	size_t size;

	if (n == 0) {
		return;
	}

	size = gt_vec_size(v);

	assert(n <= size);

	memmove(v, (u8 *)v + n * szof, (size - n) * szof);

	gt__vec_resize(v, alc, szof, size - n, 0);
}

void
gt__vec_free(void *v, struct gt_allocator *alc)
{
	if (v != NULL) {
		gt_a_free_internal(alc, gt_vec_get_header(v));
	}
}

size_t
gt_str_len(char *s)
{
	size_t size;

	size = gt_vec_size(s);
	return size ? size - 1 : 0;
}

static int
gt_str_add3(char **s, const char *data, size_t size)
{
	int rc;
	size_t len, cap, count;

	len = gt_str_len(*s);

	rc = 0;
	count = size;

	rc = gt_vec_resize(*s, gt_get_allocator(), len + size + 1, 0);
	if (rc) {
		cap = gt_vec_capacity(*s);
		rc = gt_vec_resize(*s, gt_get_allocator(), cap, 0);
		assert(rc == 0);
		count = cap - len - 1;
	}

	memcpy(*s + len, data, count);
	(*s)[len + count] = '\0';
	return rc;
}

int
gt__str_addcstr(char **s, const char *cstr)
{
	size_t len;

	len = strlen(cstr);
	return gt_str_add3(s, cstr, len);
}

int
gt__str_addchar(char **s, char ch)
{
	return gt_str_add3(s, &ch, 1);
}

char *
gt__str_vprintf(char **s, const char *format, va_list ap)
{
	int rc;
	size_t len, cap, count;
	va_list cp;

	len = gt_str_len(*s);
	cap = gt_vec_capacity(*s);

	va_copy(cp, ap);
	count = vsnprintf(*s + len, cap - len, format, cp);
	va_end(cp);

	if (count >= cap - len) {
		rc = gt_vec_reserve(*s, gt_get_allocator(), len + count + 1);
		if (rc) {
			count = cap - len - 1;
			(*s)[len + count] = '\0';
		} else {
			vsnprintf(*s + len, count + 1, format, ap);
		}
	}

	rc = gt_vec_resize(*s, gt_get_allocator(), len + count + 1, 0);
	assert(rc == 0);

	return *s + len;
}

char *
gt__str_printf(char **s, const char *format, ...)
{
	char *res;
	va_list ap;

	va_start(ap, format);
	res = gt__str_vprintf(s, format, ap);
	va_end(ap);

	return res;
}
