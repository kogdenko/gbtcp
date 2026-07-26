// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_VECTOR_H
#define GBTCP_VECTOR_H

#include <gbtcp/kernel/subr.h>

struct gt_allocator;
struct gt_allocator *gt_get_allocator(void);

struct gt_vec_header {
	size_t vh_size;
	size_t vh_capacity;
};

#define gt_vec_get_header(v) (((struct gt_vec_header *)(v)) - 1)

#define gt_vec_add3(v, alc, e, n) \
	({ \
		int rc_; \
\
		rc_ = gt_vec_resize(v, alc, gt_vec_size(v) + n, 0); \
		if (rc_ == 0) { \
			memcpy((v) + gt_vec_size(v) - n, e, n * sizeof(*v)); \
		} \
		rc_; \
	})

#define gt_vec_add(v, alc, e) \
	({ \
		int rc_; \
\
		rc_ = gt_vec_resize(v, alc, gt_vec_size(v) + 1, 0); \
		if (rc_ == 0) { \
			(v)[gt_vec_size(v) - 1] = (e); \
		} \
		rc_; \
	})

#define gt_vec_del(v, alc, index) \
	({ \
		(v)[index] = (v)[gt_vec_size(v) - 1]; \
		gt__vec_resize(v, alc, sizeof(*(v)), gt_vec_size(v) - 1, 0); \
	})

#define gt_vec_size(v) ((v) == NULL ? 0 : gt_vec_get_header(v)->vh_size)
#define gt_vec_is_empty(v) (!gt_vec_size(v))
#define gt_vec_capacity(v) ((v) == NULL ? 0 : gt_vec_get_header(v)->vh_capacity)

#define gt_vec_reserve(v, alc, capacity) \
	({ \
		int rc_; \
		typeof((v)) new_v_; \
\
		new_v_ = gt__vec_reserve(v, alc, sizeof(*(v)), capacity); \
		if (new_v_ == NULL && (capacity) > 0) { \
			rc_ = -ENOMEM; \
		} else { \
			rc_ = 0; \
			(v) = new_v_; \
		} \
		rc_; \
	})

#define gt_vec_resize(v, alc, size, flags) \
	({ \
		int rc_; \
		typeof(v) new_v_; \
\
		new_v_ = gt__vec_resize(v, alc, sizeof(*(v)), size, flags); \
		if (new_v_ == NULL && (size) > 0) { \
			rc_ = -ENOMEM; \
		} else { \
			rc_ = 0; \
			(v) = new_v_; \
		} \
		rc_; \
	})

#define gt_vec_copy(dst, alc, src) \
	({ \
		int rc_; \
\
		rc_ = gt_vec_resize(dst, alc, gt_vec_size(src), 0); \
		if (rc_ == 0) { \
			memcpy(dst, src, gt_vec_size(src) * sizeof(*(dst))); \
		} \
		rc_; \
	})

#define GT_VEC_FOREACH(e, v) \
	for (int i = 0; (i < gt_vec_size(v) && (e = (v)[i])); ++i)

#define GT_VEC_FOREACH_PTR(pe, v) for (pe = v; pe < (v) + gt_vec_size(v); ++pe)

#define GT_VEC_FOREACH_INDEX(i, v) for (i = 0; i < gt_vec_size(v); ++i)

void *gt__vec_reserve(void *v, struct gt_allocator *alc, size_t szof,
		      size_t size);

void *gt__vec_resize(void *v, struct gt_allocator *alc, size_t szof,
		     size_t size, u8 flags);

void gt__vec_pop_front(void *v, struct gt_allocator *alc, size_t n,
		       size_t szof);
#define gt_vec_pop_front(v, alc, n) gt__vec_pop_front(v, alc, n, sizeof(*(v)))

void gt__vec_free(void *v, struct gt_allocator *alc);
#define gt_vec_free(v, alc) \
	if ((v) != NULL) { \
		gt__vec_free(v, alc); \
		(v) = NULL; \
	}

size_t gt_str_len(char *s);

int gt__str_addcstr(char **s, const char *cstr);
#define gt_str_addcstr(s, cstr) gt__str_addcstr(&s, cstr)

int gt__str_addchar(char **s, char ch);
#define gt_str_addchar(s, ch) gt__str_addchar(&s, ch)

char *gt__str_vprintf(char **s, const char *format, va_list ap);
#define gt_str_vprintf(s, format, ap) gt__str_vprintf(&s, format, ap)

char *gt__str_printf(char **s, const char *format, ...)
	__attribute__((format(printf, 2, 3)));
#define gt_str_printf(s, format, ...) gt__str_printf(&s, format, __VA_ARGS__)

#define gt_str_free(s) gt_vec_free(s, gt_get_allocator())

#endif
