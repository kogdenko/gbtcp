// gpl2
#include "internals.h"

#define CURMOD htable

struct htable_id {
	uint32_t lo;
	uint32_t hi;
};

void
htable_bucket_init(struct htable_bucket *b)
{
	dlist_init(&b->htb_head);
	spinlock_init(&b->htb_lock);
}

static void
htable_free_array(struct htable *t)
{
	free_f free_fn;

	if (t->ht_flags & HTABLE_SHARED) {
		free_fn = shm_free;
	} else {
		free_fn = sys_free;
	}
	(*free_fn)(t->ht_array);
	t->ht_array = NULL;
}

static int
htable_resize(struct htable *t, int size)
{
	int i;
	void *ptr;
	int new_size, new_mask; 
	malloc_f malloc_fn;

	if (t->ht_flags & HTABLE_POWOF2) {
		new_size = upper_pow2_32(size);
		new_mask = new_size - 1;
	} else {
		new_size = size;
		new_mask = 0;
	}
	if (t->ht_flags & HTABLE_SHARED) {
		malloc_fn = shm_malloc;
	} else {
		malloc_fn = sys_malloc;
	}
	ptr = (*malloc_fn)(new_size * sizeof(struct htable_bucket));
	if (ptr == NULL) {
		return -ENOMEM;
	}
	htable_free_array(t);
	t->ht_array = ptr;
	t->ht_size = new_size;
	t->ht_mask = new_mask;
	for (i = 0; i < t->ht_size; ++i) {
		htable_bucket_init(t->ht_array + i);
	}
	return 0;
}

int
htable_init(struct htable *t, int size, htable_f fn, int flags)
{
	int rc;

	t->ht_flags = flags;
	t->ht_fn = fn;
	t->ht_array = NULL;
	t->ht_sysctl_fn = NULL;
	rc = htable_resize(t, size);
	return rc; 
}

void
htable_deinit(struct htable *t)
{
	htable_free_array(t);
}

struct htable_bucket *
htable_bucket_get(struct htable *t, uint32_t h) 
{
	int i;

	if (t->ht_flags & HTABLE_POWOF2) {
		i = h & t->ht_mask;
	} else {
		i = h % t->ht_size;
	}
	return t->ht_array + i;
}

static int
sysctl_htable_size(struct sysctl_conn *cp, void *udata,
	const char *new, struct strbuf *out)
{
	int rc, new_size;
	char *endptr;
	struct htable *t;

	t = udata;
	strbuf_addf(out, "%d", t->ht_size);
	if (new == NULL) {
		return 0;
	}
	new_size = strtoul(new, &endptr, 10);
	if (new_size == 0 || *endptr != '\0') {
		return -EINVAL;
	}
	if (new_size == t->ht_size) {
		return 0;
	}
	rc = htable_resize(t, new_size);
	return rc;
}

static int
sysctl_htable_list_next(void *udata, const char *ident, struct strbuf *out)
{
	int rc, lo;
	struct dlist *e;
	struct htable *t;
	struct htable_id id;
	struct htable_bucket *b;

	id.hi = id.lo = 0;
	if (ident != NULL) {
		rc = sscanf(ident, "%d.%d", &id.hi, &id.lo);
		if (rc == 2) {
			id.lo++;
		}
	}
	t = (struct htable *)udata;
	assert(t->ht_sysctl_fn != NULL);
	for (; id.hi < t->ht_size; ++id.hi) {
		b = t->ht_array + id.hi;
		lo = 0;
		HTABLE_BUCKET_LOCK(b);
		dlist_foreach(e, &b->htb_head) {
			if (lo == id.lo) {
				HTABLE_BUCKET_UNLOCK(b);
				strbuf_addf(out, "%d.%d", id.hi, id.lo);
				return 0;
			}
			lo++;
		}
		HTABLE_BUCKET_UNLOCK(b);
		id.lo = 0;
	}
	return -ENOENT;
}

static int
sysctl_htable_list(void *udata, const char *ident,
	const char *new, struct strbuf *out)
{
	int rc, lo;
	struct dlist *e;
	struct htable *t;
	struct htable_id id;
	struct htable_bucket *b;

	rc = sscanf(ident, "%d.%d", &id.hi, &id.lo);
	if (rc != 2) {
		return -EPROTO;
	}
	t = (struct htable *)udata;
	assert(t->ht_sysctl_fn != NULL);
	if (id.hi >= t->ht_size) {
		return 0;
	}
	b = t->ht_array + id.hi;
	lo = 0;
	HTABLE_BUCKET_LOCK(b);
	dlist_foreach(e, &b->htb_head) {
		if (lo == id.lo) {
			(*t->ht_sysctl_fn)(e, new, out);
			break;
		}
		lo++;
	}
	HTABLE_BUCKET_UNLOCK(b);
	return 0;
}

void
sysctl_add_htable_size(const char *path, struct htable *t)
{
	assert(t->ht_fn != NULL);
	sysctl_add(path, SYSCTL_LD, t, NULL, sysctl_htable_size);
}

void
sysctl_add_htable_list(const char *path, int mode, struct htable *t,
	htable_sysctl_f fn)
{
	assert(t->ht_sysctl_fn == NULL);
	assert(fn != NULL);
	t->ht_sysctl_fn = fn;
	sysctl_add_list(path, mode, t,
	                sysctl_htable_list_next,
	                sysctl_htable_list);
}
