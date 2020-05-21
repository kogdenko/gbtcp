#include "internals.h"

#define HTABLE_BUCKET(t, e) \
	(struct htable_bucket **)((u_char *)e + t->htd_bucket_off)

struct htable_mod {
	struct log_scope log_scope;
};

static struct htable_mod *curmod;

int
htable_mod_init(struct log *log, void **pp)
{
	int rc;
	struct htable_mod *mod;

	LOG_TRACE(log);
	rc = shm_malloc(log, pp, sizeof(*mod));
	if (!rc) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "htable");
	}
	return rc;
}

int
htable_mod_attach(struct log *log, void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

void
htable_mod_deinit(struct log *log, void *raw_mod)
{
	struct htable_mod *mod;

	mod = raw_mod;
	LOG_TRACE(log);
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}

void
htable_mod_detach(struct log *log)
{
	curmod = NULL;
}

static int
htable_static_init(struct htable_static *t, int size, htable_f fn, int flags)
{
	int i, rc;
	malloc_f malloc_fn;
	struct htable_bucket *b;

	t->hts_size = size;
	t->hts_mask = size - 1;
	t->hts_fn = fn;
	if (flags & HTABLE_FLAG_SHARED) {
		malloc_fn = shm_malloc;
	} else {
		malloc_fn = sys_malloc;
	}
	rc = (*malloc_fn)(NULL, (void **)&t->hts_array, size * sizeof(*b));
	if (rc) {
		return rc;
	}
	t->hts_size = size;
	t->hts_mask = size - 1;
	for (i = 0; i < size; ++i) {
		b = t->hts_array + i;
		dlist_init(&b->htb_head);
		spinlock_init(&b->htb_lock);
	}
	return 0;
}

static void
htable_static_deinit(struct htable_static *t, int flags)
{
	free_f free_fn;

	if (flags & HTABLE_FLAG_SHARED) {
		free_fn = shm_free;
	} else {
		free_fn = sys_free;
	}
	(*free_fn)(t->hts_array);
	t->hts_array = NULL;
}

struct htable_bucket *
htable_static_bucket_get(struct htable_static *t, uint32_t h) 
{
	return t->hts_array + ((h) & (t)->hts_mask);
}

void
htable_static_del(struct htable_static *t, htable_entry_t *e)
{
	dlist_remove(e);
}

int
htable_init(struct log *log, struct htable *t, int size,
	htable_f fn, int flags, int bucket_off)
{
	int rc;

	t->htd_flags = flags;
	t->htd_bucket_off = bucket_off;
	t->htd_size_min = size;
	t->htd_nentries = 0;
	t->htd_resize_discard = 0;
	t->htd_old = NULL;
	t->htd_new = t->htd_tables + 0;
	t->htd_tables[1].hts_array = NULL;
	rc = htable_static_init(t->htd_new, size, fn, flags);
	return rc;
}

void
htable_deinit(struct htable *t)
{
	int i;

	for (i = 0; i < 2; ++i) {
		htable_static_deinit(t->htd_tables + i, t->htd_flags);
	}
}

struct htable_bucket *
htable_bucket_get(struct htable *t, uint32_t h) 
{
//	int i;
	struct htable_bucket *b;
	struct htable_static *ts;

	/*
	if (t->htd_old == NULL) {
		ts = t->htd_new;
	} else {
		i = h & t->htd_old->hts_mask;
		if (i <= t->htd_resize_progress) {
			ts = t->htd_new;
		} else {
			ts = t->htd_old;
		}
	}
	*/
	ts = t->htd_new;
	b = htable_static_bucket_get(ts, h);
	return b;
}

void
htable_add(struct htable *t, struct htable_bucket *b, htable_entry_t *e)
{
	dlist_insert_tail(&b->htb_head, e);
	*HTABLE_BUCKET(t, e) = b;
	t->htd_nentries++;
}

void
htable_del(struct htable *t, htable_entry_t *e)
{
	ASSERT(t->htd_nentries > 0);
	dlist_remove(e);
	t->htd_nentries--;
}

#if 0
static struct htable_1s *
htable_1d_new(struct htable *t)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(t->htd_tables); ++i) {
		if (t->htd_tables[i].hts_array == NULL) {
			return t->htd_tables + i;
		}
	}
	BUG;
	return 0;
}


static void
htable_resize(struct htable *t)
{
	int rc, size, new_size;
	htable_1_bucket_t *b;
	htable_entry_t *e;
	struct log *log;
	struct htable_1s *tmp;

	if (t->htd_old == NULL) {
		new_size = 0;
		size = t->htd_new->hts_size;
		if (t->htd_nentries > size) {
			new_size = size << 1;
		} else if (t->htd_nentries < (size >> 2)) {
			new_size = size >> 1;
		}
		if (!new_size) {
			return;
		}
		if (new_size < t->htd_size_min) {
			return;
		}
		if (t->htd_resize_discard) {
			t->htd_resize_discard--;
			return;
		}
		tmp = htable_1d_new(t);
		log = log_trace0();
		rc = htable_1s_init(log, tmp, new_size, t->htd_new->hts_fn,
		                    t->htd_flags, t->htd_bucket_off);
		if (rc) {
			t->htd_resize_discard = new_size;
			return;
		}
		t->htd_old = t->htd_new;
		t->htd_new = tmp;
		t->htd_resize_progress = 0;
		log = log_trace0();
		LOGF(log, LOG_INFO, 0, "ok; size=%d->%d, nentries=%d",
		     size, new_size, t->htd_nentries);
	} else {
		ASSERT(t->htd_old->hts_size > t->htd_resize_progress);
		b = t->htd_old->hts_array + t->htd_resize_progress;
		while (!dlist_is_empty(b)) {
			e = dlist_first(b);
			dlist_remove(e);
			htable_1s_add(t->htd_new, b, e);
		}
		t->htd_resize_progress++;
		if (t->htd_old->hts_size == t->htd_resize_progress) {
			htable_1s_deinit(t->htd_old);
			t->htd_old = NULL;
			log = log_trace0();
			LOGF(log, LOG_INFO, 0, "done; nentries=%d",
			     t->htd_nentries);
		}
	}
}
#endif
