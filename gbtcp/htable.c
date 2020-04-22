#include "internals.h"

#define HTABLE_LOG_MSG_FOREACH(x) \
	x(mod_deinit) \
	x(create) \
	x(resize)

struct htable_mod {
	struct log_scope log_scope;
	HTABLE_LOG_MSG_FOREACH(LOG_MSG_DECLARE);
};

static struct htable_mod *current_mod;

int
htable_mod_init(struct log *log, void **pp)
{
	int rc;
	struct htable_mod *mod;
	LOG_TRACE(log);
	rc = mm_alloc(log, pp, sizeof(*mod));
	if (rc)
		return rc;
	mod = *pp;
	log_scope_init(&mod->log_scope, "htable");
	return 0;
}
int
htable_mod_attach(struct log *log, void *raw_mod)
{
	current_mod = raw_mod;
	return 0;
}
void
htable_mod_deinit(struct log *log, void *raw_mod)
{
	struct htable_mod *mod;
	mod = raw_mod;
	LOG_TRACE(log);
	log_scope_deinit(log, &mod->log_scope);
	mm_free(mod);
}
void
htable_mod_detach(struct log *log)
{
	current_mod = NULL;
}
int
htable_static_create(struct log *log, struct htable_static *t,
	int size, htable_hash_f hash_fn)
{
	int i, rc;
	LOG_TRACE(log);
	t->hts_size = size;
	t->hts_mask = size - 1;
	t->hts_hash_fn = hash_fn;
	rc = sys_malloc(log, (void **)&t->hts_array,
	                size * sizeof(struct dlist));
	if (rc) {
		return rc;
	}
	t->hts_size = size;
	t->hts_mask = size - 1;
	for (i = 0; i < size; ++i) {
		dlist_init(t->hts_array + i);
	}
	return 0;
}
void
htable_static_free(struct htable_static *t)
{
	free(t->hts_array);
	t->hts_array = NULL;
}

struct dlist *
htable_static_bucket(struct htable_static *t, uint32_t h) 
{
	return t->hts_array + ((h) & (t)->hts_mask);
}
void
htable_static_add(struct htable_static *t, struct dlist *elem)
{
	uint32_t h;
	struct dlist *bucket;
	h = (*t->hts_hash_fn)(elem);
	bucket = htable_static_bucket(t, h);
	dlist_insert_tail(bucket, elem);
}
void
htable_static_del(struct htable_static *t, struct dlist *elem)
{
	dlist_remove(elem);
}
int
htable_dynamic_create(struct log *log, struct htable_dynamic *t,
	int size, htable_hash_f hash_fn)
{
	int rc;
	t->htd_size_min = size;
	t->htd_nr_elems = 0;
	t->htd_resize_discard = 0;
	t->htd_old = NULL;
	t->htd_new = t->htd_tables + 0;
	t->htd_tables[1].hts_array = NULL;
	rc = htable_static_create(log, t->htd_new, size, hash_fn);
	return rc;
}
void
htable_dynamic_free(struct htable_dynamic *t)
{
	int i;
	for (i = 0; i < 2; ++i) {
		htable_static_free(t->htd_tables + i);
	}
}
struct dlist *
htable_dynamic_bucket(struct htable_dynamic *t, uint32_t h) 
{
	int i;
	struct dlist *bucket;
	struct htable_static *ts;
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
	bucket = htable_static_bucket(ts, h);
	return bucket;
}
static struct htable_static *
htable_dynamic_new(struct htable_dynamic *t)
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
htable_dynamic_resize(struct htable_dynamic *t)
{
	int rc, size, new_size;
	struct dlist *elem, *bucket;
	struct log *log;
	struct htable_static *tmp;
	if (t->htd_old == NULL) {
		new_size = 0;
		size = t->htd_new->hts_size;
		if (t->htd_nr_elems > size) {
			new_size = size << 1;
		} else if (t->htd_nr_elems < (size >> 2)) {
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
		tmp = htable_dynamic_new(t);
		log = log_trace0();
		rc = htable_static_create(log, tmp, new_size,
		                             t->htd_new->hts_hash_fn);
		if (rc) {
			t->htd_resize_discard = new_size;
			return;
		}
		t->htd_old = t->htd_new;
		t->htd_new = tmp;
		t->htd_resize_progress = 0;
		log = log_trace0();
		LOGF(log, LOG_MSG(resize), LOG_INFO, 0,
		     "ok; size=%d->%d, elements=%d",
		     size, new_size, t->htd_nr_elems);
	} else {
		ASSERT(t->htd_old->hts_size > t->htd_resize_progress);
		bucket = t->htd_old->hts_array + t->htd_resize_progress;
		while (!dlist_is_empty(bucket)) {
			elem = dlist_first(bucket);
			dlist_remove(elem);
			htable_static_add(t->htd_new, elem);
		}
		t->htd_resize_progress++;
		if (t->htd_old->hts_size == t->htd_resize_progress) {
			htable_static_free(t->htd_old);
			t->htd_old = NULL;
			log = log_trace0();
			LOGF(log, LOG_MSG(resize), LOG_INFO, 0,
			     "done; elements=%d", t->htd_nr_elems);
		}
	}
}
void
htable_dynamic_add(struct htable_dynamic *t, struct dlist *elem)
{
	uint32_t h;
	struct dlist *bucket;
	h = (*t->htd_new->hts_hash_fn)(elem);
	bucket = htable_dynamic_bucket(t, h);
	dlist_insert_tail(bucket, elem);
	t->htd_nr_elems++;
	htable_dynamic_resize(t);
}
void
htable_dynamic_del(struct htable_dynamic *t, struct dlist *elem)
{
	ASSERT(t->htd_nr_elems > 0);
	dlist_remove(elem);
	t->htd_nr_elems--;
	htable_dynamic_resize(t);
}
