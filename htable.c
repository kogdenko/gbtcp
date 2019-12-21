#include "htable.h"
#include "log.h"
#include "sys.h"
#include "list.h"

#define GT_HTABLE_LOG_NODE_FOREACH(x) \
	x(mod_deinit) \
	x(create) \
	x(resize)

GT_HTABLE_LOG_NODE_FOREACH(GT_LOG_NODE_STATIC);
static struct gt_log_scope this_log;

static struct gt_htable_static *gt_htable_dynamic_new(
	struct gt_htable_dynamic *t);
static void gt_htable_dynamic_resize(struct gt_htable_dynamic *t);

int
gt_htable_mod_init()
{
	gt_log_scope_init(&this_log, "htable");
	GT_HTABLE_LOG_NODE_FOREACH(GT_LOG_NODE_INIT);
	return 0;
}

void
gt_htable_mod_deinit(struct gt_log *log)
{
	log = GT_LOG_TRACE(log, mod_deinit);
	gt_log_scope_deinit(log, &this_log);
}

int
gt_htable_static_create(struct gt_log *log, struct gt_htable_static *t,
                        int size, gt_htable_hash_f hash_fn)
{
	int i, rc;

	log = GT_LOG_TRACE(log, create);
	t->hts_size = size;
	t->hts_mask = size - 1;
	t->hts_hash_fn = hash_fn;
	rc = gt_sys_malloc(log, (void **)&t->hts_array,
	                   size * sizeof(struct gt_list_head));
	if (rc) {
		return rc;
	}
	t->hts_size = size;
	t->hts_mask = size - 1;
	for (i = 0; i < size; ++i) {
		gt_list_init(t->hts_array + i);
	}
	return 0;
}

void
gt_htable_static_free(struct gt_htable_static *t)
{
	free(t->hts_array);
	t->hts_array = NULL;
}

struct gt_list_head *
gt_htable_static_bucket(struct gt_htable_static *t, uint32_t h) 
{
	return t->hts_array + ((h) & (t)->hts_mask);
}

void
gt_htable_static_add(struct gt_htable_static *t, struct gt_list_head *elem)
{
	uint32_t h;
	struct gt_list_head *bucket;

	h = (*t->hts_hash_fn)(elem);
	bucket = gt_htable_static_bucket(t, h);
	gt_list_insert_tail(bucket, elem);
}

void
gt_htable_static_del(struct gt_htable_static *t, struct gt_list_head *elem)
{
	gt_list_remove(elem);
}

int
gt_htable_dynamic_create(struct gt_log *log, struct gt_htable_dynamic *t,
                         int size, gt_htable_hash_f hash_fn)
{
	int rc;

	t->htd_size_min = size;
	t->htd_nr_elems = 0;
	t->htd_resize_discard = 0;
	t->htd_old = NULL;
	t->htd_new = t->htd_tables + 0;
	t->htd_tables[1].hts_array = NULL;
	rc = gt_htable_static_create(log, t->htd_new, size, hash_fn);
	return rc;
}

void
gt_htable_dynamic_free(struct gt_htable_dynamic *t)
{
	int i;

	for (i = 0; i < 2; ++i) {
		gt_htable_static_free(t->htd_tables + i);
	}
}

struct gt_list_head *
gt_htable_dynamic_bucket(struct gt_htable_dynamic *t, uint32_t h) 
{
	int i;
	struct gt_list_head *bucket;
	struct gt_htable_static *ts;

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
	bucket = gt_htable_static_bucket(ts, h);
	return bucket;
}

void
gt_htable_dynamic_add(struct gt_htable_dynamic *t, struct gt_list_head *elem)
{
	uint32_t h;
	struct gt_list_head *bucket;

	h = (*t->htd_new->hts_hash_fn)(elem);
	bucket = gt_htable_dynamic_bucket(t, h);
	gt_list_insert_tail(bucket, elem);
	t->htd_nr_elems++;
	gt_htable_dynamic_resize(t);
}

void
gt_htable_dynamic_del(struct gt_htable_dynamic *t, struct gt_list_head *elem)
{
	GT_ASSERT(t->htd_nr_elems > 0);
	gt_list_remove(elem);
	t->htd_nr_elems--;
	gt_htable_dynamic_resize(t);
}

static struct gt_htable_static *
gt_htable_dynamic_new(struct gt_htable_dynamic *t)
{
	int i;

	for (i = 0; i < GT_ARRAY_SIZE(t->htd_tables); ++i) {
		if (t->htd_tables[i].hts_array == NULL) {
			return t->htd_tables + i;
		}
	}
	GT_BUG;
	return 0;
}

static void
gt_htable_dynamic_resize(struct gt_htable_dynamic *t)
{
	int rc, size, new_size;
	struct gt_list_head *elem, *bucket;
	struct gt_log *log;
	struct gt_htable_static *tmp;

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
		tmp = gt_htable_dynamic_new(t);
		log = GT_LOG_TRACE1(resize);
		rc = gt_htable_static_create(log, tmp, new_size,
		                             t->htd_new->hts_hash_fn);
		if (rc) {
			t->htd_resize_discard = new_size;
			return;
		}
		t->htd_old = t->htd_new;
		t->htd_new = tmp;
		t->htd_resize_progress = 0;
		GT_LOGF(log, LOG_INFO, 0, "ok; size=%d->%d, elements=%d",
		        size, new_size, t->htd_nr_elems);
	} else {
		GT_ASSERT(t->htd_old->hts_size > t->htd_resize_progress);
		bucket = t->htd_old->hts_array + t->htd_resize_progress;
		while (!gt_list_empty(bucket)) {
			elem = gt_list_first(bucket);
			gt_list_remove(elem);
			gt_htable_static_add(t->htd_new, elem);
		}
		t->htd_resize_progress++;
		if (t->htd_old->hts_size == t->htd_resize_progress) {
			gt_htable_static_free(t->htd_old);
			t->htd_old = NULL;
			log = GT_LOG_TRACE1(resize);
			GT_LOGF(log, LOG_INFO, 0, "done; elements=%d",
			        t->htd_nr_elems);
		}
	}
}
