#ifndef GBTCP_HTABLE_H
#define GBTCP_HTABLE_H

#include "subr.h"

typedef uint32_t (*gt_htable_hash_f)(void *elem);

struct gt_htable_static {
	int hts_size;
	int hts_mask;
	gt_htable_hash_f hts_hash_fn;
	struct dllist *hts_array;
};

struct gt_htable_dynamic {
	struct gt_htable_static *htd_new;
	struct gt_htable_static *htd_old;
	int htd_size_min;
	int htd_nr_elems;
	int htd_resize_discard;
	int htd_resize_progress;
	struct gt_htable_static htd_tables[2];
};

#if 0
typedef struct gt_htable_static gt_htable_t;

#define gt_htable_create gt_htable_static_create
#define gt_htable_free gt_htable_static_free
#define gt_htable_bucket gt_htable_static_bucket
#define gt_htable_add gt_htable_static_add
#define gt_htable_del gt_htable_static_del
#else
typedef struct gt_htable_dynamic gt_htable_t;

#define gt_htable_create gt_htable_dynamic_create
#define gt_htable_free gt_htable_dynamic_free
#define gt_htable_bucket gt_htable_dynamic_bucket
#define gt_htable_add gt_htable_dynamic_add
#define gt_htable_del gt_htable_dynamic_del
#endif

int gt_htable_mod_init();

void gt_htable_mod_deinit(struct gt_log *);

int gt_htable_static_create(struct gt_log *, struct gt_htable_static *,
	int, gt_htable_hash_f);

void gt_htable_static_free(struct gt_htable_static *t);

struct dllist *gt_htable_static_bucket(struct gt_htable_static *, uint32_t);

void gt_htable_static_add(struct gt_htable_static *, struct dllist *);

void gt_htable_static_del(struct gt_htable_static *, struct dllist *);

int gt_htable_dynamic_create(struct gt_log *, struct gt_htable_dynamic *,
	int, gt_htable_hash_f);

void gt_htable_dynamic_free(struct gt_htable_dynamic *t);

struct dllist *gt_htable_dynamic_bucket(struct gt_htable_dynamic *t, uint32_t);

void gt_htable_dynamic_add(struct gt_htable_dynamic *, struct dllist *);

void gt_htable_dynamic_del(struct gt_htable_dynamic *, struct dllist *);

#endif /* GBTCP_HTABLE_H */
