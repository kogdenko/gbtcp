// GPL2 license
#ifndef GBTCP_HTABLE_H
#define GBTCP_HTABLE_H

#include "subr.h"

#define HTABLE_SHARED (1 << 0)
#define HTABLE_RESIZABLE (1 << 2)

typedef struct dlist htable_entry_t;

typedef uint32_t (*htable_f)(void *);

struct htable_bucket {
	struct spinlock htb_lock;
	struct dlist htb_head;
};

struct htable_static {
	int hts_size;
	int hts_mask;
	htable_f hts_fn;
	struct htable_bucket *hts_array;
};

struct htable {
	struct htable_static *htd_new;
	struct htable_static *htd_old;
	int htd_flags;
	int htd_bucket_off;
	int htd_size_min;
	int htd_nentries;
	int htd_resize_discard;
	int htd_resize_progress;
	struct htable_static htd_tables[2];
};

int htable_mod_init(struct log *, void **);
int htable_mod_attach(struct log *, void *);
void htable_mod_deinit(struct log *, void *);
void htable_mod_detach(struct log *);

void htable_bucket_init(struct htable_bucket *);
int htable_init(struct log *, struct htable *, int, htable_f, int, int);
void htable_deinit(struct htable *);
struct htable_bucket *htable_bucket_get(struct htable *, uint32_t);
void htable_add(struct htable *, struct htable_bucket *, htable_entry_t *);
void htable_del(struct htable *, htable_entry_t *);

#endif // GBTCP_HTABLE_H
