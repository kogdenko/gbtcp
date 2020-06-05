// gpl2 license
#ifndef GBTCP_LIST_H
#define GBTCP_LIST_H

#include "subr.h"

// Double linked list
struct dlist {
	struct dlist *dls_next;
	struct dlist *dls_prev;
};

#define dlist_entry_rcu(ptr, type, member) \
	container_of(READ_ONCE(ptr), type, member)

void dlist_init(struct  dlist *);
void dlist_init_rcu(struct dlist *);
int dlist_size(struct dlist *);
int dlist_is_empty(struct dlist *);
struct dlist *dlist_first(struct dlist *);
struct dlist *dlist_last(struct dlist *);
void dlist_insert_head(struct dlist *, struct dlist *);
void dlist_insert_tail(struct dlist *, struct dlist *);
void dlist_insert_tail_rcu(struct dlist *, struct dlist *);
void dlist_insert_before(struct dlist *, struct dlist *);
void dlist_insert_after(struct dlist *, struct dlist *);
void dlist_remove(struct dlist *);
void dlist_remove_rcu(struct dlist *);
void dlist_replace(struct dlist *, struct dlist *);
void dlist_replace_init(struct dlist *, struct dlist *);
void dlist_splice_tail(struct dlist *, struct dlist *);
void dlist_splice_tail_init(struct dlist *, struct dlist *);

#define DLIST_HEAD_INIT(name) { &name, &name }

#define DLIST_HEAD(name) struct dlist name = DLIST_HEAD_INIT(name)

#define DLIST_FIRST(head, type, field) \
	container_of((head)->dls_next, type, field)

#define DLIST_LAST(head, type, field) \
	container_of((head)->dls_prev, type, field)

#define DLIST_NEXT(var, field) \
	container_of((var)->field.dls_next, __typeof__(*(var)), field)

#define DLIST_INSERT_HEAD(head, var, field) \
	dlist_insert_head(head, &((var)->field))

#define DLIST_INSERT_TAIL(head, var, field) \
	dlist_insert_tail(head, &((var)->field))

#define DLIST_INSERT_BEFORE(var, bvar, field) \
	dlist_insert_before( &((var)->field), &((bvar)->field))

#define DLIST_INSERT_AFTER(avar, var, field) \
	dlist_insert_after(&((avar)->field), &((var)->field))

#define DLIST_REMOVE(var, field) \
	dlist_remove(&(var)->field)

#define dlist_foreach(var, head) \
	for (var = (head)->dls_next; var != (head); var = var->dls_next)

#define DLIST_FOREACH(var, head, field) \
	for (var = DLIST_FIRST(head, typeof(*(var)), field); \
	     &((var)->field) != (head); \
	     var = DLIST_NEXT(var, field))

#define DLIST_FOREACH_RCU(var, head, field) \
	for (var = dlist_entry_rcu((head)->dls_next, typeof(*(var)), field); \
	     &var->field != (head); \
	     var = dlist_entry_rcu(var->field.dls_next, typeof(*(var)), field))

#define DLIST_FOREACH_CONTINUE(var, head, field) \
	for (; &((var)->field) != (head); var = DLIST_NEXT(var, field))

#define DLIST_FOREACH_SAFE(var, head, field, tvar) \
	for (var = DLIST_FIRST(head, typeof(*(var)), field); \
	     (&((var)->field) != (head)) && \
	     ((tvar = DLIST_NEXT(var, field)), 1); \
	     var = tvar)

#endif // GBTCP_LIST_H
