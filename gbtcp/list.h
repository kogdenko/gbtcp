// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_LIST_H
#define GBTCP_LIST_H

#include "subr.h"

// Double linked list
struct gt_dlist {
	struct gt_dlist *dls_next;
	struct gt_dlist *dls_prev;
};

#define gt_dlist_entry_rcu(ptr, type, member) \
	container_of(READ_ONCE(ptr), type, member)

void gt_dlist_init(struct gt_dlist *);
void gt_dlist_init_rcu(struct gt_dlist *);
int gt_dlist_size(struct gt_dlist *);
bool gt_dlist_is_empty(struct gt_dlist *);
struct gt_dlist *dlist_first(struct gt_dlist *);
struct gt_dlist *dlist_last(struct gt_dlist *);
void gt_dlist_insert_head(struct gt_dlist *, struct gt_dlist *);
void gt_dlist_insert_tail(struct gt_dlist *, struct gt_dlist *);
void gt_dlist_insert_tail_rcu(struct gt_dlist *, struct gt_dlist *);
void gt_dlist_insert_before(struct gt_dlist *, struct gt_dlist *);
void gt_dlist_insert_after(struct gt_dlist *, struct gt_dlist *);
void gt_dlist_remove(struct gt_dlist *);
void gt_dlist_remove_rcu(struct gt_dlist *);
void gt_dlist_replace(struct gt_dlist *, struct gt_dlist *);
void gt_dlist_replace_init(struct gt_dlist *, struct gt_dlist *);
void gt_dlist_splice_tail(struct gt_dlist *, struct gt_dlist *);
void gt_dlist_splice_tail_init(struct gt_dlist *, struct gt_dlist *);

#define GT_DLIST_HEAD_INIT(name) { &name, &name }

#define GT_DLIST_HEAD(name) struct gt_dlist name = GT_DLIST_HEAD_INIT(name)

#define GT_DLIST_FIRST(head, type, field) \
	container_of((head)->dls_next, type, field)

#define GT_DLIST_LAST(head, type, field) \
	container_of((head)->dls_prev, type, field)

#define GT_DLIST_PREV(var, field) \
	container_of((var)->field.dls_prev, __typeof__(*(var)), field)

#define GT_DLIST_NEXT(var, field) \
	container_of((var)->field.dls_next, __typeof__(*(var)), field)

#define GT_DLIST_INSERT_HEAD(head, var, field) \
	gt_dlist_insert_head(head, &((var)->field))

#define GT_DLIST_INSERT_TAIL(head, var, field) \
	gt_dlist_insert_tail(head, &((var)->field))

#define GT_DLIST_INSERT_BEFORE(var, bvar, field) \
	gt_dlist_insert_before(&((var)->field), &((bvar)->field))

#define GT_DLIST_INSERT_AFTER(avar, var, field) \
	gt_dlist_insert_after(&((avar)->field), &((var)->field))

#define GT_DLIST_REMOVE(var, field) \
	gt_dlist_remove(&(var)->field)

#define gt_dlist_foreach(var, head) \
	for (var = (head)->dls_next; var != (head); var = var->dls_next)

#define gt_dlist_foreach_rcu(var, head) \
	for (var = READ_ONCE((head)->dls_next); \
			var != (head); var = READ_ONCE(var->dls_next))

#define GT_DLIST_FOREACH(var, head, field) \
	for (var = GT_DLIST_FIRST(head, typeof(*(var)), field); \
			&((var)->field) != (head); var = GT_DLIST_NEXT(var, field))

#define GT_DLIST_FOREACH_RCU(var, head, field) \
	for (var = gt_dlist_entry_rcu((head)->dls_next, typeof(*(var)), field); \
			&var->field != (head); \
			var = gt_dlist_entry_rcu(var->field.dls_next, typeof(*(var)), field))

#define GT_DLIST_FOREACH_CONTINUE(var, head, field) \
	for (; &((var)->field) != (head); var = GT_DLIST_NEXT(var, field))

#define GT_DLIST_FOREACH_SAFE(var, head, field, tvar) \
	for (var = GT_DLIST_FIRST(head, typeof(*(var)), field); \
			(&((var)->field) != (head)) && ((tvar = GT_DLIST_NEXT(var, field)), 1); \
			var = tvar)

#endif // GBTCP_LIST_H
