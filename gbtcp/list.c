// SPDX-License-Identifier: LGPL-2.1-only

#include "list.h"

void
gt_dlist_init(struct  gt_dlist *head)
{
	head->dls_next = head->dls_prev = head;
}

int
gt_dlist_size(struct gt_dlist *head)
{
	int size;
	struct gt_dlist *cur;

	size = 0;
	gt_dlist_foreach(cur, head) {
		size++;
	}
	return size;
}

bool
gt_dlist_is_empty(struct gt_dlist *head)
{
	return head->dls_next == head;
}

struct gt_dlist *
gt_dlist_first(struct gt_dlist *head)
{
	return head->dls_next;
}

struct gt_dlist *
gt_dlist_last(struct gt_dlist *head)
{
	return head->dls_prev;
}

void
gt_dlist_insert_head(struct gt_dlist *head, struct gt_dlist *l)
{
	l->dls_next = head->dls_next;
	l->dls_prev = head;
	head->dls_next->dls_prev = l;
	head->dls_next = l;
}

void
gt_dlist_insert_tail(struct gt_dlist *head, struct gt_dlist *l)
{
	l->dls_next = head;
	l->dls_prev = head->dls_prev;
	head->dls_prev->dls_next = l;
	head->dls_prev = l;
}

void
gt_dlist_insert_tail_rcu(struct gt_dlist *head, struct gt_dlist *l)
{
	l->dls_next = head;
	l->dls_prev = head->dls_prev;
	rcu_assign_pointer(head->dls_prev->dls_next, l);
	head->dls_prev = l;
}

void
gt_dlist_insert_before(struct gt_dlist *l, struct gt_dlist *b)
{
	l->dls_next = b;
	l->dls_prev = b->dls_prev;
	b->dls_prev->dls_next = l;
	b->dls_prev = l;
}

void
gt_dlist_insert_after(struct gt_dlist *a, struct gt_dlist *l)
{
	l->dls_prev = a;
	l->dls_next = a->dls_next;
	a->dls_next->dls_prev = l;
	a->dls_next = l;
}

void
gt_dlist_remove(struct gt_dlist *list)
{
	list->dls_next->dls_prev = list->dls_prev;
	list->dls_prev->dls_next = list->dls_next;
}

void
gt_dlist_remove_rcu(struct gt_dlist *list)
{
	list->dls_next->dls_prev = list->dls_prev;
	WRITE_ONCE(list->dls_prev->dls_next, list->dls_next);
}

void
gt_dlist_replace(struct gt_dlist *new, struct gt_dlist *old)
{
	new->dls_next = old->dls_next;
	new->dls_next->dls_prev = new;
	new->dls_prev = old->dls_prev;
	new->dls_prev->dls_next = new;
}

void
gt_dlist_replace_init(struct gt_dlist *new, struct gt_dlist *old)
{
	gt_dlist_replace(new, old);
	gt_dlist_init(old);	
}

// prev <-> {list} <-> next
void
gt_dlist_splice(struct gt_dlist *prev, struct gt_dlist *next, struct gt_dlist *list)
{
	list->dls_next->dls_prev = prev;
	prev->dls_next = list->dls_next;
	list->dls_prev->dls_next = next;
	next->dls_prev = list->dls_prev;
}

void
gt_dlist_splice_tail_init(struct gt_dlist *dst, struct gt_dlist *src)
{
	assert(!gt_dlist_is_empty(src));
	gt_dlist_splice(dst->dls_prev, dst, src);
	gt_dlist_init(src);
}
