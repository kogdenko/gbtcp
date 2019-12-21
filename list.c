#include "list.h"

void
gt_list_init(struct  gt_list_head *head)
{
	head->ls_next = head->ls_prev = head;
}

int
gt_list_size(struct gt_list_head *head)
{
	int size;
	struct gt_list_head *cur;

	size = 0;
	gt_list_foreach(cur, head) {
		size++;
	}
	return size;
}

int
gt_list_empty(struct gt_list_head *head)
{
	return head->ls_next == head;
}

struct gt_list_head *
gt_list_first(struct gt_list_head *head)
{
	return head->ls_next;
}

struct gt_list_head *
gt_list_last(struct gt_list_head *head)
{
	return head->ls_prev;
}

void
gt_list_insert_head(struct gt_list_head *head, struct gt_list_head *l)
{
	l->ls_next = head->ls_next;
	l->ls_prev = head;
	head->ls_next->ls_prev = l;
	head->ls_next = l;
}

void
gt_list_insert_tail(struct gt_list_head *head, struct gt_list_head *l)
{
	l->ls_next = head;
	l->ls_prev = head->ls_prev;
	head->ls_prev->ls_next = l;
	head->ls_prev = l;
}

void
gt_list_insert_before(struct gt_list_head *b, struct gt_list_head *l)
{
	l->ls_next = b;
	l->ls_prev = b->ls_prev;
	b->ls_prev = l;
}

void
gt_list_insert_after(struct gt_list_head *a, struct gt_list_head *l)
{
	l->ls_next = a->ls_next;
	l->ls_prev = a;
	a->ls_next = l;
}

void
gt_list_remove(struct gt_list_head *list)
{
	list->ls_next->ls_prev = list->ls_prev;
	list->ls_prev->ls_next = list->ls_next;
}

void
gt_list_replace(struct gt_list_head *old, struct gt_list_head *new)
{
	new->ls_next = old->ls_next;
	new->ls_next->ls_prev = new;
	new->ls_prev = old->ls_prev;
	new->ls_prev->ls_next = new;
}

void
gt_list_replace_init(struct gt_list_head *old, struct gt_list_head *new)
{
	gt_list_replace(old, new);
	gt_list_init(old);	
}
