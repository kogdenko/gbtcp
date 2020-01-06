#ifndef GBTCP_LIST_H
#define GBTCP_LIST_H

struct gt_list_head {
	struct gt_list_head *ls_next;
	struct gt_list_head *ls_prev;
};

void gt_list_init(struct  gt_list_head *head);
int gt_list_size(struct gt_list_head *head);
int gt_list_empty(struct gt_list_head *head);
struct gt_list_head *gt_list_first(struct gt_list_head *head);
struct gt_list_head *gt_list_last(struct gt_list_head *head);
void gt_list_insert_head(struct gt_list_head *head, struct gt_list_head *l);
void gt_list_insert_tail(struct gt_list_head *head, struct gt_list_head *l);
void gt_list_insert_before(struct gt_list_head *b, struct gt_list_head *l);
void gt_list_insert_after(struct gt_list_head *a, struct gt_list_head *l);
void gt_list_remove(struct gt_list_head *list);
void gt_list_replace(struct gt_list_head *old, struct gt_list_head *new);
void gt_list_replace_init(struct gt_list_head *old, struct gt_list_head *new);

#define GT_LIST_HEAD_INIT(name) { &name, &name }

#define GT_LIST_HEAD(name) struct gt_list_head name = GT_LIST_HEAD_INIT(name)

#define GT_LIST_FIRST(head, type, field) \
	gt_container_of((head)->ls_next, type, field)

#define GT_LIST_LAST(head, type, field) \
	gt_container_of((head)->ls_prev, type, field)

#define GT_LIST_NEXT(var, field) \
	gt_container_of((var)->field.ls_next, __typeof__(*(var)), field)

#define GT_LIST_INSERT_HEAD(head, var, field) \
	gt_list_insert_head(head, &((var)->field))

#define GT_LIST_INSERT_TAIL(head, var, field) \
	gt_list_insert_tail(head, &((var)->field))

#define GT_LIST_INSERT_BEFORE(bvar, var, field) \
	gt_list_insert_before(&((bvar)->field), &((var)->field))

#define GT_LIST_INSERT_AFTER(avar, var, field) \
	gt_list_insert_after(&((avar)->field), &((var)->field))

#define GT_LIST_REMOVE(var, field) \
	gt_list_remove(&(var)->field)

#define gt_list_foreach(var, head) \
	for (var = (head)->ls_next; var != (head); var = var->ls_next)

#define GT_LIST_FOREACH(var, head, field) \
	for (var = GT_LIST_FIRST(head, typeof(*(var)), field); \
		&((var)->field) != (head); \
		var = GT_LIST_NEXT(var, field))

#define GT_LIST_FOREACH_CONTINUE(pos, head, field) \
	for (; &((pos)->field) != (head); \
		pos = GT_LIST_NEXT(pos, field))

#define GT_LIST_FOREACH_SAFE(var, head, field, tvar) \
	for (var = GT_LIST_FIRST(head, typeof(*(var)), field); \
		(&((var)->field) != (head)) && \
		((tvar = GT_LIST_NEXT(var, field)), 1); \
		var = tvar)

#endif /* GBTCP_LIST_H */
