#ifndef GBTCP_LPTREE_H
#define GBTCP_LPTREE_H

#include "subr.h"
#include "list.h"
#include "mbuf.h"

struct gt_lptree_node {
	struct gt_mbuf n_mbuf;
	struct gt_list_head n_rules;
	struct gt_lptree_rule *n_hidden;
	struct gt_lptree_node *n_parent;
	void *n_children[256];
};

struct gt_lptree_rule {
	struct gt_mbuf lpr_mbuf;
	struct gt_lptree_node *lpr_parent;
	uint32_t lpr_key;
	uint8_t lpr_key_rem;
	uint8_t lpr_depth;
	uint8_t lpr_depth_rem;
};

int gt_lptree_mod_init();

void gt_lptree_mod_deinit(struct gt_log *log);

int gt_lptree_init(struct gt_log *log, struct gt_lptree_node *root,
	struct gt_mbuf_pool *rule_pool);

void gt_lptree_deinit(struct gt_lptree_node *root);

struct gt_lptree_rule *gt_lptree_search(struct gt_lptree_node *root,
	uint32_t key);

void gt_lptree_del(struct gt_lptree_rule *rule);

struct gt_lptree_rule *gt_lptree_find(struct gt_lptree_node *root,
	uint32_t key, int depth);

int gt_lptree_add(struct gt_log *log, struct gt_lptree_node *root,
	struct gt_lptree_rule *rule, uint32_t key, int depth);

#endif /* GBTCP_LPTREE_H */
