#include "lptree.h"
#include "log.h"
#include "mbuf.h"

#define LPTREE_LOG_NODE_FOREACH(x) \
	x(mod_init) \
	x(add) \
	x(node_alloc)


static struct gt_mbuf_pool *gt_lptree_node_pool;
static struct gt_log_scope this_log;
LPTREE_LOG_NODE_FOREACH(GT_LOG_NODE_STATIC);

#define GT_LPTREE_IS_NODE(m) \
	((m)->mb_pool_id == gt_lptree_node_pool->mbp_id)

static void
gt_lptree_node_init(struct gt_lptree_node *node, struct gt_lptree_node *parent)
{
	memset(node->n_children, 0, sizeof(node->n_children));
	gt_list_init(&node->n_rules);
	node->n_hidden = NULL;
	node->n_parent = parent;
}

static int
gt_lptree_node_alloc(struct gt_log *log, struct gt_lptree_node *parent,
	struct gt_lptree_node **pnode)
{
	int rc;

	log = GT_LOG_TRACE(log, node_alloc);
	rc = gt_mbuf_alloc(log, gt_lptree_node_pool, (struct gt_mbuf **)pnode);
	if (rc) {
		return rc;
	}
	gt_lptree_node_init(*pnode, parent);
	return 0;
}

static int
gt_lptree_node_empty(struct gt_lptree_node *node)
{
	int i;

	if (!gt_list_empty(&node->n_rules)) {
		return 0;
	}
	for (i = 0; i < 256; ++i) {
		if (node->n_children[i] != NULL) {
			return 0;
		}
	}
	return 1;
}

static void
gt_lptree_node_free(struct gt_lptree_node *node)
{
	GT_ASSERT(gt_lptree_node_empty(node));
	gt_mbuf_free(&node->n_mbuf);
}

int
gt_lptree_mod_init()
{
	int rc;
	struct gt_log *log;

	gt_log_scope_init(&this_log, "lptree");
	LPTREE_LOG_NODE_FOREACH(GT_LOG_NODE_INIT);
	log = GT_LOG_TRACE1(mod_init);
	rc = gt_mbuf_pool_new(log, &gt_lptree_node_pool,
	                      sizeof(struct gt_lptree_node));
	return rc;
}

void
gt_lptree_mod_deinit(struct gt_log *log)
{
	gt_mbuf_pool_del(gt_lptree_node_pool);
}

int
gt_lptree_init(struct gt_log *log, struct gt_lptree_node *root,
            struct gt_mbuf_pool *rule_pool)
{
	gt_lptree_node_init(root, NULL);
	return 0;
}

void
gt_lptree_deinit(struct gt_lptree_node *root)
{
	GT_ASSERT(gt_lptree_node_empty(root));
}

struct gt_lptree_rule *
gt_lptree_search(struct gt_lptree_node *root, uint32_t key)
{
	int i;
	uint32_t k;
	struct gt_mbuf *m;
	struct gt_lptree_node *node;
	struct gt_lptree_rule *rule;

	node = root;
	for (i = 0; i < 4; ++i) {
		k = (key >> ((3 - i) << 3)) & 0x000000FF;
		m = node->n_children[k];
		if (m == NULL) {
			break;
		} else if (GT_LPTREE_IS_NODE(m)) {
			node = (struct gt_lptree_node *)m;
		} else {
			rule = (struct gt_lptree_rule *)m;
			return rule;
		}
	}
	if (node->n_hidden != NULL) {
		return node->n_hidden;
	}
	return NULL;
}



static int
gt_lptree_node_set(struct gt_log *log, struct gt_lptree_node *parent,
	int idx, struct gt_lptree_node **pnode)
{
	int rc;
	struct gt_mbuf *m;
	struct gt_lptree_rule *rule;

	m = parent->n_children[idx];
	if (m == NULL) {
		rc = gt_lptree_node_alloc(log, parent, pnode);
		if (rc) {
			return rc;
		}
	} else if (GT_LPTREE_IS_NODE(m))  {
		*pnode = (struct gt_lptree_node *)m;
		return 0;
	} else {
		rule = (struct gt_lptree_rule *)m;
		rc = gt_lptree_node_alloc(log, parent, pnode);
		if (rc) {
			return rc;
		}
		(*pnode)->n_hidden = rule;
	}
	parent->n_children[idx] = (struct gt_mbuf *)(*pnode);
	return 0;
}

static void
gt_lptree_node_unset(struct gt_lptree_node *node)
{
	int i;
	struct gt_mbuf *m;
	struct gt_lptree_node *parent;

	parent = node->n_parent;
	for (i = 0; i < 256; ++i) {
		if (parent->n_children[i] == node) {
			if (node->n_hidden != NULL) {
				m = (struct gt_mbuf *)node->n_hidden;
			} else {
				m = NULL;
			}
			parent->n_children[i] = m;
			break;
		}
	}
}

static void
gt_lptree_rule_set(struct gt_lptree_rule *rule)
{
	int i, n;
	uint32_t idx;
	void **slot;
	struct gt_mbuf *m;
	struct gt_lptree_node *node;
	struct gt_lptree_rule *tmp;

	n = 1 << (8 - rule->lpr_depth_rem);
	GT_ASSERT(rule->lpr_key_rem + n <= 256);
	for (i = 0; i < n; ++i) {
		idx = rule->lpr_key_rem + i;
		slot = rule->lpr_parent->n_children + idx;
		m = (struct gt_mbuf *)(*slot);
		if (m == NULL) {
			*slot = rule;
		} else if (GT_LPTREE_IS_NODE(m)) {
			node = (struct gt_lptree_node *)m;
			tmp = node->n_hidden;
			if (tmp == NULL || rule->lpr_depth > tmp->lpr_depth) {
				node->n_hidden = rule;
			}
		} else {
			tmp = (struct gt_lptree_rule *)m;
			if (rule->lpr_depth > tmp->lpr_depth) {
				*slot = rule;
			}
		}
	}
}

static void
gt_lptree_rule_unset(struct gt_lptree_rule *rule)
{
	int i;
	struct gt_mbuf *m;
	struct gt_lptree_node *node;

	for (i = 0; i < 256; ++i) {
		m = rule->lpr_parent->n_children[i];
		if (m == NULL) {
			continue;
		}
		if (m == (struct gt_mbuf *)rule) {
			rule->lpr_parent->n_children[i] = NULL;
		} else if (GT_LPTREE_IS_NODE(m)) {
			node = (struct gt_lptree_node *)m;
			if (node->n_hidden == rule) {
				node->n_hidden = NULL;
			}
		}
	}
}

void
gt_lptree_del(struct gt_lptree_rule *rule)
{
	struct gt_lptree_node *node, *parent;
	struct gt_lptree_rule *cur;

	GT_LIST_REMOVE(rule, lpr_mbuf.mb_list);
	node = rule->lpr_parent;
	gt_lptree_rule_unset(rule);
	GT_LIST_FOREACH(cur, &node->n_rules, lpr_mbuf.mb_list) {
		if (cur->lpr_depth < rule->lpr_depth) {
			gt_lptree_rule_set(cur);
		} else {
			break;
		}
	}
	gt_mbuf_free(&rule->lpr_mbuf);
	while (1) {
		parent = node->n_parent;
		if (parent != NULL && gt_lptree_node_empty(node)) {
			gt_lptree_node_unset(node);
			gt_lptree_node_free(node);
			node = parent;
		} else {
			break;
		}
	}
}

static int
gt_lptree_gen(struct gt_log *log, struct gt_lptree_node *root,
	struct gt_lptree_rule **prule, uint32_t key, int depth)
{
	int i, d, rc;
	uint32_t k, m;
	struct gt_lptree_node *node, *parent;
	struct gt_lptree_rule *rule, *after;

	GT_ASSERT(depth > 0);
	GT_ASSERT(depth <= 32);
	parent = root;
	for (i = 0; i < 4; ++i) {
		k = (key >> ((3 - i) << 3)) & 0x000000FF;
		d = depth - (i << 3);
		GT_ASSERT(d);
		GT_ASSERT(k < 256);
		if (d > 8) {
			if (*prule == NULL) {
				node = parent->n_children[k];
				if (node == NULL) {
					return -ESRCH;
				}
			} else {
				rc = gt_lptree_node_set(log, parent, k, &node);
				if (rc) {
					return rc;
				}
			}
			parent = node;
		} else {
			m = (0xff << (8 - d));
			k &= m;
			break;
		}
	}
	after = NULL;
	rc = 0;
	GT_LIST_FOREACH(rule, &parent->n_rules, lpr_mbuf.mb_list) {
		if (rule->lpr_depth == depth && rule->lpr_key == key) {
			if (*prule == NULL) {
				*prule = rule;
			}
			return -EEXIST;
		} else if (depth < rule->lpr_depth) {
			break;
		} else {
			after = rule;
		}
	}
	rule = *prule;
	if (rule == NULL) {
		return -ESRCH;
	}
	rule->lpr_key = key;
	rule->lpr_depth = depth;
	rule->lpr_key_rem = k;
	rule->lpr_depth_rem = d;
	rule->lpr_parent = parent;
	gt_lptree_rule_set(rule);
	if (after == NULL) {
		GT_LIST_INSERT_HEAD(&parent->n_rules, rule, lpr_mbuf.mb_list);
	} else {
		GT_LIST_INSERT_AFTER(after, rule, lpr_mbuf.mb_list);
	}
	return 0;
}

struct gt_lptree_rule *
gt_lptree_find(struct gt_lptree_node *root, uint32_t key, int depth)
{
	int rc;
	struct gt_lptree_rule *rule;

	rule = NULL;
	rc = gt_lptree_gen(NULL, root, &rule, key, depth);
	GT_ASSERT(rc);
	if (rc == -EEXIST) {
		return rule;
	} else {
		return NULL;
	}
}

int
gt_lptree_add(struct gt_log *log, struct gt_lptree_node *root,
	struct gt_lptree_rule *rule, uint32_t key, int depth)
{
	int rc;

	log = GT_LOG_TRACE(log, add);
	rc = gt_lptree_gen(log, root, &rule, key, depth);
	return rc;
}
