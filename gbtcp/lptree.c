/* GPL2 license */
#include "internals.h"

struct lptree_node {
	struct mbuf lpn_mbuf;
	struct dlist lpn_rules;
	struct lptree_rule *lpn_hidden;
	struct lptree_node *lpn_parent;
	void *lpn_children[UINT8_MAX];
};

#define IS_LPTREE_NODE(tree, m) \
	(mbuf_get_pool(m) == &(tree)->lpt_pool)

static void
lptree_node_init(struct lptree_node *node, struct lptree_node *parent)
{
	memset(node->lpn_children, 0, sizeof(node->lpn_children));
	dlist_init(&node->lpn_rules);
	node->lpn_hidden = NULL;
	node->lpn_parent = parent;
}

static int
lptree_node_alloc(struct lptree *tree, struct lptree_node *parent,
	struct lptree_node **pnode)
{
	int rc;

	rc = mbuf_alloc(&tree->lpt_pool, (struct mbuf **)pnode);
	if (!rc) {
		lptree_node_init(*pnode, parent);
	}
	return rc;
}

static int
lptree_node_is_empty(struct lptree_node *node)
{
	int i;

	if (!dlist_is_empty(&node->lpn_rules)) {
		return 0;
	}
	for (i = 0; i < UINT8_MAX; ++i) {
		if (node->lpn_children[i] != NULL) {
			return 0;
		}
	}
	return 1;
}

static void
lptree_node_free(struct lptree_node *node)
{
	assert(lptree_node_is_empty(node));
	mbuf_free(&node->lpn_mbuf);
}

void
lptree_init(struct lptree *tree)
{
	mbuf_pool_init(&tree->lpt_pool, 0, sizeof(struct lptree_node));
	tree->lpt_root = NULL;
}

void
lptree_deinit(struct lptree *tree)
{
	if (tree->lpt_root != NULL) {
		assert(lptree_node_is_empty(tree->lpt_root));
		lptree_node_free(tree->lpt_root);
		tree->lpt_root = NULL;
	}
	mbuf_pool_deinit(&tree->lpt_pool);
}

struct lptree_rule *
lptree_search(struct lptree *tree, uint32_t key)
{
	int i;
	uint32_t id;
	struct mbuf *m;
	struct lptree_node *node;
	struct lptree_rule *rule, *hidden;

	node = READ_ONCE(tree->lpt_root);
	if (node == NULL) {
		return NULL;
	}
	for (i = 0; i < 4; ++i) {
		id = (key >> ((3 - i) << 3)) & 0x000000FF;
		m = READ_ONCE(node->lpn_children[id]);
		if (m == NULL) {
			break;
		} else if (IS_LPTREE_NODE(tree, m)) {
			node = (struct lptree_node *)m;
		} else {
			rule = (struct lptree_rule *)m;
			return rule;
		}
	}
	hidden = READ_ONCE(node->lpn_hidden);
	return hidden;
}

static int
lptree_node_set(struct lptree *tree, struct lptree_node *parent, int id,
	struct lptree_node **pnode)
{
	int rc;
	struct mbuf *m;
	struct lptree_rule *rule;

	m = parent->lpn_children[id];
	if (m == NULL) {
		rc = lptree_node_alloc(tree, parent, pnode);
		if (rc) {
			return rc;
		}
	} else if (IS_LPTREE_NODE(tree, m))  {
		*pnode = (struct lptree_node *)m;
		return 0;
	} else {
		rule = (struct lptree_rule *)m;
		rc = lptree_node_alloc(tree, parent, pnode);
		if (rc) {
			return rc;
		}
		(*pnode)->lpn_hidden = rule;
	}
	parent->lpn_children[id] = (struct mbuf *)(*pnode);
	return 0;
}

static void
lptree_node_unset(struct lptree_node *node)
{
	int i;
	struct mbuf *m;
	struct lptree_node *parent;

	parent = node->lpn_parent;
	for (i = 0; i < UINT8_MAX; ++i) {
		if (parent->lpn_children[i] == node) {
			if (node->lpn_hidden != NULL) {
				m = (struct mbuf *)node->lpn_hidden;
			} else {
				m = NULL;
			}
			parent->lpn_children[i] = m;
			break;
		}
	}
}

static void
lptree_rule_set(struct lptree *tree, struct lptree_rule *rule)
{
	int i, n;
	uint32_t id;
	void **slot;
	struct mbuf *m;
	struct lptree_node *node;
	struct lptree_rule *tmp;

	n = 1 << (8 - rule->lpr_depth_rem);
	assert(rule->lpr_key_rem + n <= UINT8_MAX);
	for (i = 0; i < n; ++i) {
		id = rule->lpr_key_rem + i;
		slot = rule->lpr_parent->lpn_children + id;
		m = (struct mbuf *)(*slot);
		if (m == NULL) {
			*slot = rule;
		} else if (IS_LPTREE_NODE(tree, m)) {
			node = (struct lptree_node *)m;
			tmp = node->lpn_hidden;
			if (tmp == NULL || rule->lpr_depth > tmp->lpr_depth) {
				node->lpn_hidden = rule;
			}
		} else {
			tmp = (struct lptree_rule *)m;
			if (rule->lpr_depth > tmp->lpr_depth) {
				*slot = rule;
			}
		}
	}
}

static void
lptree_rule_unset(struct lptree *tree, struct lptree_rule *rule)
{
	int i;
	struct mbuf *m;
	struct lptree_node *node;

	for (i = 0; i < UINT8_MAX; ++i) {
		m = rule->lpr_parent->lpn_children[i];
		if (m == NULL) {
			continue;
		}
		if (m == (struct mbuf *)rule) {
			rule->lpr_parent->lpn_children[i] = NULL;
		} else if (IS_LPTREE_NODE(tree, m)) {
			node = (struct lptree_node *)m;
			if (node->lpn_hidden == rule) {
				node->lpn_hidden = NULL;
			}
		}
	}
}

void
lptree_del(struct lptree *tree, struct lptree_rule *rule)
{
	struct lptree_node *node, *parent;
	struct lptree_rule *cur;

	DLIST_REMOVE(rule, lpr_list);
	node = rule->lpr_parent;
	lptree_rule_unset(tree, rule);
	DLIST_FOREACH(cur, &node->lpn_rules, lpr_list) {
		if (cur->lpr_depth < rule->lpr_depth) {
			lptree_rule_set(tree, cur);
		} else {
			break;
		}
	}
	mbuf_free(&rule->lpr_mbuf);
	while (1) {
		parent = node->lpn_parent;
		if (parent != NULL && lptree_node_is_empty(node)) {
			lptree_node_unset(node);
			lptree_node_free(node);
			node = parent;
		} else {
			break;
		}
	}
}

static int
lptree_traverse(struct lptree *tree, struct lptree_rule **prule,
	uint32_t key, int depth)
{
	int i, d, rc;
	uint32_t k, m;
	struct lptree_node *node, *parent;
	struct lptree_rule *rule, *after;

	assert(depth > 0);
	assert(depth <= 32);
	if (tree->lpt_root == NULL) {
		rc = lptree_node_alloc(tree, NULL, &tree->lpt_root);
		if (rc) {
			return rc;
		}
	}
	parent = tree->lpt_root;
	for (i = 0; i < 4; ++i) {
		k = (key >> ((3 - i) << 3)) & 0x000000FF;
		d = depth - (i << 3);
		assert(d);
		assert(k < UINT8_MAX);
		if (d > 8) {
			if (*prule == NULL) {
				node = parent->lpn_children[k];
				if (node == NULL) {
					return -ESRCH;
				}
			} else {
				rc = lptree_node_set(tree, parent, k, &node);
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
	DLIST_FOREACH(rule, &parent->lpn_rules, lpr_list) {
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
	lptree_rule_set(tree, rule);
	if (after == NULL) {
		DLIST_INSERT_HEAD(&parent->lpn_rules, rule, lpr_list);
	} else {
		DLIST_INSERT_AFTER(after, rule, lpr_list);
	}
	return 0;
}

struct lptree_rule *
lptree_get(struct lptree *tree, uint32_t key, int depth)
{
	int rc;
	struct lptree_rule *rule;

	rule = NULL;
	rc = lptree_traverse(tree, &rule, key, depth);
	assert(rc);
	if (rc == -EEXIST) {
		return rule;
	} else {
		return NULL;
	}
}

int
lptree_set(struct lptree *tree, struct lptree_rule *rule,
	uint32_t key, int depth)
{
	int rc;

	rc = lptree_traverse(tree, &rule, key, depth);
	return rc;
}
