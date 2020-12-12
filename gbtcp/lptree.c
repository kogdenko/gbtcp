// GPL v2
#include "internals.h"

#define LPTREE_NODE_N_CHILDREN_MAX 256

struct lptree_node {	
	int lpn_is_node;
	struct dlist lpn_rules;
	struct lptree_rule *lpn_hidden;
	struct lptree_node *lpn_parent;
	void *lpn_children[LPTREE_NODE_N_CHILDREN_MAX];
};

int
IS_LPTREE_NODE(void *ptr)
{
	return *(int *)ptr;
}

static void
lptree_node_init(struct lptree_node *node, struct lptree_node *parent)
{
	memset(node->lpn_children, 0, sizeof(node->lpn_children));
	node->lpn_is_node = 1;
	dlist_init(&node->lpn_rules);
	node->lpn_hidden = NULL;
	node->lpn_parent = parent;
}

static struct lptree_node *
lptree_alloc_node(struct lptree *tree, struct lptree_node *parent)
{
	struct lptree_node *node;

	node = mbuf_alloc(tree->lpt_node_pool);
	if (node != NULL) {
		lptree_node_init(node, parent);
	}
	return node;
}

static int
lptree_node_is_empty(struct lptree_node *node)
{
	int i;

	if (!dlist_is_empty(&node->lpn_rules)) {
		return 0;
	}
	for (i = 0; i < LPTREE_NODE_N_CHILDREN_MAX; ++i) {
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
	mbuf_free(node);
}

int
lptree_init(struct lptree *tree)
{
	int rc;

	tree->lpt_root = NULL;
	rc = mbuf_pool_alloc(&tree->lpt_node_pool, CONTROLLER_SID,
		sizeof(struct lptree_node));
	return rc;
}

void
lptree_deinit(struct lptree *tree)
{
	mbuf_pool_free(tree->lpt_node_pool);
	tree->lpt_node_pool = NULL;
	tree->lpt_root = NULL;
}

struct lptree_rule *
lptree_search(struct lptree *tree, uint32_t key)
{
	int i;
	uint32_t id;
	void *child;
	struct lptree_node *node;
	struct lptree_rule *rule, *hidden;

	node = READ_ONCE(tree->lpt_root);
	if (node == NULL) {
		return NULL;
	}
	for (i = 0; i < 4; ++i) {
		id = (key >> ((3 - i) << 3)) & 0x000000FF;
		child = READ_ONCE(node->lpn_children[id]);
		if (child == NULL) {
			break;
		} else if (IS_LPTREE_NODE(child)) {
			node = (struct lptree_node *)child;
		} else {
			rule = (struct lptree_rule *)child;
			return rule;
		}
	}
	hidden = READ_ONCE(node->lpn_hidden);
	return hidden;
}

static struct lptree_node *
lptree_add_child(struct lptree *tree, struct lptree_node *parent, int id)
{
	void *child;
	struct lptree_node *node;
	struct lptree_rule *rule;

	child = parent->lpn_children[id];
	if (child == NULL) {
		node = lptree_alloc_node(tree, parent);
		if (node == NULL) {
			return NULL;
		}
	} else if (IS_LPTREE_NODE(child))  {
		node = (struct lptree_node *)child;
		return 0;
	} else {
		rule = (struct lptree_rule *)child;
		node = lptree_alloc_node(tree, parent);
		if (node == NULL) {
			return node;
		}
		node->lpn_hidden = rule;
	}
	parent->lpn_children[id] = node;
	return node;
}

static void
lptree_node_unset(struct lptree_node *node)
{
	int i;
	void *child;
	struct lptree_node *parent;

	parent = node->lpn_parent;
	for (i = 0; i < LPTREE_NODE_N_CHILDREN_MAX; ++i) {
		if (parent->lpn_children[i] == node) {
			if (node->lpn_hidden != NULL) {
				child = node->lpn_hidden;
			} else {
				child = NULL;
			}
			parent->lpn_children[i] = child;
			break;
		}
	}
}

static void
lptree_rule_set(struct lptree *tree, struct lptree_rule *rule)
{
	int i, n;
	uint32_t id;
	void *child;
	struct lptree_node *node;
	struct lptree_rule *tmp;

	n = 1 << (8 - rule->lpr_depth_rem);
	assert(rule->lpr_key_rem + n <= LPTREE_NODE_N_CHILDREN_MAX);
	for (i = 0; i < n; ++i) {
		id = rule->lpr_key_rem + i;
		child = rule->lpr_parent->lpn_children[id];
		if (child == NULL) {
			rule->lpr_parent->lpn_children[id] = rule;
		} else if (IS_LPTREE_NODE(child)) {
			node = child;
			tmp = node->lpn_hidden;
			if (tmp == NULL || rule->lpr_depth > tmp->lpr_depth) {
				node->lpn_hidden = rule;
			}
		} else {
			tmp = child;
			if (rule->lpr_depth > tmp->lpr_depth) {
				rule->lpr_parent->lpn_children[id] = rule;
			}
		}
	}
}

static void
lptree_rule_unset(struct lptree *tree, struct lptree_rule *rule)
{
	int i;
	void *child;
	struct lptree_node *node;

	for (i = 0; i < LPTREE_NODE_N_CHILDREN_MAX; ++i) {
		child = rule->lpr_parent->lpn_children[i];
		if (child == NULL) {
			continue;
		}
		if (child == rule) {
			rule->lpr_parent->lpn_children[i] = NULL;
		} else if (IS_LPTREE_NODE(child)) {
			node = child;
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
	mbuf_free(rule);
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
	int i, d; 
	uint32_t k, m;
	struct lptree_node *node, *parent;
	struct lptree_rule *rule, *after;

	assert(depth > 0);
	assert(depth <= 32);
	if (tree->lpt_root == NULL) {
		tree->lpt_root = lptree_alloc_node(tree, NULL);
		if (tree->lpt_root == NULL) {
			return -ENOMEM;
		}
	}
	parent = tree->lpt_root;
	for (i = 0; i < 4; ++i) {
		k = (key >> ((3 - i) << 3)) & 0x000000FF;
		d = depth - (i << 3);
		assert(d);
		assert(k < LPTREE_NODE_N_CHILDREN_MAX);
		if (d > 8) {
			if (*prule == NULL) {
				node = parent->lpn_children[k];
				if (node == NULL) {
					return -ESRCH;
				}
			} else {
				node = lptree_add_child(tree, parent, k);
				if (node == NULL) {
					return -ENOMEM;
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
