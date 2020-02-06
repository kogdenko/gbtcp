/* GPL2 license */
#include "lptree.h"
#include "log.h"
#include "mbuf.h"

#define LPTREE_LOG_NODE_FOREACH(x) \
	x(mod_init) \
	x(add) \
	x(node_alloc)

static struct gt_mbuf_pool *lpnode_pool;
static struct gt_log_scope this_log;
LPTREE_LOG_NODE_FOREACH(GT_LOG_NODE_STATIC);

#define is_lpnode(m) ((m)->mb_pool_id == lpnode_pool->mbp_id)

static void
lpnode_init(struct lpnode *node, struct lpnode *parent)
{
	memset(node->lpn_children, 0, sizeof(node->lpn_children));
	dllist_init(&node->lpn_rules);
	node->lpn_hidden = NULL;
	node->lpn_parent = parent;
}

static int
lpnode_alloc(struct gt_log *log, struct lpnode *parent, struct lpnode **pnode)
{
	int rc;

	log = GT_LOG_TRACE(log, node_alloc);
	rc = mballoc(log, lpnode_pool, (struct gt_mbuf **)pnode);
	if (rc) {
		return rc;
	}
	lpnode_init(*pnode, parent);
	return 0;
}

static int
lpnode_isempty(struct lpnode *node)
{
	int i;

	if (!dllist_isempty(&node->lpn_rules)) {
		return 0;
	}
	for (i = 0; i < 256; ++i) {
		if (node->lpn_children[i] != NULL) {
			return 0;
		}
	}
	return 1;
}

static void
lpnode_free(struct lpnode *node)
{
	GT_ASSERT(lpnode_isempty(node));
	mbfree(&node->lpn_mbuf);
}

int
lptree_mod_init()
{
	int rc;
	struct gt_log *log;

	gt_log_scope_init(&this_log, "lptree");
	LPTREE_LOG_NODE_FOREACH(GT_LOG_NODE_INIT);
	log = GT_LOG_TRACE1(mod_init);
	rc = gt_mbuf_pool_new(log, &lpnode_pool, sizeof(struct lpnode));
	return rc;
}

void
lptree_mod_deinit(struct gt_log *log)
{
	gt_mbuf_pool_del(lpnode_pool);
}

int
lptree_init(struct gt_log *log, struct lpnode *root)
{
	lpnode_init(root, NULL);
	return 0;
}

void
lptree_deinit(struct lpnode *root)
{
	GT_ASSERT(lpnode_isempty(root));
}

struct lprule *
lptree_search(struct lpnode *root, uint32_t key)
{
	int i;
	uint32_t idx;
	struct gt_mbuf *m;
	struct lpnode *node;
	struct lprule *rule;

	node = root;
	for (i = 0; i < 4; ++i) {
		idx = (key >> ((3 - i) << 3)) & 0x000000FF;
		m = node->lpn_children[idx];
		if (m == NULL) {
			break;
		} else if (is_lpnode(m)) {
			node = (struct lpnode *)m;
		} else {
			rule = (struct lprule *)m;
			return rule;
		}
	}
	if (node->lpn_hidden != NULL) {
		return node->lpn_hidden;
	}
	return NULL;
}

static int
lpnode_set(struct gt_log *log,struct lpnode *parent,
	int idx, struct lpnode **pnode)
{
	int rc;
	struct gt_mbuf *m;
	struct lprule *rule;

	m = parent->lpn_children[idx];
	if (m == NULL) {
		rc = lpnode_alloc(log, parent, pnode);
		if (rc) {
			return rc;
		}
	} else if (is_lpnode(m))  {
		*pnode = (struct lpnode *)m;
		return 0;
	} else {
		rule = (struct lprule *)m;
		rc = lpnode_alloc(log, parent, pnode);
		if (rc) {
			return rc;
		}
		(*pnode)->lpn_hidden = rule;
	}
	parent->lpn_children[idx] = (struct gt_mbuf *)(*pnode);
	return 0;
}

static void
lpnode_unset(struct lpnode *node)
{
	int i;
	struct gt_mbuf *m;
	struct lpnode *parent;

	parent = node->lpn_parent;
	for (i = 0; i < 256; ++i) {
		if (parent->lpn_children[i] == node) {
			if (node->lpn_hidden != NULL) {
				m = (struct gt_mbuf *)node->lpn_hidden;
			} else {
				m = NULL;
			}
			parent->lpn_children[i] = m;
			break;
		}
	}
}

static void
lprule_set(struct lprule *rule)
{
	int i, n;
	uint32_t idx;
	void **slot;
	struct gt_mbuf *m;
	struct lpnode *node;
	struct lprule *tmp;

	n = 1 << (8 - rule->lpr_depth_rem);
	GT_ASSERT(rule->lpr_key_rem + n <= 256);
	for (i = 0; i < n; ++i) {
		idx = rule->lpr_key_rem + i;
		slot = rule->lpr_parent->lpn_children + idx;
		m = (struct gt_mbuf *)(*slot);
		if (m == NULL) {
			*slot = rule;
		} else if (is_lpnode(m)) {
			node = (struct lpnode *)m;
			tmp = node->lpn_hidden;
			if (tmp == NULL || rule->lpr_depth > tmp->lpr_depth) {
				node->lpn_hidden = rule;
			}
		} else {
			tmp = (struct lprule *)m;
			if (rule->lpr_depth > tmp->lpr_depth) {
				*slot = rule;
			}
		}
	}
}

static void
lprule_unset(struct lprule *rule)
{
	int i;
	struct gt_mbuf *m;
	struct lpnode *node;

	for (i = 0; i < 256; ++i) {
		m = rule->lpr_parent->lpn_children[i];
		if (m == NULL) {
			continue;
		}
		if (m == (struct gt_mbuf *)rule) {
			rule->lpr_parent->lpn_children[i] = NULL;
		} else if (is_lpnode(m)) {
			node = (struct lpnode *)m;
			if (node->lpn_hidden == rule) {
				node->lpn_hidden = NULL;
			}
		}
	}
}

void
lptree_del(struct lprule *rule)
{
	struct lpnode *node, *parent;
	struct lprule *cur;

	DLLIST_REMOVE(rule, lpr_list);
	node = rule->lpr_parent;
	lprule_unset(rule);
	DLLIST_FOREACH(cur, &node->lpn_rules, lpr_list) {
		if (cur->lpr_depth < rule->lpr_depth) {
			lprule_set(cur);
		} else {
			break;
		}
	}
	mbfree(&rule->lpr_mbuf);
	while (1) {
		parent = node->lpn_parent;
		if (parent != NULL && lpnode_isempty(node)) {
			lpnode_unset(node);
			lpnode_free(node);
			node = parent;
		} else {
			break;
		}
	}
}

static int
lptree_getset(struct gt_log *log, struct lpnode *root,
	struct lprule **prule, uint32_t key, int depth)
{
	int i, d, rc;
	uint32_t k, m;
	struct lpnode *node, *parent;
	struct lprule *rule, *after;

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
				node = parent->lpn_children[k];
				if (node == NULL) {
					return -ESRCH;
				}
			} else {
				rc = lpnode_set(log, parent, k, &node);
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
	DLLIST_FOREACH(rule, &parent->lpn_rules, lpr_list) {
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
	lprule_set(rule);
	if (after == NULL) {
		DLLIST_INSERT_HEAD(&parent->lpn_rules, rule, lpr_list);
	} else {
		DLLIST_INSERT_AFTER(after, rule, lpr_list);
	}
	return 0;
}

struct lprule *
lptree_get(struct lpnode *root, uint32_t key, int depth)
{
	int rc;
	struct lprule *rule;

	rule = NULL;
	rc = lptree_getset(NULL, root, &rule, key, depth);
	GT_ASSERT(rc);
	if (rc == -EEXIST) {
		return rule;
	} else {
		return NULL;
	}
}

int
lptree_set(struct gt_log *log, struct lpnode *root,
	struct lprule *rule, uint32_t key, int depth)
{
	int rc;

	log = GT_LOG_TRACE(log, add);
	rc = lptree_getset(log, root, &rule, key, depth);
	return rc;
}
