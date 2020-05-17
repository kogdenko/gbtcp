#include "internals.h"

#define SYSCTL_DEPTH_MAX 32
#define SYSCTL_NODE_NAME_MAX 128
#define SYSCTL_NTOKENS_MAX 3

struct sysctl_mod {
	struct log_scope log_scope;
};

struct sysctl_int_data {
	union {
		int (*i_ptr_intfn)(const long long *new, long long *);
		int32_t *i_ptr_int32;
		int64_t *i_ptr_int64;
		void *i_ptr;
	};
	int i_sizeof;
	long long i_min;
	long long i_max;
};

struct sysctl_list_data {
	sysctl_list_next_f l_next_fn;
	sysctl_list_f l_fn;
};

struct sysctl_node {
	struct dlist n_list;
	struct dlist n_children;
	struct sysctl_node *n_parent;
	union {
		uint32_t n_flags;
		struct {
			unsigned int n_mode : 2;
			unsigned int n_is_added : 1;
			unsigned int n_is_list : 1;
			unsigned int n_has_subscribers : 1;
		};
	};
	int n_name_len;
	void *n_udata;
	sysctl_f n_fn;
	void (*n_free_fn)(void *);
	char n_name[SYSCTL_NODE_NAME_MAX];
	union {
		struct sysctl_int_data n_int_data;
		struct sysctl_list_data n_list_data;
	} n_udata_buf;
};

static struct sysctl_node *sysctl_root;
static struct sysctl_mod *curmod;

static int sysctl_node_alloc(struct log *, struct sysctl_node **,
	struct sysctl_node *, const char *, int);

static void sysctl_node_del(struct log *log, struct sysctl_node *node);

static int sysctl_node_in_list(struct sysctl_node *,
	const char *, const char *, struct strbuf *);

static int sysctl_node_in_branch(struct sysctl_node *,
	const char *, struct strbuf *);

static int sysctl_node_in_leaf(struct log *log, struct sysctl_conn *,
	struct sysctl_node *, const char *, struct strbuf *);

static int sysctl_process_events(void *udata, short revents);

static int sysctl_in(struct log *, struct sysctl_conn *, const char *, int,
	const char *, struct strbuf *);

static int sysctl_in_req(struct sysctl_conn *, struct iovec *);

static int
sysctl_verify(const char *s)
{
	for (; *s != '\0'; ++s) {
		switch (*s) {
		case 'a' ... 'z':
		case 'A' ... 'Z':
		case '0' ... '9':
		case ',':
		case '.':
		case ':':
		case '_':
		case '-':
		case '+':
		case '^':
		case '/':
		case '{':
		case '}':
		case '%':
			break;
		default:
			return 0;
		}
	}
	return 1;
}

int
sysctl_mod_init(struct log *log, void **pp)
{
	int rc;
	struct sysctl_mod *mod;

	LOG_TRACE(log);
	rc = shm_alloc(log, pp, sizeof(*mod));
	if (rc == 0) {
		mod = *pp;
		log_scope_init(&mod->log_scope, "sysctl");
	}
	return rc;
}

int
sysctl_mod_attach(struct log *log, void *raw_mod)
{
	curmod = raw_mod;
	return 0;
}

int
sysctl_root_init(struct log *log)
{
	int rc;

	LOG_TRACE(log);
	rc = sysctl_node_alloc(log, &sysctl_root,
	                       NULL, NULL, 0);
	if (rc == 0) {
		sysctl_root->n_is_added = 1;
	}
	return rc;
}

void
sysctl_mod_deinit(struct log *log, void *raw_mod)
{
	struct sysctl_mod *mod;
	LOG_TRACE(log);
	mod = raw_mod;
	log_scope_deinit(log, &mod->log_scope);
	shm_free(mod);
}

void
sysctl_mod_detach(struct log *log)
{
	curmod = NULL;
}

void
sysctl_root_deinit(struct log *log)
{
	LOG_TRACE(log);
	sysctl_node_del(log, sysctl_root);
	sysctl_root = NULL;
}

static int
sysctl_setsockopt(struct log *log, int fd)
{
	int rc, opt;

	opt = GT_SYSCTL_BUFSIZ;
	rc = sys_setsockopt(log, fd, SOL_SOCKET, SO_SNDBUF,
			    &opt, sizeof(opt));
	if (rc < 0) {
		return rc;
	}
	opt = GT_SYSCTL_BUFSIZ;
	rc = sys_setsockopt(log, fd, SOL_SOCKET, SO_RCVBUF,
			    &opt, sizeof(opt));
	if (rc < 0) {
		return rc;
	}
	rc = fcntl_setfl_nonblock2(log, fd);
	return rc;
}

void
sysctl_make_sockaddr_un(struct sockaddr_un *a, int pid)
{
	a->sun_family = AF_UNIX;
	snprintf(a->sun_path, sizeof(a->sun_path), "%s/%d.sock",
	         SYSCTL_PATH, pid);
}

static void
sysctl_strbuf_add_node(struct strbuf *sb, struct sysctl_node *node)
{
	int i, n;
	struct sysctl_node *path[SYSCTL_DEPTH_MAX];

	ASSERT(node != NULL);
	n = 0;
	for (; node != sysctl_root; node = node->n_parent) {
		ASSERT(node != NULL);
		ASSERT(n < ARRAY_SIZE(path));
		path[n++] = node;
	}
	for (i = n - 1; i >= 0; --i) {
		if (sb->sb_len) {
			strbuf_add_ch(sb, '.');
		}
		strbuf_add_str(sb, path[i]->n_name);
	}
}

const char *
sysctl_log_add_node(struct sysctl_node *node) 
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	sysctl_strbuf_add_node(sb, node);
	return strbuf_cstr(sb);
}

static int
sysctl_split_path(struct log *log, const char *path, struct iovec *iovec)
{
	int i, rc;

	rc = strsplit(path, ".", iovec, SYSCTL_DEPTH_MAX);
	if (rc > SYSCTL_DEPTH_MAX) {
		return -ENAMETOOLONG;
	}
	for (i = 0; i < rc; ++i) {
		if (iovec[i].iov_len >= SYSCTL_NODE_NAME_MAX) {
			return -ENAMETOOLONG;
		}
	}
	return rc;
}

static void
sysctl_split_msg(struct iovec *t, char *msg)
{
	int i, rc;

	rc = strsplit(msg, " \r\n\t", t, SYSCTL_NTOKENS_MAX);
	for (i = 0; i < rc; ++i) {
		((char *)t[i].iov_base)[t[i].iov_len] = '\0';
	}
	for (; i < SYSCTL_NTOKENS_MAX; ++i) {
		t[i].iov_base = NULL;
		t[i].iov_len = 0;
	}
	if (t[0].iov_base == NULL) {
		t[0].iov_base = "";
	}
}

static int
sysctl_parse_line(struct log *log, char *s)
{
	int rc;
	char *ptr, *path, *new;
	ptr = strchr(s, '#');
	if (ptr != NULL) {
		*ptr = '\0';
	}
	new = strchr(s, '=');
	if (new != NULL) {
		*new = '\0';
		new = strtrim(new + 1);
	}
	path = strtrim(s);
	rc = sysctl_in(log, NULL, path, 1, new, NULL);
	return rc;
}

int
sysctl_read_file(struct log *log, const char *proc_name)
{
	int rc, line;
	const char *path;
	char path_buf[PATH_MAX];
	char str[2000];
	FILE *file;

	LOG_TRACE(log);
	path = getenv("GBTCP_CTL");
	if (path != NULL) { 
		rc = sys_realpath(log, path, path_buf);
		if (rc) {
			return rc;
		}
	} else {
		snprintf(path_buf, sizeof(path_buf), "%s/sysctl/%s.conf",
		         GT_PREFIX, proc_name);
	}
	path = path_buf;
	rc = sys_fopen(log, &file, path, "r");
	if (rc) {
		return rc;
	}
	rc = 0;
	line = 0;
	while (fgets(str, sizeof(str), file) != NULL) {
		line++;
		rc = sysctl_parse_line(log, str);
		if (rc) {
			LOGF(log, LOG_ERR, -rc,
			     "bad line; file='%s', line=%d",  path, line);
		}
	}
	fclose(file);
	LOGF(log, LOG_INFO, 0, "ok; file='%s'", path);
	return rc;
}

static int
sysctl_node_alloc(struct log *log, struct sysctl_node **pnode,
	struct sysctl_node *parent, const char *name, int name_len)
{
	int rc;
	struct sysctl_node *node;

	LOG_TRACE(log);
	rc = sys_malloc(log, (void **)pnode, sizeof(struct sysctl_node));
	if (rc) {
		return rc;
	}
	node = *pnode;
	ASSERT(name_len < SYSCTL_NODE_NAME_MAX);
	memset(node, 0, sizeof(*node));
	node->n_name_len = name_len;
	memcpy(node->n_name, name, name_len);
	node->n_name[name_len] = '\0';
	dlist_init(&node->n_children);
	node->n_parent = parent;
	if (parent != NULL) {
		DLIST_INSERT_TAIL(&parent->n_children, node, n_list);
	}
	return 0;
}

static struct sysctl_node *
sysctl_node_find_child(struct sysctl_node *node, const char *name,
	int name_len)
{
	struct sysctl_node *child;

	DLIST_FOREACH(child, &node->n_children, n_list) {
		if (child->n_name_len == name_len &&
		    !memcmp(child->n_name, name, name_len)) {
			return child;
		}
	}
	return NULL;
}

static int
sysctl_node_find(struct log *log, const char *path,
	struct sysctl_node **pnode, char **ptail)
{
	int i, rc, name_len, path_iovcnt;
	char *name;
	struct sysctl_node *child, *node;
	struct iovec path_iov[SYSCTL_DEPTH_MAX];

	LOG_TRACE(log);
	node = sysctl_root;
	if (node == NULL) {
		return -ENOENT;
	}
	rc = sysctl_split_path(log, path, path_iov);
	if (rc < 0) {
		return rc;
	}
	path_iovcnt = rc;
	for (i = 0; i < path_iovcnt; ++i) {
		name = path_iov[i].iov_base;
		name_len = path_iov[i].iov_len;
		child = sysctl_node_find_child(node, name, name_len);
		if (child == NULL) {
			if (i < path_iovcnt - 1) {
				return -ENOENT;
			}
			*pnode = node;
			if (ptail == NULL) {
				return -ENOENT;
			} else {
				*ptail = path_iov[i].iov_base;
				return 0;
			}
		}
		node = child;
	}
	*pnode = node;
	if (ptail != NULL) {
		*ptail = NULL;
	}
	return 0;
}

static int
sysctl_node_add(struct log *log, const char *path, int mode,
	void *udata, void (*free_fn)(void *), sysctl_f fn,
	struct sysctl_node **pnode)
{
	int i, rc, name_len, path_len, path_iovcnt;
	char *name;
	struct iovec path_iov[SYSCTL_DEPTH_MAX];
	struct sysctl_node *child, *node;

	ASSERT(mode == SYSCTL_RD || mode == SYSCTL_LD || mode == SYSCTL_WR);
	LOG_TRACE(log);
	node = sysctl_root;
	path_len = strlen(path);
	if (path_len >= PATH_MAX) {
		return -EINVAL;
	}
	rc = sysctl_split_path(log, path, path_iov);
	if (rc < 0) {
		return rc;
	}
	path_iovcnt = rc;
	for (i = 0; i < path_iovcnt; ++i) {
		name = path_iov[i].iov_base;
		name_len = path_iov[i].iov_len;
		child = sysctl_node_find_child(node, name, name_len);
		if (child == NULL) {
			rc = sysctl_node_alloc(log, &child, node,
			                       name, name_len);
			if (rc < 0) {
				return rc;
			}
		} else if (child->n_fn != NULL) {
			if (i == path_iovcnt - 1) {
				*pnode = node;
				return -EEXIST;
			} else {
				return -EBUSY;
			}
		}
		node = child;
	}
	node->n_mode = mode;
	node->n_is_added = 1;
	if (fn != NULL) {
		node->n_fn = fn;
		node->n_free_fn = free_fn;
		node->n_udata = udata;
	}
	*pnode = node;
	return 0;
}

static void
sysctl_node_del(struct log *log, struct sysctl_node *node)
{
	struct sysctl_node *child;

	if (node == NULL) {
		return;
	}
	while (!dlist_is_empty(&node->n_children)) {
		child = DLIST_FIRST(&node->n_children,
		                    struct sysctl_node, n_list);
		sysctl_node_del(log, child);
	}
	DLIST_REMOVE(node, n_list);
	if (node->n_free_fn != NULL) {
		(*node->n_free_fn)(node->n_udata);
	}
	free(node);
}


static int
sysctl_node_in(struct log *log, struct sysctl_conn *cp,
	struct sysctl_node *node, char *tail, int load,
	const char *new, struct strbuf *out)
{
	int rc, len;
	char buf[GT_SYSCTL_BUFSIZ];
	const char *access;
	struct strbuf stub;

	if (tail == NULL) {
		tail = "";
	}
	if (new != NULL) {
		access = NULL;
		switch (node->n_mode) {
		case SYSCTL_LD:
			if (load == 0) {
				access = "load";
			}
			break;
		case SYSCTL_RD:
			access = "read";
			break;
		default:
			break;
		}
		if (access != NULL) {
			return -EACCES;
		}
	}
	if (out == NULL) {
		strbuf_init(&stub, buf, sizeof(buf));
		out = &stub;
	}
	len = out->sb_len;
	if (node->n_is_list) {
		rc = sysctl_node_in_list(node, tail, new, out);
	} else if (node->n_fn == NULL) {
		rc = sysctl_node_in_branch(node, tail, out);
	} else {
		if (tail[0] != '\0') {
			rc = 1;
		} else {
			rc = sysctl_node_in_leaf(log, cp, node, new, out);
		}
	}
	if (rc == 1) {
		return -ENOENT;
	}
	if (rc < 0) {
		out->sb_len = len;
	}
	return rc;
}

static int
sysctl_node_in_list(struct sysctl_node *node, const char *tail,
	const char *new, struct strbuf *out)
{
	int rc, id;
	char *endptr;
	struct sysctl_list_data *data;

	data = &node->n_udata_buf.n_list_data;
	if (tail[0] == '\0') {
		id = 0;
		goto next;
	}
	id = strtoul(tail, &endptr, 10);
	switch (*endptr) {
	case '\0':
		rc = (data->l_fn)(node->n_udata, id, new, out);
		ASSERT3(0, rc <= 0, "%s", sysctl_log_add_node(node));
		return rc;
	case '+':
		if (*(endptr + 1) != '\0') {
			return 1;
		}
		id++;
next:
		rc = (*data->l_next_fn)(node->n_udata, id);
		if (rc >= 0) {
			strbuf_addf(out, ",%d", rc);
		}
		return 0;
	default:
		return 1;
	}
}

static int
sysctl_node_in_branch(struct sysctl_node *node, const char *tail,
	struct strbuf *out)
{
	int len;
	struct sysctl_node *x, *first, *last;

	if (dlist_is_empty(&node->n_children)) {
		return 0;
	}
	first = DLIST_FIRST(&node->n_children, struct sysctl_node, n_list);
	last = DLIST_LAST(&node->n_children, struct sysctl_node, n_list);
	if (tail[0] == '\0') {
		x = first;
	} else {
		len = strlen(tail);
		if (tail[len - 1] != '+') {
			return 1;
		}
		x = sysctl_node_find_child(node, tail, len - 1);
		if (x == NULL || x == last) {
			return 0;
		}
		x = DLIST_NEXT(x, n_list);
	}
	strbuf_addf(out, ",%s", x->n_name);
	return 0;
}

static int
sysctl_node_in_leaf(struct log *log, struct sysctl_conn *cp,
	struct sysctl_node *node, const char *new, struct strbuf *out)
{
	int rc, off;
	char *old;

	off = out->sb_len;
	rc = (*node->n_fn)(log, cp, node->n_udata, new, out);
	if (rc < 0) {
		LOGF(log, LOG_ERR, -rc,
		     "handler failed; path='%s', new='%s'",
		     sysctl_log_add_node(node), new);
		return rc;
	}
	if (off < out->sb_cap) {
		old = strbuf_cstr(out) + off;
		rc = sysctl_verify(old);
		if (rc == 0) {
			return -EINVAL;
		}
	}	 
	return 0;
}

static int
sysctl_node_in_int(struct log *log, struct sysctl_conn *cp,
	void *udata, const char *new, struct strbuf *out)
{
	int rc;
	long long x, old;
	char *endptr;
	struct sysctl_int_data *data;

	rc = 0;
	old = 0;
	data = udata;
	LOG_TRACE(log);
	if (new == NULL) {
		switch (data->i_sizeof) {
		case 0:
			rc = (*data->i_ptr_intfn)(NULL, &old);
			break;
		case 4:
			old = *data->i_ptr_int32;
			break;
		case 8:
			old = *data->i_ptr_int64;
			break;
		default:
			BUG;
		}
	} else {
		x = strtoll(new, &endptr, 10);
		if (*endptr != '\0') {
			return -EPROTO;
		}
		if (x < data->i_min || x > data->i_max) {
			return -ERANGE;
		}
		switch (data->i_sizeof) {
		case 0:
			rc = (*data->i_ptr_intfn)(&x, &old);
			break;
		case 4:
			old = *data->i_ptr_int32;
			*data->i_ptr_int32 = x;
			break;
		case 8:
			old = *data->i_ptr_int64;
			*data->i_ptr_int64 = x;
			break;
		default:
			BUG;
		}
	}
	strbuf_addf(out, "%lld", old);
	return rc;
}

int
sysctl_conn_fd(struct sysctl_conn *cp)
{
	return cp->sccn_event->fde_fd;
}

int
sysctl_conn_open(struct log *log, struct sysctl_conn **cpp, int fd)
{
	int rc;
	char name[PATH_MAX];
	struct sysctl_conn *cp;

	LOG_TRACE(log);
	rc = sys_malloc(log, (void **)cpp, sizeof(*cp));
	if (rc) {
		return rc;
	}
	cp = *cpp;
	memset(cp, 0, sizeof(*cp));
	snprintf(name, sizeof(name), "sysctl.%d", fd);
	rc = gt_fd_event_new(log, &cp->sccn_event, fd, name,
	                     sysctl_process_events, cp);
	if (rc < 0) {
		sys_free(cp);
	} else {
		gt_fd_event_set(cp->sccn_event, POLLIN);
	}
	return rc;
}

static int
sysctl_conn_accept(struct log *log, struct sysctl_conn *cp)
{
	int rc, fd, peer_pid, new_fd;
	char *endptr;
	const char *filename;
	socklen_t sa_len;
	struct sockaddr_un a;
	struct sysctl_conn *new_cp;

	LOG_TRACE(log);
	sa_len = sizeof(a);
	fd = sysctl_conn_fd(cp);
	rc = sys_accept4(log, fd, (struct sockaddr *)&a, &sa_len,
	                 SOCK_NONBLOCK|SOCK_CLOEXEC);
	if (rc < 0) {
		return rc;
	}
	new_fd = rc;
	peer_pid = 0;
	if (sa_len >= sizeof(sa_family_t)) {
		sa_len -= sizeof(sa_family_t);
		ASSERT(sa_len < sizeof(a.sun_path));
		a.sun_path[sa_len] = '\0';
		filename = basename(a.sun_path);
		rc = strtoul(filename, &endptr, 10);
		if (!strcmp(endptr, ".sock")) {
			peer_pid = rc;
		}
	}
	rc = sysctl_setsockopt(log, fd);
	if (rc) {
		goto err;
	}
	rc = sysctl_conn_open(log, &new_cp, new_fd);
	if (rc) {
		goto err;
	}
	new_cp->sccn_accept_conn = 0;
	new_cp->sccn_peer_pid = peer_pid;
	new_cp->sccn_close_fn = cp->sccn_close_fn;
	return 0;
err:
	sys_close(log, fd);
	return rc;
}

static int
sysctl_conn_recv(struct log *log, struct sysctl_conn *cp)
{
	int rc, fd;
	char *ptr;
	struct iovec t[SYSCTL_NTOKENS_MAX];
	char buf[GT_SYSCTL_BUFSIZ];

	LOG_TRACE(log);
	fd = sysctl_conn_fd(cp);
	rc = sys_read(log, fd, buf, sizeof(buf));
	if (rc < 0) {
		if (rc == -EAGAIN) {
			return 0;
		} else {
			return rc;
		}
	} else if (rc == 0) {
		return -ECONNRESET;
	} else {
		ptr = memchr(buf, '\n', rc);
		if (ptr == NULL) {
			return -EPROTO;
		}		
		*ptr = '\0';
		sysctl_split_msg(t, buf);
		rc = sysctl_in_req(cp, t);
		return rc;
	}
}

void
sysctl_conn_close(struct log *log, struct sysctl_conn *cp)
{
	LOG_TRACE(log);
	if (cp == NULL) {
		return;
	}
	if (cp->sccn_close_fn != NULL) {
		(*cp->sccn_close_fn)(log, cp);
	}
	sys_close(log, sysctl_conn_fd(cp));
	gt_fd_event_del(cp->sccn_event);
}

static int
sysctl_conn_send(struct log *log, struct sysctl_conn *cp, struct strbuf *sb)
{
	int rc, fd;

	LOG_TRACE(log);
	fd = sysctl_conn_fd(cp);
	rc = sys_send(log, fd, sb->sb_buf, sb->sb_len, MSG_NOSIGNAL);
	if (rc < 0) {
		return rc;
	} else if (rc != sb->sb_len) {
		return -ENOBUFS;
	} else {
		return 0;
	}
}

static int
sysctl_process_events(void *udata, short revents)
{
	int rc;
	struct log *log;
	struct sysctl_conn *cp;

	log = log_trace0();
	cp = udata;
	if (cp->sccn_accept_conn) {
		do {
			rc = sysctl_conn_accept(log, cp);
		} while (rc == 0);
	} else {
		rc = sysctl_conn_recv(log, cp);
		if (rc < 0) {
			sysctl_conn_close(log, cp);
		}
	}
	return 0;
}

static int
sysctl_in(struct log *log, struct sysctl_conn *cp,
	const char *path, int load,
          const char *new, struct strbuf *out)
{
	int rc;
	char *tail;
	struct sysctl_node *node;

	LOG_TRACE(log);
	rc = sysctl_node_find(log, path, &node, &tail);
	if (rc == 0) {
		rc = sysctl_node_in(log, cp, node, tail, load, new, out);
	}
	return rc;
}

static int
sysctl_in_req(struct sysctl_conn *cp, struct iovec *t)
{
	int rc;
	char buf[GT_SYSCTL_BUFSIZ];
	const char *path;
	struct strbuf sb;
	struct log *log;

	log = log_trace0();
	path = t[0].iov_base;
	strbuf_init(&sb, buf, sizeof(buf));
	rc = sysctl_in(log, cp, path, 0, t[1].iov_base, &sb);
	if (rc) {
		strbuf_addf(&sb, "error %d", -rc);
	}
	strbuf_add_ch(&sb, '\n');
	if (strbuf_space(&sb) == 0) {
		LOGF(log, LOG_ERR, 0, "too long msg; path='%s'", path);
		return -ENOBUFS;
	}
	rc = sysctl_conn_send(log, cp, &sb);
	return rc;
}

// Add/Del
static void
sysctl_add6(struct log *log, const char *path, int mode, void *udata,
	void (*free_fn)(void *), sysctl_f fn, struct sysctl_node **pnode)
{
	int rc;

	LOG_TRACE(log);
	rc = sysctl_node_add(log, path, mode, udata, free_fn, fn, pnode);
	if (rc < 0) {
		die(log, -rc, "sysctl_add('%s') failed", path);
	}
}

void
sysctl_add(struct log *log, const char *path, int mode, void *udata,
	void (*free_fn)(void *), sysctl_f fn)
{
	struct sysctl_node *node;

	sysctl_add6(log, path, mode, udata, free_fn, fn, &node);
}

static void
sysctl_add_int_union(struct log *log, const char *path,
	int mode, void *ptr, int int_sizeof, int64_t min, int64_t max)
{
	struct sysctl_int_data *data;
	struct sysctl_node *node;
	
	ASSERT(min <= max);
	sysctl_add6(log, path, mode, NULL, NULL,
	            sysctl_node_in_int, &node);
	data = &node->n_udata_buf.n_int_data;
	node->n_udata = data;
	data->i_ptr = ptr;
	data->i_min = min;
	data->i_max = max;
	data->i_sizeof = int_sizeof;
	data->i_ptr = ptr;
}

void
sysctl_add_intfn(struct log *log, const char *path, int mode,
	int (*intfn)(const long long *, long long *), int min, int max)
{

	sysctl_add_int_union(log, path, mode, intfn, 0, min, max);
}

void
sysctl_add_int(struct log *log, const char *path, int mode,
	int *ptr, int min, int max)
{
	sysctl_add_int_union(log, path, mode, ptr, sizeof(*ptr), min, max);
}

void
sysctl_add_int64(struct log *log, const char *path, int mode,
	int64_t *ptr, int64_t min, int64_t max)
{
	sysctl_add_int_union(log, path, mode, ptr, sizeof(*ptr), min, max);
}

void
sysctl_add_uint64(struct log *log, const char *path, int mode,
	uint64_t *ptr, int64_t min, int64_t max)
{
	sysctl_add_int_union(log, path, mode, ptr, sizeof(*ptr), min, max);
}

void
sysctl_add_list(struct log *log, const char *path, int mode,
	void *udata, sysctl_list_next_f next_fn, sysctl_list_f fn)
{
	struct sysctl_node *node;
	struct sysctl_list_data *data;

	sysctl_add6(log, path, mode, NULL, NULL, NULL, &node);
	node->n_is_list = 1;
	data = &node->n_udata_buf.n_list_data;
	node->n_udata = udata;
	data->l_next_fn = next_fn;
	data->l_fn = fn;
}

int
sysctl_del(struct log *log, const char *path)
{
	int rc;
	struct sysctl_node *node;

	LOG_TRACE(log);
	rc = sysctl_node_find(log, path, &node, NULL);
	if (rc == 0) {
		sysctl_node_del(log, node);
	}
	return rc;
}

int
sysctl_delf(struct log *log, const char *fmt, ...)
{
	int rc;
	va_list ap;
	char path[PATH_MAX];

	va_start(ap, fmt);
	vsnprintf(path, sizeof(path), fmt, ap);
	va_end(ap);
	rc = sysctl_del(log, path);
	return rc;
}

int
sysctl_connect(struct log *log, int fd)
{
	int rc;
	uint64_t to;
	struct sockaddr_un a;

	LOG_TRACE(log);
	a.sun_family = AF_UNIX;
	strzcpy(a.sun_path, SYSCTL_CONTROLLER_PATH, sizeof(a.sun_path));
	to = 2 * NANOSECONDS_SECOND;
	rc = connect_timed(log, fd, (struct sockaddr *)&a, sizeof(a), &to);
	return rc;
}

int
sysctl_can_connect(struct log *log, int pid)
{
	int rc, fd;
	uint64_t to;
	struct sockaddr_un a;

	LOG_TRACE(log);
	rc = sys_socket(log, AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	sysctl_make_sockaddr_un(&a, pid);
	to = 0;
	rc = connect_timed(log, fd, (struct sockaddr *)&a, sizeof(a), &to);
	sys_close(log, fd);
	if (rc == 0 || rc == -ETIMEDOUT) {
		return 1;
	} else {
		sys_unlink(log, a.sun_path);
		return 0;
	}
}

int
sysctl_bind(struct log *log, const struct sockaddr_un *a, int accept_conn)
{
	int rc, fd;
	struct stat stat;
	struct group *group;

	LOG_TRACE(log);
	rc = sys_socket(log, AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	sys_unlink(log, a->sun_path);
	rc = sys_bind(log, fd, (const struct sockaddr *)a, sizeof(*a));
	if (rc < 0) {
		goto err;
	}
	rc = sys_getgrnam(log, GT_GROUP_NAME, &group);
	if (rc == 0) {
		sys_chown(log, a->sun_path, -1, group->gr_gid);
	}
	rc = sys_stat(log, a->sun_path, &stat);
	if (rc == 0) {
		sys_chmod(log, a->sun_path,
		          stat.st_mode|S_IRGRP|S_IWGRP|S_IXGRP);
	}
	if (accept_conn) {
		rc = sys_listen(log, fd, 5);
	} else {
		rc = sysctl_setsockopt(log, fd);
	}
	if (rc) {
		goto err;
	}
	return fd;
err:
	sys_close(log, fd);
	return rc;
}

int
sysctl_send_req(struct log *log, int fd, const char *path, const char *new)
{
	int rc, len;
	char buf[GT_SYSCTL_BUFSIZ];

	LOG_TRACE(log);
	len = snprintf(buf, sizeof(buf), "%s %s\n", path, new);
	if (len >= sizeof(buf)) {
		return -EINVAL;
	}
	rc = send_full_buf(log, fd, buf, len, MSG_NOSIGNAL);
	return rc;
}

int
sysctl_recv_rpl(struct log *log, int fd, char *old)
{
	int rc, len, errnum;
	char *ptr;
	uint64_t to;
	struct iovec t[SYSCTL_NTOKENS_MAX];

	LOG_TRACE(log);
	to = 5 * NANOSECONDS_SECOND;
	len = 0;
	while (1) {
		rc = read_timed(log, fd, old + len,
		                GT_SYSCTL_BUFSIZ - len, &to);
		if (rc < 0) {
			return rc;
		} else if (rc == 0) {
			return -EPROTO;
		} else {
			ptr = memchr(old + len, '\n', rc);
			if (ptr == NULL) {
				len += rc;
				if (len == GT_SYSCTL_BUFSIZ) {
					return -EPROTO;
				}
			} else {
				*ptr = '\0';
				break;
			}
		}
	}
	sysctl_split_msg(t, old);
	if (t[1].iov_len) {
		errnum = strtoul(t[1].iov_base, &ptr, 10);
		if (strcmp(t[0].iov_base, "error") ||
		    errnum == 0 || *ptr != '\0') {
			return -EPROTO;
		} else {
			return errnum;
		}
	} else {
		rc = sysctl_verify(t[0].iov_base);
		if (!rc) {
			return -EPROTO;
		}
		return 0;
	}
}

int
sysctl_req(struct log *log, int fd, const char *path, char *old,
	const char *new)
{
	int rc;

	rc = sysctl_send_req(log, fd, path, new);
	if (rc == 0) {
		rc = sysctl_recv_rpl(log, fd, old);
	}
	return rc;
}

static int
sysctl_req_safe(struct log *log, const char *path, char *old, const char *new)
{
	int rc, fd, path_len;

	ASSERT(path != NULL);
	path_len = strlen(path);
	if (path_len >= PATH_MAX) {
		return -EINVAL;
	}
	rc = sysctl_verify(path);
	if (!rc) {
		return -EINVAL;
	}
	if (new == NULL) {
		new = "";
	} else {
		rc = sysctl_verify(new);
		if (!rc) {
			return -EINVAL;
		}
	}
	rc = sys_socket(log, AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	rc = sysctl_connect(log, fd);
	if (rc == 0) {
		rc = sysctl_req(log, fd, path, old, new);
	}
	sys_close(log, fd);
	return rc;
}

int
gt_sysctl(const char *path, char *old, const char *new)
{
	int rc;
	static int inited;
	struct log *log;

	log = log_trace0();
	if (!inited) {
		inited = 1;
		proc_init();
	}
	LOGF(log, LOG_INFO, 0, "hit; path='%s'", path);
	rc = sysctl_req_safe(log, path, old, new);
	if (rc < 0) {
		if (new == NULL) {
			LOGF(log, LOG_INFO, -rc, "failed; path='%s'", path);
		} else {
			LOGF(log, LOG_INFO, -rc, "failed; path='%s', new='%s'",
			     path, new);
		}
	} else {
		LOGF(log, LOG_INFO, 0, "ok");
	}
	API_RETURN(rc);
}
