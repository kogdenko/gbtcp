// gpl2
#include "internals.h"

#define CURMOD sysctl

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

struct sysctl_list_udata {
	sysctl_list_next_f l_next_fn;
	sysctl_list_f l_fn;
};

struct sysctl_node {
	struct dlist scn_list;
	struct dlist scn_children;
	struct sysctl_node *scn_parent;
	u_char scn_mode;
	u_char scn_is_added;
	u_char scn_is_list;
	int scn_name_len;
	void *scn_udata;
	sysctl_f scn_fn;
	void (*scn_free_fn)(void *);
	char scn_name[SYSCTL_NODE_NAME_MAX];
	union {
		struct sysctl_int_data nud_int_data;
		struct sysctl_list_udata nud_list_data;
	} scn_udata_buf;
#define scn_int_udata scn_udata_buf.nud_int_data
#define scn_list_udata scn_udata_buf.nud_list_data
};

static struct sysctl_node *sysctl_root;

static struct sysctl_node *sysctl_node_alloc(struct sysctl_node *,
	const char *, int);

static void sysctl_node_del(struct sysctl_node *);

static int sysctl_list_handler(struct sysctl_node *,
	const char *, const char *, struct strbuf *);

static int sysctl_branch_handler(struct sysctl_node *,
	const char *, struct strbuf *);

static int sysctl_handler(struct sysctl_conn *, struct sysctl_node *,
	const char *, struct strbuf *);

static int sysctl_process_events(void *udata, short revents);

static int sysctl_process(struct sysctl_conn *, const char *, int,
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
sysctl_root_init(void)
{
	sysctl_root = sysctl_node_alloc(NULL, NULL, 0);
	if (sysctl_root == NULL) {
		return -ENOMEM;
	} else {
		sysctl_root->scn_is_added = 1;
		return 0;
	}
}

void
sysctl_root_deinit(void)
{
	sysctl_node_del(sysctl_root);
	sysctl_root = NULL;
}

static int
sysctl_setsockopt(int fd)
{
	int rc, opt;

	opt = GT_SYSCTL_BUFSIZ;
	rc = sys_setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
			    &opt, sizeof(opt));
	if (rc < 0) {
		return rc;
	}
	opt = GT_SYSCTL_BUFSIZ;
	rc = sys_setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
			    &opt, sizeof(opt));
	if (rc < 0) {
		return rc;
	}
	rc = fcntl_setfl_nonblock2(fd);
	return rc;
}

void
sysctl_make_sockaddr_un(struct sockaddr_un *a, int pid)
{
	a->sun_family = AF_UNIX;
	snprintf(a->sun_path, sizeof(a->sun_path), "%s/%d.sock",
		SYSCTL_SOCK_PATH, pid);
}

static void
strbuf_add_sysctl_node(struct strbuf *sb, struct sysctl_node *node)
{
	int i, n;
	struct sysctl_node *path[SYSCTL_DEPTH_MAX];

	assert(node != NULL);
	n = 0;
	for (; node != sysctl_root; node = node->scn_parent) {
		assert(node != NULL);
		assert(n < ARRAY_SIZE(path));
		path[n++] = node;
	}
	for (i = n - 1; i >= 0; --i) {
		if (sb->sb_len) {
			strbuf_add_ch(sb, '.');
		}
		strbuf_add_str(sb, path[i]->scn_name);
	}
}

const char *
log_add_sysctl_node(struct sysctl_node *node) 
{
	struct strbuf *sb;

	sb = log_buf_alloc_space();
	strbuf_add_sysctl_node(sb, node);
	return strbuf_cstr(sb);
}

static int
sysctl_split_path(const char *path, struct iovec *iovec)
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
sysctl_parse_line(int loader, char *s)
{
	int rc;
	char *ptr, *path, *new;
	char out_buf[GT_SYSCTL_BUFSIZ];
	struct strbuf out;

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
	strbuf_init(&out, out_buf, sizeof(out_buf));
	rc = sysctl_process(NULL, path, loader, new, &out);
	return rc;
}

int
sysctl_read_file(int loader)
{
	int rc, line;
	const char *path;
	char *s;
	char path_buf[PATH_MAX];
	char buf[2000];
	FILE *file;

	path = getenv("GBTCP_CONF");
	if (path == NULL) {
		return 0;
	}
	rc = sys_realpath(path, path_buf);
	if (rc) {
		return rc;
	}
	path = path_buf;
	NOTICE(0, "Read sysctl file '%s'", path);
	rc = sys_fopen(&file, path, "r");
	if (rc) {
		return rc == -ENOENT ? 0 : rc;
	}
	rc = 0;
	line = 0;
	while ((s = fgets(buf, sizeof(buf), file)) != NULL) {
		line++;
		rc = sysctl_parse_line(loader, s);
		if (rc) {
			ERR(-rc, "%s:%d: Inavlid configuration", path, line);
		}
	}
	fclose(file);
	return rc;
}

static struct sysctl_node *
sysctl_node_alloc(struct sysctl_node *parent, const char *name, int name_len)
{
	struct sysctl_node *node;

	node = sys_malloc(sizeof(struct sysctl_node));
	if (node == NULL) {
		return NULL;
	}
	assert(name_len < SYSCTL_NODE_NAME_MAX);
	memset(node, 0, sizeof(*node));
	node->scn_name_len = name_len;
	memcpy(node->scn_name, name, name_len);
	node->scn_name[name_len] = '\0';
	dlist_init(&node->scn_children);
	node->scn_parent = parent;
	if (parent != NULL) {
		DLIST_INSERT_TAIL(&parent->scn_children, node, scn_list);
	}
	return node;
}

static struct sysctl_node *
sysctl_node_find_child(struct sysctl_node *node, const char *name,
	int name_len)
{
	struct sysctl_node *child;

	DLIST_FOREACH(child, &node->scn_children, scn_list) {
		if (child->scn_name_len == name_len &&
		    !memcmp(child->scn_name, name, name_len)) {
			return child;
		}
	}
	return NULL;
}

static int
sysctl_node_find(const char *path, struct sysctl_node **pnode, char **ptail)
{
	int i, rc, name_len, path_iovcnt;
	char *name;
	struct sysctl_node *child, *node;
	struct iovec path_iov[SYSCTL_DEPTH_MAX];

	node = sysctl_root;
	if (node == NULL) {
		return -ENOENT;
	}
	rc = sysctl_split_path(path, path_iov);
	if (rc < 0) {
		return rc;
	}
	path_iovcnt = rc;
	for (i = 0; i < path_iovcnt; ++i) {
		name = path_iov[i].iov_base;
		name_len = path_iov[i].iov_len;
		child = sysctl_node_find_child(node, name, name_len);
		if (child == NULL) {
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
sysctl_node_add(const char *path, int mode,
	void *udata, void (*free_fn)(void *), sysctl_f fn,
	struct sysctl_node **pnode)
{
	int i, rc, name_len, path_len, path_iovcnt;
	char *name;
	struct iovec path_iov[SYSCTL_DEPTH_MAX];
	struct sysctl_node *child, *node;

	assert(mode == SYSCTL_RD || mode == SYSCTL_LD || mode == SYSCTL_WR);
	node = sysctl_root;
	path_len = strlen(path);
	if (path_len >= PATH_MAX) {
		return -EINVAL;
	}
	rc = sysctl_split_path(path, path_iov);
	if (rc < 0) {
		return rc;
	}
	path_iovcnt = rc;
	for (i = 0; i < path_iovcnt; ++i) {
		name = path_iov[i].iov_base;
		name_len = path_iov[i].iov_len;
		child = sysctl_node_find_child(node, name, name_len);
		if (child == NULL) {
			child = sysctl_node_alloc(node, name, name_len);
			if (child == NULL) {
				return -ENOMEM;
			}
		} else if (child->scn_fn != NULL) {
			if (i == path_iovcnt - 1) {
				*pnode = node;
				return -EEXIST;
			} else {
				return -EBUSY;
			}
		}
		node = child;
	}
	node->scn_mode = mode;
	node->scn_is_added = 1;
	if (fn != NULL) {
		node->scn_fn = fn;
		node->scn_free_fn = free_fn;
		node->scn_udata = udata;
	}
	*pnode = node;
	return 0;
}

static void
sysctl_node_del(struct sysctl_node *node)
{
	struct sysctl_node *child;

	if (node == NULL) {
		return;
	}
	while (!dlist_is_empty(&node->scn_children)) {
		child = DLIST_FIRST(&node->scn_children,
		                    struct sysctl_node, scn_list);
		sysctl_node_del(child);
	}
	if (node->scn_parent != NULL) {
		node->scn_parent = NULL;
		DLIST_REMOVE(node, scn_list);
	}
	if (node->scn_free_fn != NULL) {
		(*node->scn_free_fn)(node->scn_udata);
	}
	sys_free(node);
}

static int
sysctl_process_node(struct sysctl_conn *cp,
	struct sysctl_node *node, char *tail, int loader,
	const char *new, struct strbuf *out)
{
	int rc;

	if (new != NULL) {
		switch (node->scn_mode) {
		case SYSCTL_RD:
			if (node->scn_fn == NULL) {
				return -ENOENT;
			} else {
				return -EACCES;
			}
		case SYSCTL_LD:
			if (loader == 0) {
				if (cp == NULL) {
					return 0;
				} else {
					return -EACCES;
				}
			}
			break;
		case SYSCTL_WR:
			if (loader) {
				return 0;
			}
			break;
		default:
			assert(!"unknown mode");
		}
	}
	if (node->scn_is_list) {
		rc = sysctl_list_handler(node, tail, new, out);
	} else if (node->scn_fn == NULL) {
		rc = sysctl_branch_handler(node, tail, out);
	} else {
		if (tail != NULL) {
			rc = -ENOENT;
		} else {
			rc = sysctl_handler(cp, node, new, out);
		}
	}
	return rc;
}

static int
sysctl_list_handler(struct sysctl_node *node, const char *tail,
	const char *new, struct strbuf *out)
{
	int rc, tail_len;
	struct sysctl_list_udata *udata;

	udata = &node->scn_list_udata;
	tail_len = strzlen(tail);
	if (tail_len == 0 || tail[tail_len - 1] == '+') {
		strbuf_add_ch(out, ',');
		rc = (*udata->l_next_fn)(node->scn_udata, tail, out);
		if (rc) {
			out->sb_len = 0;
		}
		return 0;
	} else {
		rc = (*udata->l_fn)(node->scn_udata, tail, new, out);
		return rc;
	}
}

static int
sysctl_branch_handler(struct sysctl_node *node, const char *tail,
	struct strbuf *out)
{
	int tail_len;
	struct sysctl_node *x, *first, *last;

	if (dlist_is_empty(&node->scn_children)) {
		return 0;
	}
	first = DLIST_FIRST(&node->scn_children, struct sysctl_node, scn_list);
	last = DLIST_LAST(&node->scn_children, struct sysctl_node, scn_list);
	tail_len = strzlen(tail);
	if (tail_len == 0) {
		x = first;
	} else if (tail[tail_len - 1] != '+') {
		return 0;
	} else {
		x = sysctl_node_find_child(node, tail, tail_len - 1);
		if (x == NULL || x == last) {
			return 0;
		}
		x = DLIST_NEXT(x, scn_list);
	}
	strbuf_addf(out, ",%s", x->scn_name);
	return 0;
}

static int
sysctl_handler(struct sysctl_conn *cp, struct sysctl_node *node,
	const char *new, struct strbuf *out)
{
	int rc, off;
	char *old;

	off = out->sb_len;
	rc = (*node->scn_fn)(cp, node->scn_udata, new, out);
	if (rc < 0) {
		ERR(-rc, "sysctl '%s' handler failed",
			log_add_sysctl_node(node));
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
sysctl_node_in_int(struct sysctl_conn *cp, void *udata,	const char *new, struct strbuf *out)
{
	int rc;
	long long x, old;
	char *endptr;
	struct sysctl_int_data *data;

	rc = 0;
	old = 0;
	data = udata;
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
			assert(!"Bad int size");
		}
	} else {
		x = strtoll(new, &endptr, 10);
		if (*endptr != '\0') {
			return -EINVAL;
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
			assert(!"Bad int size");
		}
	}
	strbuf_addf(out, "%lld", old);
	return rc;
}

int
sysctl_conn_fd(struct sysctl_conn *cp)
{
	return cp->scc_event->fde_fd;
}

int
sysctl_conn_open(struct sysctl_conn **cpp, int fd)
{
	int rc;
	struct sysctl_conn *cp;

	cp = sys_malloc(sizeof(*cp));
	if (cp == NULL) {
		return -ENOMEM;
	}
	memset(cp, 0, sizeof(*cp));
	rc = fd_event_add(&cp->scc_event, fd, cp, sysctl_process_events);
	if (rc < 0) {
		sys_free(cp);
	} else {
		fd_event_set(cp->scc_event, POLLIN);
		*cpp = cp;
	}
	return rc;
}

static int
sysctl_conn_accept(struct sysctl_conn *cp)
{
	int rc, fd, new_fd;
	struct sysctl_conn *new_cp;

	fd = sysctl_conn_fd(cp);
	rc = sys_accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
	if (rc < 0) {
		return rc;
	}
	new_fd = rc;
	rc = sysctl_setsockopt(new_fd);
	if (rc) {
		goto err;
	}
	rc = sysctl_conn_open(&new_cp, new_fd);
	if (rc) {
		goto err;
	}
	new_cp->scc_accept_conn = 0;
	new_cp->scc_close_fn = cp->scc_close_fn;
	return 0;
err:
	sys_close(fd);
	return rc;
}

static int
sysctl_conn_recv(struct sysctl_conn *cp)
{
	int rc, fd;
	char *ptr;
	struct iovec t[SYSCTL_NTOKENS_MAX];
	char buf[GT_SYSCTL_BUFSIZ];

	fd = sysctl_conn_fd(cp);
	rc = sys_read(fd, buf, sizeof(buf));
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
sysctl_conn_close(struct sysctl_conn *cp)
{
	if (cp == NULL) {
		return;
	}
	if (cp->scc_close_fn != NULL) {
		(*cp->scc_close_fn)(cp);
	}
	sys_close(sysctl_conn_fd(cp));
	fd_event_del(cp->scc_event);
	sys_free(cp);
}

static int
sysctl_conn_send(struct sysctl_conn *cp, struct strbuf *sb)
{
	int rc, fd;

	fd = sysctl_conn_fd(cp);
	rc = sys_send(fd, sb->sb_buf, sb->sb_len, MSG_NOSIGNAL);
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
	struct sysctl_conn *cp;

	cp = udata;
	if (cp->scc_accept_conn) {
		do {
			rc = sysctl_conn_accept(cp);
		} while (rc == 0);
	} else {
		rc = sysctl_conn_recv(cp);
		if (rc < 0) {
			sysctl_conn_close(cp);
		}
	}
	return 0;
}

static int
sysctl_process(struct sysctl_conn *cp, const char *path, int loader,
		const char *new, struct strbuf *out)
{
	int rc;
	char *tail;
	struct sysctl_node *node;

	rc = sysctl_node_find(path, &node, &tail);
	if (rc == 0) {
		rc = sysctl_process_node(cp, node, tail, loader, new, out);
	}
	return rc;
}

static int
sysctl_in_req(struct sysctl_conn *cp, struct iovec *t)
{
	int rc;
	char out_buf[GT_SYSCTL_BUFSIZ];
	const char *path;
	struct strbuf out;

	path = t[0].iov_base;
	strbuf_init(&out, out_buf, sizeof(out_buf));
	rc = sysctl_process(cp, path, 0, t[1].iov_base, &out);
	if (rc) {
		out.sb_len = 0;
		strbuf_addf(&out, "error %d", -rc);
	}
	strbuf_add_ch(&out, '\n');
	if (strbuf_space(&out) == 0) {
		ERR(0, "%s: Too long message", path);
		return -ENOBUFS;
	}
	rc = sysctl_conn_send(cp, &out);
	return rc;
}

static void
sysctl_add6(const char *path, int mode, void *udata,
	void (*free_fn)(void *), sysctl_f fn, struct sysctl_node **pnode)
{
	int rc;

	assert(sysctl_root != NULL);
	rc = sysctl_node_add(path, mode, udata, free_fn, fn, pnode);
	if (rc < 0) {
		gtl_die(-rc, "sysctl_add('%s') failed", path);
	}
}

void
sysctl_add(const char *path, int mode, void *udata, void (*free_fn)(void *), sysctl_f fn)
{
	struct sysctl_node *node;

	sysctl_add6(path, mode, udata, free_fn, fn, &node);
}

static void
sysctl_add_int_union(const char *path, int mode, void *ptr,
		int int_sizeof, int64_t min, int64_t max)
{
	struct sysctl_int_data *data;
	struct sysctl_node *node;
	
	assert(min <= max);
	sysctl_add6(path, mode, NULL, NULL, sysctl_node_in_int, &node);
	data = &node->scn_int_udata;
	node->scn_udata = data;
	data->i_ptr = ptr;
	data->i_min = min;
	data->i_max = max;
	data->i_sizeof = int_sizeof;
	data->i_ptr = ptr;
}

void
sysctl_add_intfn(const char *path, int mode,
		int (*intfn)(const long long *, long long *), int min, int max)
{
	sysctl_add_int_union(path, mode, intfn, 0, min, max);
}

void
sysctl_add_int(const char *path, int mode, int *ptr, int min, int max)
{
	sysctl_add_int_union(path, mode, ptr, sizeof(*ptr), min, max);
}

void
sysctl_add_int64(const char *path, int mode, int64_t *ptr, int64_t min, int64_t max)
{
	sysctl_add_int_union(path, mode, ptr, sizeof(*ptr), min, max);
}

void
sysctl_add_uint64(const char *path, int mode, uint64_t *ptr, int64_t min, int64_t max)
{
	sysctl_add_int_union(path, mode, ptr, sizeof(*ptr), min, max);
}

void
sysctl_add_list(const char *path, int mode,
		void *udata, sysctl_list_next_f next_fn, sysctl_list_f fn)
{
	struct sysctl_node *node;
	struct sysctl_list_udata *list_udata;

	sysctl_add6(path, mode, NULL, NULL, NULL, &node);
	node->scn_is_list = 1;
	list_udata = &node->scn_list_udata;
	node->scn_udata = udata;
	list_udata->l_next_fn = next_fn;
	list_udata->l_fn = fn;
}

int
sysctl_del(const char *path)
{
	int rc;
	struct sysctl_node *node;

	rc = sysctl_node_find(path, &node, NULL);
	if (rc == 0) {
		sysctl_node_del(node);
	}
	return rc;
}

int
sysctl_delf(const char *fmt, ...)
{
	int rc;
	va_list ap;
	char path[PATH_MAX];

	va_start(ap, fmt);
	vsnprintf(path, sizeof(path), fmt, ap);
	va_end(ap);
	rc = sysctl_del(path);
	return rc;
}

int
sysctl_connect(int fd)
{
	int rc;
	uint64_t to;
	struct sockaddr_un a;

	a.sun_family = AF_UNIX;
	gt_strzcpy(a.sun_path, SYSCTL_CONTROLLER_PATH, sizeof(a.sun_path));
	to = 2 * NSEC_SEC;
	rc = connect_timed(fd, (struct sockaddr *)&a, sizeof(a), &to);
	return rc;
}

int
sysctl_bind(const struct sockaddr_un *a)
{
	int rc, fd;
	//struct stat buf;

	rc = sys_socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	sys_unlink(a->sun_path);
	rc = sys_bind(fd, (const struct sockaddr *)a, sizeof(*a));
	if (rc < 0) {
		goto err;
	}
//	rc = fchgrp(fd, &buf, GT_GROUP_NAME);
//	if (rc == 0) {
//		sys_fchmod(fd, buf.st_mode|S_IRGRP|S_IWGRP|S_IXGRP);
//	}
	rc = sysctl_setsockopt(fd);
	if (rc) {
		goto err;
	}
	return fd;
err:
	sys_close(fd);
	return rc;
}

int
sysctl_send_req(int fd, const char *path, const char *new)
{
	int rc, len;
	char buf[GT_SYSCTL_BUFSIZ];

	len = snprintf(buf, sizeof(buf), "%s %s\n", path, new);
	if (len >= sizeof(buf)) {
		return -EINVAL;
	}
	rc = send_record(fd, buf, len, MSG_NOSIGNAL);
	return rc;
}

int
sysctl_recv_rpl(int fd, char *old)
{
	int rc, len, errnum;
	char *ptr;
	uint64_t to;
	struct iovec t[SYSCTL_NTOKENS_MAX];

	to = 5 * NSEC_SEC;
	len = 0;
	while (1) {
		rc = read_timed(fd, old + len, GT_SYSCTL_BUFSIZ - len, &to);
		if (rc < 0) {
			return rc;
		} else if (rc == 0) {
			return -ECONNREFUSED;
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
sysctl_req(int fd, const char *path, char *old, const char *new)
{
	int rc;

	rc = sysctl_send_req(fd, path, new);
	if (rc == 0) {
		rc = sysctl_recv_rpl(fd, old);
	}
	return rc;
}

static int
sysctl_req_safe(const char *path, char *old, const char *new)
{
	int rc, fd, path_len;

	assert(path != NULL);
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
	rc = sys_socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	rc = sysctl_connect(fd);
	if (rc == 0) {
		rc = sysctl_req(fd, path, old, new);
	}
	sys_close(fd);
	return rc;
}

// TODO: Move to API
int
gt_sysctl(const char *path, char *old, const char *new)
{
	int rc;

	rc = sysctl_req_safe(path, old, new);
	if (rc < 0) {
		INFO(-rc, "gt_sysctl('%s') failed", path);
	} else {
		INFO(0, "gt_stsctl('%s') ok", path);
	}
	GT_RETURN(rc);
}

int
gt_get_build_version(char *version, int size)
{
	return snprintf(version, size, "%s", GT_VERSION);
}

int
gt_get_build_config(char *config, int size)
{
#ifdef GT_HAVE_XDP
#define HAVE_XDP " GT_HAVE_XDP"
#else // GT_HAVE_XDP
#define HAVE_XDP ""
#endif // GT_HAVE_XDP

#ifdef GT_HAVE_NETMAP
#define HAVE_NETMAP " GT_HAVE_NETMAP"
#else // GT_HAVE_NETMAP
#define HAVE_NETMAP ""
#endif // GT_HAVE_NETMAP

#ifdef GT_HAVE_VALE
#define HAVE_VALE " GT_HAVE_VALE"
#else // GT_HAVE_VAL
#define HAVE_VALE ""
#endif // GT_HAVE_VALE

	return snprintf(config, size, "%s%s%s", HAVE_XDP, HAVE_NETMAP, HAVE_VALE);
}
