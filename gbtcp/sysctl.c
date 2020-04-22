#include "internals.h"

#define GT_CTL_DEPTH_MAX 32
#define GT_CTL_NODE_NAME_MAX 128


enum {
	GT_CTL_CONN_UNDEF,
	GT_CTL_CONN_LISTEN,
	GT_CTL_CONN_CLIENT,
	GT_CTL_CONN_SERVER,
};

#define SYSCTL_LOG_MSG_FOREACH(x) \
	x(bind) \
	x(find) \
	x(add) \
	x(del) \
	x(open) \
	x(close) \
	x(recv) \
	x(send) \
	x(in) \
	x(process) \
	x(req_done) \
	x(req_timo) \
	x(read_file) \

struct sysctl_mod {
	struct log_scope log_scope;
	SYSCTL_LOG_MSG_FOREACH(LOG_MSG_DECLARE);
};

struct sysctl_conn;

typedef void (*sysctl_conn_close_f)(struct sysctl_conn *);

struct sysctl_conn {
	int c_pid;
	int c_type;
	void *c_req_udata;
	sysctl_f c_req_fn;
	sysctl_conn_close_f c_close_fn;
	struct gt_fd_event *c_event;
	struct gt_timer c_timer;
	struct strbuf c_rcvbuf;
	struct strbuf c_sndbuf;
	gt_time_t c_req_time;
	struct log *c_log;
	struct log c_log_stack[LOG_STACKSIZ];
	char c_req_path[PATH_MAX];
	char c_rcvbuf_buf[GT_SYSCTL_BUFSIZ];
	char c_sndbuf_buf[GT_SYSCTL_BUFSIZ];
};

struct sysctl_int_data {
	union {
		int (*sid_ptr_intfn)(const long long *new, long long *);
		int32_t *sid_ptr_int32;
		int64_t *sid_ptr_int64;
		void *sid_ptr;
	};
	int sid_int_sizeof;
	long long sid_min;
	long long sid_max;
};

struct sysctl_list_data {
	sysctl_list_next_f sld_next_fn;
	sysctl_list_f sld_fn;
};

struct sysctl_wait {
	char *w_old;
	int w_cnt;
	int w_eno;
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
	sysctl_node_f n_fn;
	void (*n_free_fn)(void *);
	char n_name[GT_CTL_NODE_NAME_MAX];
	union {
		struct sysctl_int_data n_int_data;
		struct sysctl_list_data n_list_data;
	} n_udata_buf;
};

static struct sysctl_node *sysctl_root;
static struct sysctl_conn *sysctl_binded;
static struct sysctl_conn *sysctl_publisher;
static struct sysctl_conn *sysctl_subscribers[GT_SERVICES_MAX];
static int sysctl_nr_subscribers;
sysctl_sub_f sysctl_sub_fn;
static void (*sysctl_publisher_close_fn)();
static struct sysctl_mod *current_mod;

static int sysctl_process_line(struct log *log, char *s);

// conn
static int sysctl_conn_fd(struct sysctl_conn *cp);

static void sysctl_conn_set_log(struct sysctl_conn *cp, struct log *log);

static int sysctl_conn_open(struct log *log,
	struct sysctl_conn **cpp, int fd, const char *path);

static void sysctl_conn_close(struct sysctl_conn *cp, int eno);

static int sysctl_conn_connect(struct log *log, struct sysctl_conn **cpp,
	int pid, const char *path);

static int sysctl_conn_listen(struct log *log, 
	struct sysctl_conn **cpp, int pid);

static int sysctl_conn_accept(struct sysctl_conn *lp);

static int sysctl_conn_recv(struct sysctl_conn *cp);

static int sysctl_conn_send(struct log *log, struct sysctl_conn *cp);

static int sysctl_conn_send_cmd(struct log *log, struct sysctl_conn *cp,
	const char *cmd, const char *path, int path_len,
	const char *new, int new_len);

static int sysctl_conn_process_events(void *udata, short revents);

static int sysctl_conn_in(struct sysctl_conn *cp, int off);

static int sysctl_conn_in_first(struct sysctl_conn *cp,
	char *buf, int off, int cnt);

static int sysctl_conn_in_next(struct sysctl_conn *cp,
	char *buf, int cnt);

static void sysctl_req_done(struct sysctl_conn *cp, int eno, char *old);

static void sysctl_req_timo(struct gt_timer *timer);

// pub/sub
static void sysctl_handle_sub(struct sysctl_conn *cp, int action);

static void sysctl_subscriber_close_cb(struct sysctl_conn *cp);

static void sysctl_publisher_close_mediator(struct sysctl_conn *cp);

static void sysctl_publish(struct log *log, struct sysctl_node *node,
	const char *new, int new_len);

static void sysctl_unsub1(int eno);

// in
static int sysctl_in(struct log *log, const char *path, int load,
	const char *new, struct strbuf *out);

static int sysctl_in_pdu(struct sysctl_conn *cp, char *data, int data_len);

// node
static int sysctl_node_get_path(struct sysctl_node *node, char *buf);

void sysctl_strbuf_add_node(struct strbuf *sb, struct sysctl_node *node);

const char *sysctl_log_add_node(struct sysctl_node *node);

static struct sysctl_node *sysctl_node_find_child(struct sysctl_node *node,
        const char *name, int name_len);

static int sysctl_node_add(struct log *log, const char *path, int mode,
	void *udata, void (*free_fn)(void *), sysctl_node_f fn,
	struct sysctl_node **pnode);

static void sysctl_node_del(struct log *log, struct sysctl_node *node);

static int sysctl_node_process(struct log *log,
	struct sysctl_node *node, char *tail, int load,
	const char *new, struct strbuf *out);

static int sysctl_node_process_dir(struct sysctl_node *node,
	const char *tail, struct strbuf *out);

static int sysctl_node_process_leaf(struct log *log,
	struct sysctl_node *node, const char *new, struct strbuf *out);

static int sysctl_node_process_list(struct sysctl_node *node,
	const char *tail, const char *new, struct strbuf *out);

static int sysctl_node_process_int(struct log *log, void *udata,
	const char *new, struct strbuf *out);

static int sysctl_node_set_has_subscribers(struct log *log,
	const char *path);

// req
static int sysctl_cb(struct log *log, void *udata, int eno, char *old);

static int sysctl_send_req(struct log *log, struct sysctl_conn **cpp,
	int pid, const char *path, void *udata, sysctl_f fn, const char *new);

// add
static int sysctl_add6(struct log *log, const char *path,
	int mode, void *udata, void (*free_fn)(void *), sysctl_node_f fn,
	struct sysctl_node **pnode);

static int sysctl_find(struct log *, const char *,
	struct sysctl_node **, char **);

static int sysctl_node_alloc(struct log *, struct sysctl_node **,
	struct sysctl_node *, const char *, int);

static int
sysctl_is_valid_token(const char *s)
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

static void
sysctl_init_sockaddr_un(struct sockaddr_un *addr, int pid)
{
	addr->sun_family = AF_UNIX;
	snprintf(addr->sun_path, sizeof(addr->sun_path),
	         "%s/sock/%d.sock", GT_PREFIX, pid);
}

int
sysctl_mod_init(struct log *log, void **pp)
{
	int rc;
	struct sysctl_mod *mod;
	LOG_TRACE(log);
	rc = sysctl_node_alloc(log, &sysctl_root, NULL, NULL, 0);
	if (rc)
		return rc;
	sysctl_root->n_is_added = 1;
	rc = mm_alloc(log, pp, sizeof(*mod));
	if (rc)
		return rc;
	mod = *pp;
	log_scope_init(&mod->log_scope, "ctl");
	return 0;
}

int
sysctl_mod_attach(struct log *log, void *raw_mod)
{
	current_mod = raw_mod;
	return 0;
}

void
sysctl_mod_deinit(struct log *log, void *raw_mod)
{
	struct sysctl_mod *mod;
	LOG_TRACE(log);
	mod = raw_mod;
	log_scope_deinit(log, &mod->log_scope);
	mm_free(mod);
}

void
sysctl_mod_detach(struct log *log)
{
	LOG_TRACE(log);
	sysctl_node_del(log, sysctl_root);
	sysctl_root = NULL;
	current_mod = NULL;
}

static int
sysctl_process_line(struct log *log, char *s)
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
		new = gt_trim(new + 1);
	}
	path = gt_trim(s);
	rc = sysctl_in(log, path, 1, new, NULL);
	return rc;
}


int
sysctl_read_file(struct log *log, const char *path)
{
	int rc, line;
	const char *tmp;
	char path_buf[PATH_MAX];
	char str[2000];
	FILE *file;

	LOG_TRACE(log);
	if (path == NULL) {
		tmp = getenv("GBTCP_CTL");
		if (tmp != NULL) { 
			rc = sys_realpath(log, tmp, path_buf);
			if (rc) {
				return rc;
			}
		} else {
			snprintf(path_buf, sizeof(path_buf), "%s/ctl/%s.conf",
			         GT_PREFIX, gt_application_name);
		}
		tmp = path_buf;
	} else {
		tmp = path;
	}
	rc = sys_fopen(log, &file, tmp, "r");
	if (rc) {
		return rc;
	}
	rc = 0;
	line = 0;
	while (fgets(str, sizeof(str), file) != NULL) {
		line++;
		rc = sysctl_process_line(log, str);
		if (rc) {
			LOGF(log, LOG_MSG(read_file), LOG_ERR, -rc,
			     "bad line; file='%s', line=%d",
			     path, line);
		}
	}
	fclose(file);
	LOGF(log, LOG_MSG(read_file), LOG_INFO, 0, "ok; file='%s'", path);
	return rc;
}

int
usysctl(struct log *log, int pid, const char *path,
	char *old, int cnt, const char *new)
{
	int rc;
	struct sysctl_conn *cp;
	struct sysctl_wait wait;

	wait.w_eno = EINPROGRESS;
	wait.w_old = old;
	wait.w_cnt = cnt;
	rc = sysctl_send_req(log, &cp, pid, path,
	                     &wait, sysctl_cb, new); 
	if (rc == 0) {
		while (wait.w_eno == EINPROGRESS) {
			gt_fd_event_mod_wait();
		}
		rc = -wait.w_eno;
	}
	return rc;
}

int
usysctl_r(struct log *log, int pid, const char *path,
         void *udata, sysctl_f fn, const char *new)
{
	int rc;
	rc = sysctl_send_req(log, NULL, pid, path, udata, fn, new);
	return rc;
}

int
sysctl_me(struct log *log, const char *path,
	const char *new, struct strbuf *old)
{
	int rc;

	ASSERT(path != NULL);
	ASSERT(sysctl_is_valid_token(path));
	ASSERT(new == NULL || sysctl_is_valid_token(new));
	LOG_TRACE(log);
	rc = sysctl_in(log, path, 0, new, old);
	return rc;
}

int
sysctl_get_pids(int *pids, int cnt)
{
	const char *path;
	int n, rc, fd, pid;
	DIR *dir;
	struct dirent *entry;
	struct sockaddr_un addr;
	struct log *log;

	log = log_trace0();
	path = GT_PREFIX"/sock";
	rc = sys_opendir(log, &dir, path);
	if (rc) {
		return rc;
	}
	n = 0;
	while ((entry = readdir(dir)) != NULL) {
		rc = sscanf(entry->d_name, "%d.sock", &pid);
		if (rc != 1)
			continue;
		sysctl_init_sockaddr_un(&addr, pid);
		rc = sys_socket(log, AF_UNIX, SOCK_STREAM, 0);
		if (rc < 0) {
			goto err;
		}
		fd = rc;
		rc = gt_connect_timed(log, fd, (struct sockaddr *)&addr,
		                      sizeof(addr), 2 * GT_SEC);
		sys_close(log, fd);
		switch (-rc) {
		case 0:
			if (n == cnt) {
				break;
			}
			pids[n++] = pid;
			break;
		case ECONNREFUSED:
			unlink(addr.sun_path);
			break;
		default:
			goto err;
		}
	}
	closedir(dir);
	return n;
err:
	closedir(dir);
	return rc;
}

int
sysctl_bind(struct log *log, int pid)
{
	int rc;
	LOG_TRACE(log);
	if (sysctl_binded != NULL) {
		LOGF(log, LOG_MSG(bind), LOG_ERR, 0, "already");
		return -EALREADY;
	}
	rc = sysctl_conn_listen(log, &sysctl_binded, pid);
	if (rc) {
		return rc;
	}
	if (pid == 0) {
		sysctl_node_set_has_subscribers(log, GT_CTL_ROUTE_ROUTE_ADD);
		sysctl_node_set_has_subscribers(log, GT_CTL_ROUTE_ROUTE_DEL);
		sysctl_node_set_has_subscribers(log, GT_CTL_ROUTE_IF_ADD);
		sysctl_node_set_has_subscribers(log, GT_CTL_ROUTE_IF_DEL);
		sysctl_node_set_has_subscribers(log, GT_CTL_ROUTE_ADDR_ADD);
		sysctl_node_set_has_subscribers(log, GT_CTL_ROUTE_ADDR_DEL);
	}
	return 0;
}

void
sysctl_unbind()
{
	if (sysctl_binded != NULL) {
		sysctl_conn_close(sysctl_binded, ECONNRESET);
		sysctl_binded = NULL;
	}
}

int
sysctl_binded_pid(struct log *log)
{
	if (sysctl_binded == NULL) {
		if (log != NULL) {
			LOG_TRACE(log);
			LOGF(log, 7, LOG_ERR, 0, "not binded");
		}
		return -EBADF;
	} else {
		return sysctl_binded->c_pid;
	}
}

 int
sysctl_sub(struct log *log, void (*close_fn)())
{
	int rc, pid;

	rc = sysctl_binded_pid(log);
	if (rc < 0) {
		return rc;
	}
	pid = rc;
	if (sysctl_publisher == NULL) {
		rc = sysctl_conn_connect(log, &sysctl_publisher, 0, "sub");
		if (rc) {
			return rc;
		}
	}
	strbuf_addf(&sysctl_publisher->c_sndbuf, "sub %d\n", pid);
	rc = sysctl_conn_send(log, sysctl_publisher);
	if (rc == 0) {
		sysctl_publisher->c_close_fn = sysctl_publisher_close_mediator;
		sysctl_publisher_close_fn = close_fn;
	} else {
		sysctl_unsub1(-rc);
	}
	return rc;
}

void
sysctl_unsub(struct log *log, int pid)
{
	int i;
	struct sysctl_conn *cp;

	for (i = 0; i < sysctl_nr_subscribers; ++i) {
		cp = sysctl_subscribers[i];
		if (cp->c_pid == pid) {
			sysctl_conn_close(cp, ECONNRESET);
			return;
		}
	}
}

void
sysctl_unsub_me()
{
	if (sysctl_publisher != NULL) {
		sysctl_unsub1(ECONNRESET);
	}
}

int
sysctl_sync(struct log *log, const char *path)
{
	int rc, len;
	char *plus;
	char buf[GT_SYSCTL_BUFSIZ];
	char path_buf[PATH_MAX];
	struct strbuf sb;
	struct sysctl_node *node, *parent, *add;

	LOG_TRACE(log);
	rc = sysctl_find(log, path, &node, NULL);
	if (rc) {
		return rc;
	}
	if (strcmp(node->n_name, "list")) {
		rc = usysctl(log, 0, path, buf, sizeof(buf), NULL);
		if (rc < 0) {
			return rc;
		}
		rc = sysctl_node_process(log, node, NULL, 0, buf, NULL);
		return rc;
	}
	/* Sync list */
	parent = node->n_parent;
	add = sysctl_node_find_child(parent, STRSZ("add"));
	if (add == NULL) {
		LOGF(log, 7, LOG_ERR, 0, "node not exists; path='%s.add'",
		     sysctl_log_add_node(parent));
		return -ENOENT;
	}
	strbuf_init(&sb, path_buf, sizeof(path_buf));
	strbuf_add_str(&sb, path);
	len = sb.sb_len;
	while (1) {
		plus = strbuf_cstr(&sb);
		rc = usysctl(log, 0, plus, buf, sizeof(buf), NULL);
		if (rc < 0) {
			return rc;
		} else if (rc > 0) {
			LOGF(log, 7, LOG_ERR, rc, "list err; path='%s'", plus);
		} else if (buf[0] == '\0') {
			return 0;
		} else if (buf[0] != ',') {
			LOGF(log, 7, LOG_ERR, 0,
			     "list invalid rpl; path='%s', reply='%s'",
			     plus, buf);
			return -EPROTO;
		}
		sb.sb_len = len;
		strbuf_addf(&sb, ".%s", buf + 1);
		rc = usysctl(log, 0, strbuf_cstr(&sb), buf, sizeof(buf), NULL);
		if (rc < 0) {
			if (rc != -ENOENT)
				return rc;
		} else {
			rc = sysctl_node_process(log, add, NULL, 0, buf, NULL);
			if (rc)
				return rc;
		}
		strbuf_add_ch(&sb, '+');
	}
}

int
sysctl_syncf(struct log *log, const char *fmt, ...)
{
	int rc;
	va_list ap;
	char path[PATH_MAX];

	va_start(ap, fmt);
	vsnprintf(path, sizeof(path), fmt, ap);
	va_end(ap);
	rc = sysctl_sync(log, path);
	return rc;
}

void
sysctl_add(struct log *log, const char *path, int mode, void *udata,
	void (*free_fn)(void *), sysctl_node_f fn)
{
	struct sysctl_node *node;
	sysctl_add6(log, path, mode, udata, free_fn, fn, &node);
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
	data->sld_next_fn = next_fn;
	data->sld_fn = fn;
}

int
sysctl_del(struct log *log, const char *path)
{
	int rc;
	struct sysctl_node *node;
	LOG_TRACE(log);
	rc = sysctl_find(log, path, &node, NULL);
	if (rc == 0)
		sysctl_node_del(log, node);
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


static int
sysctl_split_path(struct log *log, int log_msg_level,
	const char *path, struct iovec *iovec)
{
	int i, rc;

	rc = gt_strsplit(path, ".", iovec, GT_CTL_DEPTH_MAX);
	if (rc > GT_CTL_DEPTH_MAX) {
		LOGF(log, log_msg_level, LOG_ERR, 0,
		     "too many dirs; path='%s'", path);
		return -ENAMETOOLONG;
	}
	for (i = 0; i < rc; ++i) {
		if (iovec[i].iov_len >= GT_CTL_NODE_NAME_MAX) {
			LOGF(log, log_msg_level, LOG_ERR, 0,
			     "too long dir; path='%s', idx=%d", path, i);
			return -ENAMETOOLONG;
		}
	}
	return rc;
}

static int
sysctl_conn_fd(struct sysctl_conn *cp)
{
	return cp->c_event->fde_fd;
}

static void
sysctl_conn_set_log(struct sysctl_conn *cp, struct log *log)
{
	cp->c_log = log_copy(cp->c_log_stack,
	                     ARRAY_SIZE(cp->c_log_stack), log);
}

static int
sysctl_conn_open(struct log *log,
	struct sysctl_conn **cpp, int fd, const char *path)
{
	int rc, opt;
	char name[PATH_MAX];
	struct sysctl_conn *cp;

	LOG_TRACE(log);
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
	rc = gt_set_nonblock(log, fd);
	if (rc < 0) {
		return rc;
	}
	rc = sys_malloc(log, (void **)&cp, sizeof(*cp));
	if (rc < 0) {
		return rc;
	}
	cp->c_log = NULL;
	cp->c_req_fn = NULL;
	cp->c_close_fn = NULL;
	cp->c_pid = -1;
	snprintf(name, sizeof(name), "ctl.%d.%s", fd, path);
	gt_timer_init(&cp->c_timer);
	rc = gt_fd_event_new(log, &cp->c_event, fd, name,
	                     sysctl_conn_process_events, cp);
	if (rc < 0) {
		free(cp);
		return rc;
	}
	strbuf_init(&cp->c_rcvbuf, cp->c_rcvbuf_buf,
	            sizeof(cp->c_rcvbuf_buf));
	strbuf_init(&cp->c_sndbuf, cp->c_sndbuf_buf,
	            sizeof(cp->c_sndbuf_buf));
	gt_fd_event_set(cp->c_event, POLLIN);
	*cpp = cp;
	LOGF(log, LOG_MSG(open), LOG_INFO, 0, "ok; fd=%d, path='%s'", fd, path);
	return 0;
}

static void
sysctl_conn_close(struct sysctl_conn *cp, int eno)
{
	struct log *log;

	log = log_trace(cp->c_log);
	LOGF(log, LOG_MSG(close), LOG_INFO, eno, "hit; fd=%d", sysctl_conn_fd(cp));
	sysctl_req_done(cp, eno, NULL);
	if (cp->c_close_fn != NULL) {
		(*cp->c_close_fn)(cp);
	}
	sys_close(log, sysctl_conn_fd(cp));
	gt_fd_event_del(cp->c_event);
	free(cp);
}

static int
sysctl_conn_connect(struct log *log, struct sysctl_conn **cpp,
	int pid, const char *path)
{
	int fd, rc;
	struct sockaddr_un addr;
	struct sysctl_conn *cp;

	LOG_TRACE(log);
	rc = sys_socket(log, AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
	if (rc < 0)
		return rc;
	fd = rc;
	sysctl_init_sockaddr_un(&addr, pid);
	rc = gt_connect_timed(log, fd, (struct sockaddr *)&addr,
	                      sizeof(addr), 2 * GT_SEC);
	if (rc < 0) {
		sys_close(log, fd);
		return rc;
	}
	rc = sysctl_conn_open(log, cpp, fd, path);
	if (rc < 0) {
		sys_close(log, fd);
		return rc;
	}
	cp = *cpp;
	cp->c_type = GT_CTL_CONN_CLIENT;
	cp->c_pid = pid;
	return 0;
}

static int
sysctl_conn_listen(struct log *log, struct sysctl_conn **cpp, int pid)
{
	int rc, fd;
	struct sockaddr_un addr;
	struct stat stat;
	struct group *group;
	struct sysctl_conn *cp;

	LOG_TRACE(log);
	rc = sys_socket(log, AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	sysctl_init_sockaddr_un(&addr, pid);
	unlink(addr.sun_path);
	rc = sys_bind(log, fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0) {
		sys_close(log, fd);
		return rc;
	}
	rc = sys_getgrnam(log, GT_GROUP_NAME, &group);
	if (rc == 0) {
		sys_chown(log, addr.sun_path, -1, group->gr_gid);
	}
	rc = sys_stat(log, addr.sun_path, &stat);
	if (rc == 0) {
		sys_chmod(log, addr.sun_path,
		             stat.st_mode|S_IRGRP|S_IWGRP|S_IXGRP);
	}
	rc = sys_listen(log, fd, 5);
	if (rc < 0) {
		sys_close(log, fd);
		return rc;
	}
	rc = sysctl_conn_open(log, cpp, fd, "listen");
	if (rc < 0) {
		sys_close(log, fd);
	} else {
		cp = *cpp;
		cp->c_type = GT_CTL_CONN_LISTEN;
		cp->c_pid = pid;
		sysctl_conn_set_log(cp, log);
	}
	return rc;
}

static int
sysctl_conn_accept(struct sysctl_conn *lp)
{
	int rc, fd, lfd;
	socklen_t addrlen;
	struct sockaddr_un addr;
	struct log *log;
	struct sysctl_conn *cp;

	log = log_trace(lp->c_log);
	addrlen = sizeof(addr);
	lfd = sysctl_conn_fd(lp);
	rc = sys_accept4(log, lfd,
	                 (struct sockaddr *)&addr, &addrlen,
	                 SOCK_NONBLOCK|SOCK_CLOEXEC);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	rc = sysctl_conn_open(log, &cp, fd, "accept");
	if (rc < 0) {
		sys_close(log, fd);
	} else {
		cp->c_type = GT_CTL_CONN_SERVER;
	}
	return rc;
}

static int
sysctl_conn_recv(struct sysctl_conn *cp)
{
	int rc, fd, off, n, m;
	struct log *log;

	log = log_trace(cp->c_log);
	fd = sysctl_conn_fd(cp);
	do {
		off = cp->c_rcvbuf.sb_len;
		n = strbuf_space(&cp->c_rcvbuf);
		ASSERT(n);
		rc = sys_read(log, fd, cp->c_rcvbuf.sb_buf + off, n);
		if (rc < 0) {
			if (rc == -EAGAIN) {
				return 0;
			} else {
				return rc;
			}
		} else if (rc == 0) {
			LOGF(log, LOG_MSG(recv), LOG_INFO, 0, "done");
			return -ECONNRESET;
		} else {
			cp->c_rcvbuf.sb_len += rc;
			rc = sysctl_conn_in(cp, off);
			if (rc < 0) {
				return rc;
			}
			m = strbuf_space(&cp->c_rcvbuf);
			if (m == 0) {
				LOGF(log, LOG_MSG(recv), LOG_ERR, 0,
				     "too long msg");
				return -EPROTO;
			}
		}
	} while (rc == n);
	return 0;
}

static int
sysctl_conn_send(struct log *log, struct sysctl_conn *cp)
{
	int rc, fd;
	struct strbuf *b;

	LOG_TRACE(log);
	b = &cp->c_sndbuf;
	rc = gt_fd_event_is_set(cp->c_event, POLLOUT);
	if (rc) {
		// Already sending data - socket buffer is full
		return 0;
	}
	if (b->sb_len == 0) {
		return 0;
	}
	fd = sysctl_conn_fd(cp);
	rc = sys_send(log, fd, b->sb_buf, b->sb_len, MSG_NOSIGNAL);
	if (rc < 0) {
		return rc;
	}
	strbuf_remove(b, 0, rc);
	if (b->sb_len) {
		gt_fd_event_set(cp->c_event, POLLOUT);
	}
	return 0;
}

static int
sysctl_conn_send_cmd(struct log *log, struct sysctl_conn *cp,
	const char *cmd, const char *path, int path_len,
	const char *new, int new_len)
{
	int rc, len;

	LOG_TRACE(log);
	len = cp->c_sndbuf.sb_len;
	strbuf_addf(&cp->c_sndbuf, "%s %.*s %.*s\n",
	            cmd, path_len, path, new_len, new);
	if (strbuf_space(&cp->c_sndbuf) == 0) {
		cp->c_sndbuf.sb_len = len;
		LOGF(log, LOG_MSG(send), LOG_ERR, 0,
		     "too long msg; path='%.*s'", path_len, path);
		return -ENOBUFS;
	}
	rc = sysctl_conn_send(log, cp);
	return rc;
}

static int
sysctl_conn_process_events(void *udata, short revents)
{
	int rc;
	struct sysctl_conn *cp;

	cp = udata;
	if (cp->c_type == GT_CTL_CONN_LISTEN) {
		if (revents & POLLIN) {	
			do {
				rc = sysctl_conn_accept(cp);
			} while (rc == 0);
		}
	} else if (revents & POLLIN) {
		rc = sysctl_conn_recv(cp);
		if (rc < 0) {
			sysctl_conn_close(cp, -rc);
		}
	} else if (revents & POLLOUT) {
		gt_fd_event_clear(cp->c_event, POLLOUT);
		rc = sysctl_conn_send(NULL, cp);
		if (rc < 0) {
			sysctl_conn_close(cp, -rc);
		}
	}
	return 0;
}

static int
sysctl_conn_in(struct sysctl_conn *cp, int off)
{
	int rc;
	struct strbuf *b;

	b = &cp->c_rcvbuf;
	rc = sysctl_conn_in_first(cp, b->sb_buf, off, b->sb_len);
	if (rc <= 0) {
		return rc;
	}
	off = rc;
	rc = sysctl_conn_in_next(cp, b->sb_buf + off, b->sb_len - off);
	if (rc < 0) {
		return rc;
	}
	off += rc;
	strbuf_remove(b, 0, off);
	return 0;
}

static int
sysctl_conn_in_first(struct sysctl_conn *cp, char *buf, int off, int cnt)
{
	int rc;
	char *ptr;

	ptr = memchr(buf + off, '\n', cnt - off);
	if (ptr == NULL) {
		return 0;
	}
	rc = sysctl_in_pdu(cp, buf, ptr - buf);
	if (rc < 0) {
		return rc;
	} else {
		return ptr - buf + 1;
	}
}

static int
sysctl_conn_in_next(struct sysctl_conn *cp, char *buf, int cnt)
{
	int rc, off, len;
	char *ptr;

	for (off = 0; off < cnt; off += len + 1) {
		ptr = memchr(buf + off, '\n', cnt - off);
		if (ptr == NULL) {
			break;
		}
		len = ptr - (buf + off);
		rc = sysctl_in_pdu(cp, buf + off, len);
		if (rc < 0) {
			return rc;
		}
	}
	return off;
}

static void
sysctl_req_done(struct sysctl_conn *cp, int eno, char *old)
{
	int rc;
	gt_timer_del(&cp->c_timer);
	if (cp->c_req_fn != NULL) {
		rc = (*cp->c_req_fn)(cp->c_log, cp->c_req_udata, eno, old);
		if (rc) {
			LOGF(cp->c_log, LOG_MSG(req_done), LOG_ERR, -rc,
			     "callback failed");
		}
		cp->c_req_fn = NULL;
	}
}

static void
sysctl_req_timo(struct gt_timer *timer)
{
	struct log *log;
	struct sysctl_conn *cp;

	cp = container_of(timer, struct sysctl_conn, c_timer);
	log = log_trace(cp->c_log);
	LOGF(log, LOG_MSG(req_timo), LOG_ERR, 0,
	     "timedout; timer=%p, dt=%"PRIu64"us",
	     &cp->c_timer, gt_nsec - cp->c_req_time);
	sysctl_conn_close(cp, ETIMEDOUT);
}

static void
sysctl_handle_sub(struct sysctl_conn *cp, int action)
{
	if (sysctl_sub_fn != NULL) {
		(*sysctl_sub_fn)(cp->c_pid, action);
	}
}

static void
sysctl_subscriber_close_cb(struct sysctl_conn *cp)
{
	int i;
	struct sysctl_conn *tmp;

	for (i = 0; i < sysctl_nr_subscribers; ++i) {
		if (sysctl_subscribers[i] == cp) {
			tmp = sysctl_subscribers[sysctl_nr_subscribers - 1];
			sysctl_subscribers[i] = tmp;
			sysctl_nr_subscribers--;
			sysctl_handle_sub(cp, GT_CTL_UNSUB);
			return;
		}
	}
}

static void
sysctl_publisher_close_mediator(struct sysctl_conn *cp)
{
	sysctl_publisher = NULL;
	if (sysctl_publisher_close_fn != NULL) {
		(*sysctl_publisher_close_fn)();
	}
}

static void
sysctl_publish(struct log *log, struct sysctl_node *node,
	const char *new, int new_len)
{
	int i, rc, path_len;
	char path[PATH_MAX];
	struct sysctl_conn *cp;

	LOG_TRACE(log);
	path_len = 0;
	for (i = 0; i < sysctl_nr_subscribers;) {
		if (path_len == 0) {
			path_len = sysctl_node_get_path(node, path);
		}
		cp = sysctl_subscribers[i];
		rc = sysctl_conn_send_cmd(log, cp, "pub",
		                          path, path_len, new, new_len);
		if (rc) {
			sysctl_conn_close(cp, -rc);
		} else {
			++i;
		}
	}
}

static void
sysctl_unsub1(int errnum)
{
	sysctl_conn_close(sysctl_publisher, errnum);
	sysctl_publisher = NULL;
}

static int
sysctl_in(struct log *log, const char *path, int load,
          const char *new, struct strbuf *out)
{
	int rc;
	char *tail;
	struct sysctl_node *node;

	LOG_TRACE(log);
	rc = sysctl_find(log, path, &node, &tail);
	if (rc == 0)
		rc = sysctl_node_process(log, node, tail, load, new, out);
	return rc;
}


static int
sysctl_in_req(struct sysctl_conn *cp, char **argv)
{
	int rc;
	const char *path;
	struct strbuf *b;
	struct log *log;

	log = log_trace(cp->c_log);
	path = argv[1];
	if (path == NULL) {
		path = "";
	}
	b = &cp->c_sndbuf;
	strbuf_add_str(b, "rpl ");
	rc = sysctl_in(log, path, 0, argv[2], b);
	if (rc) {
		strbuf_addf(b, " error %d", -rc);
	}
	strbuf_add_ch(b, '\n');
	if (strbuf_space(b) == 0) {
		LOGF(log, LOG_MSG(in), LOG_ERR, 0,
		     "too long msg; path='%s'", path);
		return -ENOBUFS;
	}
	rc = sysctl_conn_send(cp->c_log, cp);
	return rc;
}

static int
sysctl_in_rpl(struct sysctl_conn *cp, char **argv)
{
	char *old, *endptr;
	int errnum;
	struct log *log;

	log = log_trace(cp->c_log);
	if (argv[2] == NULL) {
		old = argv[1];
		if (old == NULL) {
			old = "";
		}
		errnum = 0;
	} else {
		old = "";
		errnum = strtoul(argv[2], &endptr, 10);
		if (strcmp(argv[1], "error") || errnum == 0 || *endptr != '\0') {
			LOGF(log, LOG_MSG(in), LOG_ERR, 0,
			     "bad err fmt; fd=%d, ('%s %s')",
			     sysctl_conn_fd(cp), argv[1], argv[2]);
			return -EPROTO;
		}
	}
	sysctl_req_done(cp, errnum, old);
	LOGF(log, LOG_MSG(in), LOG_INFO, 0, "ok; fd=%d",
	     sysctl_conn_fd(cp));
	return -ECONNRESET;
}

static int
sysctl_in_pub(struct sysctl_conn *cp, char **argv)
{
	int rc, len;
	const char *path, *new;
	struct log *log;
	struct strbuf *b;

	log = log_trace(cp->c_log);
	path = argv[1];
	new = argv[2];
	if (path == NULL) {
		LOGF(log, LOG_MSG(in), LOG_ERR, 0, "no path");
		return -EPROTO;
	}
	if (new == NULL) {
		LOGF(log, LOG_MSG(in), LOG_ERR, 0, "no new; path='%s'", path);
		return -EPROTO;
	}
	b = &cp->c_sndbuf;
	len = b->sb_len;
	rc = sysctl_in(log, path, 0, new, b);
	b->sb_len = len;
	return rc;
}

static int
sysctl_in_sub(struct sysctl_conn *cp, char **argv)
{
	int i, rc, peer_pid;
	const char *a_pid;
	struct log *log;

	log = log_trace(cp->c_log);
	a_pid = argv[1];
	if (a_pid == NULL) {
		LOGF(log, LOG_MSG(in), LOG_ERR, 0, "no pid");
		return -EPROTO;
	}
	rc = sscanf(a_pid, "%d", &peer_pid);
	if (rc != 1) {
		LOGF(log, LOG_MSG(in), LOG_ERR, 0,
		     "invalid pid; pid='%s'", a_pid);
		return -EPROTO;
	}
	rc = sysctl_binded_pid(log);
	if (rc < 0) {
		return rc;
	}
	for (i = 0; i < sysctl_nr_subscribers; ++i) {
		if (sysctl_subscribers[i] == cp) {
			LOGF(log, LOG_MSG(in), LOG_ERR, 0,
			     "already subscribed");
			return -EALREADY;
		}
	}
	if (sysctl_nr_subscribers == ARRAY_SIZE(sysctl_subscribers)) {
		LOGF(log, LOG_MSG(in), LOG_ERR, 0, "too many subscribers");
		return -EOVERFLOW;
	}
	cp->c_pid = peer_pid;
	sysctl_subscribers[sysctl_nr_subscribers++] = cp;
	cp->c_close_fn = sysctl_subscriber_close_cb;
	sysctl_handle_sub(cp, GT_CTL_SUB);
	return 0;
}

static int
sysctl_in_pdu(struct sysctl_conn *cp, char *data, int data_len)
{
	int i, rc;
	char *argv[4], *tmp;
	struct iovec *token, tokens[4];
	struct log *log;

	log = log_trace(cp->c_log);
	data[data_len] = '\0'; // FIXME:
	rc = gt_strsplit(data, " \r\n\t", tokens, ARRAY_SIZE(tokens));
	if (rc > ARRAY_SIZE(tokens)) {
		LOGF(log, LOG_MSG(in), LOG_ERR, 0,
		     "too many tokens; data='%.*s'", data_len, data);
		return -EPROTO;
	}
	for (i = 0; i < rc; ++i) {
		token = tokens + i;
		tmp = token->iov_base;
		tmp[token->iov_len] = '\0';
		argv[i] = tmp;
	}
	for (; i < ARRAY_SIZE(argv); ++i) {
		argv[i] = NULL;
	}
	if (cp->c_type == GT_CTL_CONN_CLIENT) {
		if (!strcmp(argv[0], "rpl")) {
			rc = sysctl_in_rpl(cp, argv);
		} else
		if (!strcmp(argv[0], "pub")) {
			rc = sysctl_in_pub(cp, argv);
		} else {
			goto unknown_cmd;
		}
	} else {
		if (!strcmp(argv[0], "req")) {
			rc = sysctl_in_req(cp, argv);
		} else
		if (!strcmp(argv[0], "sub")) {
			rc = sysctl_in_sub(cp, argv);
		} else {
			goto unknown_cmd;
		}
	}
	return rc;
unknown_cmd:
	LOGF(log, LOG_MSG(in), LOG_ERR, 0,
	     "unknown cmd; cmd='%s'", argv[0]);
	return -EPROTO;
}

static int
sysctl_node_get_path(struct sysctl_node *node, char *buf)
{
	struct strbuf sb;

	strbuf_init(&sb, buf, PATH_MAX);
	sysctl_strbuf_add_node(&sb, node);
	ASSERT(sb.sb_len < PATH_MAX);
	strbuf_cstr(&sb);
	return sb.sb_len;
}

void
sysctl_strbuf_add_node(struct strbuf *sb, struct sysctl_node *node)
{
	int i, n;
	struct sysctl_node *path[GT_CTL_DEPTH_MAX];
	ASSERT(node != NULL);
	n = 0;
	for (; node != sysctl_root; node = node->n_parent) {
		ASSERT(node != NULL);
		ASSERT(n < ARRAY_SIZE(path));
		path[n++] = node;
	}
	for (i = n - 1; i >= 0; --i) {
		if (sb->sb_len)
			strbuf_add_ch(sb, '.');
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
sysctl_node_alloc(struct log *log, struct sysctl_node **pnode,
	struct sysctl_node *parent, const char *name, int name_len)
{
	int rc;
	struct sysctl_node *node;
	LOG_TRACE(log);
	rc = sys_malloc(log, (void **)pnode, sizeof(struct sysctl_node));
	if (rc == 0) {
		node = *pnode;
		ASSERT(name_len < GT_CTL_NODE_NAME_MAX);
		memset(node, 0, sizeof(*node));
		node->n_name_len = name_len;
		memcpy(node->n_name, name, name_len);
		node->n_name[name_len] = '\0';
		dlist_init(&node->n_children);
		node->n_parent = parent;
		if (parent != NULL)
			DLIST_INSERT_TAIL(&parent->n_children, node, n_list);
	}
	return rc;
}



static int
sysctl_find(struct log *log, const char *path,
	struct sysctl_node **pnode, char **ptail)
{
	int i, rc, name_len, path_iovcnt;
	char *name;
	struct sysctl_node *child, *node;
	struct iovec path_iov[GT_CTL_DEPTH_MAX];

	LOG_TRACE(log);
	rc = sysctl_split_path(log, LOG_MSG(find), path, path_iov);
	if (rc < 0) {
		return rc;
	}
	path_iovcnt = rc;
	node = sysctl_root;
	for (i = 0; i < path_iovcnt; ++i) {
		name = path_iov[i].iov_base;
		name_len = path_iov[i].iov_len;
		child = sysctl_node_find_child(node, name, name_len);
		if (child == NULL) {
			if (i < path_iovcnt - 1) {
				LOGF(log, LOG_MSG(find), LOG_ERR, 0,
				     "not exists; path='%s', idx=%d",
				     path, i);
				return -ENOENT;
			}
			*pnode = node;
			if (ptail == NULL) {
				LOGF(log, LOG_MSG(find), LOG_ERR, 0,
				     "not a leaf; path='%s'", path);
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

static struct sysctl_node *
sysctl_node_find_child(struct sysctl_node *node,
	const char *name, int name_len)
{
	struct sysctl_node *child;
	DLIST_FOREACH(child, &node->n_children, n_list) {
		if (child->n_name_len == name_len &&
		    !memcmp(child->n_name, name, name_len))
			return child;
	}
	return NULL;
}

static int
sysctl_node_add(struct log *log, const char *path, int mode,
	void *udata, void (*free_fn)(void *), sysctl_node_f fn,
	struct sysctl_node **pnode)
{
	int i, rc, name_len, path_len, path_iovcnt;
	char *name;
	struct iovec path_iov[GT_CTL_DEPTH_MAX];
	struct sysctl_node *child, *node;

	ASSERT(mode == SYSCTL_RD || mode == SYSCTL_LD || mode == SYSCTL_WR);
	LOG_TRACE(log);
	node = sysctl_root;
	path_len = strlen(path);
	if (path_len >= PATH_MAX) {
		LOGF(log, LOG_MSG(add), LOG_ERR, 0, 
		     "too long path; path='%s'", path);
		return -EINVAL;
	}
	rc = sysctl_split_path(log, LOG_MSG(add), path, path_iov);
	if (rc < 0)
		return rc;
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
			LOGF(log, LOG_MSG(add), LOG_ERR, 0,
			     "already exists; path='%s'", path);
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
	LOGF(log, LOG_MSG(add), LOG_INFO, 0, "ok; node='%s'", path);
	return 0;
}

static void
sysctl_node_del(struct log *log, struct sysctl_node *node)
{
	struct sysctl_node *child;
	LOGF(log, LOG_MSG(del), LOG_INFO, 0, "hit; node='%s'",
	     sysctl_log_add_node(node));
	while (!dlist_is_empty(&node->n_children)) {
		child = DLIST_FIRST(&node->n_children,
		                    struct sysctl_node, n_list);
		sysctl_node_del(log, child);
	}
	DLIST_REMOVE(node, n_list);
	if (node->n_free_fn != NULL)
		(*node->n_free_fn)(node->n_udata);
	free(node);
}

static int
sysctl_node_process(struct log *log,
	struct sysctl_node *node, char *tail, int load,
	const char *new, struct strbuf *out)
{
	int rc, len;
	char buf[GT_SYSCTL_BUFSIZ];
	const char *access;
	struct strbuf stub;

	LOG_TRACE(log);
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
			LOGF(log, LOG_MSG(process), LOG_ERR, 0,
			     "%s only; path='%s', tail='%s'",
			     access, sysctl_log_add_node(node),
			     tail);
			return -EACCES;
		}
	}
	if (out == NULL) {
		strbuf_init(&stub, buf, sizeof(buf));
		out = &stub;
	}
	len = out->sb_len;
	if (node->n_is_list) {
		rc = sysctl_node_process_list(node, tail, new, out);
	} else if (node->n_fn == NULL) {
		rc = sysctl_node_process_dir(node, tail, out);
	} else {
		if (tail[0] != '\0') {
			rc = 1;
		} else {
			rc = sysctl_node_process_leaf(log, node, new, out);
		}
	}
	if (rc == 1) {
		LOGF(log, LOG_MSG(process), LOG_ERR, 0,
		     "not exists; path='%s.%s'",
		     sysctl_log_add_node(node), tail);
		return -ENOENT;
	}
	if (rc < 0)
		out->sb_len = len;
	return rc;
}

static int
sysctl_node_process_dir(struct sysctl_node *node,
	const char *tail, struct strbuf *out)
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
sysctl_node_process_leaf(struct log *log, struct sysctl_node *node,
	const char *new, struct strbuf *out)
{
	int rc, off, new_len;
	char *old;

	off = out->sb_len;
	rc = (*node->n_fn)(log, node->n_udata, new, out);
	if (rc < 0) {
		LOGF(log, LOG_MSG(process), LOG_ERR, -rc,
		     "handler failed; path='%s', new='%s'",
		     sysctl_log_add_node(node), new);
		return rc;
	}
	if (off < out->sb_cap) {
		old = strbuf_cstr(out) + off;
		rc = sysctl_is_valid_token(old);
		if (rc == 0) {
			LOGF(log, LOG_MSG(process), LOG_ERR, 0,
			     "invalid old; path='%s', old='%s'",
			     sysctl_log_add_node(node), old);
			return -EINVAL;
		}
	}	 
	if (new == NULL) {
		new_len = 0;
	} else {
		new_len = strlen(new);
	}
	if (new_len && node->n_has_subscribers) {
		sysctl_publish(log, node, new, new_len);
	}	
	return 0;
}

static int
sysctl_node_process_list(struct sysctl_node *node,
	const char *tail, const char *new, struct strbuf *out)
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
		rc = (data->sld_fn)(node->n_udata, id, new, out);
		ASSERT3(0, rc <= 0, "%s", sysctl_log_add_node(node));
		return rc;
	case '+':
		if (*(endptr + 1) != '\0') {
			return 1;
		}
		id++;
next:
		rc = (*data->sld_next_fn)(node->n_udata, id);
		if (rc >= 0) {
			strbuf_addf(out, ",%d", rc);
		}
		return 0;
	default:
		return 1;
	}
}

static int
sysctl_node_process_int(struct log *log, void *udata,
	const char *new, struct strbuf *out)
{
	int rc;
	long long x, old;
	char *endptr;
	struct sysctl_node *node;
	struct sysctl_int_data *data;

	rc = 0;
	old = 0;
	data = udata;
	LOG_TRACE(log);
	node = container_of(data, struct sysctl_node, n_udata_buf.n_int_data);
	UNUSED(node);
	if (new == NULL) {
		switch (data->sid_int_sizeof) {
		case 0:
			rc = (*data->sid_ptr_intfn)(NULL, &old);
			break;
		case 4:
			old = *data->sid_ptr_int32;
			break;
		case 8:
			old = *data->sid_ptr_int64;
			break;
		default:
			BUG;
		}
	} else {
		x = strtoll(new, &endptr, 10);
		if (*endptr != '\0') {
			LOGF(log, LOG_MSG(process), LOG_ERR, 0,
			     "not an int; path='%s', new='%s'",
			     sysctl_log_add_node(node), new);
			return -EPROTO;
		}
		if (x < data->sid_min || x > data->sid_max) {
			LOGF(log, LOG_MSG(process), LOG_ERR, 0,
			     "not in range; path='%s', new=%lld, range=[%lld, %lld]",
			     sysctl_log_add_node(node), x,
			     data->sid_min, data->sid_max);
			return -ERANGE;
		}
		switch (data->sid_int_sizeof) {
		case 0:
			rc = (*data->sid_ptr_intfn)(&x, &old);
			break;
		case 4:
			old = *data->sid_ptr_int32;
			*data->sid_ptr_int32 = x;
			break;
		case 8:
			old = *data->sid_ptr_int64;
			*data->sid_ptr_int64 = x;
			break;
		default:
			BUG;
		}
	}
	strbuf_addf(out, "%lld", old);
	return rc;
}

static int
sysctl_node_set_has_subscribers(struct log *log, const char *path)
{
	int rc;
	struct sysctl_node *node;

	rc = sysctl_find(log, path, &node, NULL); 
	ASSERT3(-rc, rc == 0, "node_set_has_subscribers('%s') failed", path);
	node->n_has_subscribers = 1;
	return rc;
}

static int
sysctl_cb(struct log *log, void *udata, int eno, char *old)
{
	int len;
	struct sysctl_wait *wait;

	wait = udata;
	wait->w_eno = eno;
	if (eno == 0 && wait->w_cnt) {
		len = strnlen(old, wait->w_cnt - 1);
		memcpy(wait->w_old, old, len);
		wait->w_old[len] = '\0';
	}
	return 0;
}

static int
sysctl_send_req(struct log *log, struct sysctl_conn **cpp,
	int pid, const char *path, void *udata, sysctl_f fn, const char *new)
{
	int rc, path_len, new_len;
	struct sysctl_conn *cp;

	LOG_TRACE(log);
	ASSERT3(0, sysctl_binded_pid(NULL) != pid, "pid=%d", pid);
	ASSERT(path != NULL);
	path_len = strlen(path);
	if (path_len >= PATH_MAX) {
		LOGF(log, LOG_MSG(send), LOG_ERR, 0 ,
		     "too long path; path='%s'", path);
		return -EINVAL;
	}
	rc = sysctl_is_valid_token(path);
	if (rc == 0) {
		LOGF(log, LOG_MSG(send), LOG_ERR, 0,
		     "invalid path; path='%s'", path);
		return -EINVAL;
	}
	if (new == NULL) {
		new_len = 0;
	} else {
		new_len = strlen(new);
		rc = sysctl_is_valid_token(new);
		if (rc == 0) {
			LOGF(log, LOG_MSG(send), LOG_ERR, 0,
			     "invalid new; new='%s'", new);
			return -EINVAL;
		}
	}
	rc = sysctl_conn_connect(log, &cp, pid, path);
	if (rc)
		return rc;
	sysctl_conn_set_log(cp, log);
	rc = sysctl_conn_send_cmd(log, cp, "req", path, path_len,
	                          new, new_len);
	if (rc) {
		sysctl_conn_close(cp, -rc);
		return rc;
	}
	strzcpy(cp->c_req_path, path, sizeof(cp->c_req_path));
	cp->c_req_udata = udata;
	cp->c_req_fn = fn;
	cp->c_req_time = gt_nsec;
	gt_timer_set(&cp->c_timer, 5 * GT_SEC, sysctl_req_timo);
	if (cpp != NULL) {
		*cpp = cp;
	}
	return 0;
}

static int
sysctl_add6(struct log *log, const char *path,
	int mode, void *udata, void (*free_fn)(void *), sysctl_node_f fn,
	struct sysctl_node **pnode)
{
	int rc;

	rc = sysctl_node_add(log, path, mode, udata, free_fn, fn, pnode);
	ASSERT3(-rc, rc == 0, "ctl_add('%s') failed", path);
	return rc;
}

static void
sysctl_add_int_union(struct log *log, const char *path,
	int mode, void *ptr, int int_sizeof, int64_t min, int64_t max)
{
	struct sysctl_int_data *data;
	struct sysctl_node *node;

	ASSERT(min <= max);
	sysctl_add6(log, path, mode, NULL, NULL,
	            sysctl_node_process_int, &node);
	data = &node->n_udata_buf.n_int_data;
	node->n_udata = data;
	data->sid_ptr = ptr;
	data->sid_min = min;
	data->sid_max = max;
	data->sid_int_sizeof = int_sizeof;
	data->sid_ptr = ptr;
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
