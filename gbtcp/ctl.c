#include "ctl.h"
#include "log.h"
#include "sys.h"
#include "timer.h"
#include "strbuf.h"
#include "gbtcp.h"
#include "fd_event.h"

#define GT_CTL_DEPTH_MAX 32
#define GT_CTL_NODE_NAME_MAX 128

#define GT_CTL_LOG_NODE_FOREACH(x) \
	x(mod_deinit) \
	x(read_file) \
	x(split_path) \
	x(binded_pid) \
	x(open) \
	x(close) \
	x(connect) \
	x(listen) \
	x(accept) \
	x(recv) \
	x(send) \
	x(req) \
	x(in) \
	x(in_req) \
	x(in_rpl) \
	x(in_sub) \
	x(in_pub) \
	x(add) \
	x(del) \
	x(new) \
	x(find) \
	x(sync) \
	x(process) \
	x(process_int) \
	x(bind) \
	x(unsub) \
	x(get_pids) \
	x(me) \
	x(publish) \

enum {
	GT_CTL_CONN_UNDEF,
	GT_CTL_CONN_LISTEN,
	GT_CTL_CONN_CLIENT,
	GT_CTL_CONN_SERVER,
};

struct gt_ctl_conn;

typedef void (*gt_ctl_conn_close_f)(struct gt_ctl_conn *);

struct gt_ctl_conn {
	int c_pid;
	int c_type;
	void *c_req_udata;
	gt_ctl_f c_req_fn;
	gt_ctl_conn_close_f c_close_fn;
	struct gt_fd_event *c_event;
	struct gt_timer c_timer;
	struct gt_strbuf c_rcvbuf;
	struct gt_strbuf c_sndbuf;
	gt_time_t c_req_time;
	struct gt_log *c_log;
	struct gt_log c_log_stack[GT_LOG_STACK_SIZE];
	char c_req_path[PATH_MAX];
	char c_rcvbuf_buf[GT_CTL_BUFSIZ];
	char c_sndbuf_buf[GT_CTL_BUFSIZ];
};

struct gt_ctl_int_data {
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

struct gt_ctl_list_data {
	gt_ctl_list_next_f sld_next_fn;
	gt_ctl_list_f sld_fn;
};

struct gt_ctl_wait {
	char *w_old;
	int w_cnt;
	int w_eno;
};

struct gt_ctl_node {
	struct gt_list_head n_list;
	struct gt_list_head n_children;
	struct gt_ctl_node *n_parent;
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
	gt_ctl_node_f n_fn;
	void (*n_free_fn)(void *);
	char n_name[GT_CTL_NODE_NAME_MAX];
	union {
		struct gt_ctl_int_data n_int_data;
		struct gt_ctl_list_data n_list_data;
	} n_udata_buf;
};

static struct gt_ctl_node gt_ctl_root;
static struct gt_ctl_conn *gt_ctl_binded;
static struct gt_ctl_conn *gt_ctl_publisher;
static struct gt_ctl_conn *gt_ctl_subscribers[GT_SERVICES_MAX];
static int gt_ctl_nr_subscribers;
gt_ctl_sub_f gt_ctl_sub_fn;
static void (*gt_ctl_publisher_close_fn)();
static struct gt_log_scope this_log;
GT_CTL_LOG_NODE_FOREACH(GT_LOG_NODE_STATIC);

static int gt_ctl_process_line(struct gt_log *log, char *s);

static int gt_ctl_is_valid_str(const char *s);

static void gt_ctl_create_sockaddr_un(struct sockaddr_un *addr, int pid);

static int gt_ctl_split_path(struct gt_log *log, const char *path,
	struct iovec *path_iovec);

// conn
static int gt_ctl_conn_fd(struct gt_ctl_conn *cp);

static void gt_ctl_conn_set_log(struct gt_ctl_conn *cp, struct gt_log *log);

static int gt_ctl_conn_open(struct gt_log *log,
	struct gt_ctl_conn **cpp, int fd, const char *path);

static void gt_ctl_conn_close(struct gt_ctl_conn *cp, int eno);

static int gt_ctl_conn_connect(struct gt_log *log, struct gt_ctl_conn **cpp,
	int pid, const char *path);

static int gt_ctl_conn_listen(struct gt_log *log, 
	struct gt_ctl_conn **cpp, int pid);

static int gt_ctl_conn_accept(struct gt_ctl_conn *lp);

static int gt_ctl_conn_recv(struct gt_ctl_conn *cp);

static int gt_ctl_conn_send(struct gt_log *log, struct gt_ctl_conn *cp);

static int gt_ctl_conn_send_cmd(struct gt_log *log, struct gt_ctl_conn *cp,
	const char *cmd, const char *path, int path_len,
	const char *new, int new_len);

static int gt_ctl_conn_process_events(void *udata, short revents);

static int gt_ctl_conn_in(struct gt_ctl_conn *cp, int off);

static int gt_ctl_conn_in_first(struct gt_ctl_conn *cp,
	char *buf, int off, int cnt);

static int gt_ctl_conn_in_next(struct gt_ctl_conn *cp,
	char *buf, int cnt);

static void gt_ctl_conn_req_done(struct gt_ctl_conn *cp, int eno, char *old);

static void gt_ctl_conn_req_timeout(struct gt_timer *timer);

// pub/sub
static void gt_ctl_handle_sub(struct gt_ctl_conn *cp, int action);

static void gt_ctl_subscriber_close_cb(struct gt_ctl_conn *cp);

static void gt_ctl_publisher_close_mediator(struct gt_ctl_conn *cp);

static void gt_ctl_publish(struct gt_log *log, struct gt_ctl_node *node,
	const char *new, int new_len);

static void gt_ctl_unsub1(int eno);

// in
static int gt_ctl_in(struct gt_log *log, const char *path, int load,
	const char *new, struct gt_strbuf *out);

static int gt_ctl_in_pdu(struct gt_ctl_conn *cp, char *data, int data_len);

static int gt_ctl_in_req(struct gt_ctl_conn *cp, char **argv);

static int gt_ctl_in_rpl(struct gt_ctl_conn *cp, char **argv);

static int gt_ctl_in_pub(struct gt_ctl_conn *cp, char **argv);

static int gt_ctl_in_sub(struct gt_ctl_conn *cp, char **argv);

// node
static int gt_ctl_node_get_path(struct gt_ctl_node *node, char *buf);

void gt_ctl_gt_strbuf_add_node_path(struct gt_strbuf *sb, struct gt_ctl_node *node);

const char *gt_ctl_log_add_node_path(struct gt_ctl_node *node);

static int gt_ctl_node_alloc(struct gt_log *log, struct gt_ctl_node **pnode,
	struct gt_ctl_node *parent, const char *name, int name_len);

static void gt_ctl_node_init(struct gt_ctl_node *node,
	struct gt_ctl_node *parent, const char *name, int name_len);

static int gt_ctl_node_find(struct gt_log *log, const char *path,
	struct gt_ctl_node **pnode, char **ptail);

static struct gt_ctl_node *gt_ctl_node_find_child(struct gt_ctl_node *node,
        const char *name, int name_len);

static int gt_ctl_node_add(struct gt_log *log, const char *path, int mode,
	void *udata, void (*free_fn)(void *), gt_ctl_node_f fn,
	struct gt_ctl_node **pnode);

static void gt_ctl_node_del(struct gt_log *log, struct gt_ctl_node *node);

static void gt_ctl_node_del_children(struct gt_log *log,
	struct gt_ctl_node *node);

static int gt_ctl_node_process(struct gt_log *log,
	struct gt_ctl_node *node, char *tail, int load,
	const char *new, struct gt_strbuf *out);

static int gt_ctl_node_process_dir(struct gt_ctl_node *node,
	const char *tail, struct gt_strbuf *out);

static int gt_ctl_node_process_leaf(struct gt_log *log,
	struct gt_ctl_node *node, const char *new, struct gt_strbuf *out);

static int gt_ctl_node_process_list(struct gt_ctl_node *node,
	const char *tail, const char *new, struct gt_strbuf *out);

static int gt_ctl_node_process_int(struct gt_log *log, void *udata,
	const char *new, struct gt_strbuf *out);

static int gt_ctl_node_set_has_subscribers(struct gt_log *log,
	const char *path);

// req
static int gt_ctl_cb(struct gt_log *log, void *udata, int eno, char *old);

static int gt_ctl_send_req(struct gt_log *log, struct gt_ctl_conn **cpp,
	int pid, const char *path, void *udata, gt_ctl_f fn, const char *new);

// add
static int gt_ctl_add6(struct gt_log *log, const char *path,
	int mode, void *udata, void (*free_fn)(void *), gt_ctl_node_f fn,
	struct gt_ctl_node **pnode);

static void gt_ctl_add_int_union(struct gt_log *log, const char *path,
	int mode, void *ptr, int int_sizeof, int64_t min, int64_t max);

int
gt_ctl_mod_init()
{
	gt_ctl_node_init(&gt_ctl_root, NULL, NULL, 0);
	gt_ctl_root.n_is_added = 1;
	gt_log_scope_init_early(&this_log, "ctl");
	GT_CTL_LOG_NODE_FOREACH(GT_LOG_NODE_INIT);
	gt_log_scope_init(&this_log, "ctl");
	return 0;
}

void
gt_ctl_mod_deinit(struct gt_log *log)
{
	log = GT_LOG_TRACE(log, mod_deinit);
	gt_log_scope_deinit(log, &this_log);
	gt_ctl_node_del_children(log, &gt_ctl_root);
}

static int
gt_ctl_process_line(struct gt_log *log, char *s)
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
	rc = gt_ctl_in(log, path, 1, new, NULL);
	return rc;
}


int
gt_ctl_read_file(struct gt_log *log, const char *path)
{
	int rc, line;
	const char *tmp;
	char path_buf[PATH_MAX];
	char str[2000];
	FILE *file;

	log = GT_LOG_TRACE(log, read_file);
	if (path == NULL) {
		tmp = getenv("GBTCP_CTL");
		if (tmp != NULL) { 
			rc = gt_sys_realpath(log, tmp, path_buf);
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
	rc = gt_sys_fopen(log, &file, tmp, "r");
	if (rc) {
		return rc;
	}
	rc = 0;
	line = 0;
	while (fgets(str, sizeof(str), file) != NULL) {
		line++;
		rc = gt_ctl_process_line(log, str);
		if (rc) {
			GT_LOGF(log, LOG_ERR, -rc,
			        "bad line; file='%s', line=%d",
			        path, line);
		}
	}
	fclose(file);
	GT_LOGF(log, LOG_INFO, 0, "ok; file='%s'", path);
	return rc;
}

int
gt_ctl(struct gt_log *log, int pid, const char *path,
	char *old, int cnt, const char *new)
{
	int rc;
	struct gt_ctl_conn *cp;
	struct gt_ctl_wait wait;

	wait.w_eno = EINPROGRESS;
	wait.w_old = old;
	wait.w_cnt = cnt;
	rc = gt_ctl_send_req(log, &cp, pid, path,
	                     &wait, gt_ctl_cb, new); 
	if (rc == 0) {
		while (wait.w_eno == EINPROGRESS) {
			gt_fd_event_mod_wait();
		}
		rc = -wait.w_eno;
	}
	return rc;
}

int
gt_ctl_r(struct gt_log *log, int pid, const char *path,
         void *udata, gt_ctl_f fn, const char *new)
{
	int rc;

	rc = gt_ctl_send_req(log, NULL, pid, path, udata, fn, new);
	return rc;
}

int
gt_ctl_me(struct gt_log *log, const char *path,
	const char *new, struct gt_strbuf *old)
{
	int rc;

	GT_ASSERT(path != NULL);
	GT_ASSERT(gt_ctl_is_valid_str(path));
	GT_ASSERT(new == NULL || gt_ctl_is_valid_str(new));
	log = GT_LOG_TRACE(log, me);
	rc = gt_ctl_in(log, path, 0, new, old);
	return rc;
}

int
gt_ctl_get_pids(int *pids, int cnt)
{
	const char *path;
	int n, rc, fd, pid;
	DIR *dir;
	struct dirent *entry;
	struct sockaddr_un addr;
	struct gt_log *log;

	log = GT_LOG_TRACE1(get_pids);
	path = GT_PREFIX"/sock";
	rc = gt_sys_opendir(log, &dir, path);
	if (rc) {
		return rc;
	}
	n = 0;
	while ((entry = readdir(dir)) != NULL) {
		rc = sscanf(entry->d_name, "%d.sock", &pid);
		if (rc != 1) {
			continue;
		}
		gt_ctl_create_sockaddr_un(&addr, pid);
		rc = gt_sys_socket(log, AF_UNIX, SOCK_STREAM, 0);
		if (rc < 0) {
			goto err;
		}
		fd = rc;
		rc = gt_connect_timed(log, fd, (struct sockaddr *)&addr,
		                      sizeof(addr), 2 * GT_SEC);
		gt_sys_close(log, fd);
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
gt_ctl_bind(struct gt_log *log, int pid)
{
	int rc;

	log = GT_LOG_TRACE(log, bind);
	if (gt_ctl_binded != NULL) {
		GT_LOGF(log, LOG_ERR, 0, "already");
		return -EALREADY;
	}
	rc = gt_ctl_conn_listen(log, &gt_ctl_binded, pid);
	if (rc) {
		return rc;
	}
	if (pid == 0) {
		gt_ctl_node_set_has_subscribers(log, GT_CTL_ROUTE_ROUTE_ADD);
		gt_ctl_node_set_has_subscribers(log, GT_CTL_ROUTE_ROUTE_DEL);
		gt_ctl_node_set_has_subscribers(log, GT_CTL_ROUTE_IF_ADD);
		gt_ctl_node_set_has_subscribers(log, GT_CTL_ROUTE_IF_DEL);
		gt_ctl_node_set_has_subscribers(log, GT_CTL_ROUTE_ADDR_ADD);
		gt_ctl_node_set_has_subscribers(log, GT_CTL_ROUTE_ADDR_DEL);
	}
	return 0;
}

void
gt_ctl_unbind()
{
	if (gt_ctl_binded != NULL) {
		gt_ctl_conn_close(gt_ctl_binded, ECONNRESET);
		gt_ctl_binded = NULL;
	}
}

int
gt_ctl_binded_pid(struct gt_log *log)
{
	if (gt_ctl_binded == NULL) {
		if (log != NULL) {
			log = GT_LOG_TRACE(log, binded_pid);
			GT_LOGF(log, LOG_ERR, 0, "not binded");
		}
		return -EBADF;
	} else {
		return gt_ctl_binded->c_pid;
	}
}

 int
gt_ctl_sub(struct gt_log *log, void (*close_fn)())
{
	int rc, pid;

	rc = gt_ctl_binded_pid(log);
	if (rc < 0) {
		return rc;
	}
	pid = rc;
	if (gt_ctl_publisher == NULL) {
		rc = gt_ctl_conn_connect(log, &gt_ctl_publisher, 0, "sub");
		if (rc) {
			return rc;
		}
	}
	gt_strbuf_addf(&gt_ctl_publisher->c_sndbuf, "sub %d\n", pid);
	rc = gt_ctl_conn_send(log, gt_ctl_publisher);
	if (rc == 0) {
		gt_ctl_publisher->c_close_fn = gt_ctl_publisher_close_mediator;
		gt_ctl_publisher_close_fn = close_fn;
	} else {
		gt_ctl_unsub1(-rc);
	}
	return rc;
}

void
gt_ctl_unsub(struct gt_log *log, int pid)
{
	int i;
	struct gt_ctl_conn *cp;

	for (i = 0; i < gt_ctl_nr_subscribers; ++i) {
		cp = gt_ctl_subscribers[i];
		if (cp->c_pid == pid) {
			gt_ctl_conn_close(cp, ECONNRESET);
			return;
		}
	}
}

void
gt_ctl_unsub_me()
{
	if (gt_ctl_publisher != NULL) {
		gt_ctl_unsub1(ECONNRESET);
	}
}

int
gt_ctl_sync(struct gt_log *log, const char *path)
{
	int rc, len;
	char *plus;
	char buf[GT_CTL_BUFSIZ];
	char path_buf[PATH_MAX];
	struct gt_strbuf sb;
	struct gt_ctl_node *node, *parent, *add;

	log = GT_LOG_TRACE(log, sync);
	rc = gt_ctl_node_find(log, path, &node, NULL);
	if (rc) {
		return rc;
	}
	if (strcmp(node->n_name, "list")) {
		rc = gt_ctl(log, 0, path, buf, sizeof(buf), NULL);
		if (rc < 0) {
			return rc;
		}
		rc = gt_ctl_node_process(log, node, NULL, 0, buf, NULL);
		return rc;
	}
	/* Sync list */
	parent = node->n_parent;
	add = gt_ctl_node_find_child(parent, GT_STRSZ("add"));
	if (add == NULL) {
		GT_LOGF(log, LOG_ERR, 0, "node not exists; path='%s.add'",
		        gt_ctl_log_add_node_path(parent));
		return -ENOENT;
	}
	gt_strbuf_init(&sb, path_buf, sizeof(path_buf));
	gt_strbuf_add_str(&sb, path);
	len = sb.sb_len;
	while (1) {
		plus = gt_strbuf_cstr(&sb);
		rc = gt_ctl(log, 0, plus, buf, sizeof(buf), NULL);
		if (rc < 0) {
			return rc;
		} else if (rc > 0) {
			GT_LOGF(log, LOG_ERR, rc, "list err; path='%s'", plus);
		} else if (buf[0] == '\0') {
			return 0;
		} else if (buf[0] != ',') {
			GT_LOGF(log, LOG_ERR, 0,
			        "list invalid rpl; path='%s', reply='%s'",
			        plus, buf);
			return -EPROTO;
		}
		sb.sb_len = len;
		gt_strbuf_addf(&sb, ".%s", buf + 1);
		rc = gt_ctl(log, 0, gt_strbuf_cstr(&sb), buf, sizeof(buf), NULL);
		if (rc < 0) {
			if (rc != -ENOENT) {
				return rc;
			}
		} else {
			rc = gt_ctl_node_process(log, add, NULL, 0, buf, NULL);
			if (rc) {
				return rc;
			}
		}
		gt_strbuf_add_ch(&sb, '+');
	}
}

int
gt_ctl_syncf(struct gt_log *log, const char *fmt, ...)
{
	int rc;
	va_list ap;
	char path[PATH_MAX];

	va_start(ap, fmt);
	vsnprintf(path, sizeof(path), fmt, ap);
	va_end(ap);
	rc = gt_ctl_sync(log, path);
	return rc;
}

void
gt_ctl_add(struct gt_log *log, const char *path, int mode, void *udata,
	void (*free_fn)(void *), gt_ctl_node_f fn)
{
	struct gt_ctl_node *node;

	gt_ctl_add6(log, path, mode, udata, free_fn, fn, &node);
}

void
gt_ctl_add_intfn(struct gt_log *log, const char *path, int mode,
	int (*intfn)(const long long *, long long *), int min, int max)
{
	gt_ctl_add_int_union(log, path, mode, intfn, 0, min, max);
}

void
gt_ctl_add_int(struct gt_log *log, const char *path, int mode,
	int *ptr, int min, int max)
{
	gt_ctl_add_int_union(log, path, mode, ptr, sizeof(*ptr), min, max);
}

void
gt_ctl_add_int64(struct gt_log *log, const char *path, int mode,
	int64_t *ptr, int64_t min, int64_t max)
{
	gt_ctl_add_int_union(log, path, mode, ptr, sizeof(*ptr), min, max);
}

void
gt_ctl_add_uint64(struct gt_log *log, const char *path, int mode,
	uint64_t *ptr, int64_t min, int64_t max)
{
	gt_ctl_add_int_union(log, path, mode, ptr, sizeof(*ptr), min, max);
}

void
gt_ctl_add_list(struct gt_log *log, const char *path, int mode,
	void *udata, gt_ctl_list_next_f next_fn, gt_ctl_list_f fn)
{
	struct gt_ctl_node *node;
	struct gt_ctl_list_data *data;

	gt_ctl_add6(log, path, mode, NULL, NULL, NULL, &node);
	node->n_is_list = 1;
	data = &node->n_udata_buf.n_list_data;
	node->n_udata = udata;
	data->sld_next_fn = next_fn;
	data->sld_fn = fn;
}

int
gt_ctl_del(struct gt_log *log, const char *path)
{
	int rc;
	struct gt_ctl_node *node;

	log = GT_LOG_TRACE(log, del);
	rc = gt_ctl_node_find(log, path, &node, NULL);
	if (rc == 0) {
		gt_ctl_node_del(log, node);
	}
	return rc;
}

int
gt_ctl_delf(struct gt_log *log, const char *fmt, ...)
{
	int rc;
	va_list ap;
	char path[PATH_MAX];

	va_start(ap, fmt);
	vsnprintf(path, sizeof(path), fmt, ap);
	va_end(ap);
	rc = gt_ctl_del(log, path);
	return rc;
}

// static
static int
gt_ctl_is_valid_str(const char *s)
{
	const char *cur;

	for (cur = s; *cur != '\0'; ++cur) {
		switch (*cur) {
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
gt_ctl_create_sockaddr_un(struct sockaddr_un *addr, int pid)
{
	addr->sun_family = AF_UNIX;
	snprintf(addr->sun_path, sizeof(addr->sun_path),
	         "%s/sock/%d.sock", GT_PREFIX, pid);
}

static int
gt_ctl_split_path(struct gt_log *log, const char *path,	struct iovec *iovec)
{
	int i, rc;

	log = GT_LOG_TRACE(log, split_path);
	rc = gt_strsplit(path, ".", iovec, GT_CTL_DEPTH_MAX);
	if (rc > GT_CTL_DEPTH_MAX) {
		GT_LOGF(log, LOG_ERR, 0,
		       "too many dirs; path='%s'", path);
		return -ENAMETOOLONG;
	}
	for (i = 0; i < rc; ++i) {
		if (iovec[i].iov_len >= GT_CTL_NODE_NAME_MAX) {
			GT_LOGF(log, LOG_ERR, 0,
			        "too long dir; path='%s', idx=%d", path, i);
			return -ENAMETOOLONG;
		}
	}
	return rc;
}

static int
gt_ctl_conn_fd(struct gt_ctl_conn *cp)
{
	return cp->c_event->fde_fd;
}

static void
gt_ctl_conn_set_log(struct gt_ctl_conn *cp, struct gt_log *log)
{
	cp->c_log = gt_log_copy(cp->c_log_stack,
	                        GT_ARRAY_SIZE(cp->c_log_stack), log);
}

static int
gt_ctl_conn_open(struct gt_log *log,
	struct gt_ctl_conn **cpp, int fd, const char *path)
{
	int rc, opt;
	char name[PATH_MAX];
	struct gt_ctl_conn *cp;

	log = GT_LOG_TRACE(log, open);
	opt = GT_CTL_BUFSIZ;
	rc = gt_sys_setsockopt(log, fd, SOL_SOCKET, SO_SNDBUF,
	                       &opt, sizeof(opt));
	if (rc < 0) {
		return rc;
	}
	opt = GT_CTL_BUFSIZ;
	rc = gt_sys_setsockopt(log, fd, SOL_SOCKET, SO_RCVBUF,
	                       &opt, sizeof(opt));
	if (rc < 0) {
		return rc;
	}
	rc = gt_set_nonblock(log, fd);
	if (rc < 0) {
		return rc;
	}
	rc = gt_sys_malloc(log, (void **)&cp, sizeof(*cp));
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
	                     gt_ctl_conn_process_events, cp);
	if (rc < 0) {
		free(cp);
		return rc;
	}
	gt_strbuf_init(&cp->c_rcvbuf, cp->c_rcvbuf_buf,
	            sizeof(cp->c_rcvbuf_buf));
	gt_strbuf_init(&cp->c_sndbuf, cp->c_sndbuf_buf,
	            sizeof(cp->c_sndbuf_buf));
	gt_fd_event_set(cp->c_event, POLLIN);
	*cpp = cp;
	GT_LOGF(log, LOG_INFO, 0, "ok; fd=%d, path='%s'", fd, path);
	return 0;
}

static void
gt_ctl_conn_close(struct gt_ctl_conn *cp, int eno)
{
	struct gt_log *log;

	log = GT_LOG_TRACE(cp->c_log, close);
	GT_LOGF(log, LOG_INFO, eno, "hit; fd=%d", gt_ctl_conn_fd(cp));
	gt_ctl_conn_req_done(cp, eno, NULL);
	if (cp->c_close_fn != NULL) {
		(*cp->c_close_fn)(cp);
	}
	gt_sys_close(log, gt_ctl_conn_fd(cp));
	gt_fd_event_del(cp->c_event);
	free(cp);
}

static int
gt_ctl_conn_connect(struct gt_log *log, struct gt_ctl_conn **cpp,
	int pid, const char *path)
{
	int fd, rc;
	struct sockaddr_un addr;
	struct gt_ctl_conn *cp;

	log = GT_LOG_TRACE(log, connect);
	rc = gt_sys_socket(log, AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	gt_ctl_create_sockaddr_un(&addr, pid);
	rc = gt_connect_timed(log, fd, (struct sockaddr *)&addr,
	                      sizeof(addr), 2 * GT_SEC);
	if (rc < 0) {
		gt_sys_close(log, fd);
		return rc;
	}
	rc = gt_ctl_conn_open(log, cpp, fd, path);
	if (rc < 0) {
		gt_sys_close(log, fd);
		return rc;
	}
	cp = *cpp;
	cp->c_type = GT_CTL_CONN_CLIENT;
	cp->c_pid = pid;
	return 0;
}

static int
gt_ctl_conn_listen(struct gt_log *log, struct gt_ctl_conn **cpp, int pid)
{
	int rc, fd;
	struct sockaddr_un addr;
	struct stat stat;
	struct group *group;
	struct gt_ctl_conn *cp;

	log = GT_LOG_TRACE(log, listen);
	rc = gt_sys_socket(log, AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	gt_ctl_create_sockaddr_un(&addr, pid);
	unlink(addr.sun_path);
	rc = gt_sys_bind(log, fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0) {
		gt_sys_close(log, fd);
		return rc;
	}
	rc = gt_sys_getgrnam(log, GT_GROUP_NAME, &group);
	if (rc == 0) {
		gt_sys_chown(log, addr.sun_path, -1, group->gr_gid);
	}
	rc = gt_sys_stat(log, addr.sun_path, &stat);
	if (rc == 0) {
		gt_sys_chmod(log, addr.sun_path,
		             stat.st_mode|S_IRGRP|S_IWGRP|S_IXGRP);
	}
	rc = gt_sys_listen(log, fd, 5);
	if (rc < 0) {
		gt_sys_close(log, fd);
		return rc;
	}
	rc = gt_ctl_conn_open(log, cpp, fd, "listen");
	if (rc < 0) {
		gt_sys_close(log, fd);
	} else {
		cp = *cpp;
		cp->c_type = GT_CTL_CONN_LISTEN;
		cp->c_pid = pid;
		gt_ctl_conn_set_log(cp, log);
	}
	return rc;
}

static int
gt_ctl_conn_accept(struct gt_ctl_conn *lp)
{
	int rc, fd, lfd;
	socklen_t addrlen;
	struct sockaddr_un addr;
	struct gt_log *log;
	struct gt_ctl_conn *cp;

	log = GT_LOG_TRACE(lp->c_log, accept);
	addrlen = sizeof(addr);
	lfd = gt_ctl_conn_fd(lp);
	rc = gt_sys_accept4(log, lfd,
	                    (struct sockaddr *)&addr, &addrlen,
	                    SOCK_NONBLOCK|SOCK_CLOEXEC);
	if (rc < 0) {
		return rc;
	}
	fd = rc;
	rc = gt_ctl_conn_open(log, &cp, fd, "accept");
	if (rc < 0) {
		gt_sys_close(log, fd);
	} else {
		cp->c_type = GT_CTL_CONN_SERVER;
	}
	return rc;
}

static int
gt_ctl_conn_recv(struct gt_ctl_conn *cp)
{
	int rc, fd, off, n, m;
	struct gt_log *log;

	log = GT_LOG_TRACE(cp->c_log, recv);
	fd = gt_ctl_conn_fd(cp);
	do {
		off = cp->c_rcvbuf.sb_len;
		n = gt_strbuf_space(&cp->c_rcvbuf);
		GT_ASSERT(n);
		rc = gt_sys_read(log, fd, cp->c_rcvbuf.sb_buf + off, n);
		if (rc < 0) {
			if (rc == -EAGAIN) {
				return 0;
			} else {
				return rc;
			}
		} else if (rc == 0) {
			GT_LOGF(log, LOG_INFO, 0, "done");
			return -ECONNRESET;
		} else {
			cp->c_rcvbuf.sb_len += rc;
			rc = gt_ctl_conn_in(cp, off);
			if (rc < 0) {
				return rc;
			}
			m = gt_strbuf_space(&cp->c_rcvbuf);
			if (m == 0) {
				GT_LOGF(log, LOG_ERR, 0, "too long msg");
				return -EPROTO;
			}
		}
	} while (rc == n);
	return 0;
}

static int
gt_ctl_conn_send(struct gt_log *log, struct gt_ctl_conn *cp)
{
	int rc, fd;
	struct gt_strbuf *b;

	log = GT_LOG_TRACE(log, send);
	b = &cp->c_sndbuf;
	rc = gt_fd_event_is_set(cp->c_event, POLLOUT);
	if (rc) {
		// Already sending data - socket buffer is full
		return 0;
	}
	if (b->sb_len == 0) {
		return 0;
	}
	fd = gt_ctl_conn_fd(cp);
	rc = gt_sys_send(log, fd, b->sb_buf, b->sb_len, MSG_NOSIGNAL);
	if (rc < 0) {
		return rc;
	}
	gt_strbuf_remove(b, 0, rc);
	if (b->sb_len) {
		gt_fd_event_set(cp->c_event, POLLOUT);
	}
	return 0;
}

static int
gt_ctl_conn_send_cmd(struct gt_log *log, struct gt_ctl_conn *cp,
	const char *cmd, const char *path, int path_len,
	const char *new, int new_len)
{
	int rc, len;

	log = GT_LOG_TRACE(log, send);
	len = cp->c_sndbuf.sb_len;
	gt_strbuf_addf(&cp->c_sndbuf, "%s %.*s %.*s\n",
	            cmd, path_len, path, new_len, new);
	if (gt_strbuf_space(&cp->c_sndbuf) == 0) {
		cp->c_sndbuf.sb_len = len;
		GT_LOGF(log, LOG_ERR, 0, "too long msg; path='%.*s'",
		       path_len, path);
		return -ENOBUFS;
	}
	rc = gt_ctl_conn_send(log, cp);
	return rc;
}

static int
gt_ctl_conn_process_events(void *udata, short revents)
{
	int rc;
	struct gt_ctl_conn *cp;

	cp = udata;
	if (cp->c_type == GT_CTL_CONN_LISTEN) {
		if (revents & POLLIN) {	
			do {
				rc = gt_ctl_conn_accept(cp);
			} while (rc == 0);
		}
	} else if (revents & POLLIN) {
		rc = gt_ctl_conn_recv(cp);
		if (rc < 0) {
			gt_ctl_conn_close(cp, -rc);
		}
	} else if (revents & POLLOUT) {
		gt_fd_event_clear(cp->c_event, POLLOUT);
		rc = gt_ctl_conn_send(NULL, cp);
		if (rc < 0) {
			gt_ctl_conn_close(cp, -rc);
		}
	}
	return 0;
}

static int
gt_ctl_conn_in(struct gt_ctl_conn *cp, int off)
{
	int rc;
	struct gt_strbuf *b;

	b = &cp->c_rcvbuf;
	rc = gt_ctl_conn_in_first(cp, b->sb_buf, off, b->sb_len);
	if (rc <= 0) {
		return rc;
	}
	off = rc;
	rc = gt_ctl_conn_in_next(cp, b->sb_buf + off, b->sb_len - off);
	if (rc < 0) {
		return rc;
	}
	off += rc;
	gt_strbuf_remove(b, 0, off);
	return 0;
}

static int
gt_ctl_conn_in_first(struct gt_ctl_conn *cp, char *buf, int off, int cnt)
{
	int rc;
	char *ptr;

	ptr = memchr(buf + off, '\n', cnt - off);
	if (ptr == NULL) {
		return 0;
	}
	rc = gt_ctl_in_pdu(cp, buf, ptr - buf);
	if (rc < 0) {
		return rc;
	} else {
		return ptr - buf + 1;
	}
}

static int
gt_ctl_conn_in_next(struct gt_ctl_conn *cp, char *buf, int cnt)
{
	int rc, off, len;
	char *ptr;

	for (off = 0; off < cnt; off += len + 1) {
		ptr = memchr(buf + off, '\n', cnt - off);
		if (ptr == NULL) {
			break;
		}
		len = ptr - (buf + off);
		rc = gt_ctl_in_pdu(cp, buf + off, len);
		if (rc < 0) {
			return rc;
		}
	}
	return off;
}

static void
gt_ctl_conn_req_done(struct gt_ctl_conn *cp, int eno, char *old)
{
	int rc;
	gt_timer_del(&cp->c_timer);
	if (cp->c_req_fn != NULL) {
		rc = (*cp->c_req_fn)(cp->c_log, cp->c_req_udata, eno, old);
		if (rc) {
			GT_LOGF(cp->c_log, LOG_ERR, -rc, "callback failed");
		}
		cp->c_req_fn = NULL;
	}
}

static void
gt_ctl_conn_req_timeout(struct gt_timer *timer)
{
	struct gt_log *log;
	struct gt_ctl_conn *cp;

	cp = gt_container_of(timer, struct gt_ctl_conn, c_timer);
	log = GT_LOG_TRACE(cp->c_log, req);
	GT_LOGF(log, LOG_ERR, 0,
	        "timedout; timer=%p, dt=%"PRIu64"us",
	        &cp->c_timer, gt_nsec - cp->c_req_time);
	gt_ctl_conn_close(cp, ETIMEDOUT);
}

static void
gt_ctl_handle_sub(struct gt_ctl_conn *cp, int action)
{
	if (gt_ctl_sub_fn != NULL) {
		(*gt_ctl_sub_fn)(cp->c_pid, action);
	}
}

static void
gt_ctl_subscriber_close_cb(struct gt_ctl_conn *cp)
{
	int i;
	struct gt_ctl_conn *tmp;

	for (i = 0; i < gt_ctl_nr_subscribers; ++i) {
		if (gt_ctl_subscribers[i] == cp) {
			tmp = gt_ctl_subscribers[gt_ctl_nr_subscribers - 1];
			gt_ctl_subscribers[i] = tmp;
			gt_ctl_nr_subscribers--;
			gt_ctl_handle_sub(cp, GT_CTL_UNSUB);
			return;
		}
	}
}

static void
gt_ctl_publisher_close_mediator(struct gt_ctl_conn *cp)
{
	gt_ctl_publisher = NULL;
	if (gt_ctl_publisher_close_fn != NULL) {
		(*gt_ctl_publisher_close_fn)();
	}
}

static void
gt_ctl_publish(struct gt_log *log, struct gt_ctl_node *node,
	const char *new, int new_len)
{
	int i, rc, path_len;
	char path[PATH_MAX];
	struct gt_ctl_conn *cp;

	log = GT_LOG_TRACE(log, publish);
	path_len = 0;
	for (i = 0; i < gt_ctl_nr_subscribers;) {
		if (path_len == 0) {
			path_len = gt_ctl_node_get_path(node, path);
		}
		cp = gt_ctl_subscribers[i];
		rc = gt_ctl_conn_send_cmd(log, cp, "pub",
		                          path, path_len, new, new_len);
		if (rc) {
			gt_ctl_conn_close(cp, -rc);
		} else {
			++i;
		}
	}
}

static void
gt_ctl_unsub1(int eno)
{
	gt_ctl_conn_close(gt_ctl_publisher, eno);
	gt_ctl_publisher = NULL;
}

static int
gt_ctl_in(struct gt_log *log, const char *path, int load,
          const char *new, struct gt_strbuf *out)
{
	int rc;
	char *tail;
	struct gt_ctl_node *node;

	log = GT_LOG_TRACE(log, in);
	rc = gt_ctl_node_find(log, path, &node, &tail);
	if (rc == 0) {
		rc = gt_ctl_node_process(log, node, tail, load, new, out);
	}
	return rc;
}

static int
gt_ctl_in_pdu(struct gt_ctl_conn *cp, char *data, int data_len)
{
	int i, rc;
	char *argv[4], *tmp;
	struct iovec *token, tokens[4];
	struct gt_log *log;

	log = GT_LOG_TRACE(cp->c_log, in);
	data[data_len] = '\0'; // FIXME:
	rc = gt_strsplit(data, " \r\n\t", tokens, GT_ARRAY_SIZE(tokens));
	if (rc > GT_ARRAY_SIZE(tokens)) {
		GT_LOGF(log, LOG_ERR, 0, "too many tokens; data='%.*s'",
		        data_len, data);
		return -EPROTO;
	}
	for (i = 0; i < rc; ++i) {
		token = tokens + i;
		tmp = token->iov_base;
		tmp[token->iov_len] = '\0';
		argv[i] = tmp;
	}
	for (; i < GT_ARRAY_SIZE(argv); ++i) {
		argv[i] = NULL;
	}
	if (cp->c_type == GT_CTL_CONN_CLIENT) {
		if (!strcmp(argv[0], "rpl")) {
			rc = gt_ctl_in_rpl(cp, argv);
		} else
		if (!strcmp(argv[0], "pub")) {
			rc = gt_ctl_in_pub(cp, argv);
		} else {
			goto unknown_cmd;
		}
	} else {
		if (!strcmp(argv[0], "req")) {
			rc = gt_ctl_in_req(cp, argv);
		} else
		if (!strcmp(argv[0], "sub")) {
			rc = gt_ctl_in_sub(cp, argv);
		} else {
			goto unknown_cmd;
		}
	}
	return rc;
unknown_cmd:
	GT_LOGF(log, LOG_ERR, 0, "unknown cmd; cmd='%s'", argv[0]);
	return -EPROTO;
}

static int
gt_ctl_in_req(struct gt_ctl_conn *cp, char **argv)
{
	int rc;
	const char *path;
	struct gt_strbuf *b;
	struct gt_log *log;

	log = GT_LOG_TRACE(cp->c_log, in_req);
	path = argv[1];
	if (path == NULL) {
		path = "";
	}
	b = &cp->c_sndbuf;
	gt_strbuf_add_str(b, "rpl ");
	rc = gt_ctl_in(log, path, 0, argv[2], b);
	if (rc) {
		gt_strbuf_addf(b, " error %d", -rc);
	}
	gt_strbuf_add_ch(b, '\n');
	if (gt_strbuf_space(b) == 0) {
		GT_LOGF(log, LOG_ERR, 0, "too long msg; path='%s'", path);
		return -ENOBUFS;
	}
	rc = gt_ctl_conn_send(cp->c_log, cp);
	return rc;
}

static int
gt_ctl_in_rpl(struct gt_ctl_conn *cp, char **argv)
{
	char *old, *endptr;
	int eno;
	struct gt_log *log;

	log = GT_LOG_TRACE(cp->c_log, in_rpl);
	if (argv[2] == NULL) {
		old = argv[1];
		if (old == NULL) {
			old = "";
		}
		eno = 0;
	} else {
		old = "";
		eno = strtoul(argv[2], &endptr, 10);
		if (strcmp(argv[1], "error") || eno == 0 || *endptr != '\0') {
			GT_LOGF(log, LOG_ERR, 0,
			        "bad err fmt; fd=%d, ('%s %s')",
			        gt_ctl_conn_fd(cp), argv[1], argv[2]);
			return -EPROTO;
		}
	}
	gt_ctl_conn_req_done(cp, eno, old);
	GT_LOGF(log, LOG_INFO, 0, "ok; fd=%d", gt_ctl_conn_fd(cp));
	return -ECONNRESET;
}

static int
gt_ctl_in_pub(struct gt_ctl_conn *cp, char **argv)
{
	int rc, len;
	const char *path, *new;
	struct gt_log *log;
	struct gt_strbuf *b;

	log = GT_LOG_TRACE(cp->c_log, in_pub);
	path = argv[1];
	new = argv[2];
	if (path == NULL) {
		GT_LOGF(log, LOG_ERR, 0, "no path");
		return -EPROTO;
	}
	if (new == NULL) {
		GT_LOGF(log, LOG_ERR, 0, "no new; path='%s'", path);
		return -EPROTO;
	}
	b = &cp->c_sndbuf;
	len = b->sb_len;
	rc = gt_ctl_in(log, path, 0, new, b);
	b->sb_len = len;
	return rc;
}

static int
gt_ctl_in_sub(struct gt_ctl_conn *cp, char **argv)
{
	int i, rc, peer_pid;
	const char *a_pid;
	struct gt_log *log;

	log = GT_LOG_TRACE(cp->c_log, in_sub);
	a_pid = argv[1];
	if (a_pid == NULL) {
		GT_LOGF(log, LOG_ERR, 0, "no pid");
		return -EPROTO;
	}
	rc = sscanf(a_pid, "%d", &peer_pid);
	if (rc != 1) {
		GT_LOGF(log, LOG_ERR, 0, "invalid pid; pid='%s'", a_pid);
		return -EPROTO;
	}
	rc = gt_ctl_binded_pid(log);
	if (rc < 0) {
		return rc;
	}
	for (i = 0; i < gt_ctl_nr_subscribers; ++i) {
		if (gt_ctl_subscribers[i] == cp) {
			GT_LOGF(log, LOG_ERR, 0, "already subscribed");
			return -EALREADY;
		}
	}
	if (gt_ctl_nr_subscribers == GT_ARRAY_SIZE(gt_ctl_subscribers)) {
		GT_LOGF(log, LOG_ERR, 0, "too many subscribers");
		return -EOVERFLOW;
	}
	cp->c_pid = peer_pid;
	gt_ctl_subscribers[gt_ctl_nr_subscribers++] = cp;
	cp->c_close_fn = gt_ctl_subscriber_close_cb;
	gt_ctl_handle_sub(cp, GT_CTL_SUB);
	return 0;
}

static int
gt_ctl_node_get_path(struct gt_ctl_node *node, char *buf)
{
	struct gt_strbuf sb;

	gt_strbuf_init(&sb, buf, PATH_MAX);
	gt_ctl_gt_strbuf_add_node_path(&sb, node);
	GT_ASSERT(sb.sb_len < PATH_MAX);
	gt_strbuf_cstr(&sb);
	return sb.sb_len;
}

void
gt_ctl_gt_strbuf_add_node_path(struct gt_strbuf *sb, struct gt_ctl_node *node)
{
	int i, n;
	struct gt_ctl_node *path[GT_CTL_DEPTH_MAX];

	GT_ASSERT(node != NULL);
	n = 0;
	for (; node != &gt_ctl_root; node = node->n_parent) {
		GT_ASSERT(node != NULL);
		GT_ASSERT(n < GT_ARRAY_SIZE(path));
		path[n++] = node;
	}
	for (i = n - 1; i >= 0; --i) {
		if (sb->sb_len) {
			gt_strbuf_add_ch(sb, '.');
		}
		gt_strbuf_add_str(sb, path[i]->n_name);
	}
}

const char *
gt_ctl_log_add_node_path(struct gt_ctl_node *node) 
{
	struct gt_strbuf *sb;

	sb = gt_log_buf_alloc_space();
	gt_ctl_gt_strbuf_add_node_path(sb, node);
	return gt_strbuf_cstr(sb);
}

static int
gt_ctl_node_alloc(struct gt_log *log, struct gt_ctl_node **pnode,
	struct gt_ctl_node *parent, const char *name, int name_len)
{
	int rc;

	log = GT_LOG_TRACE(log, new);
	rc = gt_sys_malloc(log, (void **)pnode, sizeof(struct gt_ctl_node));
	if (rc < 0) {
		return rc;
	}
	gt_ctl_node_init(*pnode, parent, name, name_len);
	return 0;
}

static void
gt_ctl_node_init(struct gt_ctl_node *node, struct gt_ctl_node *parent,
	const char *name, int name_len)
{
	GT_ASSERT(name_len < GT_CTL_NODE_NAME_MAX);
	memset(node, 0, sizeof(*node));
	node->n_name_len = name_len;
	memcpy(node->n_name, name, name_len);
	node->n_name[name_len] = '\0';
	gt_list_init(&node->n_children);
	node->n_parent = parent;
	if (parent != NULL) {
		GT_LIST_INSERT_TAIL(&parent->n_children, node, n_list);
	}
}

static int
gt_ctl_node_find(struct gt_log *log, const char *path,
	struct gt_ctl_node **pnode, char **ptail)
{
	int i, rc, name_len, path_iovcnt;
	char *name;
	struct gt_ctl_node *child, *node;
	struct iovec path_iov[GT_CTL_DEPTH_MAX];

	log = GT_LOG_TRACE(log, find);
	rc = gt_ctl_split_path(log, path, path_iov);
	if (rc < 0) {
		return rc;
	}
	path_iovcnt = rc;
	node = &gt_ctl_root;
	for (i = 0; i < path_iovcnt; ++i) {
		name = path_iov[i].iov_base;
		name_len = path_iov[i].iov_len;
		child = gt_ctl_node_find_child(node, name, name_len);
		if (child == NULL) {
			if (i < path_iovcnt - 1) {
				GT_LOGF(log, LOG_ERR, 0,
				        "not exists; path='%s', idx=%d",
				        path, i);
				return -ENOENT;
			}
			*pnode = node;
			if (ptail == NULL) {
				GT_LOGF(log, LOG_ERR, 0,
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

static struct gt_ctl_node *
gt_ctl_node_find_child(struct gt_ctl_node *node,
	const char *name, int name_len)
{
	struct gt_ctl_node *child;

	GT_LIST_FOREACH(child, &node->n_children, n_list) {
		if (child->n_name_len == name_len &&
		    !memcmp(child->n_name, name, name_len)) {
			return child;
		}
	}
	return NULL;
}

static int
gt_ctl_node_add(struct gt_log *log, const char *path, int mode,
	void *udata, void (*free_fn)(void *), gt_ctl_node_f fn,
	struct gt_ctl_node **pnode)
{
	int i, rc, name_len, path_len, path_iovcnt;
	char *name;
	struct iovec path_iov[GT_CTL_DEPTH_MAX];
	struct gt_ctl_node *child, *node;

	GT_ASSERT(mode == GT_CTL_RD || mode == GT_CTL_LD || mode == GT_CTL_WR);
	log = GT_LOG_TRACE(log, add);
	node = &gt_ctl_root;
	path_len = strlen(path);
	if (path_len >= PATH_MAX) {
		GT_LOGF(log, LOG_ERR, 0, "too long path; path='%s'", path);
		return -EINVAL;
	}
	rc = gt_ctl_split_path(log, path, path_iov);
	if (rc < 0) {
		return rc;
	}
	path_iovcnt = rc;
	for (i = 0; i < path_iovcnt; ++i) {
		name = path_iov[i].iov_base;
		name_len = path_iov[i].iov_len;
		child = gt_ctl_node_find_child(node, name, name_len);
		if (child == NULL) {
			rc = gt_ctl_node_alloc(log, &child, node,
			                       name, name_len);
			if (rc < 0) {
				return rc;
			}
		} else if (child->n_fn != NULL) {
			GT_LOGF(log, LOG_ERR, 0, "already exists; path='%s'",
			        path);
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
	GT_LOGF(log, LOG_INFO, 0, "ok; node='%s'", path);
	return 0;
}

static void
gt_ctl_node_del(struct gt_log *log, struct gt_ctl_node *node)
{
	GT_LOGF(log, LOG_INFO, 0, "hit; node='%s'",
	        gt_ctl_log_add_node_path(node));
	gt_ctl_node_del_children(log, node);
	GT_LIST_REMOVE(node, n_list);
	if (node->n_free_fn != NULL) {
		(*node->n_free_fn)(node->n_udata);
	}
	free(node);
}

static void
gt_ctl_node_del_children(struct gt_log *log, struct gt_ctl_node *node)
{
	struct gt_ctl_node *child;

	while (!gt_list_empty(&node->n_children)) {
		child = GT_LIST_FIRST(&node->n_children,
		                      struct gt_ctl_node, n_list);
		gt_ctl_node_del(log, child);
	}
}

static int
gt_ctl_node_process(struct gt_log *log,
	struct gt_ctl_node *node, char *tail, int load,
	const char *new, struct gt_strbuf *out)
{
	int rc, len;
	char buf[GT_CTL_BUFSIZ];
	const char *access;
	struct gt_strbuf stub;

	log = GT_LOG_TRACE(log, process);
	if (tail == NULL) {
		tail = "";
	}
	if (new != NULL) {
		access = NULL;
		switch (node->n_mode) {
		case GT_CTL_LD:
			if (load == 0) {
				access = "load";
			}
			break;
		case GT_CTL_RD:
			access = "read";
			break;
		default:
			break;
		}
		if (access != NULL) {
			GT_LOGF(log, LOG_ERR, 0,
			        "%s only; path='%s', tail='%s'",
			        access, gt_ctl_log_add_node_path(node),
			        tail);
			return -EACCES;
		}
	}
	if (out == NULL) {
		gt_strbuf_init(&stub, buf, sizeof(buf));
		out = &stub;
	}
	len = out->sb_len;
	if (node->n_is_list) {
		rc = gt_ctl_node_process_list(node, tail, new, out);
	} else if (node->n_fn == NULL) {
		rc = gt_ctl_node_process_dir(node, tail, out);
	} else {
		if (tail[0] != '\0') {
			rc = 1;
		} else {
			rc = gt_ctl_node_process_leaf(log, node, new, out);
		}
	}
	if (rc == 1) {
		GT_LOGF(log, LOG_ERR, 0, "not exists' path='%s.%s'",
		        gt_ctl_log_add_node_path(node), tail);
		return -ENOENT;
	}
	if (rc < 0) {
		out->sb_len = len;
	}
	return rc;
}

static int
gt_ctl_node_process_dir(struct gt_ctl_node *node,
	const char *tail, struct gt_strbuf *out)
{
	int len;
	struct gt_ctl_node *x, *first, *last;

	if (gt_list_empty(&node->n_children)) {
		return 0;
	}
	first = GT_LIST_FIRST(&node->n_children, struct gt_ctl_node, n_list);
	last = GT_LIST_LAST(&node->n_children, struct gt_ctl_node, n_list);
	if (tail[0] == '\0') {
		x = first;
	} else {
		len = strlen(tail);
		if (tail[len - 1] != '+') {
			return 1;
		}
		x = gt_ctl_node_find_child(node, tail, len - 1);
		if (x == NULL || x == last) {
			return 0;
		}
		x = GT_LIST_NEXT(x, n_list);
	}
	gt_strbuf_addf(out, ",%s", x->n_name);
	return 0;
}

static int
gt_ctl_node_process_leaf(struct gt_log *log,
	struct gt_ctl_node *node, const char *new, struct gt_strbuf *out)
{
	int rc, off, new_len;
	char *old;

	off = out->sb_len;
	rc = (*node->n_fn)(log, node->n_udata, new, out);
	if (rc < 0) {
		GT_LOGF(log, LOG_ERR, -rc,
		        "handler failed; path='%s', new='%s'",
		        gt_ctl_log_add_node_path(node), new);
		return rc;
	}
	if (off < out->sb_cap) {
		old = gt_strbuf_cstr(out) + off;
		rc = gt_ctl_is_valid_str(old);
		if (rc == 0) {
			GT_LOGF(log, LOG_ERR, 0,
			        "invalid old; path='%s', old='%s'",
			        gt_ctl_log_add_node_path(node), old);
			return -EINVAL;
		}
	}	 
	if (new == NULL) {
		new_len = 0;
	} else {
		new_len = strlen(new);
	}
	if (new_len && node->n_has_subscribers) {
		gt_ctl_publish(log, node, new, new_len);
	}	
	return 0;
}

static int
gt_ctl_node_process_list(struct gt_ctl_node *node,
	const char *tail, const char *new, struct gt_strbuf *out)
{
	int rc, id;
	char *endptr;
	struct gt_ctl_list_data *data;

	data = &node->n_udata_buf.n_list_data;
	if (tail[0] == '\0') {
		id = 0;
		goto next;
	}
	id = strtoul(tail, &endptr, 10);
	switch (*endptr) {
	case '\0':
		rc = (data->sld_fn)(node->n_udata, id, new, out);
		GT_ASSERT3(0, rc <= 0, "%s",
		           gt_ctl_log_add_node_path(node));
		return rc;
	case '+':
		if (*(endptr + 1) != '\0') {
			return 1;
		}
		id++;
next:
		rc = (*data->sld_next_fn)(node->n_udata, id);
		if (rc >= 0) {
			gt_strbuf_addf(out, ",%d", rc);
		}
		return 0;
	default:
		return 1;
	}
}

static int
gt_ctl_node_process_int(struct gt_log *log, void *udata,
	const char *new, struct gt_strbuf *out)
{
	int rc;
	long long x, old;
	char *endptr;
	struct gt_ctl_node *node;
	struct gt_ctl_int_data *data;

	rc = 0;
	old = 0;
	data = udata;
	log = GT_LOG_TRACE(log, process_int);
	node = gt_container_of(data, struct gt_ctl_node, n_udata_buf.n_int_data);
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
			GT_BUG;
		}
	} else {
		x = strtoll(new, &endptr, 10);
		if (*endptr != '\0') {
			GT_LOGF(log, LOG_ERR, 0,
			        "not an int; path='%s', new='%s'",
			        gt_ctl_log_add_node_path(node), new);
			return -EPROTO;
		}
		if (x < data->sid_min || x > data->sid_max) {
			GT_LOGF(log, LOG_ERR, 0,
			        "not in range; path='%s', new=%lld, range=[%lld, %lld]",
			        gt_ctl_log_add_node_path(node), x,
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
			GT_BUG;
		}
	}
	gt_strbuf_addf(out, "%lld", old);
	return rc;
}

static int
gt_ctl_node_set_has_subscribers(struct gt_log *log, const char *path)
{
	int rc;
	struct gt_ctl_node *node;

	rc = gt_ctl_node_find(log, path, &node, NULL); 
	GT_ASSERT3(-rc, rc == 0, "node_set_has_subscribers('%s') failed", path);
	node->n_has_subscribers = 1;
	return rc;
}

static int
gt_ctl_cb(struct gt_log *log, void *udata, int eno, char *old)
{
	int len;
	struct gt_ctl_wait *wait;

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
gt_ctl_send_req(struct gt_log *log, struct gt_ctl_conn **cpp,
	int pid, const char *path, void *udata, gt_ctl_f fn, const char *new)
{
	int rc, path_len, new_len;
	struct gt_ctl_conn *cp;

	log = GT_LOG_TRACE(log, req);
	GT_ASSERT3(0, gt_ctl_binded_pid(NULL) != pid, "pid=%d", pid);
	GT_ASSERT(path != NULL);
	path_len = strlen(path);
	if (path_len >= PATH_MAX) {
		GT_LOGF(log, LOG_ERR, 0 , "too long path; path='%s'", path);
		return -EINVAL;
	}
	rc = gt_ctl_is_valid_str(path);
	if (rc == 0) {
		GT_LOGF(log, LOG_ERR, 0, "invalid path; path='%s'", path);
		return -EINVAL;
	}
	if (new == NULL) {
		new_len = 0;
	} else {
		new_len = strlen(new);
		rc = gt_ctl_is_valid_str(new);
		if (rc == 0) {
			GT_LOGF(log, LOG_ERR, 0, "invalid new; new='%s'", new);
			return -EINVAL;
		}
	}
	rc = gt_ctl_conn_connect(log, &cp, pid, path);
	if (rc) {
		return rc;
	}
	gt_ctl_conn_set_log(cp, log);
	rc = gt_ctl_conn_send_cmd(log, cp, "req", path, path_len,
	                          new, new_len);
	if (rc) {
		gt_ctl_conn_close(cp, -rc);
		return rc;
	}
	gt_strzcpy(cp->c_req_path, path, sizeof(cp->c_req_path));
	cp->c_req_udata = udata;
	cp->c_req_fn = fn;
	cp->c_req_time = gt_nsec;
	gt_timer_set(&cp->c_timer, 5 * GT_SEC, gt_ctl_conn_req_timeout);
	if (cpp != NULL) {
		*cpp = cp;
	}
	return 0;
}

static int
gt_ctl_add6(struct gt_log *log, const char *path,
	int mode, void *udata, void (*free_fn)(void *), gt_ctl_node_f fn,
            struct gt_ctl_node **pnode)
{
	int rc;

	rc = gt_ctl_node_add(log, path, mode, udata, free_fn, fn, pnode);
	GT_ASSERT3(-rc, rc == 0, "ctl_add('%s') failed", path);
	return rc;
}

static void
gt_ctl_add_int_union(struct gt_log *log, const char *path,
	int mode, void *ptr, int int_sizeof, int64_t min, int64_t max)
{
	struct gt_ctl_int_data *data;
	struct gt_ctl_node *node;

	GT_ASSERT(min <= max);
	gt_ctl_add6(log, path, mode, NULL, NULL,
	            gt_ctl_node_process_int, &node);
	data = &node->n_udata_buf.n_int_data;
	node->n_udata = data;
	data->sid_ptr = ptr;
	data->sid_min = min;
	data->sid_max = max;
	data->sid_int_sizeof = int_sizeof;
	data->sid_ptr = ptr;
}
