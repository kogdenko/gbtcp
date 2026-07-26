// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <readline/history.h>
#include <readline/readline.h>

#include <gbtcp/kernel/api.h>
#include <gbtcp/kernel/cli.h>
#include <gbtcp/kernel/cli.pb-c.h>
#include <gbtcp/kernel/fd_event.h>
#include <gbtcp/kernel/list.h>
#include <gbtcp/kernel/mm.h>
#include <gbtcp/kernel/shm.h>
#include <gbtcp/kernel/vector.h>

#define GT_CLI_BUF_SIZE 8192

#define GT_CLI_REQUIRED (1 << 1)

#define GT_CLI_PROMPT "gbtcp> "

struct gt_cli_arg_type {
	struct gt_dlist link;
	const char *name;
	gt_cli_arg_parse_f parse_fn;
	gt_cli_arg_free_f free_fn;
};

struct gt_cli_arg_desc {
	char *arg_name;

	u32 arg_flags;

	u8 arg_is_present;

	struct gt_cli_arg_type *arg_type;
};

struct gt_cli_node {
	char *nd_name;
	struct gt_cli_arg_desc *nd_args;

	struct gt_dlist nd_link;

	struct gt_dlist nd_child_link;
	struct gt_dlist nd_children;
	struct gt_cli_node *nd_parent;

	gt_cli_command_f nd_command_fn;
	void *nd_udata;
};

struct gt_cli_context {
	struct gt_api_conn *client;
	void (*output)(struct gt_cli_context *ctx, u32 marker, char *output);
};

static struct gt_cli_node gt_cli_root;
static struct gt_dlist gt_cli_arg_type_head;

// The command tree, arg descriptors and parsed arg values are built only by
// the controller (the server), always attached — plain allocations,
// duplication and vectors use gt_kmalloc/gt_kmemdup/gt_kstrdup/gt_kstrndup/
// gt_kvec_add/gt_kvec_free/gt_kfree (shm.h), which assert attachment,
// instead of the ambient gt_get_allocator(), which would silently fall back
// to sys_malloc if this code ever ran unattached. The client side (gbtcpctl)
// below uses sys_malloc directly instead, since it never attaches at all.
// Strings flowing into protobuf replies and readline-owned memory come from
// neither (see gt_pbc_free() and the readline free() contract in
// gt_cli_custom_completion()).

static struct gt_api_conn *gt_client;
static struct fd_event *gt_stdin_fd;
static char *gt_cli_cache_path;
static char *gt_cli_cache_input;
static char *gt_cli_cache_match;
static u8 gt_cli_printed;

u8 gt_cli_done;

static char **gt_cli_custom_completion(const char *text, int start, int end);

static void
gt_cli_node_init(struct gt_cli_node *node)
{
	gt_dlist_init(&node->nd_children);
	node->nd_parent = NULL;
	node->nd_command_fn = NULL;
	node->nd_args = NULL;
}

static struct gt_cli_node *
gt_cli_get_child(struct gt_cli_node *parent, const char *name)
{
	size_t len;
	struct gt_cli_node *node, *child;

	child = NULL;
	len = strlen(name);

	GT_DLIST_FOREACH(node, &parent->nd_children, nd_child_link) {
		if (!strncmp(node->nd_name, name, len)) {
			if (child != NULL) {
				return NULL;
			}
			child = node;
		}
	}

	return child;
}

static void
gt_cli_del_branch(struct gt_cli_node *branch)
{
	struct gt_cli_arg_desc *arg;
	struct gt_cli_node *child;

	while (gt_dlist_is_empty(&branch->nd_children)) {
		child = GT_DLIST_FIRST(&branch->nd_children, struct gt_cli_node,
				       nd_child_link);
		gt_cli_del_branch(child);
	}

	GT_DLIST_REMOVE(branch, nd_child_link);
	gt_kfree_internal(branch->nd_name);

	GT_VEC_FOREACH_PTR(arg, branch->nd_args) {
		gt_kfree_internal(arg->arg_name);
	}
	gt_kvec_free(branch->nd_args);

	gt_kfree_internal(branch);
}

static void
gt_cli_node_path_r(char **res, struct gt_cli_node *node)
{
	if (node == &gt_cli_root) {
		return;
	}

	gt_cli_node_path_r(res, node->nd_parent);
	if (*res != NULL) {
		gt_str_addchar(*res, ' ');
	}
	gt_str_addcstr(*res, node->nd_name);
}

static char *
gt_cli_node_path(struct gt_cli_node *node)
{
	char *path;

	path = NULL;
	gt_cli_node_path_r(&path, node);
	return path;
}

static void
gt_get_leafs(struct gt_dlist *leaf_head, struct gt_cli_node *parent)
{
	struct gt_cli_node *node;

	if (parent->nd_command_fn != NULL) {
		GT_DLIST_INSERT_HEAD(leaf_head, parent, nd_link);
	}

	GT_DLIST_FOREACH(node, &parent->nd_children, nd_child_link) {
		gt_get_leafs(leaf_head, node);
	}
}

static void
gt_cli_arg_help(struct gt_cli_arg_desc *arg, char **s)
{
	u8 required;

	required = GT_FLAG_ISSET(arg->arg_flags, GT_CLI_REQUIRED);

	gt__str_addchar(s, ' ');

	gt__str_addchar(s, required ? '<' : '[');
	gt__str_addcstr(s, arg->arg_name);
	if (arg->arg_type != NULL) {
		gt__str_printf(s, " <%s>", arg->arg_type->name);
	}
	gt__str_addchar(s, required ? '>' : ']');
}

static void
gt_cli_output_help(struct gt_cli_context *ctx, struct gt_cli_node *node)
{
	int len;
	char *path, *s;
	struct gt_dlist leaf_head;
	struct gt_cli_arg_desc *arg;
	struct gt_cli_node *leaf;

	gt_dlist_init(&leaf_head);
	gt_get_leafs(&leaf_head, node);

	len = 0;
	GT_DLIST_FOREACH(leaf, &leaf_head, nd_link) {
		path = gt_cli_node_path(leaf);
		len = GT_MAX(len, gt_str_len(path));
		gt_str_free(path);
	}

	GT_DLIST_FOREACH(leaf, &leaf_head, nd_link) {
		s = NULL;
		path = gt_cli_node_path(leaf);
		if (path != NULL) {
			gt_str_printf(s, "%-*s", len, path);
		}

		GT_VEC_FOREACH_PTR(arg, leaf->nd_args) {
			gt_cli_arg_help(arg, &s);
		}
		gt_str_addchar(s, '\n');

		gt_str_free(path);
		gt_cli_output(ctx, s);
	}
}

struct gt_cli_node *
gt_cli_new_node(const char *name, struct gt_cli_node *parent)
{
	struct gt_cli_node *node;

	node = gt_kmalloc_align(sizeof(*node), sizeof(void *), 0);
	if (node == NULL) {
		return NULL;
	}

	node->nd_name = gt_kstrdup(name);
	if (node->nd_name == NULL) {
		gt_kfree_internal(node);
		return NULL;
	}

	gt_cli_node_init(node);

	node->nd_parent = parent;
	GT_DLIST_INSERT_HEAD(&parent->nd_children, node, nd_child_link);

	return node;
}

static struct gt_cli_arg_desc *
gt_cli_get_arg(struct gt_cli_arg_desc *args, const char *name)
{
	struct gt_cli_arg_desc *arg;

	GT_VEC_FOREACH_PTR(arg, args) {
		if (!strcmp(arg->arg_name, name)) {
			return arg;
		}
	}

	return NULL;
}

static struct gt_cli_arg_type *
gt_cli_get_arg_type(const char *arg_type_name)
{
	struct gt_cli_arg_type *arg_type;

	GT_DLIST_FOREACH(arg_type, &gt_cli_arg_type_head, link) {
		if (!strcmp(arg_type->name, arg_type_name)) {
			return arg_type;
		}
	}

	return NULL;
}

static void *
gt_cli_parse_string(const char *s)
{
	return gt_kstrdup(s);
}

static void *
gt_cli_parse_u32(const char *s)
{
	u32 res;
	unsigned long long d;
	char *endptr;

	d = strtoull(s, &endptr, 10);
	if (*endptr != '\0' || d > UINT32_MAX) {
		return NULL;
	} else {
		res = d;
		return gt_kmemdup(&res, sizeof(res));
	}
}

static void *
gt_cli_parse_ip4_address(const char *s)
{
	int rc;
	struct ipaddr addr;

	rc = ipaddr_pton(AF_INET, &addr, s);
	if (rc == 0) {
		return gt_kmemdup(&addr, sizeof(addr));
	} else {
		return NULL;
	}
}

static void *
gt_cli_parse_ip4_prefix(const char *s)
{
	int rc;
	long len;
	char buf[128];
	char *sep, *endptr;
	struct gt_ip_prefix pfx;

	gt_strzcpy(buf, s, sizeof(buf));
	sep = strchr(buf, '/');
	if (sep == NULL) {
		pfx.len = 32;
	} else {
		*sep = '\0';
		len = strtoul(sep + 1, &endptr, 10);
		if (len > 32) {
			return NULL;
		}
		pfx.len = len;
	}

	rc = ipaddr_pton(AF_INET, &pfx.addr, buf);
	if (rc == 0) {
		return gt_kmemdup(&pfx, sizeof(pfx));
	} else {
		return NULL;
	}
}

static void *
gt_cli_parse_eth_address(const char *s)
{
	int rc;
	struct gt_eth_addr addr;

	rc = eth_addr_aton(&addr, s);
	if (rc == 0) {
		return gt_kmemdup(&addr, sizeof(addr));
	} else {
		return NULL;
	}
}

static char *
gt_cli_skip_spaces(char *s)
{
	while (*s != '\0' && strchr(" \r\n\t", *s) != NULL) {
		++s;
	}
	return s;
}

char *
gt_cli_get_token(char *s, char **token)
{
	char *e;

	e = s = gt_cli_skip_spaces(s);
	while (isalnum(*e) || *e == '-' || *e == '_') {
		++e;
	}

	*token = e == s ? NULL : s;

	return e;
}

static char *
gt_cli_parse_arg(char *s, struct gt_cli_arg_desc *arg)
{
	char left, *nam, *nam_end, *val, *val_end;

	s = gt_cli_skip_spaces(s);
	if (*s == '\0') {
		return s;
	}

	if (strchr("<[", *s) == NULL) {
		return NULL;
	}
	left = *s;
	++s;

	s = gt_cli_get_token(s, &nam);
	if (nam == NULL) {
		return NULL;
	}
	nam_end = s;

	s = gt_cli_get_token(s, &val);
	val_end = s;

	s = gt_cli_skip_spaces(s);
	if (left == '[' && *s == ']') {
		arg->arg_flags = 0;
	} else if (left == '<' && *s == '>') {
		arg->arg_flags = GT_CLI_REQUIRED;
	} else {
		return NULL;
	}

	if (val != NULL) {
		*val_end = '\0';
		arg->arg_type = gt_cli_get_arg_type(val);
		if (arg->arg_type == NULL) {
			return NULL;
		}
	}

	arg->arg_name = gt_kstrndup(nam, nam_end - nam);

	return s + 1;
}

int
gt_cli_node_parse_arg_description(struct gt_cli_node *node, const char *desc)
{
	int rc;
	char buf[GT_CLI_BUF_SIZE], *s;
	struct gt_cli_arg_desc arg;

	gt_strzcpy(buf, desc, sizeof(buf));
	s = buf;

	do {
		arg.arg_name = NULL;
		arg.arg_type = NULL;
		arg.arg_is_present = 0;

		s = gt_cli_parse_arg(s, &arg);
		if (s == NULL) {
			return -EINVAL;
		}

		if (arg.arg_name == NULL) {
			break;
		}

		rc = gt_kvec_add(node->nd_args, arg);
		if (rc) {
			gt_kfree_internal(arg.arg_name);
			return rc;
		}
	} while (*s != '\0');

	return 0;
}

int
gt_cli_register_command(const char *path, gt_cli_command_f command_fn,
			void *udata, const char *arg_description)
{
	int rc;
	char *s;
	char buf[GT_CLI_BUF_SIZE];
	struct gt_cli_node *parent, *node, *branch;

	branch = NULL;
	parent = node = &gt_cli_root;
	gt_strzcpy(buf, path, sizeof(buf));

	for (s = strtok(buf, " "); s != NULL; s = strtok(NULL, " ")) {
		node = gt_cli_get_child(parent, s);
		if (node == NULL) {
			node = gt_cli_new_node(s, parent);
			if (node == NULL) {
				rc = -ENOMEM;
				goto err;
			}

			if (branch != NULL) {
				branch = node;
			}
		}

		parent = node;
	}

	if (node->nd_command_fn != NULL) {
		rc = -EEXIST;
		goto err;
	}

	if (!gt_dlist_is_empty(&node->nd_children)) {
		rc = -EBUSY;
		goto err;
	}

	node->nd_command_fn = command_fn;
	node->nd_udata = udata;
	rc = gt_cli_node_parse_arg_description(node, arg_description);
	if (rc) {
		goto err;
	}

	return 0;

err:
	if (branch != NULL) {
		gt_cli_del_branch(branch);
	}
	return rc;
}

int
gt_cli_register_arg_type(const char *arg_type_name, gt_cli_arg_parse_f parse_fn,
			 gt_cli_arg_free_f free_fn)
{
	struct gt_cli_arg_type *arg_type;

	arg_type = gt_cli_get_arg_type(arg_type_name);
	if (arg_type != NULL) {
		return -EEXIST;
	}

	arg_type = gt_kmalloc_align(sizeof(*arg_type), sizeof(void *), 0);
	if (arg_type == NULL) {
		return -ENOMEM;
	}

	arg_type->name = arg_type_name;

	arg_type->parse_fn = parse_fn;
	arg_type->free_fn = free_fn;

	GT_DLIST_INSERT_TAIL(&gt_cli_arg_type_head, arg_type, link);

	return 0;
}

static int
gt_cli_completion(struct gt_api_conn *cp, char *path, char *input, char ***res)
{
	int len;
	char *s, **matches;
	struct gt_cli_arg_desc *arg;
	struct gt_cli_node *parent, *node;

	*res = NULL;
	parent = &gt_cli_root;

	for (s = strtok(path, " "); s != NULL; s = strtok(NULL, " ")) {
		node = gt_cli_get_child(parent, s);
		if (node == NULL) {
			break;
		}
		parent = node;
	}

	matches = NULL;
	len = strlen(input);

	GT_DLIST_FOREACH(node, &parent->nd_children, nd_child_link) {
		if (!strncmp(node->nd_name, input, len)) {
			s = gt_pbc_strdup(cp, node->nd_name);
			if (s != NULL) {
				gt_kvec_add(matches, s);
			}
		}
	}

	GT_VEC_FOREACH_PTR(arg, parent->nd_args) {
		if (!strncmp(arg->arg_name, input, len)) {
			s = gt_pbc_strdup(cp, arg->arg_name);
			if (s != NULL) {
				gt_kvec_add(matches, s);
			}
		}
	}

	*res = matches;
	return 0;
}

static void
gt_cli_Invalid_input(struct gt_cli_context *ctx, u32 marker)
{
	gt_cli_printf3(ctx, marker, "Invalid input detected at '^' marker\n");
}

static void
gt_cli_Incomplete_command(struct gt_cli_context *ctx)
{
	gt_cli_printf(ctx, "Incomplete command\n");
}

static void
gt_cli_Error(struct gt_cli_context *ctx, u32 errnum)
{
	gt_cli_printf(ctx, "Error: %s\n", strerror(errnum));
}

static int
gt_cli_command3(struct gt_cli_context *ctx, const char *input, char *input_buf)
{
	int rc;
	char *s;
	struct gt_dlist arg_head;
	struct gt_cli_arg_desc *arg;
	struct gt_cli_arg *a;
	struct gt_cli_node *node, *child;

	gt_dlist_init(&arg_head);
	node = &gt_cli_root;

	for (s = strtok(input_buf, " "); s != NULL; s = strtok(NULL, " ")) {
		if (!strcmp(s, "?")) {
			gt_cli_output_help(ctx, node);
			return 0;
		}

		if (node->nd_command_fn != NULL) {
			break;
		}

		child = gt_cli_get_child(node, s);
		if (child == NULL) {
			break;
		}

		node = child;
	}

	if (node->nd_command_fn == NULL) {
		if (s == NULL) {
			gt_cli_Incomplete_command(ctx);
		} else {
			gt_cli_Invalid_input(ctx, s - input_buf);
		}
		return 0;
	}

	for (; s != NULL; s = strtok(NULL, " ")) {
		arg = gt_cli_get_arg(node->nd_args, s);
		if (arg == NULL) {
			gt_cli_Invalid_input(ctx, s - input_buf);
			return 0;
		}

		a = gt_kmalloc_align(sizeof(*a), sizeof(void *), 0);
		if (a == NULL) {
			gt_cli_Error(ctx, ENOMEM);
			goto out;
		}

		a->arg_name = arg->arg_name;
		a->arg_desc = arg;
		arg->arg_is_present = 1;
		a->arg_value = NULL;
		GT_DLIST_INSERT_TAIL(&arg_head, a, arg_link);

		if (arg->arg_type != NULL) {
			s = strtok(NULL, " ");
			if (s == NULL) {
				gt_cli_Incomplete_command(ctx);
				goto out;
			}

			a->arg_value = (*arg->arg_type->parse_fn)(s);
			if (a->arg_value == NULL) {
				gt_cli_Invalid_input(ctx, s - input_buf);
				goto out;
			}
		}
	}

	GT_VEC_FOREACH_PTR(arg, node->nd_args) {
		if (GT_FLAG_ISSET(arg->arg_flags, GT_CLI_REQUIRED) &&
		    arg->arg_is_present == 0) {
			gt_cli_printf(ctx, "Missing \"%s\" argument\n",
				      arg->arg_name);
			goto out;
		}
	}

	rc = (node->nd_command_fn)(ctx, &arg_head, node->nd_udata);
	if (rc < 0) {
		gt_cli_Error(ctx, -rc);
	}

out:
	while (!gt_dlist_is_empty(&arg_head)) {
		a = GT_DLIST_FIRST(&arg_head, struct gt_cli_arg, arg_link);
		GT_DLIST_REMOVE(a, arg_link);

		arg = a->arg_desc;
		arg->arg_is_present = 0;
		if (a->arg_value != NULL) {
			(*arg->arg_type->free_fn)(a->arg_value);
		}
		gt_kfree_internal(a);
	}

	return 0;
}

static int
gt_cli_command(struct gt_cli_context *ctx, const char *input)
{
	int rc;
	char *input_buf;

	input_buf = gt_kstrdup(input);
	if (input_buf == NULL) {
		return -ENOMEM;
	}
	rc = gt_cli_command3(ctx, input, input_buf);
	gt_kfree_internal(input_buf);
	return rc;
}

static void
gt__cli_output3(struct gt_cli_context *ctx, u32 marker, char *output)
{
	Gt__CliCommandDetails *rp;

	rp = gt_api_alloc_details(ctx->client, rp, cli_command);
	if (rp == NULL) {
		return;
	}

	rp->output = output;
	rp->marker = marker;

	gt_api_send_details(ctx->client, rp, cli_command);
}

void
gt_cli_output3(struct gt_cli_context *ctx, u32 marker, char *output)
{
	if (ctx->output != NULL) {
		(*ctx->output)(ctx, marker, output);
	} else {
		gt_str_free(output);
	}
}

void
gt_cli_printf3(struct gt_cli_context *ctx, u32 marker, const char *format, ...)
{
	va_list ap;
	char *s;

	s = NULL;
	va_start(ap, format);
	gt__str_vprintf(&s, format, ap);
	va_end(ap);

	gt_cli_output3(ctx, marker, s);
}

static int
gt_cli_completion_api_handler(struct gt_api_conn *cp, Gt__CliCompletion *rq)
{
	int rc;
	char **matches;
	Gt__CliCompletionReply *rp;

	rc = gt_cli_completion(cp, rq->path, rq->input, &matches);
	if (rc < 0) {
		return rc;
	}

	rp = gt_api_alloc_reply(cp, rp, cli_completion);
	if (rp == NULL) {
		return -ENOMEM;
	}

	rp->n_matches = gt_vec_size(matches);
	rp->matches = matches;

	return gt_api_send_reply(cp, rp, cli_completion);
}

GT_API_SERVER_DEFINE_HANDLER(cli_completion, gt_cli_completion_api_handler)

static int
gt_cli_command_dump_api_handler(struct gt_api_conn *cp, Gt__CliCommandDump *rq)
{
	int rc;
	struct gt_cli_context context;

	context.output = gt__cli_output3;
	context.client = cp;

	rc = gt_cli_command(&context, rq->input);
	return rc;
}

GT_API_SERVER_DEFINE_HANDLER(cli_command_dump, gt_cli_command_dump_api_handler)

static int
gt_test_echo_cli_handler(void *ctx, struct gt_dlist *arg_head, void *udata)
{
	u32 i, n;
	char *data, *tmp;
	struct gt_cli_arg *arg;

	n = 1;
	data = NULL;

	GT_DLIST_FOREACH(arg, arg_head, arg_link) {
		if (!strcmp(arg->arg_name, "data")) {
			data = arg->arg_value;
		} else if (!strcmp(arg->arg_name, "n")) {
			n = *(u32 *)arg->arg_value;
		}
	}

	for (i = 0; i < n; ++i) {
		tmp = NULL;
		gt_str_printf(tmp, "%s\n", data);
		gt_cli_output(ctx, tmp);
	}

	return 0;
}

static void
gt_cli_arg_free(void *ptr)
{
	gt_kfree_internal(ptr);
}

void
gt_cli_server_init(void)
{
	gt_cli_node_init(&gt_cli_root);

	gt_dlist_init(&gt_cli_arg_type_head);

	gt_cli_register_arg_type("string", gt_cli_parse_string,
				 gt_cli_arg_free);
	gt_cli_register_arg_type("u32", gt_cli_parse_u32, gt_cli_arg_free);
	gt_cli_register_arg_type("ip4-address", gt_cli_parse_ip4_address,
				 gt_cli_arg_free);
	gt_cli_register_arg_type("ip4-prefix", gt_cli_parse_ip4_prefix,
				 gt_cli_arg_free);
	gt_cli_register_arg_type("eth-address", gt_cli_parse_eth_address,
				 gt_cli_arg_free);

	gt_api_register_request(&gt_main_conn, cli_completion);
	gt_api_register_request(&gt_main_conn, cli_command_dump);

	gt_cli_register_command("test echo", gt_test_echo_cli_handler, NULL,
				"<data string> [n u32]");
}

int
gt_cli_server_play_file(void)
{
	int rc;
	const char *path;
	char *s, *input;
	char path_buf[PATH_MAX];
	char buf[2000];
	FILE *file;
	struct gt_cli_context context;

	path = getenv("GBTCP_CONF");
	if (path == NULL) {
		return 0;
	}
	rc = sys_realpath(path, path_buf);
	if (rc) {
		return rc;
	}
	path = path_buf;
	rc = sys_fopen(&file, path, "r");
	if (rc) {
		return rc == -ENOENT ? 0 : rc;
	}
	rc = 0;
	context.output = NULL;
	context.client = NULL;
	while ((s = fgets(buf, sizeof(buf), file)) != NULL) {
		input = strtrim(buf);
		gt_cli_command(&context, input);
	}
	fclose(file);
	return 0;
}

// Client side
static void
gt_cli_client_print_error(int rc)
{
	if (rc < 0) {
		fprintf(stderr, "Transport error: %s\n", strerror(-rc));
	} else {
		fprintf(stderr, "Command failed: %s\n", strerror(rc));
	}
}

static void
gt_cli_client_input(char *input)
{
	if (input == NULL) {
		// EOF
		gt_cli_done = 1;
		return;
	}

	if (strlen(input) == 0) {
		sys_free(input);
		return;
	}

	add_history(input);

	if (!strcmp(input, "quit") || !strcmp(input, "exit") ||
	    !strcmp(input, "q")) {
		gt_cli_done = 1;
	} else {
		gt_cli_execute_command(input);
	}

	sys_free(input);
}

static int
gt_cli_stdin_handler(void *udata, short events, struct gt_dlist *dh)
{
	rl_callback_read_char();
	return 0;
}

int
gt_cli_client_init(void)
{
	int rc;

	// gt_cli_client_init() runs both attached (the controller's own
	// interactive CLI) and unattached (gbtcpctl) — the one place in this
	// file where the allocator genuinely can't be pinned to one or the
	// other ahead of time.
	gt_client = gt_api_conn_alloc(gt_get_allocator());
	if (gt_client == NULL) {
		return -ENOMEM;
	}
	gt_cli_done = 0;
	gt_cli_cache_path = NULL;
	gt_cli_cache_input = NULL;
	gt_cli_cache_match = NULL;
	gt_cli_printed = 0;

	rl_initialize();

	rl_attempted_completion_function = gt_cli_custom_completion;
	rl_completion_append_character = '\0';
	rl_bind_key('\t', rl_complete);

	rl_callback_handler_install(GT_CLI_PROMPT, gt_cli_client_input);

	rc = fd_event_add(&gt_stdin_fd, STDIN_FILENO, NULL,
			  gt_cli_stdin_handler);
	if (rc == 0) {
		fd_event_set(gt_stdin_fd, POLLIN);
	}

	return rc;
}

void
gt_cli_client_deinit(void)
{
	rl_deprep_terminal();
}

int
gt_cli_client_connect(void)
{
	int rc;

	if (gt_api_conn_is_opened(gt_client)) {
		return 0;
	}

	rc = gt_api_client_connect(gt_client, GT_API_SOCK_PATH);
	if (rc < 0) {
		gt_cli_client_print_error(rc);
	}

	return rc;
}

static int
gt_cli_completion_reply_api_handler(struct gt_api_conn *cp, u32 errnum,
				    Gt__CliCompletionReply *rp)
{
	int i, j, len, rows, cols;

	if (rp == NULL || rp->n_matches == 0) {
		return 0;
	}

	if (rp->n_matches == 1) {
		gt_cli_cache_match = strdup(rp->matches[0]);
	}

	len = 0;
	for (i = 0; i < rp->n_matches; ++i) {
		len = GT_MAX(len, strlen(rp->matches[i]));
	}

	len += 2;

	rl_get_screen_size(&rows, &cols);

	for (i = 0, j = 0; i < rp->n_matches; ++i) {
		if (j == 0) {
			printf("\n");
		}
		j++;
		if (j == cols / len) {
			j = 0;
		}

		printf("%-*s", len, rp->matches[i]);
	}

	printf("\n");
	rl_on_new_line();
	rl_redisplay();

	return 0;
}

GT_API_CLIENT_DEFINE_HANDLER(cli_completion_reply,
			     gt_cli_completion_reply_api_handler)

static char **
gt_cli_custom_completion(const char *text, int start, int end)
{
	int rc;
	char **res;
	Gt__CliCompletion *rq;
	char *path, *input;

	rl_attempted_completion_over = 1;

	rc = gt_cli_client_connect();
	if (rc) {
		return NULL;
	}

	path = sys_strndup(rl_line_buffer, start);
	if (path == NULL) {
		return NULL;
	}
	input = sys_strndup(text, end - start);
	if (input == NULL) {
		sys_free(path);
		return NULL;
	}

	if (gt_cli_cache_path != NULL && gt_cli_cache_input != NULL &&
	    gt_cli_cache_match != NULL && !strcmp(path, gt_cli_cache_path) &&
	    !strcmp(input, gt_cli_cache_input)) {
		sys_free(path);
		sys_free(input);

		// readline frees the returned array and its elements with
		// free(): they must come from the system allocator.
		res = sys_malloc(2 * sizeof(char *));
		if (res == NULL) {
			return NULL;
		}

		res[0] = sys_strdup(gt_cli_cache_match);
		if (res[0] == NULL) {
			sys_free(res);
			return NULL;
		}
		res[1] = NULL;
		return res;
	}

	gt_sys_free_safe(gt_cli_cache_path);
	gt_sys_free_safe(gt_cli_cache_input);
	gt_sys_free_safe(gt_cli_cache_match);
	gt_cli_cache_path = path;
	gt_cli_cache_input = input;

	rq = gt_api_alloc_request(gt_client, rq, cli_completion);
	if (rq == NULL) {
		return NULL;
	}

	rq->path = gt_pbc_strdup(gt_client, gt_cli_cache_path);
	rq->input = gt_pbc_strdup(gt_client, gt_cli_cache_input);
	if (rq->path == NULL || rq->input == NULL) {
		gt_api_free_request(gt_client, rq, cli_completion);
		return NULL;
	}

	rc = gt_api_send_request(gt_client, rq, cli_completion);
	if (rc < 0 && rc != EAGAIN) {
		gt_cli_client_print_error(rc);
		return NULL;
	}

	return NULL;
}

static void
gt_cli_print_marker(u32 marker)
{
	u32 off;
	int i, rows, cols;

	rl_get_screen_size(&rows, &cols);

	off = sizeof(GT_CLI_PROMPT) - 1 + marker;
	if (off > cols) {
		return;
	}

	for (i = 0; i < off; ++i) {
		fprintf(stdout, " ");
	}
	fprintf(stdout, "^\n");
}

static int
gt_cli_command_details_api_handler(struct gt_api_conn *cp, u32 errnum,
				   Gt__CliCommandDetails *rp)
{
	if (rp != NULL && strlen(rp->output)) {
		if (gt_cli_printed == 0) {
			rl_set_prompt("");
			rl_redisplay();
		}

		if (rp->marker != ~0) {
			gt_cli_print_marker(rp->marker);
		}

		fprintf(stdout, "%s", rp->output);
		fflush(stdout);

		gt_cli_printed = 1;
	}

	if (errnum != 0 && errnum != EAGAIN) {
		gt_cli_client_print_error(errnum);
	}

	if (errnum && gt_cli_printed) {
		gt_cli_printed = 0;
		rl_set_prompt(GT_CLI_PROMPT);
		rl_redisplay();
	}

	return 0;
}

GT_API_CLIENT_DEFINE_HANDLER(cli_command_details,
			     gt_cli_command_details_api_handler);

void
gt_cli_execute_command(char *input)
{
	int rc;
	Gt__CliCommandDump *rq;

	rc = gt_cli_client_connect();
	if (rc) {
		return;
	}

	rq = gt_api_alloc_dump(gt_client, rq, cli_command);
	if (rq == NULL) {
		return;
	}

	rq->input = gt_pbc_strdup(gt_client, input);
	if (rq->input == NULL) {
		gt_api_free_dump(gt_client, rq, cli_command);
		return;
	}

	rc = gt_api_send_dump(gt_client, rq, cli_command);
	if (rc) {
		gt_cli_client_print_error(rc);
	}
}
