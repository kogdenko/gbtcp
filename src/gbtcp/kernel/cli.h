// SPDX-License-Identifier: LGPL-2.1-only

#ifndef GBTCP_CLI_H
#define GBTCP_CLI_H

#include <gbtcp/kernel/ip_addr.h>
#include <gbtcp/kernel/list.h>

struct gt_cli_context;
struct gt_cli_arg_desc;

struct gt_cli_arg {
	struct gt_dlist arg_link;

	const char *arg_name;
	void *arg_value;

	// Internal use
	struct gt_cli_arg_desc *arg_desc;
};

typedef int (*gt_cli_command_f)(void *ctx, struct gt_dlist *arg_head,
				void *udata);
typedef void *(*gt_cli_arg_parse_f)(const char *s);
typedef void (*gt_cli_arg_free_f)(void *arg);

extern u8 gt_cli_done;

int gt_cli_register_command(const char *path, gt_cli_command_f command_fn,
			    void *udata, const char *arg_description);

int gt_cli_register_arg_type(const char *arg_type_name,
			     gt_cli_arg_parse_f parse_fn,
			     gt_cli_arg_free_f free_fn);

void gt_cli_output3(struct gt_cli_context *ctx, u32 marker, char *output);
#define gt_cli_output(ctx, output) gt_cli_output3(ctx, ~0, output)

void gt_cli_printf3(struct gt_cli_context *ctx, u32 marker, const char *format,
		    ...) __attribute__((format(printf, 3, 4)));
#define gt_cli_printf(ctx, format, ...) \
	gt_cli_printf3(ctx, ~0, format, ##__VA_ARGS__)

void gt_cli_server_init(void);

int gt_cli_server_play_file(void);

int gt_cli_client_init(void);
void gt_cli_client_deinit(void);
int gt_cli_client_connect(void);
void gt_cli_execute_command(char *input);

#endif
