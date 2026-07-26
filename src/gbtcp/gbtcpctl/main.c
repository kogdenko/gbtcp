// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gbtcp/kernel/cli.h>
#include <gbtcp/kernel/fd_event.h>
#include <gbtcp/kernel/mm.h>
#include <gbtcp/kernel/vector.h>
#include <gbtcp/kernel/worker.h>

int
main(int argc, char **argv)
{
	int i, rc, ret;
	char *input;

	// TODO: gt_utility_init() not good name
	// Not a worker: no service slot, no shared memory — all further
	// allocations (CLI, API, protobuf) come from the system heap via
	// gt_get_allocator().
	rc = gt_utility_init();
	if (rc) {
		fprintf(stderr, "gbtcpctl: init failed (%s)\n", strerror(-rc));
		return 1;
	}

	ret = 0;
	rc = gt_cli_client_init();
	if (rc) {
		ret = 1;
		goto out;
	}

	rc = gt_cli_client_connect();
	if (rc) {
		ret = 2;
		goto out;
	}

	if (argc > 1) {
		input = NULL;
		for (i = 1; i < argc; ++i) {
			if (input != NULL) {
				gt_str_addchar(input, ' ');
			}
			gt_str_addcstr(input, argv[i]);
		}

		gt_cli_execute_command(input);

		gt_str_free(input);
		goto out;
	}

	while (!gt_cli_done) {
		wait_for_fd_events();
	}

	gt_cli_client_deinit();
	printf("\n");
out:
	return ret;
}
