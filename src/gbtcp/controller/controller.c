// SPDX-License-Identifier: LGPL-2.1-only

#include <gbtcp/kernel/cli.h>
#include <gbtcp/kernel/subr.h>
#include <gbtcp/kernel/worker.h>

static void
gt_print_usage(void)
{
	printf("gbtcp-controller [-h] [-a <cpu>] [-d]\n"
	       "Options:\n"
	       "-h:  Print this help\n"
	       "-a:  Set affinity\n"
	       "-d:  Daemonize\n");
}

int
main(int argc, char **argv)
{
	int rc, opt, daemonize, affinity;

	daemonize = 0;
	affinity = -1;
	//log_set_level(LOG_DEBUG);
	while ((opt = getopt(argc, argv, "ha:d")) != -1) {
		switch (opt) {
		case 'h':
			gt_print_usage();
			return 0;

		case 'a':
			affinity = strtoul(optarg, NULL, 10);
			break;

		case 'd':
			daemonize = 1;
			break;
		}
	}

	rc = gt_controller_init(daemonize);
	if (rc) {
		return EXIT_FAILURE;
	}

	if (affinity != -1) {
		gt_set_affinity(affinity);
	}

	while (daemonize || !gt_cli_done) {
		controller_process();
	}

	gt_controller_deinit();
	return 0;
}
