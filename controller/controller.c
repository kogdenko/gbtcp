#include <gbtcp/internals.h>

int
main(int argc, char **argv)
{
	int rc, opt, daemonize;
	const char *proc_name;

	daemonize = 0;
	proc_name = "controller";
	gt_init();
	//log_set_level(LOG_DEBUG);
	while ((opt = getopt(argc, argv, "n:d")) != -1) {
		switch (opt) {
		case 'n':
			proc_name = optarg;
			break;
		case 'd':
			daemonize = 1;
			break;
		}
	}
	rc = controller_init(daemonize, proc_name);
	if (rc) {
		return EXIT_FAILURE;
	}
	controller_loop();
	return 0;
}
