// gpl2
#include <gbtcp/internals.h>

static void
usage()
{
	printf("TODO: usage\n");
}

int
main(int argc, char **argv)
{
	int rc, opt, daemonize, affinity, persist;
	const char *proc_name;

	daemonize = 0;
	affinity = -1;
	persist = 0;
	proc_name = "controller";
	while ((opt = getopt(argc, argv, "hn:a:dp")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			return 0;
		case 'n':
			proc_name = optarg;
			break;
		case 'a':
			affinity = strtoul(optarg, NULL, 10);
			break;
		case 'd':
			daemonize = 1;
			break;
		case 'p':
			persist = 1;
			break;
		}
	}
	rc = controller_init(daemonize, 1, proc_name);
	if (rc) {
		return EXIT_FAILURE;
	}
	if (affinity != -1) {
		set_affinity(affinity);
	}
	while (!controller_done || persist) {
		controller_process();
	}
	controller_deinit();
	return 0;
}
