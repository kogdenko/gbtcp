// gpl2
#include <gbtcp/internals.h>

int
main(int argc, char **argv)
{
	int rc, opt, daemonize, affinity, persist;

	daemonize = 0;
	affinity = -1;
	persist = 0;
	//log_set_level(LOG_DEBUG);
	while ((opt = getopt(argc, argv, "a:dp")) != -1) {
		switch (opt) {
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
	rc = gtl_controller_init(daemonize);
	if (rc) {
		return EXIT_FAILURE;
	}
	if (affinity != -1) {
		gtl_set_affinity(affinity);
	}
	gtl_controller_start(persist);
	return 0;
}
