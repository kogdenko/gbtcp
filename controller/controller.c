// gpl2
#include <gbtcp/internals.h>

int
main(int argc, char **argv)
{
	int rc, opt, daemonize, affinity, persist;
	const char *proc_comm;

	daemonize = 0;
	affinity = -1;
	persist = 0;
	proc_comm = "controller";
	//log_set_level(LOG_DEBUG);
	while ((opt = getopt(argc, argv, "n:a:dp")) != -1) {
		switch (opt) {
		case 'n':
			proc_comm = optarg;
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
	rc = controller_init(daemonize, proc_comm);
	if (rc) {
		return EXIT_FAILURE;
	}
	if (affinity != -1) {
		set_affinity(affinity);
	}
	controller_start(persist);
	return 0;
}
