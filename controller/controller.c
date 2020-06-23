#include <gbtcp/internals.h>

int
main(int argc, char **argv)
{
	int rc, opt, daemonize, affinity;
	const char *proc_comm;

	daemonize = 0;
	affinity = -1;
	proc_comm = "sched";
	//log_set_level(LOG_DEBUG);
	while ((opt = getopt(argc, argv, "n:a:d")) != -1) {
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
		}
	}
	rc = sched_init(daemonize, proc_comm);
	if (rc) {
		return EXIT_FAILURE;
	}
	if (affinity != -1) {
		set_affinity(affinity);
	}
	sched_loop();
	sched_deinit();
	return 0;
}
