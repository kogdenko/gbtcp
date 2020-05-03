#include <gbtcp/internals.h>

int
main(int argc, char **argv)
{
	int rc, opt, daemonize;
	const char *proc_name;
	struct log *log;

	daemonize = 0;
	proc_name = "controller";
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
	dlsym_all();
	log_init_early();
	log = log_trace0();
	rc = proc_controller_init(log, daemonize, proc_name);
	if (rc) {
		return EXIT_FAILURE;
	}
	proc_controller_loop();
	return 0;
}
