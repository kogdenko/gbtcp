#include "test.h"
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/queue.h>

enum {
	TEST_SIMPLE,
	TEST_PKT
};

struct test {
	LIST_ENTRY(test) list;
	int type;
	char name[128];
};

LIST_HEAD(test_head, test);

#define TEST_DIR "test"
#define BIN_DIR "bin"

static struct test_head tests;
static char root_path[PATH_MAX];
static char *netstat;
static char *sysctl_conf;
static char *libgbtcp;
static char *tcpkt;
static int run_mode = 3;

static void
strcatv(char **pdst, ...)
{
	int len, off;
	char *x, *dst;
	va_list ap;

	dst = *pdst;
	if (dst == NULL) {
		off = 0;
	} else {
		off = strlen(dst);
	}
	va_start(ap, pdst);
	while ((x = va_arg(ap, char *)) != NULL) {
		len = strlen(x);
		dst = xrealloc(dst, off + len + 1);
		memcpy(dst + off, x, len);
		off += len;
	}
	va_end(ap);
	dst[off] = '\0';
	*pdst = dst;
}

static int
isexec(const char *path)
{
	int rc;
	struct stat sb;

	rc = stat(path, &sb);
	if (rc == -1) {
		return -errno;
	}
	return (sb.st_mode & S_IXUSR) ? 1 : 0;
}

static void
xisexec(const char *path)
{
	int rc;

	rc = isexec(path);
	if (rc <= 0) {
		die(-rc, "'%s': is not an executable", path);
	}
}

static int
isdir(const char *path)
{
	int rc;
	struct stat sb;

	rc = stat(path, &sb);
	if (rc == -1) {
		return -errno;
	}
	return S_ISDIR(sb.st_mode);
}

static void
xisdir(const char *path)
{
	int rc;

	rc = isdir(path);
	if (rc <= 0) {
		die(-rc, "'%s': is not a directory", path);
	}
}

static int
isreg(const char *path)
{
	int rc;
	struct stat sb;

	rc = stat(path, &sb);
	if (rc == -1) {
		return -errno;
	}
	return S_ISREG(sb.st_mode);
}

void
xisreg(const char *path)
{
	int rc;

	rc = isreg(path);
	if (rc <= 0) {
		die(-rc, "'%s': is not a regular file", path);
	}
}

static void
set_root_path(const char *path)
{
	char *tmppath;

	if (path == NULL) {
		getcwd(root_path, PATH_MAX);
	} else {
		strzcpy(root_path, path, PATH_MAX);
	}
	basename(root_path);
	xisdir(root_path);
	tmppath = NULL;
	strcatv(&tmppath, root_path, "/"TEST_DIR, NULL);
	xisdir(tmppath);
	free(tmppath);
	strcatv(&netstat, root_path, "/"BIN_DIR"/", "netstat", NULL);
	xisexec(netstat);
	strcatv(&sysctl_conf, root_path, "/"TEST_DIR"/", "sysctl.conf", NULL);
	xisreg(sysctl_conf);
	strcatv(&libgbtcp, root_path, "/"BIN_DIR"/", "libgbtcp.so", NULL);
	xisexec(libgbtcp);
	strcatv(&tcpkt, root_path, "/"TEST_DIR"/", "tcpkt.sh", NULL);
	xisexec(tcpkt);
}

static void
add_test(const char *filename)
{
	char *tmppath;
	struct test *test;

	test = xmalloc(sizeof(*test));
	memset(test, 0, sizeof(*test));
	strzcpy(test->name, filename, sizeof(test->name));
	tmppath = NULL;
	strcatv(&tmppath, root_path, "/"TEST_DIR"/", filename, ".pkt", NULL);
	if (isreg(tmppath) == 1) {
		test->type = TEST_PKT;
	} else {
		test->type = TEST_SIMPLE;
	}
	free(tmppath);
	LIST_INSERT_HEAD(&tests, test, list);
}

static struct test *
find_test(const char *name)
{
	struct test *test;

	LIST_FOREACH(test, &tests, list) {
		if (!strcmp(test->name, name)) {
			return test;
		}
	}
	return NULL;
}

static void
mk_log_dir()
{
	int rc;
	char *tmppath;

	tmppath = NULL;
	strcatv(&tmppath, root_path, "/"TEST_DIR"/unittest.log", NULL);
	rc = mkdir(tmppath, ACCESSPERMS);
	if (rc == -1 && errno != EEXIST) {
		die(errno, "mkdir('%s') failed", tmppath);
	}
	free(tmppath);
}

static FILE *
open_log(const char *filename, const char *suffix)
{
	char *tmppath;
	FILE *file;

	tmppath = NULL;
	strcatv(&tmppath, root_path, "/"TEST_DIR"/unittest.log/",
	        filename, suffix, NULL);
	file = fopen(tmppath, "w");
	if (file == NULL) {
		die(errno, "fopen('%s') failed", tmppath);
	}
	free(tmppath);
	return file;
}

struct proc {
	char *command;
	FILE *pipe;
	FILE *log;
};

static void
start_process(const char *filename, int preload, struct proc *proc)
{
	proc->log = open_log(filename, NULL);
	proc->command = NULL;
	if (preload) {
		strcatv(&proc->command, "GBTCP_SYSCTL=", sysctl_conf,
		        " LD_PRELOAD=", libgbtcp, " ", NULL);
	}
	strcatv(&proc->command, root_path, "/"BIN_DIR"/", filename, NULL);
	proc->pipe = popen(proc->command, "r");
	if (proc->pipe == NULL) {
		die(errno, "popen('%s') failed", proc->command);
	}
}

static void
start_tcpkt(const char *filename, struct proc *proc)
{
	proc->log = open_log(filename, ".pkt");
	proc->command = NULL;
	strcatv(&proc->command, tcpkt, " ", root_path, "/"TEST_DIR"/",
	        filename, ".pkt", NULL);
	proc->pipe = popen(proc->command, "r");
	if (proc->pipe == NULL) {
		die(errno, "popen('%s') failed", proc->command);
	}
}

static int
stop_process(struct proc *proc)
{
	int rc;

	if (proc->pipe == NULL) {
		return 0;
	} else {
		rc = pclose(proc->pipe);
		if (rc == -1) {
			die(errno, "pclose('%s') failed", proc->command);
		}
		fclose(proc->log);
		free(proc->command);
		return WEXITSTATUS(rc);
	}
}

static int
exec_test_simple(struct test *test, int preload)
{
	int rc;
	char buf[256];
	struct pollfd pfd;
	struct proc proc;

	start_process(test->name, preload, &proc);
	pfd.fd = fileno(proc.pipe);
	pfd.events = POLLIN;
	while (1) {
		rc = poll(&pfd, 1, -1);
		if (rc == 1) {
			rc = read(pfd.fd, buf, sizeof(buf));
			if (rc <= 0) {
				break;
			}
			fwrite(buf, 1, rc, proc.log);
		}
	}
	rc = stop_process(&proc);
	return rc;
}

static int
exec_test_pkt(struct test *test, int preload)
{
	int i, rc, rc0, rc1, tcpkt_started = 0;
	void *ptr;
	char buf[256];
	struct pollfd pfds[2];
	struct proc procs[2];

	start_process(test->name, preload, procs + 0);
	memset(procs + 1, 0, sizeof(struct proc));
	pfds[0].fd = fileno(procs[0].pipe);
	pfds[0].events = POLLIN;
	pfds[1].fd = -1;
	pfds[1].events = POLLIN;
	while (pfds[0].fd != -1 || pfds[1].fd != -1) {
		poll(pfds, 2, -1);
		for (i = 0; i < 2; ++i) {
			if (pfds[i].fd == -1 ||
			    (pfds[i].revents | POLLIN) == 0) {
				continue;
			}
			rc = read(pfds[i].fd, buf, sizeof(buf));
			if (rc <= 0) {
				pfds[i].fd = -1;
				continue;
			}
			fwrite(buf, 1, rc, procs[i].log);
			if (i == 0 && tcpkt_started == 0) {
				ptr = memmem(buf, rc, STRSZ("\nReady"));
				if (ptr != NULL) {
					tcpkt_started = 1;
					start_tcpkt(test->name, procs + 1);
					pfds[1].fd = fileno(procs[1].pipe);
				} else {
					ptr = memmem(buf, rc, STRSZ("\nFailed"));
					if (ptr != NULL) {
						stop_process(procs + 0);
						return 1;
					}
				}
			}
		}
	}
	rc0 = stop_process(procs + 0);
	rc1 = stop_process(procs + 1);
	if (rc0) {
		return rc0;
	}
	if (rc1) {
		return rc1;
	}
	return 0;
}

static int
exec_test(struct test *test, int preload)
{
	int rc;

	switch (test->type) {
	case TEST_PKT:
		rc = exec_test_pkt(test, preload);
		break;
	case TEST_SIMPLE:
		rc = exec_test_simple(test, preload);
		break;
	default:
		rc = 0;
		assert(0);
		break;
	}
	return rc;
}

static void
scan_test_dir()
{
	int rc;
	char *tmppath;
	DIR *dir;
	struct dirent *entry;
	struct stat sb;
	char x[PATH_MAX];

	LIST_INIT(&tests);
	tmppath = NULL;
	strcatv(&tmppath, root_path, "/"BIN_DIR, NULL);
	dir = opendir(tmppath);
	if (dir == NULL) {
		die(errno, "opendir('%s') failed", tmppath);
	}	
	while ((entry = readdir(dir)) != NULL) {
		if (!strncmp(entry->d_name, "test_", 5)) {
			snprintf(x, sizeof(x), "%s/%s", tmppath, entry->d_name);
			rc = stat(x, &sb);
			if (rc == -1) {
				die(errno, "stat('%s') failed", x);
			}
			if (sb.st_mode & S_IXUSR) {
				add_test(entry->d_name);
			}
		}
	}
	free(tmppath);
	closedir(dir);
}

/*static void
invalid_arg(int opt, const char *val)
{
	die(0, "Invalid argument '-%c': %s", opt, val);
}*/

static void
sig_handler(int signum)
{
	switch (signum) {
	case SIGALRM:
		printf(".");
		fflush(stdout);
		alarm(1);
		break;
	}
}

static void
exec_test_wrap(struct test *test)
{
	int rc, i;

	printf("%s ", test->name);
	fflush(stdout);
	for (i = 0; i < 2; ++i) {
		alarm(1);
		if (run_mode && (1 << i)) {
			rc = exec_test(test, i);
			alarm(0);
			if (rc == 0) {
				printf(" [Ok] ");
			} else {
				printf(" [Failed %d] ", rc);
			}
		}
	}
	printf("\n");
}

int
main(int argc, char **argv)
{
	int opt, lflag;
	struct test *test;

	signal(SIGALRM, sig_handler);
	lflag = 0;
	while ((opt = getopt(argc, argv, "hr:lm:")) != -1) {
		switch (opt) {
		case 'h':
		case 'r':
			set_root_path(optarg);
			break;
		case 'l':
			lflag = 1;
			break;
		case 'm':
			run_mode = strtoul(optarg, NULL, 10);
			break;
		}
	}
	if (root_path[0] == '\0') {
		set_root_path(NULL);
	}
	scan_test_dir();
	mk_log_dir();
	if (lflag) {
		LIST_FOREACH(test, &tests, list) {
			if (test->type == TEST_PKT) {
				printf("%s(.pkt)\n", test->name);
			} else {
				printf("%s\n", test->name);
			}      
		}
		return 0;
	}
	if (optind == argc) {
		LIST_FOREACH(test, &tests, list) {
			exec_test_wrap(test);
		}
	} else {
		for (; optind < argc; ++optind) {
			test = find_test(argv[optind]);
			if (test == NULL) {
				fprintf(stderr, "test '%s' not found\n",
				        argv[optind]);
				return EXIT_FAILURE;
			}
			exec_test_wrap(test);
		}
	}
	return EXIT_SUCCESS;
}
