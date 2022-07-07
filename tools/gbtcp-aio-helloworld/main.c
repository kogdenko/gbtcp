// GPL V2 License
#include <tools/common/subr.h>
#include <tools/common/worker.h>
#include <gbtcp/gbtcp.h>

#define PROG_NAME "gbtcp-aio-helloworld"

#ifdef GTL_HAVE_XDP
#define HAVE_XDP " GTL_HAVE_XDP"
#else // GTL_HAVE_XDP
#define HAVE_XDP ""
#endif // GTL_HAVE_XDP

#ifdef GTL_HAVE_NETMAP
#define HAVE_NETMAP " GTL_HAVE_NETMAP"
#else // GTL_HAVE_NETMAP
#define HAVE_NETMAP ""
#endif // GTL_HAVE_NETMAP

#ifdef GTL_HAVE_VALE
#define HAVE_VALE " GTL_HAVE_VALE"
#else // GTL_HAVE_VAL
#define HAVE_VALE ""
#endif // GTL_HAVE_VALE

static int g_fd;
static int http_len;
static const char *http =
	"HTTP/1.0 200 OK\r\n"
	"Server: "PROG_NAME"\r\n"
	"Content-Type: text/html\r\n"
	"Connection: close\r\n"
	"Hi\r\n\r\n";

static void
read_handler(void *unused, int fd, short revents)
{
	int rc;
	struct iovec iov;

	if (revents & POLLIN) {
		rc = gt_aio_recvfrom(fd, &iov, 0, NULL, NULL);
		if (rc > 0) {
			gt_recvdrain(fd, rc);
			iov.iov_base = (char *)http;
			iov.iov_len = http_len;
			gt_send(fd, http, http_len, MSG_NOSIGNAL);
			gt_close(fd);
			return;
		}
	}
	if (revents & (POLLERR|POLLHUP)) {
		gt_close(fd);
	}
}

static void
accept_handler(void *unused, int fd, short revents)
{
	int rc, new_fd;

	rc = gt_accept4(fd, NULL, NULL, 0);
	if (rc > 0) {
		new_fd = rc;
		gt_aio_set(new_fd, read_handler);
	}
}

static void *
worker_loop(void *udata)
{
	struct worker *worker;

	worker = udata;	
	set_affinity(worker->wrk_cpu);
	gt_aio_set(g_fd, accept_handler);
	gt_poll(NULL, 0, -1);
	return NULL;
}

static void
usage(void)
{
}

int
main(int argc, char **argv)
{
	int rc, fd, opt, port, Sflag;
	struct sockaddr_in a;
	cpuset_t worker_cpus;

	Sflag = 0;
	port = 80;
	http_len = strlen(http);
	CPU_ZERO(&worker_cpus);
	while ((opt = getopt(argc, argv, "hvp:la:S")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			return EXIT_SUCCESS;
		case 'v':
			printf("version: 0.5.1\n");
			printf("gbtcp: 0.2.1\n");
			printf("commit: %s\n", GTL_COMMIT);
			printf("config:%s%s%s\n", HAVE_XDP, HAVE_NETMAP, HAVE_VALE);
			return EXIT_SUCCESS;
		case 'p':
			port = strtoul(optarg, NULL, 10);
			break;
		case 'a':
			rc = cpuset_from_string(&worker_cpus, optarg);
			if (rc < 0) {
				die(-rc, "-a: Invalid cpu list");
			}
			break;
		case 'S':
			Sflag = 1;
			break;
		}
	}
	if (Sflag) {
		stop_master(PROG_NAME, port);
		return EXIT_SUCCESS;
	}
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = 0;
	a.sin_port = htons(port);
	gt_preload_passthru = 1;
	rc = gt_socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
	if (rc < 0) {
		die(-rc, "gt_socket() failed");
	}
	fd = rc;
	rc = gt_bind(fd, (struct sockaddr *)&a, sizeof(a));
	if (rc < 0) {
		die(-rc, "gt_bind() failed");
	}
	rc = gt_listen(fd, 0);
	if (rc < 0) {
		die(-rc, "gt_listen() failed");
	}
	g_fd = fd;
	start_master(&worker_cpus,
		0,
		PROG_NAME,
		port,
		worker_loop,
		gt_fork,
		gt_sleep);
	return EXIT_SUCCESS;
}
