#include <gbtcp/internals.h>

#define CURMOD app

static struct sock *lso;
static int http_len;
static const char *http =
	"HTTP/1.0 200 OK\r\n"
	"Server: so_echo\r\n"
	"Content-Type: text/html\r\n"
	"Connection: close\r\n"
	"Hi\r\n\r\n";

int
set_affinity(int cpu_id)
{
	int rc;
	cpu_set_t cpumask;

	CPU_ZERO(&cpumask);
	CPU_SET(cpu_id, &cpumask);
	rc = pthread_setaffinity_np(pthread_self(), sizeof(cpumask), &cpumask);
	if (rc != 0) {
		ERR(rc, "failed; cpu_id=%d", cpu_id);
	}
	return -rc;
}

static void
on_read(struct file_aio *aio, int fd, short revents)
{
	int rc;
	struct sock *so;
	struct iovec iov;

	so = (struct sock *)aio - 1;
	file_aio_cancel(aio);
	rc = so_recvfrom_zerocopy(so, &iov, 0, NULL, NULL);
	if (rc > 0) {
		so_recv_drain(so, rc);
		iov.iov_base = (char *)http;
		iov.iov_len = http_len;
		so_sendto(so, &iov, 1, 0, 0, 0);
	}
	so_close(so);
	
}

static void
on_accept(struct file_aio *a, int fd, short revents)
{
	int rc;
	struct file_aio *aio;
	struct sock *so;

	while (1) {
		rc = so_accept(&so, lso, NULL, NULL, SOCK_NONBLOCK);
		if (rc < 0) {
			break;
		}
		aio = (struct file_aio *)(so + 1);
		file_aio_init(aio);
		file_aio_set(&so->so_file, aio, POLLIN, on_read);
	}
}

static void
loop(struct sockaddr_in *a, int affinity)
{
	int rc;
	struct file_aio aio;

	if (affinity >= 0) {
		set_affinity(affinity);
	}
	rc = service_attach();
	if (rc) {
		die(-rc, "service_attach() failed");
	}
	SERVICE_LOCK;
	rc = so_socket(&lso, AF_INET, SOCK_STREAM, SOCK_NONBLOCK, 0);
	if (rc < 0) {
		die(-rc, "socket() failed");
	}
	rc = so_bind(lso, a);
	if (rc < 0) {
		die(-rc, "bind() failed");
	}
	rc = so_listen(lso, 0);
	if (rc < 0) {
		die(-rc, "listen() failed");
	}
	file_aio_init(&aio);
	file_aio_set(&lso->so_file, &aio, POLLIN, on_accept);
	while (1) {
		wait_for_fd_events();
	}
	SERVICE_UNLOCK;
}

int
main(int argc, char **argv)
{
	int i, rc, opt, nprocs, affinity;
	struct sockaddr_in a;

	nprocs = 1;
	affinity = -1;
	while ((opt = getopt(argc, argv, "a:P:")) != -1) {
		switch (opt) {
		case 'a':
			affinity = strtoul(optarg, NULL, 10);
			break;
		case 'P':
			nprocs = strtoul(optarg, NULL, 10);
			break;
		}
	}
	http_len = strlen(http);
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = 0;
	a.sin_port = htons(80);
	if (nprocs < 1) {
		nprocs = 1;
	}
	gt_init(NULL);
	gt_preload_passthru = 1;
	for (i = 1; i < nprocs; ++i) {
		rc = sys_fork();
		if (rc == 0) {
			loop(&a, affinity == -1 ? affinity : affinity + i);
		}
	}
	loop(&a, affinity);
	return 0;
}
