// SPDX-License-Identifier: LGPL-2.1-only

#include "test.h"

void
die(int errnum, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	if (errnum) {
		fprintf(stderr, " (%d:%s)\n", errnum, strerror(errnum));
	} else {
		fprintf(stderr, "\n");
	}
	abort();
}

void *
xmalloc(int size)
{
	void *ptr;

	ptr = malloc(size);
	if (ptr == NULL) {
		die(0, "malloc(%d) failed", size);
	}
	return ptr;
}

void *
xrealloc(void *ptr, int size)
{
	void *new_ptr;

	new_ptr = realloc(ptr, size);
	if (new_ptr == NULL) {
		die(0, "realloc(%d)", size);
	}
	return new_ptr;
}

char *
strzcpy(char *dest, const char *src, size_t n)
{
	size_t i;

	for (i = 0; i < n - 1; ++i) {
		if (src[i] == '\0') {
			break;
		}
		dest[i] = src[i];
	}
	dest[i] = '\0';
	return dest;
}

void
trace_api_failed(int rc)
{
	int e;

	e = errno;
	printf("Failed, %d", rc);
	if (e) {
		printf(" (%s)", strerror(e));
	}
	printf("\n");
}

void
assertion_failed(int e, const char *expr, const char *file, int line)
{
	fprintf(stderr, "Assertion failed '%s' at %s:%u", expr, file, line); 
	if (e) {
		fprintf(stderr, " (%s)", strerror(e));
	}
	fprintf(stderr, "\n");
	abort();
}


static volatile int fired_SIGUSR1;

static void
sig_handler(int sig_num)
{
	if (sig_num == SIGUSR1) {
		fired_SIGUSR1 = 1;
	}
}

void
wait_SIGUSR1(void)
{
	while (1) {
		if (fired_SIGUSR1) {
			break;
		}
		usleep(1000);
	}
}

void
init_testcase(int argc, char **argv)
{
	signal(SIGUSR1, sig_handler);
}

int
sockaddr_in_aton(struct sockaddr_in *addr, const char *s)
{
	int rc, port;
	char *p, *endptr;
	char buf[32];

	strzcpy(buf, s, sizeof(buf));
	p = strchr(buf, ':');
	if (p == NULL) {
		return -EINVAL;
	}
	*p = 0;
	rc = inet_aton(buf, &addr->sin_addr);
	if (rc != 1) {
		return -EINVAL;
	}
	port = strtoul(p + 1, &endptr, 10);
	if (*endptr != '\0' || port < 0 || port > 65535) {
		return -EINVAL;
	}
	addr->sin_family = AF_INET;
	addr->sin_port = htons(port);
	return 0;
}

int
test_accept(int argc, char **argv)
{
	int fd, fd2, opt;
	struct sockaddr_in addr;

	sockaddr_in_aton(&addr, "0.0.0.0:7385");
	init_testcase(argc, argv);
	TRACE_API((fd = socket(AF_INET, SOCK_STREAM, 0)), != -1);
	opt = 1;
	TRACE_API(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)), != -1);
	opt = 1;
	TRACE_API(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)), != -1);
	TRACE_API(bind(fd, (struct sockaddr *)&addr, sizeof(addr)), != -1);
	TRACE_API(listen(fd, 5), != -1);
	printf("Ready\n");
	fflush(stdout);
	TRACE_API((fd2 = accept(fd, NULL, NULL)), != -1);
	return fd2;
}

int
test_connect(int argc, char **argv)
{
	int fd;
	struct sockaddr_in addr;

	sockaddr_in_aton(&addr, "48.0.0.1:7385");
	init_testcase(argc, argv);
	TRACE_API((fd = socket(AF_INET, SOCK_STREAM, 0)), != -1);
	TRACE_API(connect(fd, (struct sockaddr *)&addr, sizeof(addr)), == 0);
	return fd;
}
