// SPDX-License-Identifier: LGPL-2.1-only

#include "subr.h"

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

int
test_accept(void)
{
	int fd, fd2, opt;
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(7385);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	assert_return_code(fd, errno);
	opt = 1;
	assert_return_code(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt,
				      sizeof(opt)),
			   errno);
	opt = 1;
	assert_return_code(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt,
				      sizeof(opt)),
			   errno);
	assert_return_code(bind(fd, (struct sockaddr *)&addr, sizeof(addr)),
			   errno);
	assert_return_code(listen(fd, 5), errno);
	printf("Ready\n");
	fflush(stdout);
	fd2 = accept(fd, NULL, NULL);
	assert_return_code(fd2, errno);
	return fd2;
}

void
test_parse_argv(int argc, char **argv, char **intf_name, char **peer_name)
{
	int opt;

	if (intf_name != NULL) {
		*intf_name = NULL;
	}

	if (peer_name != NULL) {
		*peer_name = NULL;
	}

	while ((opt = getopt(argc, argv, "i:p:")) != -1) {
		switch (opt) {
		case 'i':
			if (intf_name != NULL) {
				*intf_name = optarg;
			}
			break;

		case 'p':
			if (peer_name != NULL) {
				*peer_name = optarg;
			}
			break;
		}
	}

	if (intf_name != NULL && *intf_name == NULL) {
		die(0, "`-i` not specified");
	}

	if (peer_name != NULL && *peer_name == NULL) {
		die(0, "`-p` not specified");
	}
}
