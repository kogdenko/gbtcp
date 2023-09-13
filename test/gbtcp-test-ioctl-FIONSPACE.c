// SPDX-License-Identifier: LGPL-2.1-only

#include "test.h"

int
main(int argc, char **argv)
{
#ifdef __linux__
#else /* __linux__ */
	int fd, rc, v, x;

	v = 32768;
	ASSERT(errno, (fd = socket(AF_INET, SOCK_DGRAM, 0)) != -1);
	ASSERT(errno, (rc = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v))) != -1);
	ASSERT(errno, (rc = ioctl(fd, FIONSPACE, &x)) != -1);
	printf("%d, %d\n", v, x);
#endif /* __linux__ */
	return 0;
}
