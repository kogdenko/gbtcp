// SPDX-License-Identifier: LGPL-2.1-only

#include "subr.h"

static void
test_ioctl_FIONSPACE(void **state)
{
#ifdef __linux__
	skip();
#else // __linux__
	int fd, v, x;

	v = 32768;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	assert_return_code(fd, errno);
	assert_return_code(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v)),
			   errno);
	assert_return_code(ioctl(fd, FIONSPACE, &x), errno);
	printf("%d, %d\n", v, x);
#endif // __linux__
}

int
main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_ioctl_FIONSPACE),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
