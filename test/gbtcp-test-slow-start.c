// SPDX-License-Identifier: LGPL-2.1-only

#include "subr.h"

static void
test_slow_start(void **state)
{
	int fd;
	ssize_t rc;
	char buf[15000];

	fd = test_accept();
	rc = write(fd, &buf, sizeof(buf));
	assert_return_code(rc, errno);
	assert_int_equal(rc, sizeof(buf));
}

int
main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_slow_start),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
