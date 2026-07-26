// SPDX-License-Identifier: LGPL-2.1-only

#include "subr.h"

static void
test_FP(void **state)
{
	int fd, buf;
	ssize_t rc;

	fd = test_accept();
	rc = read(fd, &buf, sizeof(buf));
	assert_return_code(rc, errno);
	assert_int_equal(rc, 1);
}

int
main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_FP),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
