// SPDX-License-Identifier: LGPL-2.1-only

#include "subr.h"

static int n_forks = 1;

static void
test_fork(void **state)
{
	int i, rc, status;

	for (i = 0; i < n_forks; ++i) {
		rc = fork();
		assert_return_code(rc, errno);
		if (rc == 0) {
			// In the child: sockets must keep working after fork()
			if (socket(AF_INET, SOCK_STREAM, 0) == -1) {
				_exit(1);
			}
			_exit(0);
		}
	}
	for (i = 0; i < n_forks; ++i) {
		assert_return_code(wait(&status), errno);
		assert_true(WIFEXITED(status));
		assert_int_equal(WEXITSTATUS(status), 0);
	}
	assert_return_code(socket(AF_INET, SOCK_STREAM, 0), errno);
}

int
main(int argc, char **argv)
{
	int opt;
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_fork),
	};

	while ((opt = getopt(argc, argv, "n:")) != -1) {
		switch (opt) {
		case 'n':
			n_forks = strtoul(optarg, NULL, 10);
			break;
		}
	}

	return cmocka_run_group_tests(tests, NULL, NULL);
}
