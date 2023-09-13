// SPDX-License-Identifier: LGPL-2.1-only

#include "test.h"

int
main(int argc, char **argv)
{
	int i, n, rc, opt;

	n = 1;
	while ((opt = getopt(argc, argv, "n:")) != -1) {
		switch (opt) {
		case 'n':
			n = strtoul(optarg, NULL, 10);
			break;
		}
	}
	for (i = 0; i < n; ++i) {
		rc = fork();
		if (rc == 0) {
			socket(AF_INET, SOCK_STREAM, 0);
		}
	}
	socket(AF_INET, SOCK_STREAM, 0);
	return 0;
}
