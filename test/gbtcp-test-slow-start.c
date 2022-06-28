#include "test.h"

int
main(int argc, char **argv)
{
	int fd;
	char buf[15000];

	fd = test_accept(argc, argv);
	TRACE_API(write(fd, &buf, sizeof(buf)), == sizeof(buf));
	return 0;
}
