#include "test.h"

int
main(int argc, char **argv)
{
	int fd, buf;

	fd = test_accept(argc, argv);
	TRACE_API(read(fd, &buf, sizeof(buf)), == 1);
	return 0;
}
