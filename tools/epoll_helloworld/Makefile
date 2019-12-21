.PHONY: clean

../../bin/bench_epoll: bench_epoll.c
	$(CC) -Wall -g -O2 -pthread bench_epoll.c -o ../../bin/bench_epoll
clean:
	rm -rf *.o ../../bin/bench_epoll
