SRCS := $(wildcard *test*.c)
TESTS := $(patsubst %.c, ../bin/%, $(SRCS))
CFLAGS := -g -Wall -Werror -O0

all:  $(TESTS)

.PHONY: clean

../bin/%: %.c subr.o
	$(CC) $(CFLAGS) $< -o $@ subr.o

subr.o: subr.c
	$(CC) $(CFLAGS) -o subr.o -c subr.c

clean:
	rm -rf $(TESTS) *.o
