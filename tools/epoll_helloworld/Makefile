.PHONY: clean

SRC = epoll_helloworld.c
BIN = ../../bin/epoll_helloworld

$(BIN): $(SRC)
	$(CC) -Wall -g -O2 -pthread $(SRC) -o $(BIN)
clean:
	rm -rf *.o $(BIN)
