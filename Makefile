.POSIX:
CC = c99
CFLAGS = -Wall -Wextra -O3
test: test.c blowfish.c blowfish.h vectors2.h
	$(CC) $(LDFLAGS) -o $@ test.c blowfish.c
clean:
	rm -f test
