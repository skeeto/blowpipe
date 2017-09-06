.POSIX:
CC     = cc -std=c99
CFLAGS = -Wall -Wextra -O3 -g3

all: blowpipe

blowpipe: blowpipe.c blowfish.c blowfish.h w32-compat/unistd.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ blowpipe.c blowfish.c

tests/tests: tests/tests.c blowfish.c blowfish.h tests/vectors2.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ tests/tests.c blowfish.c

tests/key.dat:
	printf "helloworld" > $@

test: check
check: tests/tests tests/key.dat blowpipe
	tests/tests
	for len in $$(seq 0 10) $$(seq 65500 65600); do \
	    head -c$$len /dev/urandom | \
	        ./blowpipe -E -c3 -ktests/key.dat | \
	        ./blowpipe -D     -ktests/key.dat > /dev/null; \
	done

clean:
	rm -f blowpipe tests/tests tests/key.dat
