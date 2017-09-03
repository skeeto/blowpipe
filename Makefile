.POSIX:
CC     = cc -std=c99
CFLAGS = -Wall -Wextra -O3 -g3

all: test blowpipe

test: test.c blowfish.c blowfish.h vectors2.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ test.c blowfish.c

blowpipe: blowpipe.c blowfish.c blowfish.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ blowpipe.c blowfish.c

key.dat:
	printf "helloworld" > $@

check: test blowpipe key.dat
	./test
	for len in $$(seq 0 10) $$(seq 65500 65600); do \
	    head -c$$len /dev/urandom | \
	        ./blowpipe -E -c3 -kkey.dat | \
	        ./blowpipe -D     -kkey.dat > /dev/null; \
	done

clean:
	rm -f test blowpipe key.dat
