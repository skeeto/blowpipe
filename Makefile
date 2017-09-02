.POSIX:
CC     = cc -std=c99
CFLAGS = -Wall -Wextra -O3

all: test blowcrypt

test: test.c blowfish.c blowfish.h vectors2.h
	$(CC) $(LDFLAGS) -o $@ test.c blowfish.c

blowcrypt: blowcrypt.c blowfish.c blowfish.h
	$(CC) $(LDFLAGS) -o $@ blowcrypt.c blowfish.c

key.dat:
	printf "helloworld" > $@

check: test blowcrypt key.dat
	./test
	for len in $$(seq 0 10) $$(seq 4080 4200); do \
	    head -c$$len /dev/urandom | \
	        ./blowcrypt -E -c3 -kkey.dat | \
	        ./blowcrypt -D     -kkey.dat > /dev/null; \
	done

clean:
	rm -f test blowcrypt key.dat
