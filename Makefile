.POSIX:
.SUFFIXES:
CC     = cc -std=c99
CFLAGS = -Wall -Wextra -O3 -g3
PREFIX = /usr/local
EXEEXT =

all: blowpipe$(EXEEXT)

blowpipe$(EXEEXT): blowpipe.c blowfish.c blowfish.h w32-compat/unistd.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ blowpipe.c blowfish.c

tests/tests$(EXEEXT): tests/tests.c blowfish.c blowfish.h tests/vectors2.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ tests/tests.c blowfish.c

tests/key.dat:
	printf "helloworld" > $@

blowpipe-cli.c: blowpipe.c blowfish.c blowfish.h w32-compat/unistd.h
	cat blowfish.h w32-compat/getopt.h w32-compat/unistd.h \
	    blowfish.c blowpipe.c | \
	    sed -r 's@^(#include +".+)@/* \1 */@g' > $@

test: check
check: tests/tests$(EXEEXT) tests/key.dat blowpipe$(EXEEXT)
	tests/tests$(EXEEXT)
	for len in $$(seq 0 10) $$(seq 65500 65600); do \
	    head -c$$len /dev/urandom | \
	        ./blowpipe$(EXEEXT) -E -c3 -ktests/key.dat | \
	        ./blowpipe$(EXEEXT) -D     -ktests/key.dat > /dev/null; \
	done

amalgamation: blowpipe-cli.c

install: blowpipe$(EXEEXT) blowpipe.1
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	mkdir -p $(DESTDIR)$(PREFIX)/share/man/man1
	cp -f blowpipe$(EXEEXT) $(DESTDIR)$(PREFIX)/bin
	gzip < blowpipe.1 > $(DESTDIR)$(PREFIX)/share/man/man1/blowpipe.1.gz

clean:
	rm -f blowpipe$(EXEEXT) tests/tests$(EXEEXT)
	rm -f tests/key.dat blowpipe-cli.c
