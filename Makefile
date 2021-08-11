CC=cc
LD=cc
CFLAGS= -g -pedantic -Wall -Wextra
LDFLAGS=-g -pedantic -Wall -Wextra

.PHONY: all clean

all: self_tests

clean:
	rm -f self_tests.o
	rm -f self_tests

self_tests: self_tests.o
	$(LD) $(LDFLAGS) $< -o $@

self_tests.o: self_tests.c dh_cuts.h
	$(CC) $(CFLAGS) $< -c -o $@

