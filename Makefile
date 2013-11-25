CFLAGS=-g -Wall
CC=gcc

PROG=kvdb

all: $(PROG)

install: $(PROG)
	install $(PROG) $(HOME)/bin

LIBS=mozilla-sha1/sha1.o

LIB_H=mozilla-sha1/sha1.h

OBJS=nvrom_test.o kvdb.o $(LIBS)

kvdb: $(OBJS)
	$(CC) $(CFLAGS) -o kvdb $(OBJS)

nvrom_test.o: $(LIB_H) kvdb.h

kvdb.o: kvdb.h

.PHONY: clean
clean:
	rm -f *.o $(PROG)

backup: clean
	cd .. ; tar jcvf kvdb.tar.bz2 kvdb
