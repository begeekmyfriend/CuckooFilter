CFLAGS=-g -Wall
CC=gcc

PROG=cuckoo_hash

all: $(PROG)

install: $(PROG)
	install $(PROG) $(HOME)/bin

LIBS=mozilla-sha1/sha1.o

LIB_H=mozilla-sha1/sha1.h

OBJS=nvrom_test.o cuckoo_hash.o $(LIBS)

cuckoo_hash: $(OBJS)
	$(CC) $(CFLAGS) -o cuckoo_hash $(OBJS)

nvrom_test.o: $(LIB_H) cuckoo_hash.h

cuckoo_hash.o: cuckoo_hash.h

.PHONY: clean
clean:
	rm -f *.o $(LIBS) $(PROG)

backup: clean
	cd .. ; tar jcvf cuckoo_hash.tar.bz2 cuckoo_hash
