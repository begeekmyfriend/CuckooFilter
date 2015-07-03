CFLAGS=-g -Wall
CC=gcc

PROG=cuckoo_db

all: $(PROG)

install: $(PROG)
	install $(PROG) $(HOME)/bin

LIBS=mozilla-sha1/sha1.o

LIB_H=mozilla-sha1/sha1.h

OBJS=nvrom_test.o cuckoo_db.o $(LIBS)

cuckoo_db: $(OBJS)
	$(CC) $(CFLAGS) -o cuckoo_db $(OBJS)

nvrom_test.o: $(LIB_H) cuckoo_db.h

cuckoo_db.o: cuckoo_db.h

.PHONY: clean
clean:
	rm -f *.o $(LIBS) $(PROG)

backup: clean
	cd .. ; tar jcvf cuckoo_db.tar.bz2 cuckoo_db
