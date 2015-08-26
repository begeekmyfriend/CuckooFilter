CFLAGS=-g -Wall
CC=gcc
PROG=cuckoo_db
LIBS=mozilla-sha1/sha1.o
LIB_H=mozilla-sha1/sha1.h
OBJS=nvrom_test.o cuckoo_filter.o $(LIBS)

all: $(PROG)

install: $(PROG)
	install $(PROG) $(HOME)/bin

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $(PROG) $(OBJS)

nvrom_test.o: $(LIB_H) cuckoo_filter.h
cuckoo_filter.o: cuckoo_filter.h

.PHONY: clean
clean:
	rm -f *.o $(LIBS) $(PROG)

backup: clean
	cd .. ; tar jcvf cuckoo_filter.tar.bz2 cuckoo_filter
