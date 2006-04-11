MAJOR=2
MINOR=1
CC?=gcc
CFLAGS?=-g -O2 -Wall 
CFLAGS+=-I. -DVERSION=\"$(MAJOR).$(MINOR)\"
prefix?=/usr/local
OBJS=\
	cbtcommon/debug.o\
	cbtcommon/hash.o\
	cbtcommon/text_util.o\
	cbtcommon/sio.o\
	cbtcommon/tcpsocket.o\
	cvsps.o\
	cache.o\
	util.o\
	stats.o\
	cap.o\
	cvs_direct.o\
	list_sort.o

all: cvsps

deps:
	makedepend -Y -I. *.c cbtcommon/*.c

cvsps: $(OBJS)
	$(CC) -o cvsps $(OBJS) -lz

install:
	[ -d $(prefix)/bin ] || mkdir -p $(prefix)/bin
	[ -d $(prefix)/share/man/man1 ] || mkdir -p $(prefix)/share/man/man1
	install cvsps $(prefix)/bin
	install -m 644 cvsps.1 $(prefix)/share/man/man1

clean:
	rm -f cvsps *.o cbtcommon/*.o core

.PHONY: install clean
# DO NOT DELETE

cache.o: ./cbtcommon/hash.h ./cbtcommon/list.h ./cbtcommon/inline.h
cache.o: ./cbtcommon/debug.h cache.h cvsps_types.h cvsps.h util.h
cap.o: ./cbtcommon/debug.h ./cbtcommon/inline.h ./cbtcommon/text_util.h cap.h
cap.o: cvs_direct.h
cvs_direct.o: ./cbtcommon/debug.h ./cbtcommon/inline.h
cvs_direct.o: ./cbtcommon/text_util.h ./cbtcommon/tcpsocket.h
cvs_direct.o: ./cbtcommon/sio.h cvs_direct.h util.h
cvsps.o: ./cbtcommon/hash.h ./cbtcommon/list.h ./cbtcommon/inline.h
cvsps.o: ./cbtcommon/list.h ./cbtcommon/text_util.h ./cbtcommon/debug.h
cvsps.o: ./cbtcommon/rcsid.h cache.h cvsps_types.h cvsps.h util.h stats.h
cvsps.o: cap.h cvs_direct.h list_sort.h
list_sort.o: list_sort.h ./cbtcommon/list.h
stats.o: ./cbtcommon/hash.h ./cbtcommon/list.h ./cbtcommon/inline.h
stats.o: cvsps_types.h cvsps.h
util.o: ./cbtcommon/debug.h ./cbtcommon/inline.h util.h
cbtcommon/debug.o: cbtcommon/debug.h ./cbtcommon/inline.h cbtcommon/rcsid.h
cbtcommon/hash.o: cbtcommon/debug.h ./cbtcommon/inline.h cbtcommon/hash.h
cbtcommon/hash.o: ./cbtcommon/list.h cbtcommon/rcsid.h
cbtcommon/sio.o: cbtcommon/sio.h cbtcommon/rcsid.h
cbtcommon/tcpsocket.o: cbtcommon/tcpsocket.h cbtcommon/debug.h
cbtcommon/tcpsocket.o: ./cbtcommon/inline.h cbtcommon/rcsid.h
cbtcommon/text_util.o: cbtcommon/text_util.h cbtcommon/rcsid.h
