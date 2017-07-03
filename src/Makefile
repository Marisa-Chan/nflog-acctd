VPATH = ../
EXEC = nflog-acctd

# Uncomment to make gcc search kernel source tree for includes
# (You may need to change the directory to match the location
# of your kernel sources.)
#KERNELDIR = -I/usr/src/linux-2.4/include

# Configuration options
# Uncomment for debugging output
DEBUG += -g

# For profiling
#DEBUG += -pg -a -fprofile-arcs

# Disable for debugging
#OPT = -O2

CFLAGS += -Wall -Wstrict-prototypes $(OPT) $(DEBUG) $(KERNELDIR) -D_FILE_OFFSET_BITS=64
OBJECTS = main.o daemon.o process.o utils.o config.o capture.c
LIBS = -lnetfilter_log -lnfnetlink
CC = gcc

all:	$(EXEC)

depend dep:
	for i in *.c;do $(CPP) -M $$i;done > .tmpdepend
	mv .tmpdepend .depend

$(EXEC):	$(OBJECTS)
		$(CC) -o $(EXEC) $(CFLAGS) $^ $(LIBS)

clean:
	rm -f *.o $(EXEC)

testconf: testconf.o config.o
	$(CC) -o testconf testconf.o config.o utils.o

ifeq (.depend,$(wildcard .depend))
include .depend
endif
