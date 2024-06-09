CC = gcc
CFLAGS = -Wall -Wextra -Wshadow -Wunreachable-code \
         -Wredundant-decls -Wmissing-declarations \
         -Wold-style-definition -Wmissing-prototypes \
         -Wdeclaration-after-statement -Wno-return-local-addr \
         -Wunsafe-loop-optimizations -Wuninitialized -Werror \
         -Wno-unused-parameter -I/u/rchaney/Classes/cs333/Labs/Lab4
DEBUG = -g
PROG = thread_hash

all: $(PROG)

$(PROG): $(PROG).o
	$(CC) $(CFLAGS) -o $(PROG) $(PROG).o -lcrypt

$(PROG).o: $(PROG).c
	$(CC) $(CFLAGS) -c $(PROG).c

clean:
	rm -f thread_hash *.o *~ \#*

git:
	if [ ! -d .git ] ; then git init; fi
	git add $(PROG).c $(PROG).h [mM]akefile

TAR_FILE = ${LOGNAME}_$(PROG).tar.gz
tar:
	rm -f $(TAR_FILE)
	tar cvfa $(TAR_FILE) thread_hash.c [Mm]akefile

