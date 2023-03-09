ifndef CC
CC = gcc
endif
ifndef LD
LD = gcc
endif

SOURCES=rnmserver.c
OBJECTS=$(SOURCES:.c=.o)

CFLAGS		+= -g -Wall -Wextra -I../librnm -I../include
LDFLAGS		+= -L../librnm -lrnm -lrn -lpthread -lconfig
all: rnmlib rnmserver

rnmlib:
	$(MAKE) -C ../librnm

rnmserver: $(OBJECTS)
	$(CC)  $(OBJECTS) -o $@.bin $(LDFLAGS)

.o:  $(SOURCES)
	$(CC) -I./ -c $(CFLAGS) $< 

clean:
	rm -f *.lst *.o *.elf *.bin *.d
