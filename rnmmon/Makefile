ifndef CC
CC = gcc
endif
ifndef LD
LD = gcc
endif


SOURCES=rnmmon.c
OBJECTS=$(SOURCES:.c=.o)


CFLAGS		+= -g -Wall -Wextra -I../librnm -I../include -Wno-unused-parameter -Wformat-truncation=0
LDFLAGS		+= -L../librnm  -lrnm -lrn -lpthread -lconfig
all: rnmlib rnmmon

rnmlib:
	$(MAKE) -C ../librnm

rnmmon: $(OBJECTS)
	$(CC)  $(OBJECTS) -o $@.bin $(LDFLAGS)

.o:  $(SOURCES)
	$(CC) -I./ -c $(CFLAGS) $< 

clean:
	rm -f *.lst *.o *.elf *.bin *.d
