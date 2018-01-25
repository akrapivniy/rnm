CC      = gcc
LD      = gcc

SOURCES=rnmmon.c
OBJECTS=$(SOURCES:.c=.o)


CFLAGS		+= -g -Wall -Wextra -I../librnm -I../include -Wno-unused-parameter
LDFLAGS		+= -L../librnm  -lrnm -lrn -lpthread -lconfig
all: rnmlib rnmmon

rnmlib:
	$(MAKE) -C ../librnm

rnmmon: $(OBJECTS)
	$(LD)  $(OBJECTS) -o $@.bin $(LDFLAGS)

.o:  $(SOURCES)
	$(CC) -I./ -c $(CFLAGS) $< 

clean:
	rm -f *.lst *.o *.elf *.bin *.d
