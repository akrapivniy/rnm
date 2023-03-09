CC      = gcc
LD      = gcc

SOURCES=rnmctrl.c
OBJECTS=$(SOURCES:.c=.o)

CFLAGS		+= -g -Wall -Wextra -I../include -I../librnm -Wno-unused-parameter -Wformat-truncation=0
LDFLAGS		+= -L../librnm -L../librn  -lrnm -lrn -lpthread -lconfig
all: rnmlib rnmctrl

rnmlib:
	$(MAKE) -C ../librnm

rnmctrl: $(OBJECTS)
	$(LD)  $(OBJECTS) -o $@.bin $(LDFLAGS)

.o:  $(SOURCES)
	$(CC) -I./ -c $(CFLAGS) $< 

clean:
	rm -f *.lst *.o *.elf *.bin *.d
