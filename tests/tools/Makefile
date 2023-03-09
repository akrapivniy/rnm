CC      = gcc
LD      = gcc

SOURCES=test_tools.c

CFLAGS		+= -g -Wall -Wextra -lrt 
LDFLAGS		+= -lpthread -lconfig -lrt 
all: test_tools.o

.o:  $(SOURCES)
	$(CC) -I./ -c $(CFLAGS) $< 

clean:
	rm -f *.lst *.o *.elf *.bin *.d
