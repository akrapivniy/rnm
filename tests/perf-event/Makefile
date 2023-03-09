CC = gcc
CFLAGS = -Wall -Winline -pipe -I../../include -I../../librnm -I../tools -Wno-multichar -Wformat-truncation=0
LIBS =  -L../../librnm -pthread  -lrnm -lrn -lconfig
OBJECTS = ../tools/test_tools.o

all:rnmlib rnm-test-server rnm-test-write-client rnm-test-event-client rnm-test-monitor

rnmlib:
	$(MAKE) -C ../../librnm

rnm-test-server:
	@$(CC) $(CFLAGS) $@.c $(OBJECTS) -o $@.bin $(LIBS)
rnm-test-monitor:
	@$(CC) $(CFLAGS) $@.c $(OBJECTS) -o $@.bin $(LIBS)
rnm-test-event-client:
	@$(CC) $(CFLAGS) $@.c $(OBJECTS) -o $@.bin $(LIBS)
rnm-test-write-client:
	@$(CC) $(CFLAGS) $@.c $(OBJECTS) -o $@.bin $(LIBS)

clean:
	rm -f *.o *.bin

