CC = gcc
CFLAGS = -Wall -Winline -pipe -I../../include -I../../librnm  -Wno-multichar -Wformat-truncation=0
LIBS =  -L../../librnm -pthread  -lrnm -lrn -lconfig

all:rnmlib rnm-test-server rnm-test-client rnm-test-monitor

rnmlib:
	$(MAKE) -C ../../librnm

rnm-test-server:
	@$(CC) $(CFLAGS) $@.c  -o $@.bin $(LIBS)

rnm-test-monitor:
	@$(CC) $(CFLAGS) $@.c  -o $@.bin $(LIBS)


rnm-test-client:
	@$(CC) $(CFLAGS) $@.c  -o $@.bin $(LIBS)

clean:
	rm -f *.o *.bin

