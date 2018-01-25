
CC = gcc
CFLAGS = -Wall -Winline -Wno-multichar -pipe -I../include -fPIC

LD = -L../librtsd -lpthread -lrtsd 
RN_SRC = rn-client.c rn-server.c rn-common.c
RN_OBJ = $(RN_SRC:.c=.o)
RN_LIB = librn.a 

RNM_SRC = rnm-client.c rnm-server.c
RNM_OBJ = $(RNM_SRC:.c=.o)
RNM_LIB = librnm.a 
RNM_LIB_DYN = librnm.so.1

all:$(RN_LIB) $(RNM_LIB) $(RNM_LIB_DYN)

$(RN_LIB): $(RN_OBJ)
	@ar rcs $@ $^

$(RNM_LIB): $(RNM_OBJ)
	@ar rcs $@ $^ 

$(RNM_LIB_DYN): $(RNM_OBJ) 
	gcc -shared -Wl,-soname,$(RNM_LIB_DYN) -o $(RNM_LIB_DYN).0 $^

.c.o:
	@$(CC) -c $(CFLAGS) $< -o $@ $(LD)

clean:
	rm -f $(RN_OBJ) $(RN_LIB) $(RNM_OBJ) $(RNM_LIB) $(RNM_LIB_DYN).0
