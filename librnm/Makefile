ifndef CC
CC = gcc
endif
ifndef AR
AR = ar
endif

CFLAGS = -Wall -Winline -Wno-multichar -pipe -I../include -fPIC -Wformat-truncation=0 -g

LFLAGS = -L../librtsd -lpthread -lrtsd 
RN_SRC = rn-client.c rn-server.c rn-common.c
RN_OBJ = $(RN_SRC:.c=.o)
RN_LIB = librn.a 

RNM_SRC = rnm-client.c rnm-server.c
RNM_OBJ = $(RNM_SRC:.c=.o)
RNM_LIB = librnm.a 
RNM_LIB_DYN = librnm.so.1

all:$(RN_LIB) $(RNM_LIB) $(RNM_LIB_DYN)

$(RN_LIB): $(RN_OBJ)
	@$(AR) rcs $@ $^

$(RNM_LIB): $(RNM_OBJ) $(RN_OBJ)
	@$(AR) rcs $@ $^ 

$(RNM_LIB_DYN): $(RNM_OBJ) $(RN_OBJ)
	@$(CC) -shared -Wl,-soname,$(RNM_LIB_DYN) -o $(RNM_LIB_DYN).0 $^

.c.o:
	@$(CC) -c $(CFLAGS) $< -o $@ $(LFLAGS)

clean:
	rm -f $(RN_OBJ) $(RN_LIB) $(RNM_OBJ) $(RNM_LIB) $(RNM_LIB_DYN).0
