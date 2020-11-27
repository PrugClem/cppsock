IDIR =.
CC=g++
CFLAGS=-I$(IDIR) -Wall -Wextra

ODIR=obj
LDIR =.

LIB_OUT = out/libcppsock.a

LIBS=-lm

_DEPS = cppsock.hpp
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = cppsock_addressinfo.cpp.o \
	   cppsock_socket.cpp.o \
	   cppsock_socketaddr.cpp.o \
	   cppsock_utility.cpp.o 
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: % $(DEPS)
	mkdir obj || true
	$(CC) -c -o $@ $< $(CFLAGS)

full:
	make lib
	make test

test:
	g++ -o cppsock_test \
		cppsock_test.cpp $(LIB_OUT)

lib: $(OBJ)
	mkdir out || true
	ar -r -s $(LIB_OUT) $(OBJ)

clear:
	rm -f $(OBJ)
	rm -f $(LIB_OUT)
	rm -f cppsock_test cppsock_test.exe

remake:
	make clear
	make full

run:
	./cppsock_test