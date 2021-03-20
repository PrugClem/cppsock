# author:	Clemens Pruggmayer
# date:		2020-12-22
# desc:		makefile used to build cppsock library adn test program	
IDIR =.
CC=g++
CFLAGS=-I$(IDIR) -Wall -Wextra

ODIR=obj
LDIR =.

full:
	make test

test:
	g++ -pthread -std=c++17 -o cppsock_test \
		cppsock_test.cpp

clear:
	rm -f cppsock_test cppsock_test.exe

remake:
	make clear
	make full

run:
	./cppsock_test

check:
	./cppsock_test 2>&1
