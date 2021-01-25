mkdir obj out
gcc -c -o obj/cppsock_addressinfo.cpp.o cppsock_addressinfo.cpp
gcc -c -o obj/cppsock_socket.cpp.o cppsock_socket.cpp
gcc -c -o obj/cppsock_socketaddr.cpp.o cppsock_socketaddr.cpp
gcc -c -o obj/cppsock_utility.cpp.o cppsock_utility.cpp
gcc -c -o obj/cppsock_winonly.cpp.o cppsock_winonly.cpp
ar -r -s out/libcppsock.a obj/cppsock_addressinfo.cpp.o obj/cppsock_socket.cpp.o obj/cppsock_socketaddr.cpp.o obj/cppsock_utility.cpp.o

g++ -o cppsock_test.exe cppsock_test.cpp out/libcppsock.a -lws2_32
