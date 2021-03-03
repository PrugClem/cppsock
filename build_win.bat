mkdir obj out
gcc -c -o obj/cppsock_addressinfo.cpp.o cppsock_addressinfo.cpp
gcc -c -o obj/cppsock_socket.cpp.o cppsock_socket.cpp
gcc -c -o obj/cppsock_socketaddr.cpp.o cppsock_socketaddr.cpp
gcc -c -o obj/cppsock_utility.cpp.o cppsock_utility.cpp
gcc -c -o obj/cppsock_tcp_client.cpp.o cppsock_tcp_client.cpp
gcc -c -o obj/cppsock_tcp_listener.cpp.o cppsock_tcp_listener.cpp
gcc -c -o obj/cppsock_tcp_socket.cpp.o cppsock_tcp_socket.cpp
ar -r -s out/libcppsock.a obj/cppsock_addressinfo.cpp.o obj/cppsock_socket.cpp.o obj/cppsock_socketaddr.cpp.o^
 obj/cppsock_utility.cpp.o obj/cppsock_tcp_client.cpp.o obj/cppsock_tcp_listener.cpp.o obj/cppsock_tcp_socket.cpp.o

g++ -o cppsock_test.exe cppsock_test.cpp out/libcppsock.a cppsock_winonly.cpp -lws2_32
