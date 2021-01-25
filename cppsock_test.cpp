/**
 *  author: Clemens Pruggmayer (PrugClem)
 *  date:   2020-12-22
 *  desc:   test program to test features for the cppsock library
 */
#include "cppsock.hpp"
#include <iostream>
#include <thread>

void print_error(const char* msg)
{
    perror(msg);
    errno = 0;
}

void print_details(const cppsock::socket &s, const std::string& id)
{
    std::cout << "Details for socket \"" << id << "\"\n"
              << "sockname: " << s.getsockname() << "\n"
              << "peername: " << s.getpeername() << "\n";
}

#define check_errno(s_msg)\
{\
    if(errno != 0)\
    {\
        print_error(s_msg);\
        std::cout << "=====================================================" << std::endl;\
        std::cout << "cppsock test failed" << std::endl << std::endl;\
        return 1;\
    }\
}

int main()
{
    cppsock::socket listener, server, client;
    const size_t buflen = 256;
    uint64_t byte_test = 0x4142434445464748;
    char sendbuf[buflen], recvbuf[buflen];
    std::vector<cppsock::addressinfo> ainfo;
    cppsock::addressinfo hints;

    std::cout << "This machine's hostname: \"" << cppsock::hostname() << "\"" << std::endl;

    std::cout << "byte_test: " << std::hex << byte_test << std::endl;
    std::cout << "cppsock::hton<uint64_t>(byte_test): " << cppsock::hton<uint64_t>(byte_test) << std::endl;
    std::cout << "cppsock::ntoh<uint64_t>(cppsock::hton<uint64_t>(byte_test)): " << cppsock::ntoh<uint64_t>(cppsock::hton<uint64_t>(byte_test)) << std::endl;
    if( byte_test != cppsock::ntoh<uint64_t>(cppsock::hton<uint64_t>(byte_test)) )
    {
        std::cerr << "error: mistake in hton or ntoh" << std::endl;
    }
    std::cout << std::dec << std::endl;

    errno = 0;
    std::cout << "Test case 1: resolving loopback addresses" << std::endl;
    std::cout << "resolving: " << strerror(cppsock::getaddrinfo(nullptr, "10000", &hints, ainfo)) << std::endl;
    std::cout << "total " << ainfo.size() << " results:" << std::endl;
    for(cppsock::addressinfo &a : ainfo)
    {
        std::cout << "result: " << a << std::endl;
    } std::cout << std::endl;
    check_errno("Error resolving");

    std::cout << "Test case 1: Simple TCP connection via loopback, port 10001" << std::endl;
    cppsock::tcp_server_setup(listener, nullptr, 10001, 1);                     check_errno("Error setting up TCP server");
    cppsock::tcp_client_connect(client, nullptr, 10001);                        check_errno("Error connecting to TCP server");
    listener.accept(server);                                                        check_errno("Error accepting TCP connection");
    print_details(server, "server-side connection socket");                         check_errno("Error printing server-side connection details");
    print_details(client, "client-side connection socket");                         check_errno("Error printing client-side connection details");
    listener.close(); server.close(); client.close(); std::cout << std::endl;       check_errno("Error closing sockets");

    std::cout << "Test case 2: Socket options" << std::endl;
    cppsock::tcp_server_setup(listener, nullptr, 10002, 1);                                                                                 check_errno("Error setting up TCP server");
    cppsock::tcp_client_connect(client, nullptr, 10002);                                                                                    check_errno("Error connecting to TCP server");
    listener.accept(server);                                                                                                                check_errno("Error accepting TCP connection");
    client.set_keepalive(false);                                                                                                            check_errno("Error while setting client keepalive");
    std::cout << "client keepalive: " << (client.get_keepalive() ? "true" : "false") << std::endl;                                          check_errno("Error while getting client keepalive");
    client.set_keepalive(true);                                                                                                             check_errno("Error while setting client keepalive");
    std::cout << "client keepalive: " << (client.get_keepalive() ? "true" : "false") << std::endl;                                          check_errno("Error while getting client keepalive");
    std::cout << "client socktype: " << ( (client.get_socktype() == SOCK_STREAM) ? "SOCK_STREAM" : "NOT SOCK_STREAM" ) << std::endl;        check_errno("Error while getting client socktype");
    std::cout << "listener socktype: " << ( (listener.get_socktype() == SOCK_STREAM) ? "SOCK_STREAM" : "NOT SOCK_STREAM" ) << std::endl;    check_errno("Error while getting listener socktype");
    listener.close(); server.close(); client.close(); std::cout << std::endl;
   check_errno("Error while setting socket options");

    std::cout << "Test case 3: sending / recving data" << std::endl;
    for(size_t i=0; i<buflen; i++)
    {
        sendbuf[i] = i & 0xFF;
        recvbuf[i] = 0;
    }
    cppsock::tcp_server_setup(listener, nullptr, 10003, 1);                     check_errno("Error setting up TCP server");
    cppsock::tcp_client_connect(client, nullptr, 10003);                        check_errno("Error connecting to TCP server");
    listener.accept(server);                                                    check_errno("Error accepting TCP connection");
    client.send(sendbuf, buflen, 0);                                            check_errno("Error sending data");
    std::cout << "bytes available: " << server.available() << std::endl;        check_errno("Error getting available bytes");
    server.recv(recvbuf, buflen, 0);                                            check_errno("Error receiving data");
    std::cout << "Transfered " << buflen << " bytes of data, " << ((memcmp(sendbuf, recvbuf, buflen) == 0) ? "data is the same" : "data is different") << std::endl;
    listener.close(); server.close(); client.close(); std::cout << std::endl;   check_errno("Error closing sockets");
    if(memcmp(sendbuf, recvbuf, buflen) != 0) {print_error("Error sending / receiving data"); return 1;}

    std::cout << "=====================================================" << std::endl
              << "cppsock test completed successfully" << std::endl << std::endl;
}
