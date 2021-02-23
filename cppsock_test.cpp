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
    fflush(stderr);
    errno = 0;
}

void print_details(const cppsock::socket &s, const std::string& id)
{
    std::cout << "Details for socket \"" << id << "\"\n"
              << "sockname: " << s.getsockname() << "\n"
              << "peername: " << s.getpeername() << "\n";
}

void check_errno(const char *s_msg)
{
    if(errno != 0)
    {
        print_error(s_msg);
        std::cout << "=====================================================" << std::endl;
        std::cout << "cppsock test failed" << std::endl << std::endl;
        exit(EXIT_FAILURE);
    }
}

int main()
{
    cppsock::socket listener, server, client;
    const size_t buflen = 256;
    uint64_t byte_test = 0x4142434445464748;
    char sendbuf[buflen], recvbuf[buflen];

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
    std::cout << "Test 0: resolving passive loopback addresses" << std::endl;
    std::vector<cppsock::addressinfo> ainfo;
    cppsock::addressinfo hints;
    hints.reset().set_socktype(SOCK_STREAM).set_protocol(IPPROTO_TCP).set_passive(true);
    error_t gai_err = cppsock::getaddrinfo(nullptr, "10000", &hints, ainfo);
    if(gai_err != 0)    {std::cout << "error resolving: (" << gai_err << ") " << gai_strerror(gai_err) << std::endl; errno = ENETDOWN;}
    else                {std::cout << "No error resolving" << std::endl;}
    std::cout << "total " << ainfo.size() << " results:" << std::endl;
    for(cppsock::addressinfo &a : ainfo)
    {
        std::cout << "result: " << a << std::endl;
    } std::cout << std::endl;
    check_errno("Error resolving check");

    std::cout << "Test 1: Simple TCP connection via loopback, port 10001" << std::endl;
    cppsock::tcp_listener_setup(listener, nullptr, 10001, 2);                       check_errno("Error setting up TCP server");
    cppsock::tcp_client_connect(client, nullptr, 10001);                            check_errno("Error connecting to TCP server");
    listener.accept(server);                                                        check_errno("Error accepting TCP connection");
    print_details(server, "server-side connection socket");                         check_errno("Error printing server-side connection details");
    print_details(client, "client-side connection socket");                         check_errno("Error printing client-side connection details");
    listener.close(); server.close(); client.close(); std::cout << std::endl;       check_errno("Error closing sockets");

    std::cout << "Test 2: Simple UDP socket, port 10002" << std::endl;
    cppsock::udp_socket_setup(server, nullptr, 10002);                              check_errno("Error setting up udp socket 10002");
    cppsock::udp_socket_setup(client, nullptr, (uint16_t)0);                        check_errno("Error setting up udp socket 0");
    cppsock::udp_socket_setup(listener, cppsock::loopback<0>);                      check_errno("Error setting up udp socket any");
    std::cout << "udp socket, port 10002: " << server.getsockname() << std::endl;   check_errno("Error printing udp 10002 sockname");
    std::cout << "udp socket, port 0: " << client.getsockname() << std::endl;       check_errno("Error printing udp null socket");
    std::cout << "udp socket any: " << listener.getsockname() << std::endl;         check_errno("Error printing udp any socket");
    listener.close(); server.close(); client.close(); std::cout << std::endl;       check_errno("Error closing sockets");

    std::cout << "Test 3: Socket options" << std::endl;
    cppsock::tcp_listener_setup(listener, nullptr, 10003, 2);                                                                               check_errno("Error setting up TCP server");
    cppsock::tcp_client_connect(client, nullptr, 10003);                                                                                    check_errno("Error connecting to TCP server");
    listener.accept(server);                                                                                                                check_errno("Error accepting TCP connection");
    client.set_keepalive(false);                                                                                                            check_errno("Error while setting client keepalive");
    std::cout << "client keepalive: " << (client.get_keepalive() ? "true" : "false") << std::endl;                                          check_errno("Error while getting client keepalive");
    client.set_keepalive(true);                                                                                                             check_errno("Error while setting client keepalive");
    std::cout << "client keepalive: " << (client.get_keepalive() ? "true" : "false") << std::endl;                                          check_errno("Error while getting client keepalive");
    std::cout << "client socktype: " << ( (client.get_socktype() == SOCK_STREAM) ? "SOCK_STREAM" : "NOT SOCK_STREAM" ) << std::endl;        check_errno("Error while getting client socktype");
    std::cout << "listener socktype: " << ( (listener.get_socktype() == SOCK_STREAM) ? "SOCK_STREAM" : "NOT SOCK_STREAM" ) << std::endl;    check_errno("Error while getting listener socktype");
    listener.close(); server.close(); client.close(); std::cout << std::endl;                                                               check_errno("Error closing sockets");

    std::cout << "Test 4: sending / recving TCP data" << std::endl;
    for(size_t i=0; i<buflen; i++)
    {
        sendbuf[i] = i & 0xFF;
        recvbuf[i] = 0;
    }
    cppsock::tcp_listener_setup(listener, nullptr, 10004, 2);                   check_errno("Error setting up TCP server");
    cppsock::tcp_client_connect(client, nullptr, 10004);                        check_errno("Error connecting to TCP server");
    listener.accept(server);                                                    check_errno("Error accepting TCP connection");
    client.send(sendbuf, buflen, 0);                                            check_errno("Error sending data");
    std::cout << "bytes available: " << server.available() << std::endl;        check_errno("Error getting available bytes");
    server.recv(recvbuf, buflen, 0);                                            check_errno("Error receiving data");
    std::cout << "Transfered " << buflen << " bytes of data, " << ((memcmp(sendbuf, recvbuf, buflen) == 0) ? "data is the same" : "data is different") << std::endl;
    listener.close(); server.close(); client.close(); std::cout << std::endl;   check_errno("Error closing sockets");
    if(memcmp(sendbuf, recvbuf, buflen) != 0) {print_error("ERROR: Data was received incorrectly"); return 1;}

    std::cout << "Test 5: sending / receiving UDP data" << std::endl;
    memset(recvbuf, 0, sizeof(recvbuf));
    // explicit IPv6
    cppsock::udp_socket_setup(server, "::", 10005);                             check_errno("Error setting up UDP socket port 10005");
    cppsock::udp_socket_setup(client, cppsock::any_addr<0, AF_INET6>);          check_errno("Error setting up UDP socket port 0");
    client.sendto(sendbuf, buflen, 0, &cppsock::loopback<10005, AF_INET6>);     check_errno("Error sending data");
    server.recvfrom(recvbuf, buflen, 0, nullptr);                               check_errno("Error receiving data");
    server.close(); client.close(); std::cout;                                  check_errno("Error closing sockets");
    if(memcmp(sendbuf, recvbuf, buflen) != 0) {print_error("ERROR: Data was received incorrectly"); return 1;}
    else {std::cout << "Data was received correctly" << std::endl;}

    std::cout << std::endl  << "=====================================================" << std::endl
                            << "cppsock test completed successfully" << std::endl << std::endl;
}
