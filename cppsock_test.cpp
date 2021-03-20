/**
 *  @author: Clemens Pruggmayer (PrugClem)
 *  @date:   2020-12-22
 *  @desc:   test program to test features for the cppsock library
 */
#include "cppsock.hpp"
#include <iostream>
#include <thread>

void print_error(const char* msg)
{
    //perror(msg);
    printf("%s: %s\n", msg, strerror(errno));
    fflush(stderr);
    errno = 0;
}

void print_details(const cppsock::socket &s, const std::string& id)
{
    std::cout << "Details for socket \"" << id << "\"\n"
              << "sockname: " << s.getsockname() << "\n"
              << "peername: " << s.getpeername() << "\n";
}

void abort(const char *a_msg, const char *add_msg = nullptr)
{
    if(a_msg != nullptr) printf("Aborting: %s\n", a_msg);
    if(add_msg != nullptr) printf("Additional message: %s\n", add_msg);
    std::cout << "Aborting..." << std::endl;
    std::cout << "=====================================================" << std::endl;
    std::cout << "cppsock test failed" << std::endl << std::endl;
    exit(EXIT_FAILURE);
}

void check_errno(const char *s_msg, const char *add_msg = nullptr)
{
    if(errno != 0)
    {
        print_error(s_msg);
        if(add_msg != nullptr) printf("Additional message: %s\n", add_msg);
        abort("Errno check failed");
    }
}

void init_buf(char *buf, size_t len)
{
    for(size_t i=0; i<len; i++)
    {
        buf[i] = i & 0xFF;
    }
}

void test_collection(uint16_t port)
{
    std::mutex stdoutmtx;
    std::vector<cppsock::tcp::client> clients;
    cppsock::tcp::socket_collection collection (
            [&stdoutmtx](std::shared_ptr<cppsock::tcp::socket> sock, cppsock::socketaddr_pair addr, void** pers)
            {   std::lock_guard<std::mutex> lock(stdoutmtx);
                std::cout << "[callback] connected " << addr.remote << std::endl;
            },
            [&stdoutmtx](std::shared_ptr<cppsock::tcp::socket> sock, cppsock::socketaddr_pair addr, void** pers)
            {   std::lock_guard<std::mutex> lock(stdoutmtx);
                char buf[16];
                sock->recv(buf, sizeof(buf), 0);
                std::cout << "[callback] echoing to " << addr.remote << ": " << buf << std::endl;
                sock->send(buf, strlen(buf)+1, 0);
            },
            [&stdoutmtx](std::shared_ptr<cppsock::tcp::socket> sock, cppsock::socketaddr_pair addr, void** pers)
            {   std::lock_guard<std::mutex> lock(stdoutmtx);
                std::cout << "[callback] disconnected " << addr.remote << std::endl;
            } 
        );
    cppsock::tcp::server server(&collection);
    server.start(cppsock::make_any(port), 2);
    std::cout << "started server" << std::endl;
    clients.resize(6);
    for(cppsock::tcp::client &client : clients)
    {
        client.connect(cppsock::make_loopback(port));
        std::lock_guard<std::mutex> lock(stdoutmtx);
        std::cout << "connected: " << client.sock().getpeername() << std::endl;
    }
    for(cppsock::tcp::client& client : clients)
    {
        client.send("Hello", 6, 0);
    }
    for(size_t i=0; i<clients.size()/2; i++) // close half sockets from the client side
    {
        cppsock::tcp::client &client = clients.at(i);
        client.shutdown(cppsock::shutdown_both);
    }
    server.stop();
    stdoutmtx.lock();
        std::cout << "stopped server" << std::endl;
        std::cout << "collection content: " << collection.count() << " connections" << std::endl;
    stdoutmtx.unlock();
    collection.clear();
    std::cout << "cleared collection" << std::endl;
}

int main()
{
    cppsock::socket sock_listener, sock_server, sock_client;
    cppsock::tcp::listener tcp_listener;
    cppsock::tcp::socket tcp_socket;
    cppsock::tcp::client tcp_client;
    cppsock::udp::socket udp_sock1, udp_sock2;

    cppsock::swap_error swap_err;

    const size_t buflen = 256;
    uint64_t byte_test = 0x4142434445464748;
    float float_test = 1.12345;
    double double_test = 1.12345;
    char sendbuf[buflen], recvbuf[buflen];

    std::cout << "This machine's hostname: \"" << cppsock::hostname() << "\"" << std::endl;

    // ntoh and hton test with uint64_t
    std::cout << "byte_test: " << std::hex << byte_test << std::endl;
    std::cout << "cppsock::hton<uint64_t>(byte_test): " << cppsock::hton<uint64_t>(byte_test) << std::endl;
    std::cout << "cppsock::ntoh<uint64_t>(cppsock::hton<uint64_t>(byte_test)): " << cppsock::ntoh<uint64_t>(cppsock::hton<uint64_t>(byte_test)) << std::endl;
    if( byte_test != cppsock::ntoh<uint64_t>(cppsock::hton<uint64_t>(byte_test)) )
    {
        abort("error: mistake in hton<uint64_t> or ntoh<uint64_t>");
    }
    std::cout << std::dec << std::endl;
    // ntoh and hton test with float
    std::cout << "float_test:" << float_test << std::endl;
    std::cout << "cppsock::ntoh<float>(cppsock::hton<float>(float_test)): " << cppsock::ntoh<float>(cppsock::hton<float>(float_test)) << std::endl;
    if(float_test != cppsock::ntoh<float>(cppsock::hton<float>(float_test)) )
    {
        abort("error: mistake in hton<float> or ntoh<float>");
    }
    // ntoh and hton test with double
    std::cout << "double_test: " << double_test << std::endl;
    std::cout << "cppsock::ntoh<double>(cppsock::hton<double>(double_test))" << cppsock::ntoh<double>(cppsock::hton<double>(double_test)) << std::endl;
    if(double_test != cppsock::ntoh<double>(cppsock::hton<double>(double_test)) )
    {
        abort("error: mistake in hton<double> or ntoh<double>");
    }

    errno = 0;
    std::cout << "Test 0: resolving passive loopback addresses" << std::endl;
    std::vector<cppsock::addressinfo> ainfo;
    cppsock::addressinfo hints;
    hints.reset().set_socktype(cppsock::socket_stream).set_protocol(cppsock::ip_protocol_tcp).set_passive(true);
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
    cppsock::tcp_listener_setup(sock_listener, nullptr, 10001, 1);                              check_errno("Error setting up TCP server");
    cppsock::tcp_client_connect(sock_client, nullptr, 10001);                                   check_errno("Error connecting to TCP server");
    sock_listener.accept(sock_server);                                                          check_errno("Error accepting TCP connection");
    print_details(sock_server, "server-side connection socket");                                check_errno("Error printing server-side connection details");
    print_details(sock_client, "client-side connection socket");                                check_errno("Error printing client-side connection details");
    sock_listener.close(); sock_server.close(); sock_client.close(); std::cout << std::endl;    check_errno("Error closing sockets");

    std::cout << "Test 2: Simple UDP socket, port 10002" << std::endl;
    cppsock::udp_socket_setup(sock_server, nullptr, 10002);                                     check_errno("Error setting up udp socket 10002");
    cppsock::udp_socket_setup(sock_client, nullptr, (uint16_t)0);                               check_errno("Error setting up udp socket 0");
    cppsock::udp_socket_setup(sock_listener, cppsock::make_loopback(0));                        check_errno("Error setting up udp socket any");
    std::cout << "udp socket, port 10002: " << sock_server.getsockname() << std::endl;          check_errno("Error printing udp 10002 sockname");
    std::cout << "udp socket, port 0: " << sock_client.getsockname() << std::endl;              check_errno("Error printing udp null socket");
    std::cout << "udp socket any: " << sock_listener.getsockname() << std::endl;                check_errno("Error printing udp any socket");
    sock_listener.close(); sock_server.close(); sock_client.close(); std::cout << std::endl;    check_errno("Error closing sockets");

    std::cout << "Test 3: Socket options" << std::endl;
    cppsock::tcp_listener_setup(sock_listener, nullptr, 10003, 1);                                                                                  check_errno("Error setting up TCP server");
    cppsock::tcp_client_connect(sock_client, nullptr, 10003);                                                                                       check_errno("Error connecting to TCP server");
    sock_listener.accept(sock_server);                                                                                                              check_errno("Error accepting TCP connection");
    sock_client.set_keepalive(false);                                                                                                               check_errno("Error while setting sock_client keepalive");
    std::cout << "sock_client keepalive: " << (sock_client.get_keepalive() ? "true" : "false") << std::endl;                                        check_errno("Error while getting sock_client keepalive");
    sock_client.set_keepalive(true);                                                                                                                check_errno("Error while setting sock_client keepalive");
    std::cout << "sock_client keepalive: " << (sock_client.get_keepalive() ? "true" : "false") << std::endl;                                        check_errno("Error while getting sock_client keepalive");
    std::cout << "sock_client socktype: " << ( (sock_client.get_socktype() == SOCK_STREAM) ? "SOCK_STREAM" : "NOT SOCK_STREAM" ) << std::endl;      check_errno("Error while getting sock_client socktype");
    std::cout << "sock_listener socktype: " << ( (sock_listener.get_socktype() == SOCK_STREAM) ? "SOCK_STREAM" : "NOT SOCK_STREAM" ) << std::endl;  check_errno("Error while getting sock_listener socktype");
    sock_listener.close(); sock_server.close(); sock_client.close(); std::cout << std::endl;                                                        check_errno("Error closing sockets");

    std::cout << "Test 4: sending / recving TCP data" << std::endl;
    init_buf(sendbuf, sizeof(sendbuf));
    memset(recvbuf, 0, sizeof(recvbuf));
    cppsock::tcp_listener_setup(sock_listener, nullptr, 10004, 1);                              check_errno("Error setting up TCP server");
    cppsock::tcp_client_connect(sock_client, nullptr, 10004);                                   check_errno("Error connecting to TCP server");
    sock_listener.accept(sock_server);                                                          check_errno("Error accepting TCP connection");
    sock_client.send(sendbuf, buflen, 0);                                                       check_errno("Error sending data");
    std::cout << "bytes available: " << sock_server.available() << std::endl;                   check_errno("Error getting available bytes");
    sock_server.recv(recvbuf, buflen, 0);                                                       check_errno("Error receiving data");
    std::cout << "Transfered " << buflen << " bytes of data, " << ((memcmp(sendbuf, recvbuf, buflen) == 0) ? "data is the same" : "data is different") << std::endl;
    sock_listener.close(); sock_server.close(); sock_client.close(); std::cout << std::endl;    check_errno("Error closing sockets");
    if(memcmp(sendbuf, recvbuf, buflen) != 0) {print_error("ERROR: Data was received incorrectly"); exit(1);}

    std::cout << "Test 5: sending / receiving UDP data" << std::endl;
    memset(recvbuf, 0, sizeof(recvbuf));
    // explicit IPv6
    cppsock::udp_socket_setup(sock_server, "::", 10005);                                check_errno("Error setting up UDP socket port 10005");
    cppsock::udp_socket_setup(sock_client, cppsock::any_addr<0, cppsock::IPv6>);        check_errno("Error setting up UDP socket port 0");
    sock_client.sendto(sendbuf, buflen, 0, &cppsock::loopback<10005, cppsock::IPv6>);   check_errno("Error sending data");
    sock_server.recvfrom(recvbuf, buflen, 0, nullptr);                                  check_errno("Error receiving data");
    sock_server.close(); sock_client.close();                                           check_errno("Error closing sockets");
    if(memcmp(sendbuf, recvbuf, buflen) != 0) {print_error("ERROR: Data was received incorrectly"); exit(1);}
    else {std::cout << "Data was received correctly" << std::endl << std::endl;}

    std::cout << "Test 6: using special tcp socket classes" << std::endl;
    init_buf(sendbuf, sizeof(sendbuf));
    memset(recvbuf, 0, sizeof(recvbuf));
    tcp_listener.setup(cppsock::any_addr<10006>, 1);                                            check_errno("Error setting up TCP listener port 10006");
    tcp_client.connect(cppsock::loopback<10006>);                                               check_errno("Error connecting to TCP Server port 10006");
    tcp_listener.accept(tcp_socket);                                                            check_errno("Error accepting TCP connection");
    tcp_client.send(sendbuf, buflen, 0);                                                        check_errno("Error sending data");
    std::cout << "bytes available: " << tcp_socket.available() << std::endl;                    check_errno("Error getting available bytes");
    tcp_socket.recv(recvbuf, buflen, 0);                                                        check_errno("Error receiving data");
    std::cout << "Transfered " << buflen << " bytes of data, " << ((memcmp(sendbuf, recvbuf, buflen) == 0) ? "data is the same" : "data is different") << std::endl;
    tcp_listener.close(); tcp_socket.close(); tcp_client.close(); std::cout << std::endl;       check_errno("Error closing sockets");

    std::cout << "Test 7: using special udp sockets" << std::endl;
    init_buf(sendbuf, sizeof(sendbuf));
    memset(recvbuf, 0, sizeof(recvbuf));
    udp_sock1.setup(cppsock::any_addr<10007>);                          check_errno("Error setting up UDP socket [::]:10007");
    udp_sock2.setup(cppsock::any_addr<0>);                              check_errno("Error setting up UDP socket [::]:0");
    udp_sock2.sendto(sendbuf, buflen, 0, &cppsock::loopback<10007>);    check_errno("Error sending data");
    udp_sock1.recvfrom(recvbuf, buflen, 0, nullptr);                    check_errno("Error receiving data");
    udp_sock1.close(); udp_sock2.close();                               check_errno("Error closing sockets");
    if(memcmp(sendbuf, recvbuf, buflen) != 0) {print_error("ERROR: Data was received incorrectly"); exit(1);}
    else {std::cout << "Data was received correctly" << std::endl << std::endl;}

    std::cout << "Test 8: swapping regular sockets into special ones" << std::endl;
    cppsock::tcp_listener_setup(sock_listener, cppsock::any_addr<10008>, 1);    check_errno("Error setting up tcp listener port 10008");
    cppsock::tcp_client_connect(sock_client, cppsock::loopback<10008>);         check_errno("Error connection to TCP server port 10008");
    sock_listener.accept(sock_server);                                          check_errno("Error accepting TCP connection");
    swap_err = tcp_listener.swap(sock_listener);                                check_errno("Error swapping listener socket", cppsock::swap_strerror(swap_err));
    swap_err = tcp_socket.swap(sock_server);                                    check_errno("Error swapping server tcp socket", cppsock::swap_strerror(swap_err));
    swap_err = tcp_client.swap(sock_client);                                    check_errno("Error swapping client tcp socket", cppsock::swap_strerror(swap_err));
    init_buf(sendbuf, sizeof(sendbuf)); memset(recvbuf, 0, sizeof(recvbuf));
    tcp_client.send(sendbuf, buflen, 0);                                        check_errno("Error sending data");
    std::cout << "bytes available: " << tcp_socket.available() << std::endl;    check_errno("Error getting available bytes");
    tcp_socket.recv(recvbuf, buflen, cppsock::waitall);                         check_errno("Error receiving data");
    std::cout << "Transfered " << buflen << " bytes of data, " << ((memcmp(sendbuf, recvbuf, buflen) == 0) ? "TCP data is the same" : "data is different") << std::endl;
    cppsock::udp_socket_setup(sock_server, cppsock::any_addr<10008>);           check_errno("Error setting up UDP socket [::]:10008");
    cppsock::udp_socket_setup(sock_client, cppsock::any_addr<0>);               check_errno("Error setting up UDP socket [::]:0");
    swap_err = udp_sock1.swap(sock_server);                                     check_errno("Error swapping UDP socket [::]:10008", cppsock::swap_strerror(swap_err));
    swap_err = udp_sock2.swap(sock_client);                                     check_errno("Error swapping UDP socket [::]:0", cppsock::swap_strerror(swap_err));
    init_buf(sendbuf, sizeof(sendbuf)); memset(recvbuf, 0, sizeof(recvbuf));
    udp_sock2.sendto(sendbuf, buflen, 0, &cppsock::loopback<10008>);            check_errno("Error sending data");
    udp_sock1.recvfrom(recvbuf, buflen, 0, nullptr);                            check_errno("Error receiving data");
    if(memcmp(sendbuf, recvbuf, buflen) != 0) {print_error("ERROR: Data was received incorrectly"); exit(1);}
    else {std::cout << "UDP Data was received correctly" << std::endl << std::endl;}
    tcp_listener.close(); tcp_client.close(); tcp_socket.close();               check_errno("Error closing TCP sockets");
    udp_sock1.close(); udp_sock2.close();                                       check_errno("Error closing UDP sockets");

    std::cout << "Test 9: swapping regular sockets into special sockets, invalid operations" << std::endl;
    cppsock::tcp_listener_setup(sock_listener, cppsock::any_addr<10009>, 1);    check_errno("Error setting up tcp listener port 10009");
    cppsock::tcp_client_connect(sock_client, cppsock::loopback<10009>);         check_errno("Error connecting to TCP server port 10009");
    sock_listener.accept(sock_server);                                          check_errno("Error accepting TCP connection");
                                                                                std::cout << "Swapping tests 1-3" << std::endl;
    if((swap_err = tcp_socket.swap(sock_listener)) == cppsock::swap_error_none) abort("swap tcp sock <-> listener succeeded", cppsock::swap_strerror(swap_err));
    if((swap_err = tcp_listener.swap(sock_server)) == cppsock::swap_error_none) abort("Swap listener <-> tcp sock succeeded", cppsock::swap_strerror(swap_err));
    if((swap_err = udp_sock1.swap(sock_client))    == cppsock::swap_error_none) abort("Swap udp sock <-> tcp sock succeeded", cppsock::swap_strerror(swap_err));
    errno=0; sock_listener.close(); sock_client.close(); sock_server.close();   check_errno("Error closing tcp sockets");
                                                                                std::cout << "Swapping tests 4" << std::endl;
    cppsock::udp_socket_setup(sock_client, cppsock::any_addr<10009>);           check_errno("Error setting up UDP socket [::]:10009");
    if((swap_err = tcp_socket.swap(sock_client))   == cppsock::swap_error_none) abort("swap tcp sock <-> udp sock succeeded", cppsock::swap_strerror(swap_err));
    errno=0; sock_client.close(); std::cout << std::endl;                       check_errno("Error closing udp socket");

    std::cout << "Test 10: using tcp handled server" << std::endl;
    test_collection(10010);
    std::cout << std::endl;

     // test completed successfully
    std::cout   << "=====================================================" << std::endl
                << "cppsock test completed successfully" << std::endl << std::endl;
}
