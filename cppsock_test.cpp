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

int main()
{
    cppsock::socket listener, server, client;
    size_t buflen = 256;
    char sendbuf[buflen], recvbuf[buflen];

    std::cout << "Test case 1: Simple TCP connection via loopback, port 10000\n";
    cppsock::tcp_server_setup(listener, nullptr, 10000, 1);
    cppsock::tcp_client_connect(client, nullptr, 10000);
    listener.accept(server);
    print_details(server, "server-side connection socket");
    print_details(client, "client-side connsction socket");
    listener.close(); server.close(); client.close(); std::cout << std::endl;

    std::cout << "Test case 2: Simple TCP connection via 127.0.0.1, port 10000\n";
    cppsock::tcp_server_setup(listener, "127.0.0.1", 10000, 1);
    cppsock::tcp_client_connect(client, "127.0.0.1", 10000);
    listener.accept(server);
    print_details(server, "server-side connection socket");
    print_details(client, "client-side connsction socket");
    listener.close(); server.close(); client.close(); std::cout << std::endl;

    std::cout << "Test case 3: Simple TCP connection via [::1], port 10000\n";
    cppsock::tcp_server_setup(listener, "::1", 10000, 1);
    cppsock::tcp_client_connect(client, "::1", 10000);
    listener.accept(server);
    print_details(server, "server-side connection socket");
    print_details(client, "client-side connsction socket");
    listener.close(); server.close(); client.close(); std::cout << std::endl;

    std::cout << "Test case 4: Socket options" << std::endl;
    cppsock::tcp_server_setup(listener, nullptr, 10000, 1);
    cppsock::tcp_client_connect(client, nullptr, 10000);
    listener.accept(server);
    client.set_keepalive(false);
    std::cout << "client keepalive: " << (client.get_keepalive() ? "true" : "false") << std::endl;
    client.set_keepalive(true);
    std::cout << "client keepalive: " << (client.get_keepalive() ? "true" : "false") << std::endl;
    listener.close(); server.close(); client.close(); std::cout << std::endl;

    std::cout << "Test case 5: sending / recving data" << std::endl;
    //memset(sendbuf, 0xff, buflen);
    for(size_t i=0; i<buflen; i++)
    {
        sendbuf[i] = i & 0xFF;
        recvbuf[i] = 0;
    }
    cppsock::tcp_server_setup(listener, nullptr, 10000, 1);
    cppsock::tcp_client_connect(client, nullptr, 10000);
    listener.accept(server);
    errno = 0;
    client.send(sendbuf, buflen, 0);
    perror("send"); errno = 0;
    server.recv(recvbuf, buflen, 0);
    perror("recv");
    std::cout << "Transfered " << buflen << " bytes of data, " << ((memcmp(sendbuf, recvbuf, buflen) == 0) ? "data is the same" : "data is different") << std::endl;
    listener.close(); server.close(); client.close(); std::cout << std::endl;
}
