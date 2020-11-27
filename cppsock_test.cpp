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
    std::cout << "Test case 1: Simple TCP connection via loopback, port 10000\n";
    cppsock::tcp_server_setup(listener, nullptr, 10000, 1);
    cppsock::tcp_client_connect(client, nullptr, 10000);
    listener.accept(server);
    print_details(server, "server-side connection socket");
    print_details(client, "client-side connsction socket");
    listener.close(); server.close(); client.close();

    std::cout << "Test case 2: Simple TCP connection via 127.0.0.1, port 10000\n";
    cppsock::tcp_server_setup(listener, "127.0.0.1", 10000, 1);
    cppsock::tcp_client_connect(client, "127.0.0.1", 10000);
    listener.accept(server);
    print_details(server, "server-side connection socket");
    print_details(client, "client-side connsction socket");
    listener.close(); server.close(); client.close();

    std::cout << "Test case 3: Simple TCP connection via [::1], port 10000\n";
    cppsock::tcp_server_setup(listener, "::1", 10000, 1);
    cppsock::tcp_client_connect(client, "::1", 10000);
    listener.accept(server);
    print_details(server, "server-side connection socket");
    print_details(client, "client-side connsction socket");
    listener.close(); server.close(); client.close();
}
