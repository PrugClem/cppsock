#include "cppsock.hpp"
#include <iostream>
#include <thread>

void print_error(const char* msg)
{
    perror(msg);
    errno = 0;
}

#if 1
int main()
{
    errno = 0;
    cppsock::socket listener, server, client;
    cppsock::tcp_server_setup(listener, nullptr, 10000, 1);
    cppsock::tcp_client_connect(client, nullptr, 10000);
    listener.accept(server);

    std::clog << std::endl;
    std::clog << "listener sockname " << listener.getsockname().get_addr() << " " << listener.getsockname().get_port() << std::endl;
    std::clog << std::endl;
    std::clog << "client sockname " << client.getsockname().get_addr() << " " << client.getsockname().get_port() << std::endl;
    std::clog << "client peername " << client.getpeername().get_addr() << " " << client.getpeername().get_port() << std::endl;
    std::clog << "server sockname " << server.getsockname().get_addr() << " " << server.getsockname().get_port() << std::endl;
    std::clog << "server peername " << server.getpeername().get_addr() << " " << server.getpeername().get_port() << std::endl;
    std::clog << std::endl;
    std::clog << "Address length: " << server.getsockname().get_addr().length() << std::endl;
    std::clog << "server sockname != listener sockname: " << (server.getsockname() != listener.getsockname()) << std::endl;
    std::clog << "server peername == client sockname: " << (server.getpeername() == client.getsockname()) << std::endl;
    std::clog << "listener address == \"::\": " << (listener.getsockname().get_addr() == "::") << std::endl;
    std::clog << std::endl;

    errno = 0;
    client.shutdown(SHUT_RDWR);
    print_error("client.shutdown()\t");
    server.shutdown(SHUT_RDWR);
    print_error("server.shutdown()\t");
    client.close();
    print_error("client.close()\t\t");
    server.close();
    print_error("server.close()\t\t");
    listener.close();
    print_error("listener.close()\t");
    return 0;
}
#else
int main()
{
    cppsock::socket listener, server, client;
    cppsock::socketaddr addr;
    std::vector<cppsock::addressinfo> res;
    error_t gai_error;
    ssize_t len;
    char buf[128];

    for(size_t i=0; i<sizeof(buf); i++)
        buf[i] = 0;

    errno = 0;
    gai_error = cppsock::resolve_tcp("localhost", res);
    print_error("cppsock::resolve()\t");
    if(gai_error != 0)
    {
        printf("%s, errno: %s", gai_strerror(gai_error), strerror(errno));
        exit(EXIT_FAILURE);
    }
    std::clog << "Number of results:\t" << res.size() << std::endl;
    addr = res.at(0);
    addr.set_port(10000);
    std::clog << "Result[0]:\t\t" << addr.get_addr() << ", port " << addr.get_port() << std::endl;

    listener.init(addr.get_family(), res.at(0).get_socktype(), res.at(0).get_protocol());
    print_error("listener.init()\t\t");
    client.init(addr.get_family(), res.at(0).get_socktype(), res.at(0).get_protocol());
    print_error("client.init()\t\t");
    listener.bind(addr);
    print_error("listener.bind()\t\t");

    std::clog << std::endl;
    std::clog << "listener sockname " << listener.getsockname().get_addr() << " " << listener.getsockname().get_port() << std::endl;
    std::clog << std::endl;

    listener.listen(1);
    print_error("listener.listen()\t");
    client.connect(addr);
    print_error("client.connect()\t");
    listener.accept(server);
    print_error("listener.accept()\t");

    std::clog << std::endl;
    std::clog << "client sockname " << client.getsockname().get_addr() << " " << client.getsockname().get_port() << std::endl;
    std::clog << "client peername " << client.getpeername().get_addr() << " " << client.getpeername().get_port() << std::endl;
    std::clog << "server sockname " << server.getsockname().get_addr() << " " << server.getsockname().get_port() << std::endl;
    std::clog << "server peername " << server.getpeername().get_addr() << " " << server.getpeername().get_port() << std::endl;
    std::clog << std::endl;

    client.set_keepalive(true);
    print_error("client.set_keepalive()\t");
    server.set_keepalive(true);
    print_error("server.set_keepalive()\t");
    std::clog << "client[KEEPALIVE]\t" << client.get_keepalive() << std::endl;
    print_error("client.get_keepalive()\t");
    std::clog << "server[KEEPALIVE]\t";
    std::clog << server.get_keepalive() << std::endl;
    print_error("server.get_keepalive()\t");
    client.set_keepalive(false);
    print_error("client.set_keepalive()\t");
    server.set_keepalive(false);
    print_error("server.set_keepalive()\t");
    std::clog << "client[KEEPALIVE]\t" << client.get_keepalive() << std::endl;
    print_error("client.get_keepalive()\t");
    std::clog << "server[KEEPALIVE]\t" << server.get_keepalive() << std::endl;
    print_error("server.get_keepalive()\t");
    std::clog << std::endl;

    client.send(buf, sizeof(buf), 0);
    print_error("client.send()\t\t");
    len = server.recv(buf, sizeof(buf), 0);
    std::cout << "server.recv[return]\t" << len << std::endl;
    print_error("server.recv()\t\t");
    server.send(buf, sizeof(buf), 0);
    print_error("server.send()\t\t");
    len = client.recv(buf, sizeof(buf), 0);
    std::cout << "client.recv[return]\t" << len << std::endl;
    print_error("client.recv()\t\t");
    std::clog << std::endl;

    client.shutdown(SHUT_RDWR);
    print_error("client.shutdown()\t");
    server.shutdown(SHUT_RDWR);
    print_error("server.shutdown()\t");
    client.close();
    print_error("client.close()\t\t");
    server.close();
    print_error("server.close()\t\t");
    listener.close();
    print_error("listener.close()\t");

    return 0;
}
#endif