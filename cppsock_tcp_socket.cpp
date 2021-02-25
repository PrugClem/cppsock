/**
 *  author: Clemens Pruggmayer (PrugClem)
 *  date:   2021-02-25
 *  desc:   implementation for tcp related sockets
 */
#include "cppsock.hpp"

cppsock::utility_error_t cppsock::tcp::listener::setup(const cppsock::socketaddr &addr, int backlog)
{
    return cppsock::tcp_listener_setup(this->_sock, addr, backlog);
}
cppsock::utility_error_t cppsock::tcp::listener::setup(const char *hostname, const char *service, int backlog)
{
    return cppsock::tcp_listener_setup(this->_sock, hostname, service, backlog);
}
cppsock::utility_error_t cppsock::tcp::listener::setup(const char *hostname, uint16_t port, int backlog)
{
    return cppsock::tcp_listener_setup(this->_sock, hostname, port, backlog);
}

error_t cppsock::tcp::listener::accept(cppsock::tcp::socket &output)
{
    return this->_sock.accept(output._sock);
}
error_t cppsock::tcp::listener::close()
{
    return this->_sock.close();
}

std::streamsize cppsock::tcp::socket::send(const void *data, std::streamsize len, cppsock::msg_flags flags)
{
    return this->_sock.send(data, len, flags);
}

std::streamsize cppsock::tcp::socket::recv(void *data, std::streamsize max_len, cppsock::msg_flags flags)
{
    return this->_sock.recv(data, max_len, flags);
}

const cppsock::socket &cppsock::tcp::socket::sock()
{
    return this->_sock;
}

#define CHECK_FLAGS(c, f) ( ( (c) & (f) ) == (f) )

error_t cppsock::tcp::socket::shutdown(std::ios_base::openmode how)
{
    if(CHECK_FLAGS(how, std::ios_base::in | std::ios_base::out))
        return this->_sock.shutdown(cppsock::socket::shutdown_both);
    if(CHECK_FLAGS(how, std::ios_base::in))
        return this->_sock.shutdown(cppsock::socket::shutdown_recv);
    if(CHECK_FLAGS(how, std::ios_base::out))
        return this->_sock.shutdown(cppsock::socket::shutdown_send);
    errno = ENOTSUP;
    return -1;
}

error_t cppsock::tcp::socket::close()
{
    return this->_sock.close();
}

cppsock::utility_error_t cppsock::tcp::client::connect(const socketaddr &addr)
{
    return cppsock::tcp_client_connect(this->_sock, addr);
}

cppsock::utility_error_t cppsock::tcp::client::connect(const char *hostname, const char *service)
{
    return cppsock::tcp_client_connect(this->_sock, hostname, service);
}
cppsock::utility_error_t cppsock::tcp::client::connect(const char *hostname, uint16_t port)
{
    return cppsock::tcp_client_connect(this->_sock, hostname, port);
}