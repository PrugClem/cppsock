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

const cppsock::socket &cppsock::tcp::socket::sock()
{
    return this->_sock;
}

cppsock::swap_error cppsock::tcp::socket::swap(cppsock::socket &s)
{
    if(s.get_socktype() != cppsock::socket_stream)
    {
        return cppsock::swap_error_socktype;
    }
    std::swap(this->_sock, s);
    return cppsock::swap_error_none;
}

error_t cppsock::tcp::listener::accept(cppsock::tcp::socket &output)
{
    error_t err = this->_sock.accept(output._sock);
    if(err == 0)
    {
        error_t err_sockopt = this->_sock.set_keepalive(true);
        if(err_sockopt < 0)
        {
            return cppsock::utility_warning_keepalive;
        }
    }
    return err;
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

error_t cppsock::tcp::socket::close()
{
    if(this->_sock.shutdown(cppsock::socket::shutdown_both) < 0)
        errno = 0; // clear error (ignore error on shutdown)
    return this->_sock.close();
}

cppsock::utility_error_t cppsock::tcp::client::connect(const socketaddr &addr)
{
    cppsock::utility_error_t err = cppsock::tcp_client_connect(this->_sock, addr);
    if(err != cppsock::utility_error_none)
    {
        error_t err_sockopt = this->_sock.set_keepalive(true);
        if(err_sockopt < 0)
        {
            return cppsock::utility_warning_keepalive;
        }
    }
    return err;
}

cppsock::utility_error_t cppsock::tcp::client::connect(const char *hostname, const char *service)
{
    cppsock::utility_error_t err = cppsock::tcp_client_connect(this->_sock, hostname, service);
    if(err != cppsock::utility_error_none)
    {
        error_t err_sockopt = this->_sock.set_keepalive(true);
        if(err_sockopt < 0)
        {
            return cppsock::utility_warning_keepalive;
        }
    }
    return err;
}
cppsock::utility_error_t cppsock::tcp::client::connect(const char *hostname, uint16_t port)
{
    cppsock::utility_error_t err = cppsock::tcp_client_connect(this->_sock, hostname, port);
    if(err != cppsock::utility_error_none)
    {
        error_t err_sockopt = this->_sock.set_keepalive(true);
        if(err_sockopt < 0)
        {
            return cppsock::utility_warning_keepalive;
        }
    }
    return err;
}
