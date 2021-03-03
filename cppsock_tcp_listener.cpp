/**
 *  @author: Clemens Pruggmayer (PrugClem)
 *  @date:   2021-03-02
 *  @desc:   implementation for tcp listener sockets
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

const cppsock::socket &cppsock::tcp::listener::sock()
{
    return this->_sock;
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