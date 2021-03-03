/**
 *  @author: Clemens Pruggmayer (PrugClem)
 *  @date:   2021-03-02
 *  @desc:   implementation for tcp client sockets
 */
#include "cppsock.hpp"

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
