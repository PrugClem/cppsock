/**
 *  @author: Clemens Pruggmayer (PrugClem)
 *  @date:   2021-02-25
 *  @desc:   implementation for udp sockets
 */
#include "cppsock.hpp"

cppsock::utility_error_t cppsock::udp::socket::setup(const cppsock::socketaddr &addr)
{
    return cppsock::udp_socket_setup(this->_sock, addr);
}

cppsock::utility_error_t cppsock::udp::socket::setup(const char *hostname, const char *service)
{
    return cppsock::udp_socket_setup(this->_sock, hostname, service);
}

cppsock::utility_error_t cppsock::udp::socket::setup(const char *hostname, uint16_t port)
{
    return cppsock::udp_socket_setup(this->_sock, hostname, port);
}

ssize_t cppsock::udp::socket::sendto(const void* data, size_t len, msg_flags flags, const socketaddr *dst)
{
    return this->_sock.sendto(data, len, flags, dst);
}
ssize_t cppsock::udp::socket::recvfrom(void* data, size_t max_len, msg_flags flags, socketaddr *src)
{
    return this->_sock.recvfrom(data, max_len, flags, src);
}

const cppsock::socket &cppsock::udp::socket::sock()
{
    return this->_sock;
}
cppsock::swap_error cppsock::udp::socket::swap(cppsock::socket &s)
{
    if(s.get_socktype() != cppsock::socket_dgram)
    {
        return cppsock::swap_error_socktype;
    }
    std::swap(s, this->_sock);
    return cppsock::swap_error_none;
}

error_t cppsock::udp::socket::close()
{
    return this->_sock.close();
}