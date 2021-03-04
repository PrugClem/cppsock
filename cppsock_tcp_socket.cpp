/**
 *  @author: Clemens Pruggmayer (PrugClem)
 *  @date:   2021-02-25
 *  @desc:   implementation for tcp stream sockets
 */
#include "cppsock.hpp"

cppsock::swap_error cppsock::tcp::socket::swap(cppsock::socket &s)
{
    if(s.get_socktype() != cppsock::socket_stream)
    {
        return cppsock::swap_error_socktype;
    }
    std::swap(this->_sock, s);
    return cppsock::swap_error_none;
}

std::streamsize cppsock::tcp::socket::send(const void *data, std::streamsize len, cppsock::msg_flags flags)
{
    return this->_sock.send(data, len, flags);
}

std::streamsize cppsock::tcp::socket::recv(void *data, std::streamsize max_len, cppsock::msg_flags flags)
{
    return this->_sock.recv(data, max_len, flags);
}

error_t cppsock::tcp::socket::available(size_t &buf)
{
    return this->_sock.available(buf);
}
size_t cppsock::tcp::socket::available()
{
    return this->_sock.available();
}

const cppsock::socket &cppsock::tcp::socket::sock()
{
    return this->_sock;
}

error_t cppsock::tcp::socket::close()
{
    if(this->_sock.shutdown(cppsock::socket::shutdown_both) < 0)
        errno = 0; // clear error (ignore error on shutdown)
    return this->_sock.close();
}
