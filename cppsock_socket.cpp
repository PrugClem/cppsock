/**
 *  author: Clemens Pruggmayer (PrugClem)
 *  date:   2020-12-22
 *  desc:   implementation for sockets, used to send/transmit data
 */
#include "cppsock.hpp"

cppsock::socket::socket()
{
    this->sock = INVALID_SOCKET;
}

cppsock::socket::~socket()
{
    this->close();
}

cppsock::socket::socket(socket&& other)
{
    this->close();
    this->sock = other.sock;
    other.sock = INVALID_SOCKET;
}

cppsock::socket& cppsock::socket::operator=(socket &&other)
{
    this->close();
    this->sock = other.sock;
    other.sock = INVALID_SOCKET;
    return *this;
}

void cppsock::socket::swap(socket &other)
{
    std::swap(this->sock, other.sock);
}

error_t cppsock::socket::init(cppsock::ip_family fam, cppsock::socket_type type, cppsock::ip_protocol protocol)
{
    if(this->sock != INVALID_SOCKET)
    {
        errno = EEXIST;
        return -1;
    }
    this->sock = ::socket(fam, type, protocol);
    if( __is_error(this->sock) )
    {
        __set_errno_from_WSA();
        return SOCKET_ERROR;
    }
    return 0;
}

error_t cppsock::socket::bind(const socketaddr &addr)
{
    if( __is_error(::bind(this->sock, addr.data(), sizeof(socketaddr)) ) )
    {
        __set_errno_from_WSA();
        return SOCKET_ERROR;
    }
    return 0;
}

error_t cppsock::socket::listen(int backlog)
{
    if( __is_error(::listen(this->sock, backlog) ) )
    {
        __set_errno_from_WSA();
        return SOCKET_ERROR;
    }
    return 0;
}

error_t cppsock::socket::accept(socket &other)
{
    other.sock = ::accept(this->sock, nullptr, nullptr);
    if( __is_error(other.sock) )
    {
        __set_errno_from_WSA();
        return SOCKET_ERROR;
    }
    return 0;
}

error_t cppsock::socket::connect(const socketaddr& addr)
{
    if( __is_error(::connect(this->sock, addr.data(), sizeof(socketaddr)) ) )
    {
        __set_errno_from_WSA();
        return SOCKET_ERROR;
    }
    return 0;
}

ssize_t cppsock::socket::send(const void* buf, size_t size, cppsock::msg_flags flags)
{
    ssize_t ret = ::send(this->sock, (const char*)buf, size, flags); // typecast to const char* is needed because windows
    if( __is_error(ret) ) __set_errno_from_WSA();
    return ret;
}

ssize_t cppsock::socket::recv(void* buf, size_t size, cppsock::msg_flags flags)
{
    ssize_t ret = ::recv(this->sock, (char*)buf, size, flags); // typecast to char* is needed because windows
    if( __is_error(ret) ) __set_errno_from_WSA();
    return ret;
}

ssize_t cppsock::socket::sendto(const void* buf, size_t size, cppsock::msg_flags flags, const socketaddr* dst)
{
    ssize_t ret = (dst == nullptr) ? ::sendto(this->sock, (const char*)buf, size, flags, nullptr, 0) :               // typecast to const char* is needed because windows
                                     ::sendto(this->sock, (const char*)buf, size, flags, dst->data(), sizeof(*dst)); // typecast to const char* is needed because windows
    if( __is_error(ret) ) __set_errno_from_WSA();
    return ret;
}

ssize_t cppsock::socket::recvfrom(void* buf, size_t size, cppsock::msg_flags flags, socketaddr* src)
{
    socklen_t socklen = sizeof(*src);
    ssize_t ret = (src == nullptr) ? ::recvfrom(this->sock, (char*)buf, size, flags, nullptr, nullptr) :     // typecast to char* is needed because windows
                                     ::recvfrom(this->sock, (char*)buf, size, flags, src->data(), &socklen); // typecast to char* is needed because windows
    if( __is_error(ret) ) __set_errno_from_WSA();
    return ret;
}

error_t cppsock::socket::available(size_t &buf)
{
    int error = ioctlsocket(this->sock, FIONREAD, (unsigned long*)&buf); // typecast because of windows
    if( __is_error(error) )
    {
        __set_errno_from_WSA();
        return error;
    }
    return 0;
}

size_t cppsock::socket::available()
{
    size_t rdy = 0;
    if( this->available(rdy) != 0 )
        rdy = 0;
    return rdy;
}

bool cppsock::socket::is_valid() const
{
    return this->sock != INVALID_SOCKET;
}

error_t cppsock::socket::shutdown(socket::shutdown_mode how)
{
    if( __is_error(::shutdown(this->sock, how)) )
    {
        __set_errno_from_WSA();
        return SOCKET_ERROR;
    }
    return 0;
}

error_t cppsock::socket::close()
{
    if( __is_error(closesocket(this->sock)) )
    {
        __set_errno_from_WSA();
        return SOCKET_ERROR;
    }
    this->sock = INVALID_SOCKET;
    return 0;
}

socket_t cppsock::socket::handle()
{
    return this->sock;
}

error_t cppsock::socket::getsockname(cppsock::socketaddr& addr) const
{
    socklen_t socklen = sizeof(addr);
    if( __is_error(::getsockname(this->sock, addr.data(), &socklen) ) )
    {
        __set_errno_from_WSA();
        return SOCKET_ERROR;
    }
    return 0;
}

error_t cppsock::socket::getpeername(cppsock::socketaddr &addr) const
{
    socklen_t socklen = sizeof(addr);
    if( __is_error(::getpeername(this->sock, addr.data(), &socklen) ) )
    {
        __set_errno_from_WSA();
        return SOCKET_ERROR;
    }
    return 0;
}

cppsock::socketaddr cppsock::socket::getsockname() const
{
    socketaddr addr;
    this->getsockname(addr);
    return addr;
}

cppsock::socketaddr cppsock::socket::getpeername() const
{
    socketaddr addr;
    this->getpeername(addr);
    return addr;
}

error_t cppsock::socket::setsockopt(int optname, const void *opt_val, socklen_t opt_size)
{
    if( __is_error(::setsockopt(this->sock, SOL_SOCKET, optname, (const char*)opt_val, opt_size) ) ) // typecast to const char* is needed because windows
    {
        __set_errno_from_WSA();
        return SOCKET_ERROR;
    }
    return 0;
}

error_t cppsock::socket::getsockopt(int optname, void *opt_val, socklen_t *opt_size) const
{
    if ( __is_error(::getsockopt(this->sock, SOL_SOCKET, optname, (char*)opt_val, opt_size) ) ) // typecast to char* is needed because windows
    {
        __set_errno_from_WSA();
        return -1;
    }
    return 0;
}

error_t cppsock::socket::set_keepalive(bool keepalive)
{
    int val = (keepalive) ? 1 : 0;
    return this->setsockopt(SO_KEEPALIVE, &val, sizeof(val));
}

error_t cppsock::socket::get_keepalive(bool &keepalive) const
{
    socklen_t len = sizeof(keepalive);
    int boolbuf;
    error_t ret = this->getsockopt(SO_KEEPALIVE, &boolbuf, &len);
    keepalive = boolbuf;
    return ret;
}

bool cppsock::socket::get_keepalive() const
{
    bool buf;
    this->get_keepalive(buf);
    return buf;
}

error_t cppsock::socket::set_reuseaddr(bool reuseaddr)
{
    return this->setsockopt(SO_REUSEADDR, (reuseaddr) ? "1" : "\0", 1);
}

error_t cppsock::socket::get_reuseaddr(bool &reuseaddr) const
{
    socklen_t len = sizeof(reuseaddr);
    int boolbuf;
    error_t ret = this->getsockopt(SO_REUSEADDR, &boolbuf, &len);
    reuseaddr = boolbuf;
    return ret;
}

bool cppsock::socket::get_reuseaddr() const
{
    bool buf;
    this->get_reuseaddr(buf);
    return buf;
}

error_t cppsock::socket::get_socktype(cppsock::socket_type &socktype) const
{
    socklen_t len = sizeof(socktype);
    error_t ret = this->getsockopt(SO_TYPE, &socktype, &len);
    return ret;
}

cppsock::socket_type cppsock::socket::get_socktype() const
{
    cppsock::socket_type buf;
    this->get_socktype(buf);
    return buf;
}
