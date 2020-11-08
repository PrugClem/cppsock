#include "cppsock.hpp"

using namespace cppsock;

socket::socket()
{
    this->sock = INVALID_SOCKET;
}

socket::socket(socket&& other)
{
    this->sock = other.sock;
    other.sock = INVALID_SOCKET;
}

cppsock::socket& socket::operator=(socket &&other)
{
    this->sock = other.sock;
    other.sock = INVALID_SOCKET;
    return *this;
}

void socket::swap(socket &other)
{
    std::swap(this->sock, other.sock);
}

error_t socket::init(sa_family_t fam, int type, int protocol)
{
    this->sock = ::socket(fam, type, protocol);
    if( this->sock == INVALID_SOCKET)
    {
        __set_errno_from_WSA();
        return INVALID_SOCKET;
    }
    return 0;
}

error_t socket::bind(const socketaddr &addr)
{
    if( ::bind(this->sock, addr.data(), sizeof(socketaddr)) == SOCKET_ERROR )
    {
        __set_errno_from_WSA();
        return SOCKET_ERROR;
    }
    return 0;
}

error_t socket::listen(int backlog)
{
    if( ::listen(this->sock, backlog) == SOCKET_ERROR )
    {
        __set_errno_from_WSA();
        return SOCKET_ERROR;
    }
    return 0;
}

error_t socket::accept(socket &other)
{
    other.sock = ::accept(this->sock, nullptr, nullptr);
    if(other.sock == INVALID_SOCKET)
    {
        __set_errno_from_WSA();
        return INVALID_SOCKET;
    }
    return 0;
}

error_t socket::connect(const socketaddr& addr)
{
    if( ::connect(this->sock, addr.data(), sizeof(socketaddr)) == SOCKET_ERROR )
    {
        __set_errno_from_WSA();
        return SOCKET_ERROR;
    }
    return 0;
}

ssize_t socket::send(const void* buf, size_t size, int flags)
{
    ssize_t ret = ::send(this->sock, (const char*)buf, size, flags); // typecast to const char* is needed because windows
    if(ret == SOCKET_ERROR) __set_errno_from_WSA();
    return ret;
}

ssize_t socket::recv(void* buf, size_t size, int flags)
{
    ssize_t ret = ::recv(this->sock, (char*)buf, size, flags); // typecast to char* is needed because windows
    if(ret == SOCKET_ERROR) __set_errno_from_WSA();
    return ret;
}

ssize_t socket::sendto(const void* buf, size_t size, int flags, const socketaddr* dst)
{
    ssize_t ret = (dst == nullptr) ? ::sendto(this->sock, (const char*)buf, size, flags, nullptr, 0) :               // typecast to const char* is needed because windows
                                     ::sendto(this->sock, (const char*)buf, size, flags, dst->data(), sizeof(*dst)); // typecast to const char* is needed because windows
    if(ret == SOCKET_ERROR) __set_errno_from_WSA();
    return ret;
}

ssize_t socket::recvfrom(void* buf, size_t size, int flags, socketaddr* src)
{
    socklen_t socklen = sizeof(*src);
    ssize_t ret = (src == nullptr) ? ::recvfrom(this->sock, (char*)buf, size, flags, nullptr, nullptr) :     // typecast to char* is needed because windows
                                     ::recvfrom(this->sock, (char*)buf, size, flags, src->data(), &socklen); // typecast to char* is needed because windows
    if(ret == SOCKET_ERROR) __set_errno_from_WSA();
    return ret;
}

bool socket::is_valid() const
{
    return this->sock != INVALID_SOCKET;
}

error_t socket::shutdown(int how)
{
    if( ::shutdown(this->sock, how) == SOCKET_ERROR )
    {
        __set_errno_from_WSA();
        return SOCKET_ERROR;
    }
    return 0;
}

error_t socket::close()
{
    if( closesocket(this->sock) == SOCKET_ERROR )
    {
        __set_errno_from_WSA();
        return SOCKET_ERROR;
    }
    this->sock = INVALID_SOCKET;
    return 0;
}

error_t socket::getsockname(socketaddr& addr) const
{
    socklen_t socklen = sizeof(addr);
    if( ::getsockname(this->sock, addr.data(), &socklen) == SOCKET_ERROR )
    {
        __set_errno_from_WSA();
        return SOCKET_ERROR;
    }
    return 0;
}

error_t socket::getpeername(socketaddr &addr) const
{
    socklen_t socklen = sizeof(addr);
    if( ::getpeername(this->sock, addr.data(), &socklen) == SOCKET_ERROR )
    {
        __set_errno_from_WSA();
        return SOCKET_ERROR;
    }
    return 0;
}

socketaddr socket::getsockname() const
{
    socketaddr addr;
    this->getsockname(addr);
    return addr;
}

socketaddr socket::getpeername() const
{
    socketaddr addr;
    this->getpeername(addr);
    return addr;
}

error_t socket::setsockopt(int optname, const void *opt_val, socklen_t opt_size)
{
    if( ::setsockopt(this->sock, SOL_SOCKET, optname, (const char*)opt_val, opt_size) == SOCKET_ERROR) // typecast to const char* is needed because windows
    {
        __set_errno_from_WSA();
        return SOCKET_ERROR;
    }
    return 0;
}

error_t socket::getsockopt(int optname, void *opt_val, socklen_t *opt_size) const
{
    if ( ::getsockopt(this->sock, SOL_SOCKET, optname, (char*)opt_val, opt_size) == SOCKET_ERROR ) // typecast to char* is needed because windows
    {
        __set_errno_from_WSA();
        return -1;
    }
    return 0;
}

error_t socket::set_keepalive(bool keepalive)
{
    return this->setsockopt(SO_KEEPALIVE, (keepalive) ? "1" : "\0", 1);
}

error_t socket::get_keepalive(bool &keepalive) const
{
    socklen_t len = sizeof(keepalive);
    int boolbuf;
    error_t ret = this->getsockopt(SO_KEEPALIVE, &boolbuf, &len);
    keepalive = boolbuf;
    return ret;
}

bool socket::get_keepalive() const
{
    bool buf;
    this->get_keepalive(buf);
    return buf;
}

error_t socket::set_reuseaddr(bool reuseaddr)
{
    return this->setsockopt(SO_REUSEADDR, (reuseaddr) ? "1" : "\0", 1);
}

error_t socket::get_reuseaddr(bool &reuseaddr) const
{
    socklen_t len = sizeof(reuseaddr);
    int boolbuf;
    error_t ret = this->getsockopt(SO_REUSEADDR, &boolbuf, &len);
    reuseaddr = boolbuf;
    return ret;
}

bool socket::get_reuseaddr() const
{
    bool buf;
    this->get_reuseaddr(buf);
    return buf;
}