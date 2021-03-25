/**
 * @file cppsock_socket.hpp
 * @author PrugClem
 * @brief Implementationfor cppsock socket class
 * @version 0.1
 * @date 2021-03-04
 * 
 * @copyright Copyright (c) 2021
 * 
 */
#include "cppsock.hpp"

#pragma once

namespace cppsock
{
    class socket
    {
    protected:
        socket_t sock{INVALID_SOCKET};
    public:
        /**
         *  @brief copying does not make sense
         */
        socket(const socket &) = delete;
        /**
         *  @brief copying does not make sense
         */
        socket& operator=(const socket&) = delete;

        /**
         *  @brief initialises an empty, invalid socket
         */
        socket()
        {
            this->sock = INVALID_SOCKET;
        }
        /**
         *  @brief dtor to close socket
         */
        ~socket()
        {
            this->close();
        }
        /**
         *  @brief move constructor
         */
        socket(socket &&other)
        {
            if(this->is_valid()) this->close();
            this->sock = other.sock;
            other.sock = INVALID_SOCKET;
        }
        /**
         *  @brief move assignment operator
         */
        socket& operator=(socket &&other)
        {
            if(this->is_valid()) this->close();
            this->sock = other.sock;
            other.sock = INVALID_SOCKET;
            return *this;
        }
        /**
         *  @brief swap 2 sockets
         */
        void swap(socket &other)
        {
            std::swap(this->sock, other.sock);
        }

        /**
         *  @brief initialise a socket and make it valid
         *  @param fam family to use, cppsock::IPv4 for IPv4, cppsock::IPv6 for IPv6
         *  @param type the socket type, e.g. SOCK_STREAM or SOCK_DGRAM
         *  @param porotcol protocol to use, e.g. IPPROTO_TCP
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t init(ip_family fam, socket_type type, ip_protocol protocol)
        {
            if(this->is_valid())
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
        /**
         *  @brief bind this socket to a given address, a bound socket can be used to accept TCP connections
         *  @param addr address the socket should be bound to
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t bind(const socketaddr& addr)
        {
            if( __is_error(::bind(this->sock, addr.data(), sizeof(socketaddr)) ) )
            {
                __set_errno_from_WSA();
                return SOCKET_ERROR;
            }
            return 0;
        }
        /**
         *  @brief sets a bound socket into listening state to allow tcp connections to be accepted
         *  @param backlog how many unestablished connections should be logged by the underlying OS
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t listen(int backlog)
        {
            if( __is_error(::listen(this->sock, backlog) ) )
            {
                __set_errno_from_WSA();
                return SOCKET_ERROR;
            }
            return 0;
        }
        /**
         *  @brief accepts a TCP connection on a listening socket
         *  @param con the socket the connection should be interacted with
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t accept(socket &con)
        {
            if(con.is_valid())
            {
                errno = EEXIST;
                return -1;
            }
            con.sock = ::accept(this->sock, nullptr, nullptr);
            if( __is_error(con.sock) )
            {
                __set_errno_from_WSA();
                return SOCKET_ERROR;
            }
            return 0;
        }
        /**
         *  @brief connects an initialised socket
         *  @param addr the address the socket should be connecting to
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t connect(const socketaddr &addr)
        {
            if( __is_error(::connect(this->sock, addr.data(), sizeof(socketaddr)) ) )
            {
                __set_errno_from_WSA();
                return SOCKET_ERROR;
            }
            return 0;
        }
        
        /**
         *  @brief sends data over a connected socket
         *  @param data pointer to the start of the data array
         *  @param len length of the buffer in bytes
         *  @param flags changes behavior of the function call, use 0 for default behavioral
         *  @return if smaller than 0, an error occured and errno is set appropriately, the total amount of bytes sent otherwise
         */
        std::streamsize send(const void* data, size_t len, msg_flags flags)
        {
            std::streamsize ret = ::send(this->sock, (const char*)data, len, flags); // typecast to const char* is needed because windows
            if( __is_error(ret) ) __set_errno_from_WSA();
            return ret;
        }
        /**
         *  @brief receives data from a connected socket
         *  @param data pointer to the start of the buffer where the data should be written into
         *  @param maxlen amount of bytes available for the buffer in bytes
         *  @param flags changes behavior of the function call, use 0 for default behavioral
         *  @return 0 if the connection has been closed, smaller than 0 if an error occured, the amount of bytes received otherwise
         */
        std::streamsize recv(void* data, size_t maxlen, msg_flags flags)
        {
            std::streamsize ret = ::recv(this->sock, (char*)data, maxlen, flags); // typecast to char* is needed because windows
            if( __is_error(ret) ) __set_errno_from_WSA();
            return ret;
        }
        /**
         *  @brief sends data over a socket
         *  @param data pointer to the start of the data array
         *  @param len length of the buffer in bytes
         *  @param flags changes behavior of the function call, use 0 for default behavioral
         *  @param dst pointer to a class where the data should be sent to, use nullptr to use default address
         *  @return if smaller than 0, an error occured and errno is set appropriately, the total amount of bytes sent otherwise
         */
        std::streamsize sendto(const void* data, size_t len, msg_flags flags, const socketaddr *dst)
        {
            std::streamsize ret = (dst == nullptr) ? ::sendto(this->sock, (const char*)data, len, flags, nullptr, 0) :               // typecast to const char* is needed because windows
                                            ::sendto(this->sock, (const char*)data, len, flags, dst->data(), sizeof(*dst)); // typecast to const char* is needed because windows
            if( __is_error(ret) ) __set_errno_from_WSA();
            return ret;
        }
        /**
         *  @brief receives data from a connected socket
         *  @param data pointer to the start of the buffer where the data should be written into
         *  @param maxlen amount of bytes available for the buffer in bytes
         *  @param flags changes behavior of the function call, use 0 for default behavioral
         *  @param src pointer to a class where the source address should be written into, use nullptr do discard the src address
         *  @return 0 if the connection has been closed, smaller than 0 if an error occured, the amount of bytes received otherwise
         */
        std::streamsize recvfrom(void* data, size_t max_len, msg_flags flags, socketaddr *src)
        {
            socklen_t socklen = sizeof(*src);
            std::streamsize ret = (src == nullptr) ? ::recvfrom(this->sock, (char*)data, max_len, flags, nullptr, nullptr) :     // typecast to char* is needed because windows
                                            ::recvfrom(this->sock, (char*)data, max_len, flags, src->data(), &socklen); // typecast to char* is needed because windows
            if( __is_error(ret) ) __set_errno_from_WSA();
            return ret;
        }

        /**
         *  @brief get the amount of bytes ready to read
         *  @param buf reference to a buffer where the amount should be written into
         *  @return 0 if everything went right; anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t available(size_t &buf)
        {
            int error = ioctlsocket(this->sock, FIONREAD, (unsigned long*)&buf); // typecast because of windows
            if( __is_error(error) )
            {
                __set_errno_from_WSA();
                return error;
            }
            return 0;
        }
        /**
         *  @brief get the amount of bytes ready to read
         *  @return the amount of bytes to read, if an error occured or no data is ready to be read, 0 is returned
         */
        size_t available()
        {
            size_t rdy = 0;
            if( this->available(rdy) != 0 )
                rdy = 0;
            return rdy;
        }

        /**
         *  @return true if the socket is valid (initialised / listening / connected)
         */
        bool    is_valid() const
        {
            return this->sock != INVALID_SOCKET;
        }
        /**
         *  @brief shuts down parts of the socket or properly terminates a socket connection, THIS CALL IS IRREVERSIBLE!
         *  The socket remains valid, no data can be sent or received
         *  @param how how the socket should be shut down, possible options are listed in the enum cppsock::socket::shutdown_mode
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t shutdown(shutdown_mode how)
        {
            if( __is_error(::shutdown(this->sock, how)) )
            {
                __set_errno_from_WSA();
                return SOCKET_ERROR;
            }
            return 0;
        }
        /**
         *  @brief closes and invalidates the socket
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t close()
        {
            if( __is_error(closesocket(this->sock)) )
            {
                __set_errno_from_WSA();
                return SOCKET_ERROR;
            }
            this->sock = INVALID_SOCKET;
            return 0;
        }
        /**
         *  @brief get the implementation-dependent socket descriptor
         */
        socket_t handle()
        {
            return this->sock;
        }

        /**
         *  @brief retrieves the local socket address
         *  @param addr reference to a buffer where the address should be written into
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t getsockname(socketaddr &addr) const
        {
            socklen_t socklen = sizeof(addr);
            if( __is_error(::getsockname(this->sock, addr.data(), &socklen) ) )
            {
                __set_errno_from_WSA();
                return SOCKET_ERROR;
            }
            return 0;
        }
        /**
         *  @brief retrieves the peer socket address
         *  @param addr reference to a buffer where the address should be written into
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t getpeername(socketaddr &addr) const
        {
            socklen_t socklen = sizeof(addr);
            if( __is_error(::getpeername(this->sock, addr.data(), &socklen) ) )
            {
                __set_errno_from_WSA();
                return SOCKET_ERROR;
            }
            return 0;
        }

        /**
         *  @brief retrieves the local socket address
         *  @return address, if an error occured, the result in undefined
         */
        socketaddr getsockname() const
        {
            socketaddr addr;
            this->getsockname(addr);
            return addr;
        }
        /**
         *  @brief retrieves the local socket address
         *  @return address, if an error occured, the result in undefined
         */
        socketaddr getpeername() const
        {
            socketaddr addr;
            this->getpeername(addr);
            return addr;
        }

        /**
         *  @brief sets a socket option
         *  @param optname socket option name, this can be OS dependant
         *  @param opt_val pointer to the option value
         *  @param opt_len length of the option value
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t setsockopt(int optname, const void* opt_val, socklen_t opt_len)
        {
            if( __is_error(::setsockopt(this->sock, SOL_SOCKET, optname, (const char*)opt_val, opt_len) ) ) // typecast to const char* is needed because windows
            {
                __set_errno_from_WSA();
                return SOCKET_ERROR;
            }
            return 0;
        }
        /**
         *  @brief retrieves a socket option
         *  @param optname socket option name, this can be OS dependant
         *  @param opt_val pointer to a buffer where the value should be written into
         *  @param opt_len length of the buffer provided in opt_val
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t getsockopt(int optname, void* opt_val, socklen_t *opt_len) const
        {
            if ( __is_error(::getsockopt(this->sock, SOL_SOCKET, optname, (char*)opt_val, opt_len) ) ) // typecast to char* is needed because windows
            {
                __set_errno_from_WSA();
                return -1;
            }
            return 0;
        }

        /**
         *  @brief sets the keepalive option
         *  @param newstate the new value for the keepalive option
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t set_keepalive(bool newstate)
        {
            int val = (newstate) ? 1 : 0;
            return this->setsockopt(SO_KEEPALIVE, &val, sizeof(val));
        }
        /**
         *  @brief get the keepalive option
         *  @param buf reference to a buffer where the current state should be written into
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t get_keepalive(bool &buf) const
        {
            socklen_t len = sizeof(buf);
            int boolbuf;
            error_t ret = this->getsockopt(SO_KEEPALIVE, &boolbuf, &len);
            buf = boolbuf;
            return ret;
        }
        /**
         *  @brief get the keepalive option
         *  @return current optionstate, if an error occured, the return value is undefined
         */
        bool    get_keepalive() const
        {
            bool buf;
            this->get_keepalive(buf);
            return buf;
        }

        /**
         *  @brief sets the reuseaddr option
         *  @param newstate the new value for the reuseaddr option
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t set_reuseaddr(bool newstate)
        {
            return this->setsockopt(SO_REUSEADDR, (newstate) ? "1" : "\0", 1);
        }
        /**
         *  @brief get the reuseaddr option
         *  @param buf rference to a buffer where the current state should be written into
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t get_reuseaddr(bool &buf) const
        {
            socklen_t len = sizeof(buf);
            int boolbuf;
            error_t ret = this->getsockopt(SO_REUSEADDR, &boolbuf, &len);
            buf = boolbuf;
            return ret;
        }
        /**
         *  @brief get the reuseaddr option
         *  @return current optionstate, if an error occured, the return value is undefined
         */
        bool    get_reuseaddr() const
        {
            bool buf;
            this->get_reuseaddr(buf);
            return buf;
        }

        /**
         *  @brief get the socket type (cppsock::socket_stream, cppsock::socket_dgram, e.t.c)
         *  @param buf reference to a buffer where the socket type should be written into
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t get_socktype(socket_type &buf) const
        {
            socklen_t len = sizeof(buf);
            error_t ret = this->getsockopt(SO_TYPE, &buf, &len);
            return ret;
        }
        /**
         *  @brief get the socket type (cppsock::socket_stream, cppsock::socket_dgram, e.t.c)
         *  @return socket type, if an error occured, the return value is undefined
         */
        socket_type get_socktype() const
        {
            cppsock::socket_type buf;
            this->get_socktype(buf);
            return buf;
        }
    };
} // namespace cppsock
