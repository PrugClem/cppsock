/**
 * @file cppsock_udp_socket.hpp
 * @author PrugClem
 * @brief implementation for cppsock udp sockets
 * @version 0.1
 * @date 2021-03-09
 * 
 * @copyright Copyright (c) 2021
 * 
 */
#include "cppsock.hpp"

#pragma once

namespace cppsock
{
    namespace udp
    {
        class socket
        {
        protected:
            cppsock::socket _sock;
        public:
            /**
             *  @brief sets up a UDP socket
             *  @param sock invalid socket that should be used to set up the udp socket
             *  @param addr local address for the udp socket, cppsock::any_addr can be used to not specify a address
             *  @return cppsock utility error code that can be transformed into a human-readable string with cppsock::utility_strerror(), 
             *          a code of smaller than zero indicates an error and errno is set to the last error
             *          a code of greater than zero indicates a warning and errno is set to the last warning
             */
            cppsock::error_t setup(const cppsock::socketaddr &addr)
            {
                return cppsock::udp_socket_setup(this->_sock, addr);
            }
            /**
             *  @brief sets a socket up to be a UDP socket
             *  @param sock invalid socket that should be used to set up the udp socket
             *  @param hostname hostname / address the socket should listen to
             *  @param service service name / port number in string for the port the socket should listen to; if the local port doesn't matter, use "0"
             *  @return cppsock utility error code that can be transformed into a human-readable string with cppsock::utility_strerror(), 
             *          a code of smaller than zero indicates an error and errno is set to the last error
             *          a code of greater than zero indicates a warning and errno is set to the last warning
             */
            cppsock::error_t setup(const char *hostname, const char *service)
            {
                return cppsock::udp_socket_setup(this->_sock, hostname, service);
            }
            /**
             *  @brief sets a socket up to be a UDP socket
             *  @param sock invalid socket that should be used to set up the udp socket
             *  @param hostname hostname / address the socket should listen to
             *  @param port port number the socket should use, in host byte order; if the local port doesn't matter, use port 0
             *  @return cppsock utility error code that can be transformed into a human-readable string with cppsock::utility_strerror(), 
             *          a code of smaller than zero indicates an error and errno is set to the last error
             *          a code of greater than zero indicates a warning and errno is set to the last warning
             */
            cppsock::error_t setup(const char *hostname, uint16_t port)
            {
                return cppsock::udp_socket_setup(this->_sock, hostname, port);
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
                return this->_sock.sendto(data, len, flags, dst);
            }
            /**
             *  @brief receives data from a connected socket
             *  @param data pointer to the start of the buffer where the data should be written into
             *  @param maxlen amount of bytes available for the buffer in bytes
             *  @param flags changes behavior of the function call, use 0 for default behavioral
             *  @param src pointer to a class where the source address should be written into, use nullptr do discard the src address
             *  @return 0 if the connection has been closed, smaller than 0 if an error occured, the amount of bytes received otherwise
             */
            std::streamsize recvfrom(void* data, size_t maxlen, msg_flags flags, socketaddr *src)
            {
                return this->_sock.recvfrom(data, maxlen, flags, src);
            }

            /**
             *  @return the underlying socket instance
             */
            const cppsock::socket &sock() const
            {
                return this->_sock;
            }
            /**
             *  @brief tries to swap a cppsock::socket into this instance
             *  @param s socket that should be swapped into this instance, can be invalid
             *  @return 0 if the sockets could be swapped,
             *          anything smaller than zero indicates an error, the socket are not swapped and errno may be set appropriately
             */
            cppsock::error_t swap(cppsock::socket &s)
            {
                if(s.is_valid())
                {
                    if(s.get_socktype() != cppsock::socket_dgram)
                    {
                        return cppsock::swap_error_socktype;
                    }
                }
                std::swap(s, this->_sock);
                errno = 0;
                return cppsock::error_none;
            }

            /**
             *  @brief closes and invalidates the socket
             *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
             */
            ::error_t close()
            {
                return this->_sock.close();
            }
        };
    } // namespace udp
    
} // namespace cppsock
