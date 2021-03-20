/**
 * @file cppsock_tcp_socket.hpp
 * @author PrugClem
 * @brief implementation for cppsock tcp sockets
 * @version 0.1
 * @date 2021-03-09
 * 
 * @copyright Copyright (c) 2021
 * 
 */
#include "cppsock.hpp"

#ifndef CPPSOCK_TCP_SOCKET_HPP_INCLUDED
#define CPPSOCK_TCP_SOCKET_HPP_INCLUDED

namespace cppsock
{
    namespace tcp
    {
        class listener;
        class socket
        {
        protected:
            cppsock::socket _sock;
        public:
            virtual ~socket()
            {
                this->close();
            }
            
            void swap(cppsock::tcp::socket &other)
            {
                std::swap(this->_sock, other._sock);
            }
            /**
             *  @brief sends data over this tcp connection
             *  @param data pointer to the start of the data array
             *  @param len length of the buffer in bytes
             *  @param flags changes behavior of the function call, use 0 for default behavioral
             *  @return if smaller than 0, an error occured and errno is set appropriately, the total amount of bytes sent otherwise
             */
            std::streamsize send(const void *data, std::streamsize len, cppsock::msg_flags flags)
            {
                return this->_sock.send(data, len, flags);
            }
            /**
             *  @brief receives data from this tcp connection
             *  @param data pointer to the start of the buffer where the data should be written into
             *  @param maxlen amount of bytes available for the buffer in bytes
             *  @param flags changes behavior of the function call, use 0 for default behavioral
             *  @return 0 if the connection has been closed, smaller than 0 if an error occured, the amount of bytes received otherwise
             */
            std::streamsize recv(void *data, std::streamsize max_len, cppsock::msg_flags flags)
            {
                return this->_sock.recv(data, max_len, flags);
            }
            /**
             *  @brief get the amount of bytes ready to read
             *  @param buf reference to a buffer where the amount should be written into
             *  @return 0 if everything went right; anything smaller than 0 indicates an error and errno is set appropriately
             */
            error_t available(size_t &buf)
            {
                return this->_sock.available(buf);
            }
            /**
             *  @brief get the amount of bytes ready to read
             *  @return the amount of bytes to read, if an error occured or no data is ready to be read, 0 is returned
             */
            size_t available()
            {
                return this->_sock.available();
            }

            friend class cppsock::tcp::listener;
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
            cppsock::swap_error swap(cppsock::socket &s)
            {
                int val = 0;
                socklen_t len = sizeof(val);
 
                if(s.is_valid())
                {
                    if((s.getsockopt(SO_ACCEPTCONN, &val, &len) != 0) || (val != 0))
                    {
                        return cppsock::swap_error_listening;
                    }
                    if(s.get_socktype() != cppsock::socket_stream)
                    {
                        return cppsock::swap_error_socktype;
                    }
                }
                std::swap(this->_sock, s);
                errno = 0;
                return cppsock::swap_error_none;
            }

            /**
             *  @brief terminates the connection, closes and invalidates the socket
             *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
             */
            error_t close()
            {
                if(this->_sock.shutdown(cppsock::shutdown_both) < 0)
                    errno = 0; // clear error (ignore error on shutdown)
                return this->_sock.close();
            }

        }; // class socket
    } // namespace tcp
} // namespace cppsock

#endif // CPPSOCK_TCP_SOCKET_HPP_INCLUDED
