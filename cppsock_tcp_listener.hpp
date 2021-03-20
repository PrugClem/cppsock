/**
 * @file cppsock_tcp_listener.hpp
 * @author PrugClem
 * @brief implementation for cppsock tcp listener sockets
 * @version 0.1
 * @date 2021-03-09
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include "cppsock.hpp"

#ifndef CPPSOCK_TCP_LISTENER_HPP_INCLUDED
#define CPPSOCK_TCP_LISTENER_HPP_INCLUDED

namespace cppsock
{
    namespace tcp
    {
        class socket;
        class listener
        {
        protected:
            cppsock::socket _sock;
        public:
            virtual ~listener()
            {
                this->close();
            }
            /**
             *  @brief sets up a tcp listener socket
             *  @param addr the address the listener should listen to
             *  @param backlog how many unestablished connections should be logged by the OS
             *  @return cppsock utility error code that can be transformed into a human-readable string with cppsock::utility_strerror(), 
             *          a code of smaller than zero indicates an error and errno is set to the last error
             *          a code of greater than zero indicates a warning and errno is set to the last warning
             */
            cppsock::utility_error_t setup(const cppsock::socketaddr &addr, int backlog)
            {
                return cppsock::tcp_listener_setup(this->_sock, addr, backlog);
            }
            /**
             *  @brief sets up a tcp listener socket
             *  @param hostname the ip address the listener should listen to
             *  @param service the service name / port number the server should listen to
             *  @param backlog how many unestablished connections should be logged by the OS
             *  @return cppsock utility error code that can be transformed into a human-readable string with cppsock::utility_strerror(), 
             *          a code of smaller than zero indicates an error and errno is set to the last error
             *          a code of greater than zero indicates a warning and errno is set to the last warning
             */
            cppsock::utility_error_t setup(const char *hostname, const char *service, int backlog)
            {
                return cppsock::tcp_listener_setup(this->_sock, hostname, service, backlog);
            }
            /**
             *  @brief sets up a tcp listener socket
             *  @param hostname the ip address the listener should listen to
             *  @param port the port number the server should listen to
             *  @param backlog how many unestablished connections should be logged by the OS
             *  @return cppsock utility error code that can be transformed into a human-readable string with cppsock::utility_strerror(), 
             *          a code of smaller than zero indicates an error and errno is set to the last error
             *          a code of greater than zero indicates a warning and errno is set to the last warning
             */
            cppsock::utility_error_t setup(const char *hostname, uint16_t port, int backlog)
            {
                return cppsock::tcp_listener_setup(this->_sock, hostname, port, backlog);
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
            cppsock::swap_error swap(cppsock::socket &s)
            {
                int val = 0;
                socklen_t len = sizeof(val);

                if(s.is_valid())
                {
                    if((s.getsockopt(SO_ACCEPTCONN, &val, &len) != 0) || (val == 0))
                    {
                        return cppsock::swap_error_not_listening;
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
             *  @brief accepts a tcp connection socket from a listener socket
             *  @param output the tcp sonnection socket the output should be written into
             *  @return 0 if everything went right, 
             *          anything smaller than 0 indicates an error and errno is set appropriately,
             *          anything greater than zero indicates a warning and errno is set appropriately
             */
            error_t accept(cppsock::tcp::socket &output)
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
            /**
             *  @brief closes and invalidates the socket
             *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
             */
            error_t close()
            {
                if(this->_sock.shutdown(cppsock::shutdown_both) < 0)
                    errno = 0; // clear error (ignore error on shutdown)
                error_t err = this->_sock.close();
                return err;
            }
        };
    } // namespace tcp
} // namespace cppsock

#endif // CPPSOCK_TCP_LISTENER_HPP_INCLUDED
