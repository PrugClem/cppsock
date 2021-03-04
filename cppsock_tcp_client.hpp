/**/
#include "cppsock.hpp"
#ifndef CPPSOCK_HPP_INCLUDED
#error this file is included by in cppsock.hpp
#endif

#include "cppsock_types.hpp"

#ifndef CPPSOCK_TCP_CLIENT_HPP_INCLUDED
#define CPPSOCK_TCP_CLIENT_HPP_INCLUDED

namespace cppsock
{
    namespace tcp
    {
        class client : public cppsock::tcp::socket
        {
        public:
            /**
             *  @brief connects this tcp socket to a server
             *  @param addr the server's IP address
             *  @return cppsock utility error code that can be transformed into a human-readable string with cppsock::utility_strerror(), 
             *          a code of smaller than zero indicates an error and errno is set to the last error
             *          a code of greater than zero indicates a warning and errno is set to the last warning
             */
            cppsock::utility_error_t connect(const cppsock::socketaddr &addr)
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
            /**
             *  @brief connects this tcp socket to a server
             *  @param hostname hostname / IP address of the server
             *  @param serivce service name / port number in string for the port the server should listen to e.g. "http" or "80" for port 80
             *  @return cppsock utility error code that can be transformed into a human-readable string with cppsock::utility_strerror(), 
             *          a code of smaller than zero indicates an error and errno is set to the last error
             *          a code of greater than zero indicates a warning and errno is set to the last warning
             */
            cppsock::utility_error_t connect(const char *hostname, const char *service)
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
            /**
             *  @brief connects this tcp socket to a server
             *  @param hostname hostname / IP address of the server
             *  @param port port number the client should connect to, in host byte order
             *  @return cppsock utility error code that can be transformed into a human-readable string with cppsock::utility_strerror(), 
             *          a code of smaller than zero indicates an error and errno is set to the last error
             *          a code of greater than zero indicates a warning and errno is set to the last warning
             */
            cppsock::utility_error_t connect(const char *hostname, uint16_t port)
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
        };
    } // namespace tcp
    
} // namespace cppsock

#endif // CPPSOCK_TCP_CLIENT_HPP_INCLUDED
