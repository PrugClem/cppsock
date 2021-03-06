/**
 * @file cppsock_utility.hpp
 * @author PrugClem
 * @brief implementation for cppsock utility functionalities
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
    /**
     *  @brief resolves a hostname
     *  @param hostname hostname that should be resolved, nullptr to use loopback
     *  @param service service name or port number in string format, e.g. "http" or "80" results in port number 80
     *  @param hints hints to restrict the results
     *  @param output reference to a output container to write the results to
     *  @return 0 if everything went right, anything else indicates an error that can pe printed with gai_strerror()
     */
    inline ::error_t getaddrinfo(const char *hostname, const char* service, const addressinfo *hints, std::vector<addressinfo>& output)
    {
        addressinfo buf;
        addrinfo *res;
        ::error_t error = ::getaddrinfo(hostname, service, (hints == nullptr) ? nullptr: hints->data(), &res);
        if(error != 0)
        {
            __set_errno_from_WSA();
            return error;
        }

        while(res)
        {
            memcpy(buf.data(), res, sizeof(*res));
            output.push_back(buf);
            res = res->ai_next;
        }
        return 0;
    }
    /**
     *  @brief ostream operator for easy output, I will not implement an istream operator
     */
    inline std::ostream& operator<<(std::ostream &o, const cppsock::socketaddr &addr)
    {
        if(addr.get_family() == AF_INET)
            return o << addr.get_addr() << ":" << addr.get_port();
        else if(addr.get_family() == AF_INET6)
            return o << "[" << addr.get_addr() << "]:" << addr.get_port();
        else
            return o << "error: unknown address family";
    }
    /**
     *  @brief gets the machine's hostname
     *  @param strbuf buffer where the hostname should be written into
     *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
     */
    inline ::error_t hostname(std::string &strbuf)
    {
        char buf[256];
        if( __is_error( gethostname(buf, sizeof(buf)) ) )
        {
            __set_errno_from_WSA();
            return -1;
        }

        strbuf = buf;
        return 0;
    }
    /**
     *  @brief gets the machine's hostname
     *  @return the machine's hostname, if an error occured the return value is undefined
     */
    inline std::string hostname()
    {
        std::string ret;
        cppsock::hostname(ret);
        return ret;
    }

    /**
     *  @brief sets up a TCP server and sets the socket into the listening state
     *  @param listener, invalid socket that should be used as the listening socket, will be initialised, bound and set into listening state
     *  @param addr the address the server should listen to, cppsock::any_addr can be used to listen an every address
     *  @param backlog how many unestablished connections should be logged by the underlying OS
     *  @return cppsock utility error code that can be transformed into a human-readable string with cppsock::utility_strerror(), 
     *          a code of smaller than zero indicates an error and errno is set to the last error
     *          a code of greater than zero indicates a warning and errno is set to the last warning
     */
    inline cppsock::error_t tcp_listener_setup(socket &listener, const socketaddr &addr, int backlog)
    {
        if(listener.is_valid()) return cppsock::utility_error_initialised;
        if((listener.init(addr.get_family(), cppsock::socket_stream, cppsock::ip_protocol_tcp)) == 0)
            if((listener.bind(addr)) == 0)
                if((listener.listen(backlog)) == 0)
                    return cppsock::error_none;
        if(listener.is_valid()) listener.close(); // close socket is it was open
        return cppsock::utility_error_fail;
    }
    /**
     *  @brief sets up a TCP server, binds and sets the listener socket into listening state
     *  @param listener invalid socket that should be used as the listening socket, will be initialised, bound and set into listening state
     *  @param hostname the hostname / address the server should listen to, nullptr to let it listen on every IP device
     *  @param serivce service name / port number in string for the port the server should listen to e.g. "http" or "80" for port 80
     *  @param backlog how many unestablished connections should be logged by the underlying OS
     *  @return cppsock utility error code that can be transformed into a human-readable string with cppsock::utility_strerror(), 
     *          a code of smaller than zero indicates an error and errno is set to the last error
     *          a code of greater than zero indicates a warning and errno is set to the last warning
     */
    inline cppsock::error_t tcp_listener_setup(socket &listener, const char *hostname, const char *service, int backlog)
    {
        std::vector<cppsock::addressinfo> res;
        addressinfo hints;
        ::error_t errno_last = errno; // store errno

        if(listener.is_valid()) return cppsock::utility_error_initialised;
        hints.reset().set_socktype(cppsock::socket_stream).set_protocol(cppsock::ip_protocol_tcp).set_passive(true); // set hints to TCP for bind()-ing
        if(cppsock::getaddrinfo(hostname, service, &hints, res) != 0)   // get addresses to bind
        {
            // getaddressinfo failed
            return cppsock::utility_error_gai_fail;
        }
        if(res.size() == 0)
        {
            // no results given
            return cppsock::utility_error_no_results;
        }
        for(addressinfo &ai : res) // go through every address
        { 
            cppsock::error_t err = cppsock::tcp_listener_setup(listener, ai, backlog);
            if(err == cppsock::error_none)
            {
                return cppsock::error_none;
            }
            errno_last = errno; // store errno
            errno = 0; // reset errno in case of a fail
        }
        errno = errno_last; // restore last errno if no address could be used
        return cppsock::utility_error_no_success; // if this is reached, no address coule be used to bind
    }
    /**
     *  @brief sets up a TCP server, binds and sets the listener socket into listening state
     *  @param listener invalid socket that should be used as the listening socket, will be initialised, bound and set into listening state
     *  @param hostname the hostname / address the server should listen to, nullptr to let it listen on every IP device
     *  @param port port number the server should listen to, in host byte order
     *  @param backlog how many unestablished connections should be logged by the underlying OS
     *  @return cppsock utility error code that can be transformed into a human-readable string with cppsock::utility_strerror(), 
     *          a code of smaller than zero indicates an error and errno is set to the last error
     *          a code of greater than zero indicates a warning and errno is set to the last warning
     */
    inline cppsock::error_t tcp_listener_setup(socket &listener, const char* hostname, uint16_t port, int backlog)
    {
        std::stringstream ss;

        ss.clear();
        ss << port;
        return tcp_listener_setup(listener, hostname, ss.str().c_str(), backlog);
    }
    /**
     *  @brief connects a TCP client to a server and connects the provided socket
     *  @param client invalid socket that should be used to connect to the server
     *  @param addr the server's IP address
     *  @return cppsock utility error code that can be transformed into a human-readable string with cppsock::utility_strerror(), 
     *          a code of smaller than zero indicates an error and errno is set to the last error
     *          a code of greater than zero indicates a warning and errno is set to the last warning
     */
    inline cppsock::error_t tcp_client_connect(socket &client, const socketaddr &addr)
    {
        if(client.is_valid()) return cppsock::utility_error_initialised;
        if ((client.init(addr.get_family(), cppsock::socket_stream, cppsock::ip_protocol_tcp)) == 0)
        {
            if ((client.connect(addr)) == 0)
            {
                return cppsock::error_none;
            }
            else
            {
                if (client.is_valid()) client.close(); // close socket if it was open
                return cppsock::utility_error_connect;
            }
        }
        if(client.is_valid()) client.close(); // close socket if it was open
        return cppsock::utility_error_fail;
    }
    /**
     *  @brief connects a TCP client to a server and connects the provided socket
     *  @param client invalid socket that should be used to connect to the server
     *  @param hostname hostname / IP address of the server
     *  @param service service name / port number in string for the port the client should connect to e.g. "http" or "80" for port 80
     *  @return cppsock utility error code that can be transformed into a human-readable string with cppsock::utility_strerror(), 
     *          a code of smaller than zero indicates an error and errno is set to the last error
     *          a code of greater than zero indicates a warning and errno is set to the last warning
     */
    inline cppsock::error_t tcp_client_connect(socket &client, const char *hostname, const char *service)
    {
        std::vector<cppsock::addressinfo> res;
        addressinfo hints;
        ::error_t errno_last = errno;

        if(client.is_valid()) return cppsock::utility_error_initialised;
        hints.reset().set_socktype(cppsock::socket_stream).set_protocol(cppsock::ip_protocol_tcp); // set hints to TCP for connect()-ing
        if(cppsock::getaddrinfo(hostname, service, &hints, res) != 0) // get addresses to connect
        {
            // getaddressinfo failed
            return cppsock::utility_error_gai_fail;
        }
        if(res.size() == 0)
        {
            // no results given
            return cppsock::utility_error_no_results;
        }
        for(addressinfo &addr : res) // go through every address
        {
            cppsock::error_t err = cppsock::tcp_client_connect(client, addr);
            if(err == cppsock::error_none)
            {
                return cppsock::error_none;
            }
            errno_last = errno; // store errno
            errno = 0; // reset errno in case of a fail
        }
        errno = errno_last; // restore last errno if no address could be used
        return cppsock::utility_error_no_success; // no address could be connected to
    }
    /**
     *  @brief connects a TCP client to a server and connects the provided socket
     *  @param client invalid socket that should be used to connect to the server
     *  @param hostname hostname / IP address of the server
     *  @param port port number the client should connect to, in host byte order
     *  @return cppsock utility error code that can be transformed into a human-readable string with cppsock::utility_strerror(), 
     *          a code of smaller than zero indicates an error and errno is set to the last error
     *          a code of greater than zero indicates a warning and errno is set to the last warning
     */
    inline cppsock::error_t tcp_client_connect(socket &client, const char* hostname, uint16_t port)
    {
        std::stringstream ss;

        ss.clear();
        ss << port;
        return tcp_client_connect(client, hostname, ss.str().c_str());
    }
    /**
     *  @brief sets up a UDP socket
     *  @param sock invalid socket that should be used to set up the udp socket
     *  @param addr local address for the udp socket, cppsock::any_addr can be used to not specify a address
     *  @return cppsock utility error code that can be transformed into a human-readable string with cppsock::utility_strerror(), 
     *          a code of smaller than zero indicates an error and errno is set to the last error
     *          a code of greater than zero indicates a warning and errno is set to the last warning
     */
    inline cppsock::error_t udp_socket_setup(socket &sock, const socketaddr &addr)
    {
        if(sock.is_valid()) return cppsock::utility_error_initialised;
        if((sock.init(addr.get_family(), cppsock::socket_dgram, cppsock::ip_protocol_udp)) == 0)
            if((sock.bind(addr)) == 0)
                return cppsock::error_none;
        if(sock.is_valid()) sock.close(); // close socket is it was open
        return cppsock::utility_error_fail;
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
    inline cppsock::error_t udp_socket_setup(socket &sock, const char *hostname, const char *service)
    {
        std::vector<addressinfo> res;
        addressinfo hints;
        ::error_t errno_last = errno;

        if(sock.is_valid()) return cppsock::utility_error_initialised;
        hints.reset().set_socktype(cppsock::socket_dgram).set_protocol(cppsock::ip_protocol_udp).set_passive(true);
        if(cppsock::getaddrinfo(hostname, service, &hints, res) != 0)
        {
            // getaddrinfo failed
            return cppsock::utility_error_gai_fail;
        }
        if(res.size() == 0)
        {
            // no results
            return cppsock::utility_error_no_results;
        }
        for(addressinfo &addr : res)
        {
            cppsock::error_t err = cppsock::udp_socket_setup(sock, addr);
            if(err == cppsock::error_none)
            {
                return cppsock::error_none;
            }
            errno_last = errno; // store errno
            errno = 0; // reset errno in case of a fail
        }
        errno = errno_last; // restore errno if no address could be used
        return cppsock::utility_error_no_success;
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
    inline cppsock::error_t udp_socket_setup(socket &sock, const char *hostname, uint16_t port)
    {
        std::stringstream ss;

        ss.clear();
        ss << port;
        return udp_socket_setup(sock, hostname, ss.str().c_str());
    }

    /**
     * @brief convert a cppsock error into a human readable string
     * @param code error code
     * @return error code as human readable string
     */
    inline const char* strerror(cppsock::error_t code)
    {
        switch (code)
        {
        case cppsock::error_none:
            return "no error";

        case cppsock::utility_warning_keepalive:
            return "failed to set keepalive socket option";
        case cppsock::utility_error_fail:
            return "utility function failed to execute successfully";
        case cppsock::utility_error_initialised:
            return "provided socket is already initialised";
        case cppsock::utility_error_gai_fail:
            return "getaddrinfo() failed to execute";
        case cppsock::utility_error_no_results:
            return "getaddrinfo() didn't resolve any addresses";
        case cppsock::utility_error_no_success:
            return "none of the resolved addresses resulted in a success";
        case utility_error_connect:
            return "syscall to connect() failed";

        case cppsock::swap_error_socktype:
            return "provided socket has wrong socket type";
        case cppsock::swap_error_listening:
            return "provided socket for stream socket is listening";
        case cppsock::swap_error_not_listening:
            return "provided socket for listener socket is not listening";

        default:
            return "unknown error code provided";
        }
    }
} // namespace cppsock
