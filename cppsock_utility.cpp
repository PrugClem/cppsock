/**
 *  author: Clemens Pruggmayer (PrugClem)
 *  date:   2020-12-22
 *  desc:   implementation for utility functionality for quicker socket development
 */
#include "cppsock.hpp"

error_t cppsock::hostname(std::string &strbuf)
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
std::string cppsock::hostname()
{
    std::string ret;
    cppsock::hostname(ret);
    return ret;
}

cppsock::utility_error_t cppsock::tcp_listener_setup(cppsock::socket &listener, const char *hostname, const char *service, int backlog)
{
    std::vector<cppsock::addressinfo> res;
    addressinfo hints;
    error_t errno_last = errno; // store errno

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
        cppsock::utility_error_t err = cppsock::tcp_listener_setup(listener, ai, backlog);
        if(err == cppsock::utility_error_none)
        {
            return cppsock::utility_error_none;
        }
        errno_last = errno; // store errno
        errno = 0; // reset errno in case of a fail
    }
    errno = errno_last; // restore last errno if no address could be used
    return cppsock::utility_error_no_success; // if this is reached, no address coule be used to bind
}

cppsock::utility_error_t cppsock::tcp_client_connect(cppsock::socket &client, const char *hostname, const char *service)
{
    std::vector<cppsock::addressinfo> res;
    addressinfo hints;
    error_t errno_last = errno;

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
        cppsock::utility_error_t err = cppsock::tcp_client_connect(client, addr);
        if(err == cppsock::utility_error_none)
        {
            return cppsock::utility_error_none;
        }
        errno_last = errno; // store errno
        errno = 0; // reset errno in case of a fail
    }
    errno = errno_last; // restore last errno if no address could be used
    return cppsock::utility_error_no_success; // no address could be connected to
}

cppsock::utility_error_t cppsock::udp_socket_setup(cppsock::socket &sock, const char *hostname, const char *service)
{
    std::vector<addressinfo> res;
    addressinfo hints;
    error_t errno_last = errno;

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
        cppsock::utility_error_t err = cppsock::udp_socket_setup(sock, addr);
        if(err == cppsock::utility_error_none)
        {
            return cppsock::utility_error_none;
        }
        errno_last = errno; // store errno
        errno = 0; // reset errno in case of a fail
    }
    errno = errno_last; // restore errno if no address could be used
    return cppsock::utility_error_no_success;
}

cppsock::utility_error_t cppsock::tcp_listener_setup(cppsock::socket& listener, const char* hostname, uint16_t port, int backlog)
{
    std::stringstream ss;

    ss.clear();
    ss << port;
    return tcp_listener_setup(listener, hostname, ss.str().c_str(), backlog);
}
cppsock::utility_error_t cppsock::tcp_client_connect(cppsock::socket& client, const char* hostname, uint16_t port)
{
    std::stringstream ss;

    ss.clear();
    ss << port;
    return tcp_client_connect(client, hostname, ss.str().c_str());
}
cppsock::utility_error_t cppsock::udp_socket_setup(cppsock::socket &sock, const char *hostname, uint16_t port)
{
    std::stringstream ss;

    ss.clear();
    ss << port;
    return udp_socket_setup(sock, hostname, ss.str().c_str());
}

cppsock::utility_error_t cppsock::tcp_listener_setup(cppsock::socket &listener, const cppsock::socketaddr &addr, int backlog)
{
    if(listener.is_valid()) return cppsock::utility_error_initialised;
    if(!__is_error(listener.init(addr.get_family(), cppsock::socket_stream, cppsock::ip_protocol_tcp)))
        if(!__is_error(listener.bind(addr)))
            if(!__is_error(listener.listen(backlog)))
                return cppsock::utility_error_none;
    if(listener.is_valid()) listener.close(); // close socket is it was open
    return cppsock::utility_error_fail;
}
cppsock::utility_error_t cppsock::tcp_client_connect(cppsock::socket &client, const cppsock::socketaddr &addr)
{
    if(client.is_valid()) return cppsock::utility_error_initialised;
    if(!__is_error(client.init(addr.get_family(), cppsock::socket_stream, cppsock::ip_protocol_tcp)))
        if(!__is_error(client.connect(addr)))
            return cppsock::utility_error_none;
    if(client.is_valid()) client.close(); // close socket is it was open
    return cppsock::utility_error_fail;
}
cppsock::utility_error_t cppsock::udp_socket_setup(cppsock::socket &sock, const cppsock::socketaddr &addr)
{
    if(sock.is_valid()) return cppsock::utility_error_initialised;
    if(!__is_error(sock.init(addr.get_family(), cppsock::socket_dgram, cppsock::ip_protocol_udp)))
        if(!__is_error(sock.bind(addr)))
            return cppsock::utility_error_none;
    if(sock.is_valid()) sock.close(); // close socket is it was open
    return cppsock::utility_error_fail;
}

const char *cppsock::utility_strerror(utility_error_t code)
{
    switch (code)
    {
    case cppsock::utility_error_none:
        return "Utility call was successful";
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
    default:
        return "unknown error code provided";
    }
}

const char *cppsock::swap_strerror(swap_error code)
{
    switch (code)
    {
    case cppsock::swap_error_socktype:
        return "provided socket has wrong socket type";
    default:
        return "unknown error code provided";
    }
}
