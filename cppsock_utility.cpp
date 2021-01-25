/**
 *  author: Clemens Pruggmayer (PrugClem)
 *  date:   2020-12-22
 *  desc:   implementation for utility functionality for quicker socket development
 */
#include "cppsock.hpp"

using namespace cppsock;

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

error_t cppsock::tcp_server_setup(cppsock::socket &listener, const char *hostname, const char *service, int backlog)
{
    std::vector<cppsock::addressinfo> res;
    addressinfo hints;
    error_t errno_old = errno; // save old errno number to rewrite it in the case of success

    hints.reset().set_socktype(SOCK_STREAM).set_protocol(IPPROTO_TCP).set_passive(true); // set hints to TCP for bind()-ing
    if(cppsock::getaddrinfo(hostname, service, &hints, res) != 0)   // get addresses to bind
    {
        // getaddressinfo failed
        return -2;
    }
    if(res.size() == 0)
    {
        // no results given
        return -3;
    }
    for(addressinfo &ai : res) // go through every address
    { // if an error occurs, continue jumps here and the loop starts over with the next address
        listener.close();                                                             // close listener socket and discard the content of errno
        if(listener.init(ai.get_family(), ai.get_socktype(), ai.get_protocol()) == (error_t)INVALID_SOCKET) continue; // init listener socket
        if(listener.bind(ai) == SOCKET_ERROR) continue; // bind address
        if(listener.listen(backlog) == SOCKET_ERROR) continue;  // set socket into listening state
        errno = errno_old; // If everything went fine, restore errno to previous vale
        return 0; // if this is reached, everything went fine
    }
    return -1; // if this is reached, no address coule be used to bind
}

error_t cppsock::tcp_client_connect(cppsock::socket &client, const char *hostname, const char *service)
{
    std::vector<cppsock::addressinfo> res;
    addressinfo hints;
    error_t errno_old = errno; // save old errno number to rewrite it in the case of success

    hints.reset().set_socktype(SOCK_STREAM).set_protocol(IPPROTO_TCP); // set hints to TCP for connect()-ing
    if(cppsock::getaddrinfo(hostname, service, &hints, res) != 0) // get addresses to connect
    {
        // getaddressinfo failed
        return -2;
    }
    if(res.size() == 0)
    {
        // no results given
        return -3;
    }
    for(addressinfo &addr : res) // go through every address
    {
        client.init(addr.get_family(), addr.get_socktype(), addr.get_protocol()); // init client socket
        if(client.connect(addr) == SOCKET_ERROR) // try to connect
        {   
            client.close(); // an error occured, close the socket and try the next address
        }
        else
        {   
            errno = errno_old; // If everything went fine, restore errno to previous vale
            return 0; // connect was successful, return immideatly
        }
    }
    return -1; // no address could be connected to
}

error_t cppsock::tcp_server_setup(cppsock::socket& listener, const char* hostname, uint16_t port, int backlog)
{
    std::stringstream ss;

    ss.clear();
    ss << port;
    return tcp_server_setup(listener, hostname, ss.str().c_str(), backlog);
}
error_t cppsock::tcp_client_connect(cppsock::socket& client, const char* hostname, uint16_t port)
{
    std::stringstream ss;

    ss.clear();
    ss << port;
    return tcp_client_connect(client, hostname, ss.str().c_str());
}

template<> uint16_t cppsock::hton<uint16_t>(uint16_t p)
{
    return htons(p);
}
template<> uint32_t cppsock::hton<uint32_t>(uint32_t p)
{
    return htonl(p);
}
template<> uint16_t cppsock::ntoh<uint16_t>(uint16_t p)
{
    return ntohs(p);
}
template<> uint32_t cppsock::ntoh<uint32_t>(uint32_t p)
{
    return ntohl(p);
}
