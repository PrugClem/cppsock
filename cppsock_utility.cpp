#include "cppsock.hpp"

using namespace cppsock;

error_t cppsock::tcp_server_setup(cppsock::socket &listener, const char *hostname, const char *service, int backlog)
{
    std::vector<cppsock::addressinfo> res;
    addressinfo hints;

    hints.reset().set_socktype(SOCK_STREAM).set_protocol(IPPROTO_TCP).data()->ai_flags |= AI_PASSIVE; // set hints to TCP for bind()-ing
    if(cppsock::getaddrinfo(hostname, service, &hints, res) != 0)   // get addresses to bind
    {
        // getaddressinfo failed
        return -2;
    }
    for(addressinfo &ai : res) // go through every address
    { // if an error occurs, continue jumps here and the loop starts over with the next address
        listener.close(); errno = 0;                                                             // close listener socket and discard the content of errno
        if(listener.init(ai.get_family(), ai.get_socktype(), ai.get_protocol()) == (error_t)INVALID_SOCKET) continue; // init listener socket
        if(listener.bind(ai) == SOCKET_ERROR) continue;                                          // bind address
        if(listener.listen(backlog) == SOCKET_ERROR) continue;                                   // set socket into listening state
        return 0;                                                                                // if this is reached, everything went fine
    }
    return -1; // if this is reached, no address coule be used to bind
}

error_t cppsock::tcp_client_connect(cppsock::socket &client, const char *hostname, const char *service)
{
    std::vector<cppsock::addressinfo> res;
    addressinfo hints;

    hints.reset().set_socktype(SOCK_STREAM).set_protocol(IPPROTO_TCP); // set hints to TCP for connect()-ing
    if(cppsock::getaddrinfo(hostname, service, &hints, res) != 0) // get addresses to connect
    {
        // getaddressinfo failed
        return -2;
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
