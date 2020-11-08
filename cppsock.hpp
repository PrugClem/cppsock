#ifndef CPPSOCK_HPP_INCLUDED
#define CPPSOCK_HPP_INCLUDED

#include <string.h>
#include <sstream>
#include <cerrno>
#include <string>
#include <vector>

#ifdef _WIN32
// Windows user newer versions
#undef WINVER
#define WINVER 0x0A00
#undef _WIN32_WINNT
#define _WIN32_WINNT 0xA00

// windows define constants with correct name
#define SHUT_RDWR SD_BOTH
#define SHUT_RD SD_RECEIVE
#define SHUT_WR SD_SEND

// Windows include files
#include <winsock2.h>
#include <ws2tcpip.h>

// windows define missing typed
using sa_family_t = unsigned short;
using in_port_t = uint16_t;
using socket_t = SOCKET;
using error_t = int;

// this is needed because windows is stupid and does not set errno
#define __set_errno_from_WSA() {errno = WSAGetLastError();}

#else // _WIN32
// Linux include files
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

// library definitions
using socket_t = int;
constexpr socket_t INVALID_SOCKET = -1;
constexpr int SOCKET_ERROR = -1;
inline int closesocket(socket_t s){return close(s);}

// this is needed because windows is stupid and does not set errno
// however in linux nothing has to be done
#define __set_errno_from_WSA(){}
#endif // else _WIN32

namespace cppsock
{
    class socketaddr
    {
        union
        {
            sa_family_t sa_family;
            sockaddr sa;
            sockaddr_in sin;
            sockaddr_in6 sin6;
            sockaddr_storage ss;
        } sa;
    public:
        static bool is(sa_family_t fam, const std::string &);
        static bool is_ipv4(const std::string&);
        static bool is_ipv6(const std::string&);

        socketaddr();
        socketaddr(const socketaddr& other);
        socketaddr(const std::string& addr, uint16_t port);

        socketaddr& operator=(const socketaddr& other);

        sockaddr *data();
        const sockaddr *data() const;

        void set_family(sa_family_t);
        error_t set_addr(const std::string&);
        error_t set_port(uint16_t); /** port in host byte order */

        error_t set(const std::string&, uint16_t); /** port in host byte order */
        void    set(sockaddr*);

        void get_family(sa_family_t&) const;
        error_t get_addr(std::string&) const;
        error_t get_port(uint16_t&) const; /** port in host byte order */

        sa_family_t get_family() const;
        std::string get_addr() const;
        uint16_t get_port() const; /** port in host byte order */

        bool operator==(const socketaddr& other) const;
        bool operator!=(const socketaddr& other) const;
    };

    class addressinfo
    {
        addrinfo _data;
    public:
        addrinfo *data();
        const addrinfo *data() const;

        addressinfo &reset();

        addressinfo &set_family(sa_family_t);
        addressinfo &set_socktype(int);
        addressinfo &set_protocol(int);

        socketaddr get_addr() const;
        sa_family_t get_family() const;
        int get_socktype() const;
        int get_protocol() const;

        operator socketaddr() const;
    };

    error_t getaddrinfo(const char *hostname, const char* service, const addressinfo *hints, std::vector<addressinfo>& output);

    class socket
    {
        socket_t sock{INVALID_SOCKET};
    public:
        socket(const socket &) = delete;
        socket& operator=(const socket&) = delete;

        socket();
        socket(socket&&);
        socket& operator=(socket&&);
        void swap(socket &);

        error_t init(sa_family_t, int type, int protocol);
        error_t bind(const socketaddr& addr);
        error_t listen(int backlog);
        error_t accept(socket&);
        error_t connect(const socketaddr &addr);
        
        ssize_t send(const void* data, size_t, int flags);
        ssize_t recv(void* data, size_t, int flags);

        ssize_t sendto(const void* data, size_t, int flags, const socketaddr*);
        ssize_t recvfrom(void* data, size_t, int flags, socketaddr*);

        bool    is_valid() const;
        error_t shutdown(int how);
        error_t close();

        error_t getsockname(socketaddr&) const;
        error_t getpeername(socketaddr&) const;

        socketaddr getsockname() const;
        socketaddr getpeername() const;

        error_t setsockopt(int optname, const void* opt_val, socklen_t opt_len);
        error_t getsockopt(int optname, void* opt_val, socklen_t *opt_len) const;

        error_t set_keepalive(bool);
        error_t get_keepalive(bool&) const;
        bool    get_keepalive() const;

        error_t set_reuseaddr(bool);
        error_t get_reuseaddr(bool&) const;
        bool    get_reuseaddr() const;
    };

    error_t tcp_server_setup(socket &listener, const char *hostname, const char *service, int backlog);
    error_t tcp_client_connect(socket &listener, const char *hostname, const char *service);
    error_t tcp_server_setup(socket& listener, const char* hostname, uint16_t port, int backlog);
    error_t tcp_client_connect(socket& client, const char* hostname, uint16_t port);
} // namespace cppsock

#endif // CPPSOCK_HPP_INCLUDED