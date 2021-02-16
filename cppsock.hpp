/**
 *  author: Clemens Pruggmayer (PrugClem)
 *  date:   2020-12-22
 *  desc:   main header file for cppsock library, used to define all classes and functions
 */
#ifndef CPPSOCK_HPP_INCLUDED
#define CPPSOCK_HPP_INCLUDED

#include <iostream>
#include <string.h>
#include <sstream>
#include <cerrno>
#include <string>
#include <vector>

#if defined __linux__ || defined __CYGWIN__
// Linux include files
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>

// library definitions
using socket_t = int;
constexpr socket_t INVALID_SOCKET = -1;
constexpr int SOCKET_ERROR = -1;
inline int closesocket(socket_t s){return close(s);}
inline int ioctlsocket(socket_t s, long cmd, void *argp) {return ioctl(s, cmd, argp);}

// this is needed because windows is stupid and does not set errno
// however in linux nothing has to be done
#define __set_errno_from_WSA(){}
#define __is_error(s) (s < 0)
#elif defined _WIN32
// Windows user newer versions
#undef WINVER
#define WINVER 0x0A00
#undef _WIN32_WINNT
#define _WIN32_WINNT 0xA00

// windows define constants with linux name
#define SHUT_RDWR SD_BOTH
#define SHUT_RD SD_RECEIVE
#define SHUT_WR SD_SEND

// Windows include files
#include <winsock2.h>
#include <ws2tcpip.h>

// windows define missing types
using sa_family_t = unsigned short;
using in_port_t = uint16_t;
using socket_t = SOCKET;
using error_t = int;

// this is needed because windows does not set errno
#define __set_errno_from_WSA() {errno = WSAGetLastError();}
#define __is_error(s) (s == SOCKET_ERROR)
#else // elif defined __WIN32__
// an unsupportet OS was used to compile, Library cannot compile
#error unsupported OS used
#endif

namespace cppsock
{
    class socketaddr
    {
    protected:
        union
        {
            sa_family_t sa_family;
            sockaddr sa;
            sockaddr_in sin;
            sockaddr_in6 sin6;
            sockaddr_storage ss;
        } sa;
    public:
        /**
         *  @param fam can be AF_INET or AF_INET6
         *  @param str string that should be checked
         *  @return true if the proveided string is a correctly formatted IP address
         */
        static bool is(sa_family_t fam, const std::string &str);
        /**
         *  @param str string that should be checked
         *  @return true if the provided string is a correctly formatted IPv4 address
         */
        static bool is_ipv4(const std::string &str);
        /**
         *  @param str string that should be checked
         *  @return true if the provided string is a correctly formatted IPv6 address
         */
        static bool is_ipv6(const std::string &str);

        /**
         *  @brief initialises the structure with an empty address
         */
        socketaddr();
        /**
         *  @brief copy constructor
         */
        socketaddr(const socketaddr& other);
        /**
         *  @brief initialises the structure with the provided address and port
         *  @param addr the IP address the structure should be set to, can be either IPv4 or IPv6
         *  @param port the port number the structure should be set to, in host byte order
         */
        socketaddr(const std::string& addr, uint16_t port);

        /**
         *  @brief copy assignment operator
         */
        socketaddr& operator=(const socketaddr& other);

        /**
         *  @brief return a pointer to the raw c-style socketaddr structure
         */
        sockaddr *data();
        /**
         *  @brief return a const pointer to the raw c-style socketaddr structure
         */
        const sockaddr *data() const;

        /**
         *  @brief clears the structure and sets the address family
         *  @param fam AF_INET for IPv4 or AF_INET6 for IPv6
         */
        void set_family(sa_family_t fam);
        /**
         *  @brief sets the address of the structure
         *  @param addr the address that should be written into the structure
         *  @return 0 if everything went right, any other return value indicates an error and errno is set appropriately
         */
        error_t set_addr(const std::string& addr);
        /**
         *  @brief set the port of the structure
         *  @param port port number in host byte order
         *  @return 0 if everything went right, any other return value indicates an error and errno is set appropriately
         */
        error_t set_port(uint16_t port);

        /**
         *  @brief sets the address and port
         *  @param addr the address, can be a IPv4 or IPv6 address
         *  @param port port port number in host byte order
         *  @return 0 if everything went right, any other return value indicates an error and errno is set appropriately
         */
        error_t set(const std::string& addr, uint16_t port);
        /**
         *  @brief copies a socket address structure into itself, if the structure is invalid, this structure is cleared
         *  @param ptr pointer to a socketaddr struture
         */
        void    set(const sockaddr* ptr);

        /**
         *  @brief gets the address family
         *  @param out reference to a buffer where the family type should be written into
         */
        void get_family(sa_family_t &out) const;
        /**
         *  @brief get the address
         *  @param out reference to a string where the address should be written into
         *  @return 0 if everything went right, any other return value indicates an error and errno is set appropriately
         */
        error_t get_addr(std::string &out) const;
        /**
         *  @brief get the port number in host byte order
         *  @param out reference to a buffer where the port should be written into
         *  @return 0 if everything went right, any other return value indicates an error and errno is set appropriately
         */
        error_t get_port(uint16_t &out) const;

        /**
         *  @brief gets the address family
         *  @return the address family
         */
        sa_family_t get_family() const;
        /**
         *  @brief get the address
         *  @return string containing the address, if an error occured, the string is empty
         */
        std::string get_addr() const;
        /**
         *  @brief get the port number in host byte order
         *  @return the port number in host byte order, if an error occured, 0 is returned
         */
        uint16_t get_port() const;

        /**
         *  @return true if this is equal to the other
         */
        bool operator==(const socketaddr &other) const;
        /**
         *  @return false if this is equal to the other
         */
        bool operator!=(const socketaddr &other) const;
        /**
         *  @brief operatuor for usage in a std::map, does not have any meaning and does not actually compare the addresses, this just uses memcmp
         */
        bool operator<(const socketaddr &other) const;

    };
    /**
     *  @brief ostream operator for easy output, I will not implement an istream operator
     */
    std::ostream& operator<<(std::ostream &, const cppsock::socketaddr&);

    class addressinfo
    {
    protected:
        addrinfo _data;
    public:
        /**
         *  @brief reutns raw data in c-style sddrinfo structure
         */
        addrinfo *data();
        /**
         *  @brief reutns raw data in c-style sddrinfo structure
         */
        const addrinfo *data() const;

        /**
         *  @brief clears this structure
         *  @return this structure to allow chaining
         */
        addressinfo &reset();

        /**
         *  @brief sets the family type for resolving
         *  @return this structure to allow chaining
         */
        addressinfo &set_family(sa_family_t);
        /**
         *  @brief sets the socket type for this strucutre, can be SOCK_STREAM for TCP or SOCK_DGRAM for UDP
         *  @return this structure to allow chaining
         */
        addressinfo &set_socktype(int);
        /**
         *  @brief specifies the protocol for this structure, 0 to use socktype defualts
         *  @return this structure to allow chaining
         */
        addressinfo &set_protocol(int);
        /**
         *  @brief sets the passive flag, if the passive flag is true, the results can be used for bind()-ing, if the passive flag is false, the address can be used for connect()-ing
         *  @return this structure to allow chaining
         */
        addressinfo &set_passive(bool);

        /**
         *  @return a socketaddr class
         */
        socketaddr get_addr() const;
        /**
         *  @return address family
         */
        sa_family_t get_family() const;
        /**
         *  @return socket type
         */
        int get_socktype() const;
        /**
         *  @return protocol that should be used
         */
        int get_protocol() const;

        /**
         *  cast operator for easy use
         */
        operator socketaddr() const;
    };

    /**
     *  @brief resolves a hostname
     *  @param hostname hostname that should be resolved, nullptr to use loopback
     *  @param service service name or port number in string format, e.g. "http" or "80" results in port number 80
     *  @return 0 if everything went right, anything else indicates an error that can pe printed with gai_strerror()
     */
    error_t getaddrinfo(const char *hostname, const char* service, const addressinfo *hints, std::vector<addressinfo>& output);

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
        socket();
        /**
         *  @brief dtor to close socket
         */
        ~socket();
        /**
         *  @brief move constructor
         */
        socket(socket&&);
        /**
         *  @brief move assignment operator
         */
        socket& operator=(socket&&);
        /**
         *  @brief swap 2 sockets
         */
        void swap(socket &);

        /**
         *  @brief initialise a socket and make it valid
         *  @param fam family to use, AF_INET for IPv4, AF_INET6 for IPv6
         *  @param type the socket type, e.g. SOCK_STREAM or SOCK_DGRAM
         *  @param porotcol protocol to use, e.g. IPPROTO_TCP
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t init(sa_family_t fam, int type, int protocol);
        /**
         *  @brief bind this socket to a given address, a bound socket can be used to accept TCP connections
         *  @param addr address the socket should be bound to
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t bind(const socketaddr& addr);
        /**
         *  @brief sets a bound socket into listening state to allow tcp connections to be accepted
         *  @param backlog how many unestablished connections should be logged
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t listen(int backlog);
        /**
         *  @brief accepts a TCP connection on a listening socket
         *  @param con the socket the connection should be interacted with
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t accept(socket &con);
        /**
         *  @brief connects an initialised socket
         *  @param addr the address the socket should be connecting to
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t connect(const socketaddr &addr);
        
        /**
         *  @brief sends data over a connected socket
         *  @param data pointer to the start of the data array
         *  @param len length of the buffer in bytes
         *  @param flags changes behavior of the function call, use 0 for default behavioral
         *  @return if smaller than 0, an error occured and errno is set appropriately, the total amount of bytes sent otherwise
         */
        ssize_t send(const void* data, size_t len, int flags);
        /**
         *  @brief receives data from a connected socket
         *  @param data pointer to the start of the buffer where the data should be written into
         *  @param maxlen amount of bytes available for the buffer in bytes
         *  @param flags changes behavior of the function call, use 0 for default behavioral
         *  @return 0 if the connection has been closed, smaller than 0 if an error occured, the amount of bytes received otherwise
         */
        ssize_t recv(void* data, size_t maxlen, int flags);

        /**
         *  @brief sends data over a socket
         *  @param data pointer to the start of the data array
         *  @param len length of the buffer in bytes
         *  @param flags changes behavior of the function call, use 0 for default behavioral
         *  @param dst pointer to a class where the data should be sent to, use nullptr to use default address
         *  @return if smaller than 0, an error occured and errno is set appropriately, the total amount of bytes sent otherwise
         */
        ssize_t sendto(const void* data, size_t, int flags, const socketaddr *dst);
        /**
         *  @brief receives data from a connected socket
         *  @param data pointer to the start of the buffer where the data should be written into
         *  @param maxlen amount of bytes available for the buffer in bytes
         *  @param flags changes behavior of the function call, use 0 for default behavioral
         *  @param src pointer to a class where the source address should be written into, use nullptr do discard the src address
         *  @return 0 if the connection has been closed, smaller than 0 if an error occured, the amount of bytes received otherwise
         */
        ssize_t recvfrom(void* data, size_t, int flags, socketaddr *src);

        /**
         *  @brief get the amount of bytes ready to read
         *  @param buf reference to a buffer where the amount should be written into
         *  @return 0 if everything went right; anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t available(size_t &buf);
        /**
         *  @brief get the amount of bytes ready to read
         *  @return the amount of bytes to read; if an error occured, 0 is returned
         */
        size_t available();

        /**
         *  @return true if the socket is valid (initialised / listening / connected)
         */
        bool    is_valid() const;
        /**
         *  @brief enum to hold values to shut down a socket connection
         */
        enum shutdown_mode : int
        {
            shutdown_send = SHUT_WR,
            shutdown_recv = SHUT_RD,
            shutdown_both = SHUT_RDWR
        };
        /**
         *  @brief shuts down parts of the socket or properly terminates a socket connection, THIS CALL IS IRREVERSIBLE!
         *  The socket remains valid, no data can be sent or received
         *  @param how how the socket should be shut down, possible options are listed in the enum cppsock::socket::shutdown_mode
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t shutdown(socket::shutdown_mode how);
        /**
         *  @brief [[deprecated]] shuts down parts of the socket or properly terminates a socket connection, THIS CALL IS IRREVERSIBLE!
         *  The socket remains valid, no data can be sent or received
         *  @param how how the socket should be shut down, possible options: SHUT_RD / SHUT_WR / SHUT_RDWR
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        [[deprecated]] error_t shutdown(int how);
        /**
         *  @brief closes and invalidates the socket
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t close();
        /**
         *  @brief get the implementation-dependent socket descriptor
         */
        socket_t handle();

        /**
         *  @brief retrieves the local socket address
         *  @param addr reference to a buffer where the address should be written into
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t getsockname(socketaddr &addr) const;
        /**
         *  @brief retrieves the peer socket address
         *  @param addr reference to a buffer where the address should be written into
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t getpeername(socketaddr &addr) const;

        /**
         *  @brief retrieves the local socket address
         *  @return address, if an error occured, the result in undefined
         */
        socketaddr getsockname() const;
        /**
         *  @brief retrieves the local socket address
         *  @return address, if an error occured, the result in undefined
         */
        socketaddr getpeername() const;

        /**
         *  @brief sets a socket option
         *  @param optname socket option name, this can be OS dependant
         *  @param opt_val pointer to the option value
         *  @param opt_len length of the option value
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t setsockopt(int optname, const void* opt_val, socklen_t opt_len);
        /**
         *  @brief retrieves a socket option
         *  @param optname socket option name, this can be OS dependant
         *  @param opt_val pointer to a buffer where the value should be written into
         *  @param opt_len length of the buffer provided in opt_val
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t getsockopt(int optname, void* opt_val, socklen_t *opt_len) const;

        /**
         *  @brief sets the keepalive option
         *  @param newstate the new value for the keepalive option
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t set_keepalive(bool newstate);
        /**
         *  @brief get the keepalive option
         *  @param buf rference to a buffer where the current state should be written into
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t get_keepalive(bool &buf) const;
        /**
         *  @brief get the keepalive option
         *  @return current optionstate, if an error occured, the return value is undefined
         */
        bool    get_keepalive() const;

        /**
         *  @brief sets the reuseaddr option
         *  @param newstate the new value for the reuseaddr option
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t set_reuseaddr(bool newstate);
        /**
         *  @brief get the reuseaddr option
         *  @param buf rference to a buffer where the current state should be written into
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t get_reuseaddr(bool &buf) const;
        /**
         *  @brief get the reuseaddr option
         *  @return current optionstate, if an error occured, the return value is undefined
         */
        bool    get_reuseaddr() const;

        /**
         *  @brief get the socket type (SOCK_STREAM, SOCK_DGRAM, e.t.c)
         *  @param buf reference to a buffer where the socktype should be written into
         *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
         */
        error_t get_socktype(int &buf) const;
        /**
         *  @brief get the socket type (SOCK_STREAM, SOCK_DGRAM, e.t.c)
         *  @return socket type, in an error occured, the return value is undefined
         */
        int get_socktype() const;
    };

    /**
     *  @brief gets the machine's hostname
     *  @param strbuf buffer where the hostname should be written into
     *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
     */
    error_t hostname(std::string &strbuf);
    /**
     *  @brief gets the machine's hostname
     *  @return the machine's hostname, if an error occured the return value is undefined
     */
    std::string hostname();
    /**
     *  @brief sets up a TCP server, binds and sets the listener socket into listening state
     *  @param listener invalid socket that should be used as the listening socket, will be initialised, bound and set into listening state
     *  @param hostname the hostname / address the server should listen to, nullptr to let it listen on every IP device
     *  @param serivce service name / port number in string for the port the server should listen to e.g. "http" or "80" for port 80
     *  @param backlog how many unestablished connections should be logged
     *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
     */
    error_t tcp_server_setup(socket &listener, const char *hostname, const char *service, int backlog);
    /**
     *  @brief connects a TCP client to a server and connects the provided socket
     *  @param client invalid socket that should be used to connect to the server
     *  @param hostname hostname / IP address of the server
     *  @param service service name / port number in string for the port the client should connect to e.g. "http" or "80" for port 80
     *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
     */
    error_t tcp_client_connect(socket &client, const char *hostname, const char *service);
    /**
     *  @brief sets a socket up to be a UDP socket
     *  @param sock invalid socket that should be used to set up the udp socket
     *  @param hostname hostname / address the socket should listen to
     *  @param service service name / port number in string for the port the socket should listen to; if the local port doesn't matter, use "0"
     *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
     */
    error_t udp_socket_setup(socket &sock, const char *hostname, const char *service);
    /**
     *  @brief sets up a TCP server, binds and sets the listener socket into listening state
     *  @param listener invalid socket that should be used as the listening socket, will be initialised, bound and set into listening state
     *  @param hostname the hostname / address the server should listen to, nullptr to let it listen on every IP device
     *  @param port port number the server should listen to, in host byte order
     *  @param backlog how many unestablished connections should be logged
     *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
     */
    error_t tcp_server_setup(socket& listener, const char* hostname, uint16_t port, int backlog);
    /**
     *  @brief connects a TCP client to a server and connects the provided socket
     *  @param client invalid socket that should be used to connect to the server
     *  @param hostname hostname / IP address of the server
     *  @param port port number the client should connect to, in host byte order
     *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
     */
    error_t tcp_client_connect(socket& client, const char* hostname, uint16_t port);
    /**
     *  @brief sets a socket up to be a UDP socket
     *  @param sock invalid socket that should be used to set up the udp socket
     *  @param hostname hostname / address the socket should listen to
     *  @param port port number the socket should use, in host byte order; if the local port doesn't matter, use port 0
     *  @return 0 if everything went right, anything smaller than 0 indicates an error and errno is set appropriately
     */
    error_t udp_socket_setup(socket &sock, const char *hostname, uint16_t port);

    // loopback address constants, default is IPv6
    template <uint16_t port, sa_family_t fam = AF_INET6> const cppsock::socketaddr loopback;
    template <uint16_t port> const cppsock::socketaddr loopback<port, AF_INET> = cppsock::socketaddr("127.0.0.1", port);
    template <uint16_t port> const cppsock::socketaddr loopback<port, AF_INET6> = cppsock::socketaddr("::1", port);
    // any address constants, default is IPv6
    template<uint16_t port, sa_family_t fam = AF_INET6> const cppsock::socketaddr any_addr;
    template<uint16_t port> const cppsock::socketaddr any_addr<port, AF_INET> = cppsock::socketaddr("0.0.0.0", port);
    template<uint16_t port> const cppsock::socketaddr any_addr<port, AF_INET6> = cppsock::socketaddr("::", port);

    /**
     *  @brief converts a number from host byte order to network byte order.
     *  You should only use this function is absolutley necessary since thin function does not convert using library functions
     */
    template<typename T> T hton(T par)
    {
        static_assert(std::is_integral<T>::value && std::is_unsigned<T>::value, 
                        "Only works with unsigned integers");
        T res = 0;
        uint8_t *poin = (uint8_t*)&res;
        for(ssize_t b=sizeof(T)-1; b>=0; b--) // iterate from MSB to LSB
        {
            // extract from MSB to LSB and write them into first to last byte
            // (T)0xff          ensure that the extraction mask is always of the parameter type
            // [...] << (8*b)   moves extraction mask from LSB to appropiate byte
            // par & [...]      extracts the appropiate byte from the input
            // [...] >> (8*b)   moves extracted byte into LSB
            // *poin++ = [...]  Stores each byte in the current memory address, then increments by one for the next byte
            *poin++ = ( (par & ((T)0xff << (8*b)) ) >> (8*b) );
        }
        return res;
    }
    /**
     *  @brief converts a number from network byte order to host byte order.
     *  You should only use this function is absolutley necessary since thin function does not convert using library functions
     */
    template<typename T> T ntoh(T par)
    {
        static_assert(std::is_integral<T>::value && std::is_unsigned<T>::value, 
                        "Only works with unsigned integers");
        T res = 0;
        uint8_t *poin = (uint8_t*)&par;
        for(ssize_t b=sizeof(T)-1; b>=0; b--) // iterate from MSB to LSB
        {
            // extract from first to last byte and write them into MSB to LSB
            // (T)*poin++       extracts bytes from first to last address as LSB
            // [...] << (8*b)   moves extracted byte from LSB into appripiate byte
            // res |= [...]     write extracted byte into result
            res |= ( (T)*poin++ << (8*b) );
        }
        return res;
    }
    /**
     *  @brief converts a 2-byte number from host byte order to network byte order
     */
    template<> uint16_t hton<uint16_t>(uint16_t);
    /**
     *  @brief converts a 4-byte number from host byte order to network byte order
     */
    template<> uint32_t hton<uint32_t>(uint32_t);
    /**
     *  @brief converts a 2-byte number from network byte order to host byte order
     */
    template<> uint16_t ntoh<uint16_t>(uint16_t);
    /**
     *  @brief converts a 4-byte number from network byte order to host byte order
     */
    template<> uint32_t ntoh<uint32_t>(uint32_t);
} // namespace cppsock

#endif // CPPSOCK_HPP_INCLUDED