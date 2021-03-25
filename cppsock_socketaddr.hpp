/**
 * @file cppsock_socketaddr.hpp
 * @author PrugClem
 * @brief implementation for the cppsock socketaddress class
 * @version 0.1
 * @date 2021-03-04
 * 
 * @copyright Copyright (c) 2021
 * 
 */
#include "cppsock.hpp"

#pragma once

namespace cppsock
{
    class socketaddr
    {
    protected:
        union
        {
            ip_family sa_family;
            sockaddr sa;
            sockaddr_in sin;
            sockaddr_in6 sin6;
            sockaddr_storage ss;
        } sa;
    public:
        /**
         *  @param fam can be cppsock::IPv4 or cppsock::IPv6
         *  @param str string that should be checked
         *  @return true if the proveided string is a correctly formatted IP address
         */
        static bool is(ip_family fam, const std::string &str)
        {
            sockaddr_storage ss;
            return inet_pton(fam, str.data(), &ss) == 1;
        }
        /**
         *  @param str string that should be checked
         *  @return true if the provided string is a correctly formatted IPv4 address
         */
        static bool is_ipv4(const std::string &str)
        {
            return is(cppsock::IPv4, str);
        }
        /**
         *  @param str string that should be checked
         *  @return true if the provided string is a correctly formatted IPv6 address
         */
        static bool is_ipv6(const std::string &str)
        {
            return is(cppsock::IPv6, str);
        }

        /**
         *  @brief initialises the structure with an empty address
         */
        socketaddr()
        {
            memset(&this->sa, 0, sizeof(this->sa));
        }
        /**
         *  @brief copy constructor
         */
        socketaddr(const socketaddr& other)
        {
            memcpy(&this->sa, &other.sa, sizeof(socketaddr::sa));
        }
        /**
         *  @brief initialises the structure with the provided address and port
         *  @param addr the IP address the structure should be set to, can be either IPv4 or IPv6
         *  @param port the port number the structure should be set to, in host byte order
         */
        socketaddr(const std::string& addr, uint16_t port)
        {
            this->set(addr, port);
        }
        /**
         *  @brief copy assignment operator
         */
        socketaddr& operator=(const socketaddr& other)
        {
            memcpy(&this->sa, &other.sa, sizeof(socketaddr::sa));
            return *this;
        }
        /**
         *  @brief return a pointer to the raw c-style socketaddr structure
         */
        sockaddr *data()
        {
            return &this->sa.sa;
        }
        /**
         *  @brief return a const pointer to the raw c-style socketaddr structure
         */
        const sockaddr *data() const
        {
            return &this->sa.sa;
        }

        /**
         *  @brief clears the structure and sets the address family
         *  @param fam cppsock::IPv4 for IPv4 or cppsock::IPv6 for IPv6
         */
        void set_family(ip_family fam)
        {
            memset(&this->sa, 0, sizeof(this->sa));
            this->sa.sa_family = fam;
        }
        /**
         *  @brief sets the address of the structure
         *  @param addr the address that should be written into the structure
         *  @return 0 if everything went right, any other return value indicates an error and errno is set appropriately
         */
        error_t set_addr(const std::string& addr)
        {
            void *addrptr;
            if(this->sa.sa_family == AF_INET)
            {
                addrptr = &this->sa.sin.sin_addr;
            }
            else if(this->sa.sa_family == AF_INET6)
            {
                addrptr = &this->sa.sin6.sin6_addr;
            }
            else
            {
                return errno = EAFNOSUPPORT;
            }
            if(inet_pton(this->sa.sa_family, addr.data(), addrptr) == 0) {return errno = EINVAL;}
            return 0;
        }
        /**
         *  @brief set the port of the structure
         *  @param port port number in host byte order
         *  @return 0 if everything went right, any other return value indicates an error and errno is set appropriately
         */
        error_t set_port(uint16_t port)
        {
            in_port_t *portaddr;
            if(this->sa.sa_family == AF_INET)
            {
                portaddr = &this->sa.sin.sin_port;
            }
            else if(this->sa.sa_family == AF_INET6)
            {
                portaddr = &this->sa.sin6.sin6_port;
            }
            else
            {
                return errno = EAFNOSUPPORT;
            }
            *portaddr = cppsock::hton<uint16_t>(port);
            return 0;
        }

        /**
         *  @brief sets the address and port
         *  @param addr the address, can be a IPv4 or IPv6 address
         *  @param port port port number in host byte order
         *  @return 0 if everything went right, any other return value indicates an error and errno is set appropriately
         */
        error_t set(const std::string& addr, uint16_t port)
        {
            error_t error;
            if( is(cppsock::IPv4, addr) )
                this->set_family(cppsock::IPv4);
            else if( is(cppsock::IPv6, addr) )
                this->set_family(cppsock::IPv6);
            else
                return errno = EAFNOSUPPORT;

            if( (error = this->set_addr(addr)) != 0 )
                return error; // errno is already set from set_addr
            if( (error = this->set_port(port)) != 0 )
                return error; // errno is already set from set_port

            return 0;
        }
        /**
         *  @brief copies a socket address structure into itself, if the structure is invalid, this structure is cleared
         *  @param ptr pointer to a sockaddr struture
         */
        void    set(const sockaddr* ptr)
        {
            this->set_family(cppsock::IP_unspec);
            if(ptr->sa_family == AF_INET) // copy IPv4 address structure
                memcpy(&this->sa.sin, ptr, sizeof(this->sa.sin));
            else if(ptr->sa_family == AF_INET6) // copy IPv6 address structure
                memcpy(&this->sa.sin6, ptr, sizeof(this->sa.sin6));
            return;
        }

        /**
         *  @brief gets the address family
         *  @param out reference to a buffer where the family type should be written into
         */
        void get_family(ip_family &out) const
        {
            out = this->sa.sa_family;
            return;
        }
        /**
         *  @brief get the address
         *  @param out reference to a string where the address should be written into
         *  @return 0 if everything went right, any other return value indicates an error and errno is set appropriately
         */
        error_t get_addr(std::string &out) const
        {
            void const *addrptr;
            if(this->sa.sa_family == AF_INET)
            {
                addrptr = &this->sa.sin.sin_addr;
            }
            else if(this->sa.sa_family == AF_INET6)
            {
                addrptr = &this->sa.sin6.sin6_addr;
            }
            else
            {
                return errno = EAFNOSUPPORT;
            }
            out.resize(INET6_ADDRSTRLEN); // preallocate memory for address
            inet_ntop(this->sa.sa_family, (void*)addrptr, &out[0], out.size()); // typecast to void* is needed because windows is stupid and needs a non-const pointer
            out = out.c_str(); // reinterpret string to cut additional '\0' characters at the end since this can cause problems
            return 0;
        }
        /**
         *  @brief get the port number in host byte order
         *  @param out reference to a buffer where the port should be written into
         *  @return 0 if everything went right, any other return value indicates an error and errno is set appropriately
         */
        error_t get_port(uint16_t &out) const
        {
            if(this->sa.sa_family == AF_INET)
            {
                out = cppsock::ntoh<uint16_t>(this->sa.sin.sin_port);
            }
            else if(this->sa.sa_family == AF_INET6)
            {
                out = cppsock::ntoh<uint16_t>(this->sa.sin6.sin6_port);
            }
            else
            {
                return errno = EAFNOSUPPORT;
            }
            return 0;
        }

        /**
         *  @brief gets the address family
         *  @return the address family
         */
        ip_family get_family() const
        {
            return this->sa.sa_family;
        }
        /**
         *  @brief get the address
         *  @return string containing the address, if an error occured, the string is empty
         */
        std::string get_addr() const
        {
            std::string ret;
            this->get_addr(ret);
            return ret;
        }
        /**
         *  @brief get the port number in host byte order
         *  @return the port number in host byte order, if an error occured, 0 is returned
         */
        uint16_t get_port() const
        {
            uint16_t ret(0);
            this->get_port(ret);
            return ret;
        }

        /**
         *  @return true if this is equal to the other
         */
        bool operator==(const socketaddr &other) const
        {
            return memcmp(&this->sa, &other.sa, sizeof(this->sa)) == 0;
        }
        /**
         *  @return false if this is equal to the other
         */
        bool operator!=(const socketaddr &other) const
        {
            return memcmp(&this->sa, &other.sa, sizeof(this->sa)) != 0;
        }
        /**
         *  @brief operatuor for usage in a std::map, does not have any meaning and does not actually compare the addresses, this just uses memcmp
         */
        bool operator<(const socketaddr &other) const
        {
            return memcmp(&this->sa, &other.sa, sizeof(this->sa)) < 0;
        }

    }; // class socketaddr

    // functions to create a loopback address without template port numbers
    template<cppsock::ip_family fam = cppsock::IPvDefault> const cppsock::socketaddr make_loopback(uint16_t port);
    template<> inline const cppsock::socketaddr make_loopback<cppsock::IPv4> (uint16_t port) { return cppsock::socketaddr("127.0.0.1", port); }
    template<> inline const cppsock::socketaddr make_loopback<cppsock::IPv6> (uint16_t port) { return cppsock::socketaddr("::1", port); }

    // functions to create any addresses without template port numbers
    template<cppsock::ip_family fam = cppsock::IPvDefault> const cppsock::socketaddr make_any(uint16_t port);
    template<> inline const cppsock::socketaddr make_any<cppsock::IPv4> (uint16_t port) { return cppsock::socketaddr("0.0.0.0", port); }
    template<> inline const cppsock::socketaddr make_any<cppsock::IPv6> (uint16_t port) { return cppsock::socketaddr("::", port); }


    // loopback address constants with template port numbers
    template <uint16_t port, ip_family fam = cppsock::IPvDefault> const cppsock::socketaddr loopback;
    template <uint16_t port> inline const cppsock::socketaddr loopback<port, cppsock::IPv4> = cppsock::make_loopback<cppsock::IPv4>(port);
    template <uint16_t port> inline const cppsock::socketaddr loopback<port, cppsock::IPv6> = cppsock::make_loopback<cppsock::IPv6>(port);

    // any address constants with template port numbers
    template<uint16_t port, ip_family fam = cppsock::IPvDefault> const cppsock::socketaddr any_addr;
    template<uint16_t port> inline const cppsock::socketaddr any_addr<port, cppsock::IPv4> = cppsock::make_any<cppsock::IPv4>(port);
    template<uint16_t port> inline const cppsock::socketaddr any_addr<port, cppsock::IPv6> = cppsock::make_any<cppsock::IPv6>(port);

    /**
     * @brief a pair that stores both local and remote address
     */
    struct socketaddr_pair
    {
        cppsock::socketaddr local, remote;
    }; // struct socketaddr_pair
    //using socketaddr_pair = std::pair<cppsock::socketaddr, cppsock::socketaddr>;
} // namespace cppsock
