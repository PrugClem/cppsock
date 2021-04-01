/**
 * @file cppsock_types.hpp
 * @author PrugClm
 * @brief types (enums, usings, constants, ...) for cppsock library
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
    // forward definitions for classes
    class socketaddr;
    class addressinfo;
    class socket;

    /**
     *  @brief enum for IP families
     */
    enum ip_family : sa_family_t
    {
        IP_unspec = AF_UNSPEC,  // unspecified / invalid IP family
        IPv4 = AF_INET,         // ip family for IPv4
        IPv6 = AF_INET6,        // ip family for IPv6
        IPvDefault = IPv6       // default IP family (IPv6)
    };

    /**
     *  @brief socket types to specify socket behavioral
     */
    enum socket_type : int
    {
        socket_unspec = 0,              // invalid / unspecified socket type
        socket_stream = SOCK_STREAM,    // connection-oriented socket type
        socket_dgram = SOCK_DGRAM       // packet-oriented socket type
    };

    /**
     *  @brief ip protocols to use (TCP, UDP)
     */
    enum ip_protocol : int
    {
        ip_protocol_unspec = 0,         // invalid / unspecified protocol
        ip_protocol_tcp = IPPROTO_TCP,  // use TCP Protocol
        ip_protocol_udp = IPPROTO_UDP   // use UDP protocol
    };

    using msg_flags = int;   // type for message flags
    static constexpr msg_flags msg_oob          = MSG_OOB;         // process out-of-band data
    static constexpr msg_flags msg_peek         = MSG_PEEK;        // peek incoming message, dont delete it from input queue
    static constexpr msg_flags msg_dontroute    = MSG_DONTROUTE;   // send without using the routing table
    static constexpr msg_flags msg_waitall      = MSG_WAITALL;     // wait until the entire packet has been processed (sent / received)
    static constexpr msg_flags oob              = cppsock::msg_oob;         // process out-of-band data
    static constexpr msg_flags peek             = cppsock::msg_peek;        // peek incoming message, dont delete it from input queue
    static constexpr msg_flags dontroute        = cppsock::msg_dontroute;   // send without using the routing table
    static constexpr msg_flags waitall          = cppsock::msg_waitall;     // wait until the entire packet has been processed (sent / received)

    /**
     * @brief enum for cppsock error codes
     */
    enum error_t : ::error_t
    {
        error_none = 0,                 // status code to indicate successful execution

        utility_error_fail = -1,        // utility call failed to execute successfully, no more information provided
        utility_error_initialised = -2, // socket is already initialised
        utility_error_gai_fail = -3,    // getaddressinfo() has failed to resolve the given parameter
        utility_error_no_results = -4,  // getaddressinfo() as not given any results
        utility_error_no_success = -5,  // no address resolved by getaddressinfo() could successfully be used
        utility_error_connect = -6,     // connect did not work successfully
        utility_warning_keepalive = 1,  // the keepalive socket option could not be set

        swap_error_socktype = -101,     // swap failed: wrong socktype
        swap_error_listening = -102,    // swap failed: socket is currently listening
        swap_error_not_listening = -103 // swap failed: socket is currently not listening
    };

    /**
     *  @brief enum to hold values to shut down a socket connection
     */
    enum shutdown_mode : int
    {
        shutdown_send = SHUT_WR,
        shutdown_recv = SHUT_RD,
        shutdown_both = SHUT_RDWR
    };

    template<typename Tout, typename Tin> Tout binary_cast(Tin in)
    {
        static_assert(sizeof(Tin) == sizeof(Tout),
            "Binary Cast only works with types of the same length");
        return * ( (Tout*) (&in) );
    }

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
        for(std::streamsize b=sizeof(T)-1; b>=0; b--) // iterate from MSB to LSB
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
        for(std::streamsize b=sizeof(T)-1; b>=0; b--) // iterate from MSB to LSB
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
    template<> inline uint16_t hton<uint16_t>(uint16_t in) {return htons(in);}
    /**
     *  @brief converts a 4-byte number from host byte order to network byte order
     */
    template<> inline uint32_t hton<uint32_t>(uint32_t in) {return htonl(in);}
    /**
     * @brief converts a float from host yte order to network byte order
     */
    template<> inline float    hton<float>   (float    in) {return binary_cast<float> (hton<uint32_t>( binary_cast<uint32_t>(in) ));}
    /**
     * @brief converts a double from host yte order to network byte order
     */
    template<> inline double   hton<double>  (double   in) {return binary_cast<double>(hton<uint64_t>( binary_cast<uint64_t>(in) ));}
    /**
     *  @brief converts a 2-byte number from network byte order to host byte order
     */
    template<> inline uint16_t ntoh<uint16_t>(uint16_t in) {return ntohs(in);}
    /**
     *  @brief converts a 4-byte number from network byte order to host byte order
     */
    template<> inline uint32_t ntoh<uint32_t>(uint32_t in) {return ntohl(in);}
    /**
     *  @brief converts a float from network byte order to host byte order
     */
    template<> inline float    ntoh<float>   (float    in) {return binary_cast<float> (hton<uint32_t>(binary_cast<uint32_t>(in) ));}
    /**
     *  @brief converts a double from network byte order to host byte order
     */
    template<> inline double   ntoh<double>  (double   in) {return binary_cast<double>(hton<uint64_t>(binary_cast<uint64_t>(in) ));}
} // namespace cppsock
