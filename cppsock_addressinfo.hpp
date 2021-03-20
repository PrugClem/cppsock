/**
 * @file cppsock_addressinfo.hpp
 * @author PrugClem
 * @brief Implementation for cppsock addressinfo class
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
    class addressinfo
    {
    protected:
        addrinfo _data;
    public:
        /**
         *  @brief reutns raw data in c-style sddrinfo structure
         */
        addrinfo *data()
        {
            return &this->_data;
        }
        /**
         *  @brief reutns raw data in c-style sddrinfo structure
         */
        const addrinfo *data() const
        {
            return &this->_data;
        }

        /**
         *  @brief clears this structure
         *  @return this structure to allow chaining
         */
        addressinfo &reset()
        {
            memset(&this->_data, 0, sizeof(this->_data));
            return *this;
        }

        /**
         *  @brief sets the family type for resolving
         *  @return this structure to allow chaining
         */
        addressinfo &set_family(ip_family fam)
        {
            this->_data.ai_family = fam;
            return *this;
        }
        /**
         *  @brief sets the socket type for this strucutre, can be SOCK_STREAM for TCP or SOCK_DGRAM for UDP
         *  @return this structure to allow chaining
         */
        addressinfo &set_socktype(socket_type sockt)
        {
            this->_data.ai_socktype = sockt;
            return *this;
        }
        /**
         *  @brief specifies the protocol for this structure, 0 to use socktype defualts
         *  @return this structure to allow chaining
         */
        addressinfo &set_protocol(ip_protocol proto)
        {
            this->_data.ai_protocol = proto;
            return *this;
        }
        /**
         *  @brief sets the passive flag, if the passive flag is true, the results can be used for bind()-ing, if the passive flag is false, the address can be used for connect()-ing
         *  @return this structure to allow chaining
         */
        addressinfo &set_passive(bool passive)
        {
            if(passive)
                this->_data.ai_flags |= AI_PASSIVE; // set passive flag
            else
                this->_data.ai_flags &= ~AI_PASSIVE; // reset passive flag
            return *this;
        }

        /**
         *  @return a socketaddr class
         */
        socketaddr get_addr() const
        {
            return cppsock::socketaddr(*this);
        }
        /**
         *  @return address family
         */
        ip_family get_family() const
        {
            return (cppsock::ip_family)this->_data.ai_family;
        }
        /**
         *  @return socket type
         */
        socket_type get_socktype() const
        {
            return (cppsock::socket_type)this->_data.ai_socktype;
        }
        /**
         *  @return protocol that should be used
         */
        ip_protocol get_protocol() const
        {
            return (cppsock::ip_protocol)this->_data.ai_protocol;
        }

        /**
         *  cast operator for easy use
         */
        operator socketaddr() const
        {
            socketaddr retbuf;
            retbuf.set(this->_data.ai_addr);
            return retbuf;
        }
    };
}; // namespace cppsock
