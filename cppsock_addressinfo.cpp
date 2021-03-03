/**
 *  @author: Clemens Pruggmayer (PrugClem)
 *  @date:   2020-12-22
 *  @desc:   implementation for addressinfo, used to resolve hostnames
 */
#include "cppsock.hpp"

addrinfo *cppsock::addressinfo::data()
{
    return &this->_data;
}

const addrinfo *cppsock::addressinfo::data() const
{
    return &this->_data;
}

cppsock::addressinfo& cppsock::addressinfo::reset()
{
    memset(&this->_data, 0, sizeof(this->_data));
    return *this;
}

cppsock::addressinfo &cppsock::addressinfo::set_family(cppsock::ip_family fam)
{
    this->_data.ai_family = fam;
    return *this;
}

cppsock::addressinfo &cppsock::addressinfo::set_socktype(cppsock::socket_type sockt)
{
    this->_data.ai_socktype = sockt;
    return *this;
}

cppsock::addressinfo &cppsock::addressinfo::set_protocol(cppsock::ip_protocol proto)
{
    this->_data.ai_protocol = proto;
    return *this;
}

cppsock::addressinfo &cppsock::addressinfo::set_passive(bool passive)
{
    if(passive)
        this->_data.ai_flags |= AI_PASSIVE; // set passive flag
    else
        this->_data.ai_flags &= ~AI_PASSIVE; // reset passive flag
    return *this;
}


cppsock::socketaddr cppsock::addressinfo::get_addr() const
{
    return cppsock::socketaddr(*this);
}


cppsock::ip_family cppsock::addressinfo::get_family() const
{
    return (cppsock::ip_family)this->_data.ai_family;
}

cppsock::socket_type cppsock::addressinfo::get_socktype() const
{
    return (cppsock::socket_type)this->_data.ai_socktype;
}

cppsock::ip_protocol cppsock::addressinfo::get_protocol() const
{
    return (cppsock::ip_protocol)this->_data.ai_protocol;
}

cppsock::addressinfo::operator socketaddr() const
{
    socketaddr retbuf;
    retbuf.set(this->_data.ai_addr);
    return retbuf;
}

error_t cppsock::getaddrinfo(const char *hostname, const char* service, const cppsock::addressinfo *hints, std::vector<cppsock::addressinfo>& output)
{
    addressinfo buf;
    addrinfo *res;
    error_t error = ::getaddrinfo(hostname, service, (hints == nullptr) ? nullptr: hints->data(), &res);
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
