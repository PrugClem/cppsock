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

cppsock::addressinfo &cppsock::addressinfo::set_family(sa_family_t fam)
{
    this->_data.ai_family = fam;
    return *this;
}

cppsock::addressinfo &cppsock::addressinfo::set_socktype(int sockt)
{
    this->_data.ai_socktype = sockt;
    return *this;
}

cppsock::addressinfo &cppsock::addressinfo::set_protocol(int proto)
{
    this->_data.ai_protocol = proto;
    return *this;
}

cppsock::socketaddr cppsock::addressinfo::get_addr() const
{
    return cppsock::socketaddr(*this);
}

sa_family_t cppsock::addressinfo::get_family() const
{
    return this->_data.ai_family;
}

int cppsock::addressinfo::get_socktype() const
{
    return this->_data.ai_socktype;
}

int cppsock::addressinfo::get_protocol() const
{
    return this->_data.ai_protocol;
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
        return error;

    while(res)
    {
        memcpy(buf.data(), res, sizeof(*res));
        output.push_back(buf);
        res = res->ai_next;
    }
    return 0;
}
