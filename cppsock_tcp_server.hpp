/**
 * @file cppsock_tcp_server.hpp
 * @author PrugClem, R-Michi
 * @brief server class to handle a listener socket
 * @version 0.1
 * @date 2021-03-20
 * 
 * @copyright Copyright (c) 2021
 * 
 */
#include "cppsock.hpp"

#ifndef CPPSOCK_TCP_SERVER_HPP_INCLUDED
#define CPPSOCK_TCP_SERVER_HPP_INCLUDED

namespace cppsock
{
    namespace tcp
    {
        class server
        {
        protected:
            std::thread _listener_thread;
            std::atomic_bool _listener_running;
            cppsock::tcp::listener _listener;
            cppsock::tcp::socket_collection *_collection;
        
            static void listen(server *tar)
            {
                cppsock::tcp::socket sock;
                while (tar->_listener_running)
                {
                    if(tar->_listener.accept(sock) == 0)
                    {
                        tar->_collection->insert(sock);
                    }
                    else
                    {
                        tar->_listener_running = false;
                    }
                }
            }

        public:
            server(void) : server(nullptr) { }
            explicit server(cppsock::tcp::socket_collection *collection) : _listener_running(false), _collection(collection) { }

            virtual ~server(void)
            {
                this->stop();
            }

            cppsock::utility_error_t start(const cppsock::addressinfo &addr, int backlog)
            {
                if(this->_collection == nullptr) return cppsock::utility_error_fail;
                cppsock::utility_error_t error = this->_listener.setup(addr, backlog);
                if(error < 0) return error;
                this->_listener_thread = std::thread(cppsock::tcp::server::listen, this);
                _listener_running = true;
                return error;
            }
            
            cppsock::utility_error_t start(const char *hostname, const char *service, int backlog)
            {
                if(this->_collection == nullptr) return cppsock::utility_error_fail;
                cppsock::utility_error_t error =  this->_listener.setup(hostname, service, backlog);
                if(error < 0) return error;
                this->_listener_thread = std::thread(cppsock::tcp::server::listen, this);
                _listener_running = true;
                return error;
            }

            cppsock::utility_error_t start(const char *hostname, uint16_t port, int backlog)
            {
                if(this->_collection == nullptr) return cppsock::utility_error_fail;
                cppsock::utility_error_t error =  this->_listener.setup(hostname, port, backlog);
                if(error < 0) return error;
                this->_listener_thread = std::thread(cppsock::tcp::server::listen, this);
                _listener_running = true;
                return error;
            }

            void stop()
            {
                if(this->_listener_running)
                {
                    this->_listener.close();
                    this->_listener_running = false;
                    this->_listener_thread.join();
                }
            }

            bool set_collection(cppsock::tcp::socket_collection *collection)
            {
                if(this->_listener_running) return false;
                this->_collection = collection;
                return true;
            }

            inline const cppsock::tcp::listener &listener()
            {
                return this->_listener;
            }
        
        }; // namespace server
    } // namespace tcp 
} // namespace cppsock

#endif // CPPSOCK_TCP_SERVER_HPP_INCLUDED
