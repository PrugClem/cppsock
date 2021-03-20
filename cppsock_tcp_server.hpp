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

#pragma once

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

            /**
             *  @brief starts the tcp handled server, a valid socket collection must be linked with this instance
             * 
             *  @param addr the address the listener should listen to
             *  @param backlog how many unestablished connections the OS should store, can be changed
             *  @return cppsock utility error code that can be transformed into a human-readable string with cppsock::utility_strerror(), 
             *          a code of smaller than zero indicates an error and errno is set to the last error
             *          a code of greater than zero indicates a warning and errno is set to the last warning
             */
            cppsock::utility_error_t start(const cppsock::socketaddr &addr, int backlog = 5)
            {
                if(this->_collection == nullptr) return cppsock::utility_error_fail;
                cppsock::utility_error_t error = this->_listener.setup(addr, backlog);
                if(error < 0) return error;
                this->_listener_thread = std::thread(cppsock::tcp::server::listen, this);
                _listener_running = true;
                return error;
            }
            /**
             *  @brief starts the tcp handled server, a valid socket collection must be linked with this instance
             * 
             *  @param hostname the ip address the listener should listen to
             *  @param service the service name / port number the server should listen to
             *  @param backlog how many unestablished connections the OS should store, can be changed
             *  @return cppsock utility error code that can be transformed into a human-readable string with cppsock::utility_strerror(), 
             *          a code of smaller than zero indicates an error and errno is set to the last error
             *          a code of greater than zero indicates a warning and errno is set to the last warning
             */
            cppsock::utility_error_t start(const char *hostname, const char *service, int backlog = 5)
            {
                if(this->_collection == nullptr) return cppsock::utility_error_fail;
                cppsock::utility_error_t error =  this->_listener.setup(hostname, service, backlog);
                if(error < 0) return error;
                this->_listener_thread = std::thread(cppsock::tcp::server::listen, this);
                _listener_running = true;
                return error;
            }
            /**
             *  @brief starts the tcp handled server, a valid socket collection must be linked with this instance
             * 
             *  @param hostname the ip address the listener should listen to
             *  @param port the port number the server should listen to
             *  @param backlog how many unestablished connections the OS should store, can be changed
             *  @return cppsock utility error code that can be transformed into a human-readable string with cppsock::utility_strerror(), 
             *          a code of smaller than zero indicates an error and errno is set to the last error
             *          a code of greater than zero indicates a warning and errno is set to the last warning
             */
            cppsock::utility_error_t start(const char *hostname, uint16_t port, int backlog = 5)
            {
                if(this->_collection == nullptr) return cppsock::utility_error_fail;
                cppsock::utility_error_t error =  this->_listener.setup(hostname, port, backlog);
                if(error < 0) return error;
                this->_listener_thread = std::thread(cppsock::tcp::server::listen, this);
                _listener_running = true;
                return error;
            }

            /**
             * @brief closes this server, connections established from this instance are not closed
             * 
             */
            void stop()
            {
                if(this->_listener_running)
                {
                    this->_listener.close();
                    this->_listener_running = false;
                    this->_listener_thread.join();
                }
            }

            /**
             * @brief Set the collection object, only works if the server is not running
             * 
             * @param collection pointer to a collection object
             * @return true on success, false if the server is running
             */
            bool set_collection(cppsock::tcp::socket_collection *collection)
            {
                if(this->_listener_running) return false;
                this->_collection = collection;
                return true;
            }

            /**
             * @brief get the underlying listener object
             * 
             * @return const referecne to the underlying listener 
             */
            inline const cppsock::tcp::listener &listener()
            {
                return this->_listener;
            }
        
        }; // namespace server
    } // namespace tcp 
} // namespace cppsock
