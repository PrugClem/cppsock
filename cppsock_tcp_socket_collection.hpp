/**
 * @file cppsock_tcp_socket_collection.hpp
 * @author PrugClem, R-Michi
 * @brief collection class for tcp connection sockets
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
        class socket_collection
        {
        public:
            /**
             * @brief stores details about the connection
             * 
             */
            struct connection_details
            {
                cppsock::socketaddr_pair addrpair;      // stores remote and own adress
                void *persistent{nullptr};              // persistent pointer for the programmer
                std::atomic_bool running{false};        // indicates if the connection is valid
                std::atomic_bool working{false};        // indicates if connection-thread is still working
                const std::atomic_size_t *connections;  // pointer to the number of TCP sockets stored in this collection
            };

            using callback_t = std::function<void(std::shared_ptr<cppsock::tcp::socket>, cppsock::socketaddr_pair, void**)>;
            //typedef void(*callback_t)(std::shared_ptr<cppsock::tcp::socket>, cppsock::socketaddr_pair, void**);
            
        protected:
            std::map<std::shared_ptr<cppsock::tcp::socket>, connection_details> sockets;    // stores all the sockets
            std::mutex map_sync;                                                            // IPS to access the socket map
            callback_t on_insert;               // function that is called if a socket gets inserted to the collection
            callback_t on_recv;                 // function that is called if data is available
            callback_t on_disconnect;           // function that is called if socket gets disconnected
            std::atomic_size_t n_connections;   // number of stored connections
            std::atomic_bool clearing;
            
            /**
             * @brief handles the raw socket I/O and calls the callback functions
             * 
             * @param tar source collection
             * @param sock affected socket
             */
            static void handle(socket_collection *tar, std::shared_ptr<cppsock::tcp::socket> sock)
            {
                connection_details &details = tar->sockets[sock];

                tar->on_insert(sock, details.addrpair, &details.persistent);            // if thread startes, socket is connected -> call insert callback
                if(!sock->sock().is_valid()) details.running = false;                   // insert callback may end the connection, if so, shutdown handler thread
                while(details.running)
                {
                    uint8_t indicator;                                                  
                    if(sock->recv(&indicator, sizeof(indicator), cppsock::peek ) > 0)   // indicate if there is something in the receive buffer, but not delete it from the buffer
                        tar->on_recv(sock, details.addrpair, &details.persistent);      // if something is in the buffer, call receive callback
                    else
                        details.running = false;                                        // receive function will return 0 if connection is closed -> shutdown handler thread
                }
                sock->close();                                                          // close socket, it may only be shutdowned
                tar->on_disconnect(sock, details.addrpair, &details.persistent);        // call disconnect callback
                tar->n_connections--;
                details.working = false;
                {   // lock guard block
                    std::unique_lock<std::mutex> lock(tar->map_sync);                   // to ensure that no other thread accesses the map while erasing the current socket
                    tar->sockets.erase(sock);
                }
            }

        public:
            /**
             *  @brief to ensure proper functionality, the default constructor is deleted!
             */
            socket_collection() = delete;

            /**
             * @brief Construct a new socket collection object
             * 
             * @param on_insert insert handler function pointer, persistent pointer is specifically for the programmer as a generic pointer
             * @param on_recv receive function pointer, persistent pointer is specifically for the programmer as a generic pointer, WARNING: a recv call to the socket may result in an error return value at any point, if this is the case, return the callback function
             * @param on_disconnect disconnect handler function pointer, persistent pointer is specifically for the programmer as a generic pointer
             *          !!! socket object is no longer valid !!!
             */
            explicit socket_collection(callback_t on_insert, callback_t on_recv, callback_t on_disconnect)
            {
                // to ensure proper work, a NULL-callback is not allowed, same counts for the default constructor
                if ((on_insert == nullptr) || (on_recv == nullptr) || (on_disconnect == nullptr))
                    throw std::logic_error("nullptr given for callback function");
                // initialize socket-collection
                this->on_insert = on_insert;
                this->on_recv = on_recv;
                this->on_disconnect = on_disconnect;
                this->n_connections = 0;
                this->clearing = false;
            }
    
            virtual ~socket_collection(void)
            {
                this->clear();
            }
            
            /**
             *  @brief adds a socket to the socket collection.
             *         The socket-connection will be handled in an unique thread.
             *  
             *  @param _sock socket to store into the collection, After the function call, this socket is moved away!
             *  @return pointer to the socket, now inside the collection, if it returns a nullptr, the socket could not be inserted into the collection
             */
            std::shared_ptr<cppsock::tcp::socket> insert(cppsock::tcp::socket &_sock, void *persistent_default = nullptr)
            {
                if(this->clearing) return nullptr;  // abort if clearing
                std::shared_ptr<cppsock::tcp::socket> sock = std::make_shared<cppsock::tcp::socket>();  // make new socket object
                connection_details details;
                sock->swap(_sock);                                                                      // move / swap _sock into the new object -> _sock gets invalid

                {   // lock guard block
                    std::unique_lock<std::mutex> lock(this->map_sync);
                    // initialize connection details for the current socket
                    this->sockets[sock].addrpair.local = sock->sock().getsockname();
                    this->sockets[sock].addrpair.remote = sock->sock().getpeername();
                    this->sockets[sock].running = true;
                    this->sockets[sock].working = true;
                    this->sockets[sock].persistent = persistent_default;
                    this->sockets[sock].connections = &(this->n_connections);
                }

                // start handler thread
                std::thread connection_thread(handle, this, sock); 
                connection_thread.detach();
                this->n_connections++;

                return sock;
            }
            
            /**
             *  @brief closes every connection that is handled by the socket-collection
             */
            void clear()
            {
                this->clearing = true;          // mark this instance to be cleared
                this->map_sync.lock();          // lock, because there can be a chance that a thread tries to remove an object from the map at the same time
                for(auto &iter : this->sockets)
                    iter.first->close();        // close all sockets in the collection
                this->map_sync.unlock();        
                while(this->sockets.size() > 0) {std::this_thread::yield();} // wait forall sockets to be removed
                this->clearing = false;         // mark this instace to be no longer cleared
            }

            /**
             * @brief get the amount of sockets in the collection
             */
            inline std::size_t count(void)
            {
                return this->sockets.size();
            }
        }; // class socket_collection
    } // namespace tcp
} // namespace cppsock
