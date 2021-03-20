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

#ifndef CPPSOCK_TCP_SOCKET_COLLECTION_HPP_INCLUDED
#define CPPSOCK_TCP_SOCKET_COLLECTION_HPP_INCLUDED

namespace cppsock
{
    namespace tcp
    {
        class socket_collection
        {
        public:
            struct connection_details
            {
                cppsock::socketaddr_pair addrpair;
                void *persistent{nullptr};
                std::atomic_bool running{false};
                std::atomic_bool working{false};
                const std::atomic_size_t *connections;
            };

            using callback_t = std::function<void(std::shared_ptr<cppsock::tcp::socket>, cppsock::socketaddr_pair, void**)>;
            
        protected:
            std::map<std::shared_ptr<cppsock::tcp::socket>, connection_details> sockets;
            callback_t on_insert;
            callback_t on_recv;
            callback_t on_disconnect;
            std::mutex map_sync;
            std::atomic_size_t n_connections;
            
            static void handle(socket_collection *tar, std::shared_ptr<cppsock::tcp::socket> sock)
            {
                connection_details &details = tar->sockets[sock];

                tar->on_insert(sock, details.addrpair, &details.persistent);
                if(!sock->sock().is_valid()) details.running = false;
                while(details.running)
                {
                    uint8_t indicator;
                    if(sock->recv(&indicator, sizeof(indicator), cppsock::peek ) > 0)
                        tar->on_recv(sock, details.addrpair, &details.persistent);
                    else
                        details.running = false;
                }
                sock->close(); // close socket
                tar->on_disconnect(sock, details.addrpair, &details.persistent);
                tar->n_connections--;
                details.working = false;
                {   // lock guard block
                    std::unique_lock<std::mutex> lock(tar->map_sync);
                    tar->sockets.erase(sock);
                }
            }

        public:
            socket_collection() = delete;
            explicit socket_collection(callback_t on_insert, callback_t on_recv, callback_t on_disconnect)
            {
                if ((on_insert == nullptr) || (on_recv == nullptr) || (on_disconnect == nullptr))
                    throw std::logic_error("nullptr given for callback function");
                this->on_insert = on_insert;
                this->on_recv = on_recv;
                this->on_disconnect = on_disconnect;
            }

            virtual ~socket_collection(void)
            {
                this->clear();
            }
            
            std::shared_ptr<cppsock::tcp::socket> insert(cppsock::tcp::socket &_sock)
            {
                std::shared_ptr<cppsock::tcp::socket> sock = std::make_shared<cppsock::tcp::socket>();
                connection_details details;
                sock->swap(_sock);

                {   // lock guard block
                    std::unique_lock<std::mutex> lock(this->map_sync);
                    this->sockets[sock].addrpair.local = sock->sock().getsockname();
                    this->sockets[sock].addrpair.remote = sock->sock().getpeername();
                    this->sockets[sock].running = true;
                    this->sockets[sock].working = true;
                    this->sockets[sock].connections = &(this->n_connections);
                }

                std::thread connection_thread(handle, this, sock);
                connection_thread.detach();
                this->n_connections++;

                return sock;
            }

            void clear()
            {
                bool done = false;
                while(!done)
                {
                    std::this_thread::yield(); // give the other threads a chance to erase the element & exit the thread
                    std::lock_guard<std::mutex> lock(this->map_sync);           // lock the access to the map
                    if(this->sockets.size() > 0)
                    {
                        auto &iter = *this->sockets.begin();                    // get the first element
                        iter.second.running = false;                            // shutdown thread
                        iter.first->close();                                    // close socket
                        while(iter.second.working) {std::this_thread::yield();} // wait for thread to finish and the element to be removed
                        iter.second.persistent = nullptr;                       // reset persistent pointer
                    }
                    else
                    {
                        done = true;    // if there are no sockets stored, the clear call is done
                    }
                }
            }

            inline std::size_t count(void)
            {
                return this->sockets.size();
            }
        }; // class socket_collection
    } // namespace tcp
} // namespace cppsock

#endif // CPPSOCK_TCP_SOCKET_COLLECTION_HPP_INCLUDED
