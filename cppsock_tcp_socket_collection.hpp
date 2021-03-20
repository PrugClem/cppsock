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
                void *persistent{nullptr};
                std::atomic_bool running{false};
                std::atomic_bool working{false};
                const std::atomic_size_t *connections;
            };

            using callback_t = std::function<void(std::shared_ptr<cppsock::tcp::socket>, void**)>;
            
        protected:
            std::map<std::shared_ptr<cppsock::tcp::socket>, connection_details> sockets;
            callback_t on_insert;
            callback_t on_recv;
            callback_t on_disconnect;
            std::mutex sync;
            std::atomic_size_t n_connections;
            
            static void handle(socket_collection *tar, std::shared_ptr<cppsock::tcp::socket> sock)
            {
                connection_details &details = tar->sockets[sock];

                tar->on_insert(sock, &details.persistent);
                if(!sock->sock().is_valid()) details.running = false;
                while(details.running)
                {
                    uint8_t indicator;
                    if(sock->recv(&indicator, sizeof(indicator), cppsock::peek ) > 0)
                        tar->on_recv(sock, &details.persistent);
                    else
                        details.running = false;
                }
                tar->on_disconnect(sock, &details.persistent);
                {   // lock guard block
                    std::unique_lock<std::mutex> lock(tar->sync);
                    tar->sockets.erase(sock);
                    tar->n_connections--;
                }
                if(sock->sock().is_valid()) sock->close();
                details.working = false;
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
            
            void insert(cppsock::tcp::socket &_sock)
            {
                std::shared_ptr<cppsock::tcp::socket> sock = std::make_shared<cppsock::tcp::socket>();
                connection_details details;
                sock->swap(_sock);

                {   // lock guard block
                    std::unique_lock<std::mutex> lock(this->sync);
                    this->sockets[sock].running = true;
                    this->sockets[sock].working = true;
                    this->sockets[sock].connections = &(this->n_connections);
                }

                std::thread connection_thread(handle, this, sock);
                connection_thread.detach();
                this->n_connections++;
            }

            void clear()
            {
                for(auto &iter : this->sockets)
                {
                    iter.second.persistent = nullptr;
                    iter.second.running = false;    // shutdown thread
                    iter.first->close();
                    while(iter.second.working) {std::this_thread::yield();} // wait for thread to finish
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
