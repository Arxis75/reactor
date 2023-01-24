#pragma once

#include "InitiationDispatcher.h"

#include <arpa/inet.h>      //IPPROTO_TCP, INADDR_ANY, htons, sockaddr_in
#include <queue>
#include <vector>
#include <condition_variable>

using std::vector;

using std::lock_guard;
using std::unique_lock;
using std::mutex;

using std::make_shared;
using std::shared_ptr;
using std::const_pointer_cast;

#define MAX_DISCV5_UDP_PACKET_SIZE 1280     // INPUT PARAMETERS 
#define MAX_ETH_TCP_PACKET_SIZE 10485100    // INPUT PARAMETERS 

#define CONNECTION_BACKLOG_SIZE 10
#define READ_BUFFER_SIZE 4096
#define WRITE_BUFFER_SIZE 4096

// A threadsafe-queue.
template <class T>
class SafeQueue
{
    public:
        SafeQueue(void)
        : q()
        , m()
        , c()
        {}

        ~SafeQueue(void)
        {}

        // Add an element to the queue.
        void enqueue(T t)
        {
            lock_guard<mutex> lock(m);
            q.push(t);
            c.notify_one();
        }

        // Get the "front"-element.
        // If the queue is empty, wait till a element is avaiable.
        T dequeue(void)
        {
            unique_lock<mutex> lock(m);
            while(q.empty())
            {
                // release lock as long as the wait and reaquire it afterwards.
                c.wait(lock);
            }
            T val = q.front();
            q.pop();
            return val;
        }
        
        auto size() const { return q.size(); }
        void clear() { while(q.size()) q.pop(); }
        
    private:
        std::queue<T> q;
        mutable std::mutex m;
        std::condition_variable c;
};

class SessionManager;
class SocketHandlerMessage;

class SocketHandler: public std::enable_shared_from_this<SocketHandler>
{
    public:
        SocketHandler(const shared_ptr<const SessionManager> m_session_manager, const uint16_t port, const int protocol);
        SocketHandler(const shared_ptr<const SessionManager> m_session_manager, const int socket);

        void start();
        int handleEvent(const struct epoll_event& event);
        void sendMsg(const shared_ptr<const SocketHandlerMessage> msg)
            { return m_egress.enqueue(const_pointer_cast<SocketHandlerMessage>(msg)); } //mandatory cast for the queue

        int getSocket() const { return m_socket; };
        int getProtocol() const { return m_protocol; };
        const shared_ptr<const SessionManager> getSessionManager() const { return m_session_manager; }

    private:
        int bindSocket(const uint16_t port);
        int acceptConnection() const;

    private:
        int m_socket;
        int m_protocol;
        bool m_is_listening_socket;
        const shared_ptr<const SessionManager> m_session_manager;
        SafeQueue<shared_ptr<const SocketHandlerMessage>> m_egress;   // egress list stored at connected socket(tp) or master socket(udp)
};

class SocketHandlerMessage
{
    public:
        SocketHandlerMessage(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address);
        
        const shared_ptr<const SocketHandler> getSocketHandler() const;
        const struct sockaddr_in& getPeerAddress() const { return m_peer_address; }

        const vector<uint8_t> &data() const { return m_payload; }

    protected:
        vector<uint8_t> &data() { return m_payload; }

    private:
        const std::weak_ptr<const SocketHandler> m_socket_handler;
        const struct sockaddr_in m_peer_address;
        vector<uint8_t> m_payload;

    friend int SocketHandler::handleEvent(const struct epoll_event& event);
};

class SessionManager: public std::enable_shared_from_this<SessionManager>
{
    public:
        SessionManager(const uint16_t master_port, const int master_protocol);

        void start();
        virtual void onNewMessage(const shared_ptr<const SocketHandlerMessage> msg_in) = 0;

    private:
        int m_master_port;
        int m_master_protocol;
        SafeQueue<shared_ptr<const SocketHandlerMessage>> m_ingress;
};