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

class SessionHandler;
class SocketMessage;

class SocketHandler: public std::enable_shared_from_this<SocketHandler>
{
    public:
        SocketHandler(const uint16_t port, const int protocol);
        SocketHandler(const int socket);

        void start();
        void stop();

        int handleEvent(const struct epoll_event &event);
        void sendMsg(const shared_ptr<const SocketMessage> msg)
            { return m_egress.enqueue(const_pointer_cast<SocketMessage>(msg)); } //mandatory cast for the queue

        int getSocket() const { return m_socket; };
        int getProtocol() const { return m_protocol; };

        // Registers a session handler for a particular peer
        const shared_ptr<SessionHandler> registerSessionHandler(const struct sockaddr_in &addr);
        // Gets the session handler for a particular peer
        const shared_ptr<SessionHandler> getSessionHandler(const struct sockaddr_in &addr);
        // Remove an Event_Handler of a particular peer
        void removeSessionHandler(const struct sockaddr_in &peer);

    protected:
        int bindSocket(const uint16_t port);
        int acceptConnection() const;

        virtual const shared_ptr<SocketHandler> makeSocketHandler(const int socket) const = 0;
        virtual const shared_ptr<SessionHandler> makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address) = 0;
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const = 0;

    private:
        int m_socket;
        int m_protocol;
        bool m_is_listening_socket;
        map<uint64_t, shared_ptr<SessionHandler>> m_session_handler_list;   // UDP = list, TCP = 1 element
        SafeQueue<shared_ptr<const SocketMessage>> m_egress;   // egress list stored at connected socket(tp) or master socket(udp)
};

class SocketMessage
{
    public:
        SocketMessage(const shared_ptr<const SessionHandler> session_handler);

        const shared_ptr<const SessionHandler> getSessionHandler() const;
        
        virtual uint64_t size() const = 0;

    protected:
        //For ingress msg
        virtual void push_back(uint8_t) = 0;
        //For egress msg
        virtual operator uint8_t*() const = 0;

    private:
        const std::weak_ptr<const SessionHandler> m_session_handler;

    friend int SocketHandler::handleEvent(const struct epoll_event &event);
};

class SessionHandler: public std::enable_shared_from_this<SessionHandler>
{
    public:
        SessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address);
    
        const shared_ptr<const SocketHandler> getSocketHandler() const;
        const struct sockaddr_in &getPeerAddress() const;

        virtual void onNewMessage(const shared_ptr<const SocketMessage> msg_in) = 0;

    private:
        const std::weak_ptr<const SocketHandler> m_socket_handler;
        const struct sockaddr_in m_peer_address;
};