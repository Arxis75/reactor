#pragma once

#include "InitiationDispatcher.h"

#include <arpa/inet.h>      //IPPROTO_TCP, INADDR_ANY, htons, sockaddr_in
#include <queue>
#include <vector>
#include <condition_variable>

using std::string;
using std::vector;

using std::lock_guard;
using std::unique_lock;
using std::mutex;

using std::make_shared;
using std::shared_ptr;
using std::const_pointer_cast;

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
        void enqueue(const T t)
        {
            lock_guard<mutex> lock(m);
            q.push(t);
            c.notify_one();
        }

        // Get the "front"-element.
        // If the queue is empty, wait till a element is avaiable.
        const T dequeue(void)
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
        // Constructor of a Master socket (TCP or UDP)
        SocketHandler(const uint16_t binding_port, const int protocol,
                      const int read_buffer_size = 4096, const int write_buffer_size = 4096,
                      const int tcp_connection_backlog_size = 10);
        // Constructor of a TCP connected socket
        SocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler);
        //Destructor of a TCP connected socket: close the kernel socket
        ~SocketHandler();

        // Starts receiving epoll socket events from the kernel
        void start();
        // Stops receiving epoll socket events from the kernel
        // and clears the session(s)
        void stop();

        // Handles in/out epoll socket events from the kernel,
        // creates session and:
        // - dispatch ingress msgs to the session(s)
        // - send egress msgs to peer(s)
        int handleEvent(const struct epoll_event &event);

        // Enqueue egress msg to be sent to peer
        void sendMsg(const shared_ptr<const SocketMessage> msg) { m_egress.enqueue(msg); }

        int getSocket() const { return m_socket; };
        const uint16_t getBindingPort() const { return m_binding_port; }
        int getProtocol() const { return m_protocol; };
        int getReadBufferSize() const { return m_read_buffer_size; };        
        int getWriteBufferSize() const { return m_write_buffer_size; };
        int getTCPConnectionBacklogSize() const { return m_tcp_connection_backlog_size; };

        // Registers a session handler for a particular peer
        const shared_ptr<const SessionHandler> registerSessionHandler(const struct sockaddr_in &addr);
        // Gets the session handler for a particular peer
        const shared_ptr<const SessionHandler> getSessionHandler(const struct sockaddr_in &addr);
        // Remove an Event_Handler of a particular peer
        void removeSessionHandler(const struct sockaddr_in &peer);

    protected:
        int bindSocket(const uint16_t port);
        int acceptConnection() const;

        virtual const shared_ptr<SocketHandler> makeSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler) const = 0;
        virtual const shared_ptr<SessionHandler> makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address) = 0;
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const = 0;

    private:
        int m_socket;
        const uint16_t m_binding_port;
        const int m_protocol;
        const int m_read_buffer_size;
        const int m_write_buffer_size;
        const int m_tcp_connection_backlog_size;
        const bool m_is_listening_socket;
        // the SocketHandler is the sole owner of the SessionHandlers
        map<uint64_t, const shared_ptr<const SessionHandler>> m_session_handler_list;   // UDP = list, TCP = 1 element
        // the SocketHandler is the sole owner of the egress msgs
        SafeQueue<shared_ptr<const SocketMessage>> m_egress;   // egress list stored at connected socket(tp) or master socket(udp)
};

class SocketMessage
{
    public:
        SocketMessage(const shared_ptr<const SessionHandler> session_handler);

        const shared_ptr<const SessionHandler> getSessionHandler() const;
        
        virtual uint64_t size() const = 0;

    protected:
        //For building msg
        virtual void push_back(const uint8_t) = 0;
        //For reading msg
        virtual operator const uint8_t*() const = 0;

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