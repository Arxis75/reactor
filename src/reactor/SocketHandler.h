#pragma once

#include "InitiationDispatcher.h"

#include <arpa/inet.h>      //IPPROTO_TCP, INADDR_ANY, htons, sockaddr_in
#include <queue>
#include <vector>
#include <condition_variable>
#include <cstring>

using std::string;
using std::vector;

using std::lock_guard;
using std::unique_lock;
using std::mutex;

using std::make_shared;
using std::shared_ptr;
using std::weak_ptr;
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

        inline int getSocket() const { return m_socket; };
        inline uint16_t getBindingPort() const { return m_binding_port; }
        inline int getProtocol() const { return m_protocol; };
        inline int getReadBufferSize() const { return m_read_buffer_size; };        
        inline int getWriteBufferSize() const { return m_write_buffer_size; };
        inline int getTCPConnectionBacklogSize() const { return m_tcp_connection_backlog_size; };

        // Registers a session handler for a particular peer
        const shared_ptr<const SessionHandler> registerSessionHandler(const struct sockaddr_in &peer_addr, const vector<uint8_t> &peer_id);
        // Constructs a session unique key: peer_id is extracted from the message itself (more selective than just IP:Port)
        virtual const vector<uint8_t> makeSessionKey(const struct sockaddr_in &peer_addr, const vector<uint8_t> &peer_id) const = 0;
        // Gets the session handler for a particular peer
        const shared_ptr<const SessionHandler> getSessionHandler(const vector<uint8_t> &session_key) const;
        // Gets the current number of living sessions
        size_t getSessionsCount() const;
        // Remove an Event_Handler of a particular peer
        void removeSessionHandler(shared_ptr<const SessionHandler> session);

        void blacklist(const bool status, const struct sockaddr_in &peer_address);
        bool isBlacklisted(const struct sockaddr_in &peer_address) const;

        // Constructs a basic unique key from IP:Port
        const uint64_t makeAddressKey(const struct sockaddr_in &peer_addr) const;

        static bool isInternalAddress(const struct sockaddr_in &addr);

    protected:
        int bindSocket(const uint16_t port);
        int acceptConnection() const;
        
        const map<vector<uint8_t>, shared_ptr<const SessionHandler>> &getSessionList() const { return m_session_handler_list; }

        const shared_ptr<SocketMessage> makeMessageWithSession(const vector<uint8_t> buffer, const struct sockaddr_in &peer_addr);

        //By default, dispatch to the message session
        virtual void dispatchMessage(const shared_ptr<const SocketMessage> msg);
        
        virtual const shared_ptr<SocketHandler> makeSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler) const { return shared_ptr<SocketHandler>(nullptr); }
        virtual const shared_ptr<SessionHandler> makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id) = 0;
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const = 0;
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const vector<uint8_t> &buffer) const = 0;

    private:
        int m_socket;
        const uint16_t m_binding_port;
        const int m_protocol;
        const int m_read_buffer_size;
        const int m_write_buffer_size;
        const int m_tcp_connection_backlog_size;
        const bool m_is_listening_socket;
        // List of SessionHandlers (key = vector forged by the session)
        map<vector<uint8_t>, shared_ptr<const SessionHandler>> m_session_handler_list;
        // List of blacklisted peers (key = vector forged by the session)
        vector<uint64_t> m_blacklisted_peers;
        // The SocketHandler (master or connected) is the sole owner of the egress msgs
        SafeQueue<shared_ptr<const SocketMessage>> m_egress;   // egress list stored at connected socket(tp) or master socket(udp)
};

class SocketMessage: public std::enable_shared_from_this<SocketMessage>
{
    public:
        //Copy Constructor
        SocketMessage(const shared_ptr<const SocketMessage> msg);
        //Raw msg constructor
        SocketMessage(const vector<uint8_t> buffer);
        //session-embedded empty msg
        SocketMessage(const shared_ptr<const SessionHandler> session_handler);

        const shared_ptr<const SessionHandler> getSessionHandler() const { return m_session_handler.lock(); }
        
        // Message attribute allowing session creation on receive
        virtual inline bool isSessionBootstrapper() const { return true; }
        
        // Retrieve the peer ID from the message content:
        virtual inline const vector<uint8_t> getPeerID() const = 0;
        
        inline void clear() { m_vect.clear(); }
        inline uint64_t size() const { return m_vect.size(); }
        inline operator const vector<uint8_t>&() const { return m_vect; }
        inline operator const uint8_t*() const { return m_vect.data(); }
        inline operator uint8_t*() { return m_vect.data(); }
        inline void resize(uint32_t value) { m_vect.resize(value, 0); }
        inline void push_back(const uint8_t value) { m_vect.push_back(value); }
        inline void push_back(const vector<uint8_t> v) { m_vect.insert(m_vect.end(), v.begin(), v.end());; }

        virtual void print() const;
    
    protected:
        friend class SocketHandler;
        void attach(const shared_ptr<const SessionHandler> session_handler) { m_session_handler = session_handler; }

    private:
        //The Peer ID is a member of the protocol-level msg class
        //It is initialized at protocol-level.
        weak_ptr<const SessionHandler> m_session_handler;
        //The message content:
        vector<uint8_t> m_vect;
};

class SessionHandler: public std::enable_shared_from_this<SessionHandler>
{
    public:
        SessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id);
    
        const shared_ptr<const SocketHandler> getSocketHandler() const;
        inline const struct sockaddr_in &getPeerAddress() const { return m_peer_address; }
        inline const vector<uint8_t> getPeerID() const { return m_peer_ID; }

        virtual void onNewMessage(const shared_ptr<const SocketMessage> msg_in);
        virtual void sendMessage(const shared_ptr<const SocketMessage> msg_out) const ;

        virtual void close() const;

    private:
        const weak_ptr<const SocketHandler> m_socket_handler;
        const struct sockaddr_in m_peer_address;
        const vector<uint8_t> m_peer_ID;
};