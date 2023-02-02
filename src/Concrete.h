#pragma once

#include <reactor/SocketHandler.h>
#include <vector>

using std::vector;

class ConcreteSocketMessage: public SocketMessage
{
    public:
        ConcreteSocketMessage(const shared_ptr<const SessionHandler> session_handler);
        
        virtual uint64_t size() const;

    protected:
        virtual operator uint8_t*() const;

        virtual void push_back(uint8_t value);
    
    private:
        vector<uint8_t> vect;
};

class ConcreteSessionHandler: public SessionHandler
{
    public:
        ConcreteSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address);

        virtual void onNewMessage(const shared_ptr<const SocketMessage> msg_in);
};

class ConcreteSocketHandler: public SocketHandler
{
    public:
        ConcreteSocketHandler(const uint16_t binding_port, const int protocol,
                              const int read_buffer_size = 4096, const int write_buffer_size = 4096,
                              const int tcp_connection_backlog_size = 10);
        ConcreteSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler);

    protected:
        virtual const shared_ptr<SocketHandler> makeSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler) const;
        virtual const shared_ptr<SessionHandler> makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address);
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const;
};
