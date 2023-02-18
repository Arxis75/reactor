#pragma once

#include <reactor/SocketHandler.h>
#include <vector>

using std::vector;

class UDPSocketMessage: public SocketMessage
{
    public:
        UDPSocketMessage(const shared_ptr<const SessionHandler> session_handler);
        
        virtual uint64_t size() const;

        virtual operator const uint8_t*() const;
        
    protected:
        virtual void push_back(const uint8_t value);
    
    private:
        vector<uint8_t> vect;
};

class UDPSessionHandler: public SessionHandler
{
    public:
        UDPSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address);

        virtual void onNewMessage(const shared_ptr<const SocketMessage> msg_in);
};

class UDPSocketHandler: public SocketHandler
{
    public:
        UDPSocketHandler(const uint16_t binding_port);
        UDPSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler);

    protected:
        virtual const shared_ptr<SocketHandler> makeSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler) const;
        virtual const shared_ptr<SessionHandler> makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address);
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const;
};
