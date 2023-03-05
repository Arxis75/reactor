#pragma once

#include <reactor/SocketHandler.h>
#include <vector>

using std::vector;

class UDPSocketMessage: public SocketMessage
{
    public:
        UDPSocketMessage(const shared_ptr<const SocketHandler> handler, const vector<uint8_t> buffer, const struct sockaddr_in &peer_addr);
        UDPSocketMessage(const shared_ptr<const SessionHandler> session_handler);

        virtual inline void print() const {};
};

class UDPSessionHandler: public SessionHandler
{
    public:
        UDPSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id);

        virtual void onNewMessage(const shared_ptr<const SocketMessage> msg_in);
};

class UDPSocketHandler: public SocketHandler
{
    public:
        UDPSocketHandler(const uint16_t binding_port);

        virtual const vector<uint8_t> makeSessionKey(const struct sockaddr_in &peer_addr, const vector<uint8_t> &peer_id) const;

    protected:
        virtual const shared_ptr<SessionHandler> makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id);
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const;        
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const shared_ptr<const SocketHandler> handler, const vector<uint8_t> buffer, const struct sockaddr_in &peer_addr) const;
};
