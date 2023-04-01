#pragma once

#include <reactor/SocketHandler.h>
#include <vector>

using std::vector;

class TCPSocketMessage: public SocketMessage
{
    public:
        TCPSocketMessage(const shared_ptr<const SocketHandler> handler, const vector<uint8_t> buffer, const struct sockaddr_in &peer_addr, const bool is_ingress = true);
        TCPSocketMessage(const shared_ptr<const SessionHandler> session_handler);

        virtual inline void print() const;
};

class TCPSessionHandler: public SessionHandler
{
    public:
        TCPSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address);

        virtual void onNewMessage(const shared_ptr<const SocketMessage> msg_in);
        virtual void sendMessage(const shared_ptr<const SocketMessage> msg_out);
};

class TCPSocketHandler: public SocketHandler
{
    public:
        TCPSocketHandler(const uint16_t binding_port);
        TCPSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler);

    protected:
        virtual const shared_ptr<SocketHandler> makeSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler) const;
        virtual const shared_ptr<SessionHandler> makeSessionHandler(const struct sockaddr_in &peer_address);
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const vector<uint8_t> buffer, const struct sockaddr_in &peer_address) const;
};
