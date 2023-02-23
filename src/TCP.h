#pragma once

#include <reactor/SocketHandler.h>
#include <vector>

using std::vector;

class TCPSocketMessage: public SocketMessage
{
    public:
        TCPSocketMessage(const vector<uint8_t> buffer);
        TCPSocketMessage(const shared_ptr<const SessionHandler> session_handler);

        virtual inline const vector<uint8_t> getPeerID() const { return {{0}}; }
        virtual inline void print() const {};
    
    private:
        vector<uint8_t> m_vect;
};

class TCPSessionHandler: public SessionHandler
{
    public:
        TCPSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id);

        virtual void onNewMessage(const shared_ptr<const SocketMessage> msg_in);
};

class TCPSocketHandler: public SocketHandler
{
    public:
        TCPSocketHandler(const uint16_t binding_port);
        TCPSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler);

    protected:
        virtual const shared_ptr<SocketHandler> makeSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler) const;
        virtual const shared_ptr<SessionHandler> makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id);
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const;        
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const vector<uint8_t> &buffer) const;
};
