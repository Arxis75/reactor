#include "TCP.h"

#include <iostream>         //cout

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::dynamic_pointer_cast;

TCPSessionHandler::TCPSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id)
    : SessionHandler(socket_handler, peer_address, peer_id)
{ }

void TCPSessionHandler::onNewMessage(const shared_ptr<const SocketMessage> msg_in)
{
    SessionHandler::onNewMessage(msg_in);

    // test echo
    sendMessage(msg_in);
}

//----------------------------------------------------------------------------------------------------------------

TCPSocketHandler::TCPSocketHandler( const uint16_t binding_port, const string &messaging_id)
    : SocketHandler(binding_port, IPPROTO_TCP, messaging_id, 4096, 4096, 0)
{ }

TCPSocketHandler::TCPSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler)
    : SocketHandler(socket, master_handler)
{ /*USELESS TCP INTERFACE*/ }

const shared_ptr<SocketHandler> TCPSocketHandler::makeSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler) const
{ 
    return make_shared<TCPSocketHandler>(socket, master_handler);
}

const shared_ptr<SessionHandler> TCPSocketHandler::makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id)
{
    return make_shared<TCPSessionHandler>(socket_handler, peer_address, peer_id);
}

const shared_ptr<SocketMessage> TCPSocketHandler::makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const
{
    return make_shared<TCPSocketMessage>(session_handler);
}

const shared_ptr<SocketMessage> TCPSocketHandler::makeSocketMessage(const vector<uint8_t> &buffer) const
{
    return make_shared<TCPSocketMessage>(buffer);
}

const vector<uint8_t> TCPSocketHandler::makeSessionKey(const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id) const
{
    vector<uint8_t> key;
    key.resize(6);
    memcpy(&key[peer_id.size()], &peer_address.sin_addr.s_addr, 4);
    memcpy(&key[peer_id.size() + 4], &peer_address.sin_port, 2);
    return key;
}

//------------------------------------------------------------------------------------------------------

TCPSocketMessage::TCPSocketMessage(const vector<uint8_t> buffer)
    : SocketMessage(buffer)
    , m_ID({{0}})
{ }

TCPSocketMessage::TCPSocketMessage(const shared_ptr<const SessionHandler> session_handler)
    : SocketMessage(session_handler)
    , m_ID(session_handler->getPeerID())
{ }
