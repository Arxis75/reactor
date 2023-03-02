#include "UDP.h"

#include <iostream>         //cout

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::dynamic_pointer_cast;

UDPSessionHandler::UDPSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id)
    : SessionHandler(socket_handler, peer_address, peer_id)
{ }

void UDPSessionHandler::onNewMessage(const shared_ptr<const SocketMessage> msg_in)
{
    SessionHandler::onNewMessage(msg_in);

    // test echo
    sendMessage(msg_in);
}

//----------------------------------------------------------------------------------------------------------------

UDPSocketHandler::UDPSocketHandler( const uint16_t binding_port, const string &messaging_id)
    : SocketHandler(binding_port, IPPROTO_UDP, messaging_id, 1374, 1374, 0)
{ }

const shared_ptr<SessionHandler> UDPSocketHandler::makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id)
{
    return make_shared<UDPSessionHandler>(socket_handler, peer_address, peer_id);
}

const shared_ptr<SocketMessage> UDPSocketHandler::makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const
{
    return make_shared<UDPSocketMessage>(session_handler);
}

const shared_ptr<SocketMessage> UDPSocketHandler::makeSocketMessage(const vector<uint8_t> &buffer) const
{
    return make_shared<UDPSocketMessage>(buffer);
}

const vector<uint8_t> UDPSocketHandler::makeSessionKey(const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id) const
{
    vector<uint8_t> key;
    key.resize(peer_id.size() + 6);
    if (peer_id.size())
        memcpy(&key[0], &peer_id[0], peer_id.size());
    memcpy(&key[peer_id.size()], &peer_address.sin_addr.s_addr, 4);
    memcpy(&key[peer_id.size() + 4], &peer_address.sin_port, 2);
    return key;
}

//------------------------------------------------------------------------------------------------------

UDPSocketMessage::UDPSocketMessage(const vector<uint8_t> buffer)
    : SocketMessage(buffer)
    , m_ID({{0}})
{ }

UDPSocketMessage::UDPSocketMessage(const shared_ptr<const SessionHandler> session_handler)
    : SocketMessage(session_handler)
    , m_ID(session_handler->getPeerID())
{ }
