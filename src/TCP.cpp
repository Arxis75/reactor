#include "TCP.h"

#include <iostream>         //cout

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::dynamic_pointer_cast;

TCPSessionHandler::TCPSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address)
    : SessionHandler(socket_handler, peer_address)
{ }

void TCPSessionHandler::onNewMessage(const shared_ptr<const SocketMessage> msg_in)
{
    SessionHandler::onNewMessage(msg_in);

    // test echo
    sendMessage(msg_in);
}

//----------------------------------------------------------------------------------------------------------------

TCPSocketHandler::TCPSocketHandler( const uint16_t binding_port)
    : SocketHandler(binding_port, IPPROTO_TCP, 4096, 4096, 0)
{ }

TCPSocketHandler::TCPSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler)
    : SocketHandler(socket, master_handler)
{ /*USELESS TCP INTERFACE*/ }

const shared_ptr<SocketHandler> TCPSocketHandler::makeSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler) const
{ 
    return make_shared<TCPSocketHandler>(socket, master_handler);
}

const shared_ptr<SessionHandler> TCPSocketHandler::makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address)
{
    return make_shared<TCPSessionHandler>(socket_handler, peer_address);
}

const shared_ptr<SocketMessage> TCPSocketHandler::makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const
{
    return make_shared<TCPSocketMessage>(session_handler);
}

const shared_ptr<SocketMessage> TCPSocketHandler::makeSocketMessage(const shared_ptr<const SocketMessage> msg) const
{
    return make_shared<TCPSocketMessage>(std::dynamic_pointer_cast<const TCPSocketMessage>(msg));
}

//------------------------------------------------------------------------------------------------------

TCPSocketMessage::TCPSocketMessage(const shared_ptr<const TCPSocketMessage> msg)
    : SocketMessage(msg->getSessionHandler())
    , m_vect(msg->m_vect)
{ }

TCPSocketMessage::TCPSocketMessage(const shared_ptr<const SessionHandler> session_handler)
    : SocketMessage(session_handler)
{ }

uint64_t TCPSocketMessage::size() const
{
    return m_vect.size();
}

TCPSocketMessage::operator const uint8_t*() const
{
    return m_vect.data();
}

TCPSocketMessage::operator uint8_t*()
{
    return m_vect.data();
}

void TCPSocketMessage::resize(const uint32_t size)
{
    m_vect.resize(size, 0);
}
