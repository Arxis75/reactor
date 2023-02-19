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
    auto msg = dynamic_pointer_cast<const TCPSocketMessage>(msg_in);
    auto handler = dynamic_pointer_cast<const TCPSocketHandler>(getSocketHandler());

    if(msg && handler)
    {
        cout << dec << "@ " << (handler->getProtocol() == IPPROTO_TCP ? "TCP" : "TCP") << " socket = " << handler->getSocket()
            << " => @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port)
            << ", " << msg->size() << " Bytes received" << endl;

        const_pointer_cast<TCPSocketHandler>(handler)->sendMsg(msg);     // test echo
    }
}

//----------------------------------------------------------------------------------------------------------------

TCPSocketHandler::TCPSocketHandler( const uint16_t binding_port)
    : SocketHandler(binding_port, IPPROTO_TCP, 4096, 4096, 10)
{ }

TCPSocketHandler::TCPSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler)
    : SocketHandler(socket, master_handler)
{ }

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

//------------------------------------------------------------------------------------------------------

TCPSocketMessage::TCPSocketMessage(const shared_ptr<const SessionHandler> session_handler)
    : SocketMessage(session_handler)
{ }

uint64_t TCPSocketMessage::size() const
{
    return vect.size();
}

TCPSocketMessage::operator const uint8_t*() const
{
    return vect.data();
}

TCPSocketMessage::operator uint8_t*()
{
    return vect.data();
}

void TCPSocketMessage::resize(const uint32_t size)
{
    vect.resize(size, 0);
}
