#include "UDP.h"

#include <iostream>         //cout

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::dynamic_pointer_cast;

UDPSessionHandler::UDPSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address)
    : SessionHandler(socket_handler, peer_address)
{ }

void UDPSessionHandler::onNewMessage(const shared_ptr<const SocketMessage> msg_in)
{
    auto msg = dynamic_pointer_cast<const UDPSocketMessage>(msg_in);
    auto handler = dynamic_pointer_cast<const UDPSocketHandler>(getSocketHandler());

    if(msg && handler)
    {
        cout << dec << "@ " << (handler->getProtocol() == IPPROTO_TCP ? "TCP" : "UDP") << " socket = " << handler->getSocket()
            << " => @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port)
            << ", " << msg->size() << " Bytes received" << endl;

        const_pointer_cast<UDPSocketHandler>(handler)->sendMsg(msg);     // test echo
    }
}

//----------------------------------------------------------------------------------------------------------------

UDPSocketHandler::UDPSocketHandler( const uint16_t binding_port)
    : SocketHandler(binding_port, IPPROTO_UDP, 1374, 1374, 0)
{ }

UDPSocketHandler::UDPSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler)
    : SocketHandler(socket, master_handler)
{ /*USELESS TCP INTERFACE*/ }

const shared_ptr<SocketHandler> UDPSocketHandler::makeSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler) const
{ 
    return make_shared<UDPSocketHandler>(socket, master_handler);
}

const shared_ptr<SessionHandler> UDPSocketHandler::makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address)
{
    return make_shared<UDPSessionHandler>(socket_handler, peer_address);
}

const shared_ptr<SocketMessage> UDPSocketHandler::makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const
{
    return make_shared<UDPSocketMessage>(session_handler);
}

//------------------------------------------------------------------------------------------------------

UDPSocketMessage::UDPSocketMessage(const shared_ptr<const SessionHandler> session_handler)
    : SocketMessage(session_handler)
{ }

uint64_t UDPSocketMessage::size() const
{
    return vect.size();
}

UDPSocketMessage::operator const uint8_t*() const
{
    return vect.data();
}

void UDPSocketMessage::push_back(const uint8_t value)
{ 
    vect.push_back(value);
}