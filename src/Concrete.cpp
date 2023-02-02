#include "Concrete.h"

#include <iostream>         //cout

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::dynamic_pointer_cast;

ConcreteSessionHandler::ConcreteSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address)
    : SessionHandler(socket_handler, peer_address)
{ }

void ConcreteSessionHandler::onNewMessage(const shared_ptr<const SocketMessage> msg_in)
{
    auto msg = dynamic_pointer_cast<const ConcreteSocketMessage>(msg_in);
    auto handler = dynamic_pointer_cast<const ConcreteSocketHandler>(getSocketHandler());

    if(msg && handler)
    {
        cout << dec << "@ " << (handler->getProtocol() == IPPROTO_TCP ? "TCP" : "UDP") << " socket = " << handler->getSocket()
            << " => @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port)
            << ", " << msg->size() << " Bytes received" << endl;

        const_pointer_cast<ConcreteSocketHandler>(handler)->sendMsg(msg);     // echo
    }
}

//----------------------------------------------------------------------------------------------------------------

ConcreteSocketHandler::ConcreteSocketHandler(const uint16_t binding_port, const int protocol,
                                             const int read_buffer_size, const int write_buffer_size,
                                             const int tcp_connection_backlog_size)
    : SocketHandler(binding_port, protocol, read_buffer_size, write_buffer_size, tcp_connection_backlog_size)
{ }

ConcreteSocketHandler::ConcreteSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler)
    : SocketHandler(socket, master_handler)
{ }

const shared_ptr<SocketHandler> ConcreteSocketHandler::makeSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler) const
{ 
    return make_shared<ConcreteSocketHandler>(socket, master_handler);
}

const shared_ptr<SessionHandler> ConcreteSocketHandler::makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address)
{
    return make_shared<ConcreteSessionHandler>(socket_handler, peer_address);
}

const shared_ptr<SocketMessage> ConcreteSocketHandler::makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const
{
    return make_shared<ConcreteSocketMessage>(session_handler);
}

//------------------------------------------------------------------------------------------------------

ConcreteSocketMessage::ConcreteSocketMessage(const shared_ptr<const SessionHandler> session_handler)
    : SocketMessage(session_handler)
{ }

uint64_t ConcreteSocketMessage::size() const
{
    return vect.size();
}

ConcreteSocketMessage::operator const uint8_t*() const
{
    return vect.data();
}

void ConcreteSocketMessage::push_back(const uint8_t value)
{ 
    vect.push_back(value);
}