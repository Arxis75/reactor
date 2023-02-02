#include "Concrete.h"

#include <iostream>         //cout

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::min;

ConcreteSessionHandler::ConcreteSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address)
    : SessionHandler(socket_handler, peer_address)
{ }

void ConcreteSessionHandler::onNewMessage(const shared_ptr<const SocketMessage> msg_in)
{
    auto handler = getSocketHandler();
    if(handler)
    {
        cout << dec << "@ " << (handler->getProtocol() == IPPROTO_TCP ? "TCP" : "UDP") << " socket = " << handler->getSocket()
            << " => @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port)
            << ", " << msg_in->size() << " Bytes received" << endl;

        const_pointer_cast<SocketHandler>(handler)->sendMsg(msg_in);     // echo
    }
}

//----------------------------------------------------------------------------------------------------------------

ConcreteSocketHandler::ConcreteSocketHandler(const string &ip, const uint16_t port, const int protocol,
                                             const int read_buffer_size, const int write_buffer_size,
                                             const int tcp_connection_backlog_size)
    : SocketHandler(ip, port, protocol, read_buffer_size, write_buffer_size, tcp_connection_backlog_size)
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

ConcreteSocketMessage::operator uint8_t*() const
{
    return const_cast<uint8_t*>(vect.data());
}

void ConcreteSocketMessage::push_back(uint8_t value)
{ 
    vect.push_back(value);
}