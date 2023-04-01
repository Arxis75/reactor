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
    msg_in->print();

    // test echo
    if( auto server = getSocketHandler() )
    {
        // Building from this session:
        auto msg_out = make_shared<TCPSocketMessage>(shared_from_this());
        msg_out->push_back(*msg_in.get());
        sendMessage(msg_out);

        // Building raw Message:
        //auto msg_out = make_shared<const TCPSocketMessage>(server, *msg_in.get(), msg_in->getPeerAddress(), false);
        //msg_out->print();
        //const_pointer_cast<SocketHandler>(server)->sendMsg(msg_out);
    }
}

void TCPSessionHandler::sendMessage(const shared_ptr<const SocketMessage> msg_out)
{
    msg_out->print();

    SessionHandler::sendMessage(msg_out);
}

//----------------------------------------------------------------------------------------------------------------

TCPSocketHandler::TCPSocketHandler( const uint16_t binding_port)
    : SocketHandler(binding_port, IPPROTO_TCP, 4096, 4096, 0)
{ }

TCPSocketHandler::TCPSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler)
    : SocketHandler(socket, master_handler)
{ }

const shared_ptr<SocketHandler> TCPSocketHandler::makeSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler) const
{ 
    return make_shared<TCPSocketHandler>(socket, master_handler);
}

const shared_ptr<SessionHandler> TCPSocketHandler::makeSessionHandler(const struct sockaddr_in &peer_address)
{
    return make_shared<TCPSessionHandler>(shared_from_this(), peer_address);
}

const shared_ptr<SocketMessage> TCPSocketHandler::makeSocketMessage(const vector<uint8_t> buffer, const struct sockaddr_in &peer_address) const
{
    return make_shared<TCPSocketMessage>(shared_from_this(), buffer, peer_address);
}

//------------------------------------------------------------------------------------------------------

TCPSocketMessage::TCPSocketMessage(const shared_ptr<const SocketHandler> handler, const vector<uint8_t> buffer, const struct sockaddr_in &peer_addr, const bool is_ingress)
    : SocketMessage(handler, buffer, peer_addr, is_ingress)
{ }

TCPSocketMessage::TCPSocketMessage(const shared_ptr<const SessionHandler> session_handler)
    : SocketMessage(session_handler)
{ }

void TCPSocketMessage::print() const
{
    cout << "TCP: "<< (isIngress() ? "RECEIVING " : "SENDING ") << dec << size() << " Bytes " << (isIngress() ? "FROM" : "TO") << " @"
         << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port);
    if( auto socket = getSocketHandler() )
        cout << " (socket = " << socket->getSocket() << ")";
    cout << endl;
}
