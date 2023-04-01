#include "UDP.h"

#include <iostream>         //cout

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::dynamic_pointer_cast;

UDPSessionHandler::UDPSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const vector<uint8_t> &session_key, const struct sockaddr_in &peer_address)
    : SessionHandler(socket_handler, session_key, peer_address)
{ }

void UDPSessionHandler::onNewMessage(const shared_ptr<const SocketMessage> msg_in)
{
    msg_in->print();

    // test echo
    if( auto server = getSocketHandler() )
    {
        // Building from this session:
        //auto msg_out = make_shared<UDPSocketMessage>(shared_from_this());
        //msg_out->push_back(*msg_in.get());
        //sendMessage(msg_out);

        // Building raw Message:
        auto msg_out = make_shared<const UDPSocketMessage>(server, *msg_in.get(), msg_in->getPeerAddress(), false);
        msg_out->print();
        const_pointer_cast<SocketHandler>(server)->sendMsg(msg_out);
    }
}

void UDPSessionHandler::sendMessage(const shared_ptr<const SocketMessage> msg_out)
{
    msg_out->print();

    SessionHandler::sendMessage(msg_out);
}

//----------------------------------------------------------------------------------------------------------------

UDPSocketHandler::UDPSocketHandler( const uint16_t binding_port)
    : SocketHandler(binding_port, IPPROTO_UDP, 1374, 1374, 0)
{ }

const shared_ptr<SessionHandler> UDPSocketHandler::makeSessionHandler(const vector<uint8_t> &session_key, const struct sockaddr_in &peer_address)
{
    return make_shared<UDPSessionHandler>(shared_from_this(), session_key, peer_address);
}

const shared_ptr<SocketMessage> UDPSocketHandler::makeSocketMessage(const vector<uint8_t> buffer, const struct sockaddr_in &peer_address) const
{
    return make_shared<UDPSocketMessage>(shared_from_this(), buffer, peer_address);
}

//------------------------------------------------------------------------------------------------------

UDPSocketMessage::UDPSocketMessage(const shared_ptr<const SocketHandler> handler, const vector<uint8_t> buffer, const struct sockaddr_in &peer_addr, const bool is_ingress)
    : SocketMessage(handler, buffer, peer_addr, is_ingress)
{ }

UDPSocketMessage::UDPSocketMessage(const shared_ptr<const SessionHandler> session_handler)
    : SocketMessage(session_handler)
{ }

void UDPSocketMessage::print() const
{
    cout << "UDP: "<< (isIngress() ? "RECEIVING " : "SENDING ") << dec << size() << " Bytes " << (isIngress() ? "FROM" : "TO") << " @"
         << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port);
    if( auto socket = getSocketHandler() )
        cout << " (socket = " << socket->getSocket() << ")";
    cout << endl;
}