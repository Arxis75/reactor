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
    msg_in->print();

    // test echo
    if( auto server = getSocketHandler() )
    {
        // Building Session-full Message:
        //auto msg_out = make_shared<UDPSocketMessage>(shared_from_this());
        //msg_out->push_back(*msg_in.get());
        //sendMessage(msg_out);

        // Building Session-less Message:
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

const shared_ptr<SessionHandler> UDPSocketHandler::makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id)
{
    return make_shared<UDPSessionHandler>(socket_handler, peer_address, peer_id);
}

const shared_ptr<SocketMessage> UDPSocketHandler::makeSocketMessage(const shared_ptr<const SocketHandler> handler, const vector<uint8_t> buffer, const struct sockaddr_in &peer_addr) const
{
    return make_shared<UDPSocketMessage>(handler, buffer, peer_addr);
}

const vector<uint8_t> UDPSocketHandler::makeSessionKey(const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id) const
{
    vector<uint8_t> key;
    key.resize(peer_id.size() + 6);
    if( peer_id.size() )
        memcpy(&key[0], &peer_id[0], peer_id.size());
    memcpy(&key[peer_id.size()], &peer_address.sin_addr.s_addr, 4);
    memcpy(&key[peer_id.size() + 4], &peer_address.sin_port, 2);
    return key;
}

//------------------------------------------------------------------------------------------------------

UDPSocketMessage::UDPSocketMessage(const shared_ptr<const SocketHandler> handler, const vector<uint8_t> buffer, const struct sockaddr_in &peer_addr, const bool is_ingress)
    : SocketMessage(handler, buffer, peer_addr, is_ingress)
{ 
    m_peer_ID = {{0}};
}

UDPSocketMessage::UDPSocketMessage(const shared_ptr<const SessionHandler> session_handler)
    : SocketMessage(session_handler)
{ 
    m_peer_ID = {{0}};
}

void UDPSocketMessage::print() const
{
    cout << "UDP: "<< (isIngress() ? "RECEIVING " : "SENDING ") << dec << size() << " Bytes " << (isIngress() ? "FROM" : "TO") << " @"
         << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port)
         << ", Peer ID = " << hex << (int)getPeerID()[0];
    if( auto socket = getSocketHandler() )
        cout << " (socket = " << socket->getSocket() << ")";
    cout << endl;
}