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
    msg_in->print();

    // test echo
    if( auto server = getSocketHandler() )
    {
        // Building Session-full Message:
        auto msg_out = make_shared<TCPSocketMessage>(shared_from_this());
        msg_out->push_back(*msg_in.get());
        sendMessage(msg_out);

        // Building Session-less Message:
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

const shared_ptr<SessionHandler> TCPSocketHandler::makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id)
{
    return make_shared<TCPSessionHandler>(socket_handler, peer_address, peer_id);
}

const shared_ptr<SocketMessage> TCPSocketHandler::makeSocketMessage(const shared_ptr<const SocketHandler> handler, const vector<uint8_t> buffer, const struct sockaddr_in &peer_addr) const
{
    return make_shared<TCPSocketMessage>(handler, buffer, peer_addr);
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

TCPSocketMessage::TCPSocketMessage(const shared_ptr<const SocketHandler> handler, const vector<uint8_t> buffer, const struct sockaddr_in &peer_addr, const bool is_ingress)
    : SocketMessage(handler, buffer, peer_addr, is_ingress)
{ 
    m_peer_ID = {{0}};
}

TCPSocketMessage::TCPSocketMessage(const shared_ptr<const SessionHandler> session_handler)
    : SocketMessage(session_handler)
{ 
    m_peer_ID = {{0}};
}

void TCPSocketMessage::print() const
{
    cout << "TCP: "<< (isIngress() ? "RECEIVING " : "SENDING ") << dec << size() << " Bytes " << (isIngress() ? "FROM" : "TO") << " @"
         << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port)
         << ", Peer ID = " << hex << (int)getPeerID()[0];
    if( auto socket = getSocketHandler() )
        cout << " (socket = " << socket->getSocket() << ")";
    cout << endl;
}
