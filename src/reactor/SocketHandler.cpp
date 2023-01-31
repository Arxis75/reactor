#include "SocketHandler.h"

#include <sys/epoll.h>
#include <fcntl.h>          //O_CLOEXEC
#include <netinet/tcp.h>    //TCP_KEEPCNT, TCP_KEEPIDLE, TCP_KEEPINTVL
#include <unistd.h>         //close socket
#include <string.h>         //memset
#include <assert.h>
#include <iostream>         //cout, EXIT_FAILURE, NULL
//#include <algorithm>

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::min;

//-----------------------------------------------------------------------------------------------------------

SocketHandlerMessage::SocketHandlerMessage(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address)
    : m_socket_handler(socket_handler)
    , m_peer_address(peer_address)
{ }

const std::shared_ptr<const SocketHandler> SocketHandlerMessage::getSocketHandler() const
{ 
    if( const std::shared_ptr<const SocketHandler> spt_handler = m_socket_handler.lock() )
        return spt_handler;
    else
        return shared_ptr<const SocketHandler>(nullptr);
}

//-----------------------------------------------------------------------------------------------------------

SessionManager::SessionManager()
{ }

void SessionManager::start(const uint16_t master_port, const int master_protocol)
{          
    std::shared_ptr<SocketHandler> master_socket_handler = std::make_shared<SocketHandler>(shared_from_this(), master_port, master_protocol);
    master_socket_handler->start();
}

//-----------------------------------------------------------------------------------------------------------

SocketHandler::SocketHandler(const shared_ptr<const SessionManager> mgr, const uint16_t port, const int protocol)
    : m_socket(0)
    , m_protocol(protocol)
    , m_is_listening_socket(protocol == IPPROTO_TCP ? true : false)
    , m_session_manager(mgr)
{
    bindSocket(port);

    if(protocol == IPPROTO_TCP)
        assert( !listen(m_socket, CONNECTION_BACKLOG_SIZE) );
}

SocketHandler::SocketHandler(const shared_ptr<const SessionManager> mgr, const int socket)
    : m_socket(socket)
    , m_protocol(IPPROTO_TCP)
    , m_is_listening_socket(false)
    , m_session_manager(mgr)
{ }

int SocketHandler::bindSocket(const uint16_t port)
{
    struct sockaddr_in address;

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;  
    address.sin_port = htons(port); 

    //TODO: handle error codes
    assert( m_socket = socket(AF_INET , (m_protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM), 0) );

    // Set to non-blocking
    assert( !fcntl(m_socket, F_SETFL, O_NONBLOCK) );

    // Or use SO_LINGER with timeout 0 ?
    int optval = 1;
    assert( !setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) );
    
    if( bind(m_socket, (struct sockaddr *)&address, sizeof(address)) && (errno==EADDRINUSE) )
    {
        cout << "Port " << port  << " is already in use!" << endl;
        exit(0);
    }   

    return 0;
}

int SocketHandler::acceptConnection() const
{
    struct sockaddr_in peer_address;
    socklen_t len = sizeof(peer_address);
    int new_socket = accept(m_socket, (struct sockaddr *)&peer_address, &len);

    // the errno conditions handle the exceptional case where
    // the fd was announced ready and the socket operation would hang
    assert(new_socket > 0 || errno == EWOULDBLOCK || errno == EAGAIN);

    if(new_socket > 0)
    {
        // Set to non-blocking
        assert( !fcntl(new_socket, F_SETFL, O_NONBLOCK) );

        //sets the KEEP_ALIVE params
        int optval = 1;
        int keepcnt = 2;            // default: 9 probes
        int keepidle = 30;          // default: 7200s = 2h before first probe
        int keepintvl = 10;         // default: 75s between probes
        assert( !setsockopt(new_socket, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(int)) );
        assert( !setsockopt(new_socket, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(int)) );
        assert( !setsockopt(new_socket, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(int)) );
        assert( !setsockopt(new_socket, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(int)) );
        return new_socket;
    }
    return 0;
}

int SocketHandler::handleEvent(const struct epoll_event& event)
{
    uint32_t ev = event.events;
    if( (ev & EPOLLRDHUP) || (ev & EPOLLHUP) || (ev & EPOLLERR) )
    {
        cout << "Socket " << m_socket << " is closing." << endl;

        Initiation_Dispatcher::GetInstance().removeHandler(m_socket);
        close(m_socket);
    }
    else
    {
        if(ev & EPOLLIN)
        {
            if( m_is_listening_socket )
            {
                if( int m_connected_socket = acceptConnection() )
                {
                    // Create a connected socket Handler
                    shared_ptr<SocketHandler> handler = make_shared<SocketHandler>(m_session_manager, m_connected_socket);
                    handler->start();

                    struct sockaddr_in peer_address;
                    socklen_t len = sizeof(peer_address);
                    assert( !getpeername (handler->getSocket(), (struct sockaddr *)&peer_address , &len ) );
                    cout << "@" << inet_ntoa(peer_address.sin_addr) << ":" << ntohs(peer_address.sin_port)
                         << " TCP socket = " << handler->getSocket() << " connected." << endl;
                }
            }
            else
            {
                char buffer[READ_BUFFER_SIZE];
                struct sockaddr_in peer_address;
                socklen_t len = sizeof(peer_address);
                int nbytes_read;

                memset(buffer, 0, sizeof(buffer));  //Is it usefull?

                if( m_protocol == IPPROTO_UDP )
                {                   
                    while( true )
                    {
                        nbytes_read = recvfrom(m_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&peer_address, &len );

                        if( nbytes_read == 0 || (nbytes_read == -1 && (errno==EAGAIN)) )
                            break;
                        else if( nbytes_read == -1 )
                            cout << "ERROR: SOCKET " << m_socket << " READ ERROR!" << endl;

                        if( nbytes_read > 0)
                        {   
                            //we have a new udp datagram
                            auto msg = make_shared<SocketHandlerMessage>(SocketHandlerMessage(shared_from_this(), peer_address));
                            for(int i=0;i<nbytes_read;i++)
                                msg->data().push_back(*reinterpret_cast<uint8_t*>(&buffer[i]));

                            //enqueue the datagram
                            // We make the assumption here that the read buffer size is big
                            // enough to contain the largest message
                            const_pointer_cast<SessionManager>(m_session_manager)->onNewMessage(msg);
                        }
                    }
                }
                else
                {
                    //Beginning of a new tcp stream
                    assert( !getpeername (m_socket , (struct sockaddr *)&peer_address , &len ));    //Is it usefull?
                    auto msg = make_shared<SocketHandlerMessage>(SocketHandlerMessage(shared_from_this(), peer_address));

                    while( true )
                    {
                        nbytes_read = recv(m_socket, buffer, sizeof(buffer), 0);

                        if( nbytes_read > 0)
                        {   
                            //pushes more packets of the same msg
                            for(int i=0;i<nbytes_read;i++)
                                msg->data().push_back(*reinterpret_cast<uint8_t*>(&buffer[i]));
                        }
                        else if( nbytes_read == 0 || (nbytes_read == -1 && (errno==EAGAIN)) )
                            break;
                        else if( nbytes_read == -1 )
                            cout << "ERROR: SOCKET " << m_socket << " READ ERROR!" << endl;
                    }

                    //enqueue the message
                    const_pointer_cast<SessionManager>(m_session_manager)->onNewMessage(msg);
                }
            }
        }

        if(ev & EPOLLOUT)
        {
            char buffer[WRITE_BUFFER_SIZE];
            
            memset(buffer, 0, sizeof(buffer));

            if( !m_egress.size())
            {
                cout << dec << "@ " << (m_protocol == IPPROTO_TCP ? "TCP" : "UDP") << " socket = " << m_socket 
                     << " ready for sending" << endl;
            }
            else
            {
                while( m_egress.size() )
                {
                    shared_ptr<const SocketHandlerMessage> msg = m_egress.dequeue();
                    
                    cout << dec << "@ " << (m_protocol == IPPROTO_TCP ? "TCP" : "UDP") << " socket = " << m_socket
                         << " => @" << inet_ntoa(msg->getPeerAddress().sin_addr) << ":" << ntohs(msg->getPeerAddress().sin_port)
                         << ", " << msg->data().size() << " Bytes requested to be sent" << endl;

                    size_t nbytes_sent = 0, already_sent = 0;
                    if( m_protocol == IPPROTO_UDP )
                    {
                        // Asserts here that the UDP buffer is large enough to send the whole datagramm
                        // Big datagrams are not recommended because there is no way to recover
                        // lost packets from the datagram fragmentation at IP level by the MTU.
                        size_t send_size =  msg->data().size();
                        assert(send_size <= sizeof(buffer));
                        
                        memcpy(buffer, &msg->data()[0], send_size);
                        
                        struct sockaddr_in peer_address = msg->getPeerAddress();
                        socklen_t len = sizeof(peer_address);
                        nbytes_sent = sendto(m_socket, buffer, send_size, 0, (const struct sockaddr *)&peer_address, len );
                        already_sent = nbytes_sent;
                    }
                    else
                    {
                        while( already_sent < msg->data().size() )
                        {
                            size_t send_size =  min(msg->data().size() - already_sent, sizeof(buffer));
                            memcpy(buffer, &msg->data()[already_sent], send_size);

                            nbytes_sent = send(m_socket, buffer, send_size, 0);

                            if( nbytes_sent > 0 )    
                                already_sent += nbytes_sent;
                            else if( nbytes_sent == 0 || (nbytes_sent == -1 && (errno==EAGAIN)) )
                                break;
                            else if( nbytes_sent == -1 )
                                cout << "ERROR: SOCKET " << m_socket << " READ ERROR!" << endl;
                        }
                    }

                    cout << dec << "@ " << (m_protocol == IPPROTO_TCP ? "TCP" : "UDP") << " socket = " << m_socket
                         << " => @" << inet_ntoa(msg->getPeerAddress().sin_addr) << ":" << ntohs(msg->getPeerAddress().sin_port)
                         << ", " << already_sent << " Bytes sent" << endl;
                }
            }
        }
    }
    return 0;
}

void SocketHandler::start()
{
    // Register with the dispatcher for edge-triggered events.
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN|EPOLLET;
    if(m_protocol == IPPROTO_UDP)
        ev.events |= EPOLLOUT;              //for UDP master socket
    if(!m_is_listening_socket)
        ev.events |= EPOLLOUT|EPOLLRDHUP;   //for TCP connected socket
    ev.data.fd = m_socket;
    Initiation_Dispatcher::GetInstance().registerHandler(shared_from_this(), ev);
}