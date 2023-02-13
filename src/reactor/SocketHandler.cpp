#include "SocketHandler.h"

#include <sys/epoll.h>
#include <fcntl.h>          //O_CLOEXEC
#include <netinet/tcp.h>    //TCP_KEEPCNT, TCP_KEEPIDLE, TCP_KEEPINTVL
#include <unistd.h>         //close socket
#include <string.h>         //memset
#include <assert.h>
#include <iostream>         //cout, EXIT_FAILURE, NULL
#include <algorithm>

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::min;

//-----------------------------------------------------------------------------------------------------------

SocketMessage::SocketMessage(const shared_ptr<const SessionHandler> session_handler)
    : m_session_handler(session_handler)
{ }

const shared_ptr<const SessionHandler> SocketMessage::getSessionHandler() const
{
    if( const std::shared_ptr<const SessionHandler> handler = m_session_handler.lock() )
        return handler;
    else
        return shared_ptr<const SessionHandler>(nullptr);
}

//-----------------------------------------------------------------------------------------------------------

SessionHandler::SessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address)
    : m_socket_handler(socket_handler)
    , m_peer_address(peer_address)
{ }

const std::shared_ptr<const SocketHandler> SessionHandler::getSocketHandler() const
{
    if( const std::shared_ptr<const SocketHandler> handler = m_socket_handler.lock() )
        return handler;
    else
        return shared_ptr<const SocketHandler>(nullptr); 
}

void SessionHandler::close() const
{
    auto handler = getSocketHandler();
    if( handler )
        const_pointer_cast<SocketHandler>(handler)->removeSessionHandler(getPeerAddress());
}

//-----------------------------------------------------------------------------------------------------------

SocketHandler::SocketHandler(const uint16_t binding_port, const int protocol,
                             const int read_buffer_size, const int write_buffer_size,
                             const int tcp_connection_backlog_size)
    : m_socket(0)
    , m_binding_port(binding_port)
    , m_protocol(protocol)
    , m_read_buffer_size(read_buffer_size)
    , m_write_buffer_size(write_buffer_size)
    , m_tcp_connection_backlog_size(tcp_connection_backlog_size)
    , m_is_listening_socket(protocol == IPPROTO_TCP ? true : false)
{
    bindSocket(m_binding_port);

    if(protocol == IPPROTO_TCP)
        assert( !listen(m_socket, m_tcp_connection_backlog_size) );
}

SocketHandler::SocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler)
    : m_socket(socket)
    , m_binding_port(master_handler->m_binding_port)
    , m_protocol(master_handler->m_protocol)
    , m_read_buffer_size(master_handler->m_read_buffer_size)
    , m_write_buffer_size(master_handler->m_write_buffer_size)
    , m_tcp_connection_backlog_size(master_handler->m_tcp_connection_backlog_size)
    , m_is_listening_socket(false)
{ }

SocketHandler::~SocketHandler()
{
    // Release the kernel socket
    close(m_socket);
}

int SocketHandler::bindSocket(const uint16_t port)
{
    struct sockaddr_in address;

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port); 

    //TODO: handle error codes
    assert( m_socket = socket(AF_INET , (m_protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM), 0) );

    // Set to non-blocking
    assert( !fcntl(m_socket, F_SETFL, O_NONBLOCK) );

    if( m_protocol == IPPROTO_TCP )
    {
        // Or use SO_LINGER with timeout 0 ?
        int optval = 1;
        assert( !setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) );
    }

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
        if( !isBlacklisted(peer_address) )
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
        else
            //Close the socket before any session creation
            close(new_socket);
    }
    return 0;
}

int SocketHandler::handleEvent(const struct epoll_event& event)
{
    uint32_t ev = event.events;
    if( (ev & EPOLLRDHUP) || (ev & EPOLLHUP) || (ev & EPOLLERR) )
        stop();
    else
    {
        if(ev & EPOLLIN)
        {
            if( m_is_listening_socket )
            {
                if( int connected_socket = acceptConnection() )
                {
                    struct sockaddr_in peer_address;
                    socklen_t len = sizeof(peer_address);
                    assert( !getpeername (connected_socket, (struct sockaddr *)&peer_address , &len ) );

                    auto socket_handler = makeSocketHandler(connected_socket, shared_from_this());
                    socket_handler->start();
                }
            }
            else
            {
                char buffer[m_read_buffer_size];
                struct sockaddr_in peer_address;
                socklen_t len = sizeof(peer_address);
                ssize_t nbytes_read;

                memset(buffer, 0, sizeof(buffer));  //Is it usefull?

                if( m_protocol == IPPROTO_UDP )
                {                   
                    while( true )
                    {
                        nbytes_read = recvfrom(m_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&peer_address, &len );

                        if( nbytes_read > 0)
                        {
                            if( isBlacklisted(peer_address) )
                                removeSessionHandler(peer_address);
                            else
                            {
                                //we have a new udp datagram
                                auto session = getSessionHandler(peer_address);
                                if(!session)
                                    session = registerSessionHandler(peer_address);
                                auto msg = makeSocketMessage(session);
                                for(int i=0;i<nbytes_read;i++)
                                    msg->push_back(*reinterpret_cast<uint8_t*>(&buffer[i]));

                                //enqueue the datagram
                                // We make the assumption here that the read buffer size is big
                                // enough to contain the largest message, i.e. 1 datagram = 1 msg
                                const_pointer_cast<SessionHandler>(session)->onNewMessage(msg);
                            }
                        }
                        else if( nbytes_read == 0 )
                            break;
                        else if( nbytes_read == -1)
                        {
                            if( errno !=EAGAIN )
                                cout << "Error: socket " << m_socket << " read error..." << endl;
                            break;
                        }
                    }
                }
                else
                {
                    //Beginning of a new TCP stream
                    assert( !getpeername (m_socket , (struct sockaddr *)&peer_address , &len ));
                    auto session = getSessionHandler(peer_address);
                    if(!session)
                        session = registerSessionHandler(peer_address);
                    auto msg = makeSocketMessage(session);

                    while( true )
                    {
                        nbytes_read = recv(m_socket, buffer, sizeof(buffer), 0);

                        if( nbytes_read > 0)
                        {   
                            //pushes more packets of the same msg
                            for(int i=0;i<nbytes_read;i++)
                                msg->push_back(*reinterpret_cast<uint8_t*>(&buffer[i]));
                        }
                        else if( nbytes_read == 0 )
                            break;
                        else if( nbytes_read == -1 )
                        {
                            if( errno != EAGAIN )
                                cout << "Error: socket " << m_socket << " read error..." << endl;
                            break;
                        }
                    }

                    //enqueue the message
                    const_pointer_cast<SessionHandler>(session)->onNewMessage(msg);
                }
            }
        }

        if(ev & EPOLLOUT)
        {
            char buffer[m_write_buffer_size];
            
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
                    shared_ptr<const SocketMessage> msg = m_egress.dequeue();
                    auto session = msg->getSessionHandler();
                    if( session )
                    {
                        cout << dec << "@ " << (m_protocol == IPPROTO_TCP ? "TCP" : "UDP") << " socket = " << m_socket
                            << " => @" << inet_ntoa(session->getPeerAddress().sin_addr)
                            << ":" << ntohs(session->getPeerAddress().sin_port)
                            << ", " << msg->size() << " Bytes requested to be sent" << endl;

                        ssize_t nbytes_sent = 0, already_sent = 0;
                        if( m_protocol == IPPROTO_UDP )
                        {
                            // Asserts here that the UDP buffer is large enough to send the whole datagramm
                            // Big datagrams are not recommended because there is no way to recover
                            // lost packets from the datagram fragmentation at IP level by the MTU.
                            size_t send_size =  msg->size();
                            assert(send_size <= sizeof(buffer));
                            
                            memcpy(buffer, &(*msg)[0], send_size);
                            
                            struct sockaddr_in peer_address = session->getPeerAddress();
                            socklen_t len = sizeof(peer_address);
                            nbytes_sent = sendto(m_socket, buffer, send_size, MSG_NOSIGNAL, (const struct sockaddr *)&peer_address, len );
                            already_sent = nbytes_sent;
                        }
                        else
                        {   //TCP:
                            while( already_sent < msg->size() )
                            {
                                size_t send_size =  min(msg->size() - already_sent, sizeof(buffer));
                                memcpy(buffer, &(*msg)[already_sent], send_size);

                                nbytes_sent = send(m_socket, buffer, send_size, MSG_NOSIGNAL);

                                if( nbytes_sent > 0 )    
                                    already_sent += nbytes_sent;
                                else if( nbytes_sent == 0 )
                                    break;
                                else if( nbytes_sent == -1 && (errno!=EAGAIN) )
                                {
                                    cout << "Error: socket " << m_socket << " write error..." << endl;
                                    break;
                                }
                            }
                        }

                        cout << dec << "@ " << (m_protocol == IPPROTO_TCP ? "TCP" : "UDP") << " socket = " << m_socket
                            << " => @" << inet_ntoa(session->getPeerAddress().sin_addr)
                            << ":" << ntohs(session->getPeerAddress().sin_port)
                            << ", " << already_sent << " Bytes sent" << endl;
                    }
                }
            }
        }
    }
    return 0;
}

const uint64_t SocketHandler::makeKeyFromSockAddr(const struct sockaddr_in &addr) const
{
    return (addr.sin_addr.s_addr << 16) + addr.sin_port;
}

// Gets the session handler for a particular peer
const shared_ptr<const SessionHandler> SocketHandler::getSessionHandler(const struct sockaddr_in &addr) const
{
    uint64_t key = makeKeyFromSockAddr(addr);
    auto it = m_session_handler_list.find(key);
    if( it != std::end(m_session_handler_list) )
        return it->second;
    else
        return shared_ptr<const SessionHandler>(nullptr);
}

// Register an Session_Handler of a particular peer
const shared_ptr<const SessionHandler> SocketHandler::registerSessionHandler(const struct sockaddr_in &addr)
{
    uint64_t key = makeKeyFromSockAddr(addr);
    auto it = m_session_handler_list.find(key);
    if( it != std::end(m_session_handler_list) )
        return it->second;
    else
    {
        shared_ptr<SessionHandler> session_handler = makeSessionHandler(shared_from_this(), addr);
        auto inserted = m_session_handler_list.insert(make_pair(key, session_handler));
        return inserted.first->second;
    }
}

// Remove an Session_Handler of a particular peer.
void SocketHandler::removeSessionHandler(const struct sockaddr_in &addr)
{
    uint64_t key = makeKeyFromSockAddr(addr);
    m_session_handler_list.erase(key);
}

void SocketHandler::start()
{
    // Register with the dispatcher for edge-triggered events.
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN|EPOLLET;
    if(m_protocol == IPPROTO_UDP)
        ev.events |= EPOLLOUT;              //for UDP master socket
    else if(!m_is_listening_socket)
        ev.events |= EPOLLOUT|EPOLLRDHUP;   //for TCP connected socket
    ev.data.fd = m_socket;
    Initiation_Dispatcher::GetInstance().registerSocketHandler(shared_from_this(), ev);
}

void SocketHandler::stop()
{
    cout << "Socket " << m_socket << " is closing." << endl;

    // The removal from Initiation_Dispatcher detroys:
    // - the SessionHandler(s),
    // - the egress message(s) in its queue,
    // - the SocketHandler => close the kernel socket through the destructor
    Initiation_Dispatcher::GetInstance().removeSocketHandler(m_socket);
}

void SocketHandler::blacklist(const struct sockaddr_in &addr)
{
    if( !isBlacklisted(addr) )
        m_blacklisted_peers.push_back(makeKeyFromSockAddr(addr));
}
bool SocketHandler::isBlacklisted(const struct sockaddr_in &addr) const
{
    return find(m_blacklisted_peers.begin(), m_blacklisted_peers.end(), makeKeyFromSockAddr(addr)) != m_blacklisted_peers.end();
}
void SocketHandler::unblacklist(const struct sockaddr_in &addr)
{
    m_blacklisted_peers.erase(remove(m_blacklisted_peers.begin(), m_blacklisted_peers.end(), makeKeyFromSockAddr(addr)), m_blacklisted_peers.end());
}