#include "SocketHandler.h"

#include <sys/epoll.h>
#include <fcntl.h>          //O_CLOEXEC
#include <netinet/tcp.h>    //TCP_KEEPCNT, TCP_KEEPIDLE, TCP_KEEPINTVL
#include <unistd.h>         //close socket
#include <string.h>         //memset
#include <assert.h>
#include <iostream>         //cout, EXIT_FAILURE, NULL

using std::cout;
using std::endl;

#define CONNECTION_BACKLOG_SIZE 10
#define READ_BUFFER_SIZE 1024

SocketHandler::SocketHandler(const uint16_t port, const int protocol)
    : m_protocol(protocol)
    , m_socket(0)
    , m_delete_on_close(false)
{
    bindSocket(port);

    if(m_protocol == IPPROTO_TCP)
        assert( !listen(m_socket, CONNECTION_BACKLOG_SIZE) );

    cacheLocalAddress();
    registerHandler();
}

SocketHandler::SocketHandler(const int socket)
    : m_protocol(IPPROTO_TCP)
    , m_socket(socket)
    , m_delete_on_close(true)
{
    cacheLocalAddress();
    cacheRemoteAddress();
    registerHandler();

    cout << "@" << inet_ntoa(m_peer_address.sin_addr) << ":" << ntohs(m_peer_address.sin_port)
         << " (socket = " << m_socket << ") connected." << endl;
}

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
    
    assert( !bind(m_socket, (struct sockaddr *)&address, sizeof(address)) );

    return 0;
}

int SocketHandler::acceptConnection()
{
    socklen_t len = sizeof(m_peer_address);
    int new_socket = accept(m_socket, (struct sockaddr *)&m_peer_address, &len);

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

int SocketHandler::handleEvent(const struct epoll_event event)
{
    uint32_t ev = event.events;
    if( (ev & EPOLLRDHUP) || (ev & EPOLLHUP) || (ev & EPOLLERR) )
    {
        Initiation_Dispatcher::GetInstance().remove_handler(m_socket);
        
        cout << "Socket " << m_socket << " is closing." << endl;
        
        close(m_socket);
        if(m_delete_on_close)
            delete this;
    }
    else
    {
        if(ev & EPOLLIN)
        {
            if( m_protocol == IPPROTO_TCP && !m_delete_on_close )   //master TCP socket
            {
                if( int m_connected_socket = acceptConnection() )
                {
                    // Create a new Logging Handler.
                    SocketHandler *handler = new SocketHandler(m_connected_socket);
                }
            }
            else
            {
                char buffer[READ_BUFFER_SIZE];
                memset(buffer, 0, sizeof(buffer));

                while( true )
                {
                    int nbytes_read;
                    if( m_protocol == IPPROTO_UDP )
                    {
                        //stores remote address infos
                        socklen_t len = sizeof(m_peer_address);
                        nbytes_read = recvfrom(m_socket, buffer, 1024, 0, (struct sockaddr *)&m_peer_address, &len );
                    }
                    else
                        nbytes_read = recv(m_socket, buffer, 1024, 0);

                    if( nbytes_read == -1 && (errno==EAGAIN) )
                        break;
                    else
                    {
                        cout << "@" << inet_ntoa(m_peer_address.sin_addr) << ":" << ntohs(m_peer_address.sin_port)
                            << " => @" << inet_ntoa(m_local_address.sin_addr) << ":" << ntohs(m_local_address.sin_port)
                            << " (socket = " << m_socket << "), " << nbytes_read << " Bytes received" << endl;
                        cout << buffer << endl;
                        memset(buffer, 0, sizeof(buffer));
                    }
                }
            }
        }

        if(ev & EPOLLOUT)
            cout << "@" << inet_ntoa(m_local_address.sin_addr) << ":" << ntohs(m_local_address.sin_port)
                 << " (socket = " << m_socket << ") ready for sending" << endl;
   }
    return 0;
}

int SocketHandler::cacheLocalAddress()
{
    //stores local address infos
    socklen_t len = sizeof(m_local_address);
    assert( !getsockname(m_socket, (struct sockaddr *)&m_local_address, &len) );
    return 0;
}

int SocketHandler::cacheRemoteAddress()
{
    //stores remote address infos
    socklen_t len = sizeof(m_peer_address);
    assert( !getpeername (m_socket , (struct sockaddr *)&m_peer_address , &len ) );
    return 0;
}

void SocketHandler::registerHandler()
{
    // Register with the dispatcher for edge-triggered events.
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN|EPOLLET;
    if(m_protocol == IPPROTO_UDP)
        ev.events |= EPOLLOUT;              //for UDP master socket
    else if(m_delete_on_close)
        ev.events |= EPOLLOUT|EPOLLRDHUP;   //for TCP connected socket
    ev.data.ptr = (void*)this;
    Initiation_Dispatcher::GetInstance().register_handler(ev);
}