#include "Event_Handler.h"

#include <sys/epoll.h>      //EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLPRI|EPOLLET
#include <netinet/tcp.h>    //TCP_KEEPCNT, TCP_KEEPIDLE, TCP_KEEPINTVL
#include <unistd.h>         //close socket
#include <string.h>         //memset
#include <fcntl.h>          // fcntl, F_SETFL, O_NONBLOCK
#include <assert.h>
#include <errno.h>      //errno
#include <iostream>     //cout

using std::cout;
using std::endl;

#define CONNECTION_BACKLOG_SIZE 10
#define FD_READ_BUFFER_SIZE 1024

PeerHandler::PeerHandler(const int fd)
    : m_peer_socket(fd)
{
    socklen_t m_peer_address_length = sizeof(m_peer_address);
    assert( !getpeername (m_peer_socket , (struct sockaddr *)&m_peer_address , &m_peer_address_length ) );

    // Register with the dispatcher for edge-triggered events.
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLET;
    ev.data.ptr = (void*)this;
    Initiation_Dispatcher::GetInstance().register_handler(ev);
}

// Hook method that handles communication with clients.
int PeerHandler::handle_event(const struct epoll_event event)
{
    uint32_t ev = event.events;
    if( (ev & EPOLLRDHUP) || (ev & EPOLLHUP) || (ev & EPOLLERR) )
    {
        Initiation_Dispatcher::GetInstance().remove_handler(m_peer_socket);
        
        cout << "Socket: " << m_peer_socket << " has been closed." << endl;
        
        close(m_peer_socket);
        delete this;
    }
    else
    {
        if(ev & EPOLLIN)
        {
            char buffer[FD_READ_BUFFER_SIZE];
            memset(buffer, 0, sizeof(buffer));

            while( true )
            {
                int ret = recv(m_peer_socket, buffer, 1024, 0);
                if( ret == -1 && (errno==EAGAIN) )
                    break;
                else
                {
                    cout << "@" << inet_ntoa(m_peer_address.sin_addr) << ":" << ntohs(m_peer_address.sin_port) << " (socket = " << m_peer_socket << "), " << ret << " Bytes received" << endl;
                    cout << buffer << endl;
                    memset(buffer, 0, sizeof(buffer));
                }
            } 
        }
        
        if(ev & EPOLLOUT)
            cout << "@" << inet_ntoa(m_peer_address.sin_addr) << ":" << ntohs(m_peer_address.sin_port) << " (socket = " << m_peer_socket << ") ready for sending" << endl;
   }

    return 0;
}

PeerAcceptor::PeerAcceptor(const uint16_t port)
{
    int master_socket;
    struct sockaddr_in address;

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;  
    address.sin_port = htons(port); 

    //TODO: handle error codes
    assert( m_master_socket = socket(AF_INET , SOCK_STREAM , 0) );

    // Set to non-blocking
    assert( !fcntl(m_master_socket, F_SETFL, O_NONBLOCK) );

    // Or use SO_LINGER with timeout 0 ?
    int optval = 1;
    assert( !setsockopt(m_master_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) );
    
    assert( !bind(m_master_socket, (struct sockaddr *)&address, sizeof(address)) );
    
    assert( !listen(m_master_socket, CONNECTION_BACKLOG_SIZE) );

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = (void*)this;
    Initiation_Dispatcher::GetInstance().register_handler(ev);
}

// Factory method that accepts a new connection and creates a PeerHandler
int PeerAcceptor::handle_event(const struct epoll_event event)
{
    uint32_t ev = event.events;
    if(ev & EPOLLIN)
    {
        struct sockaddr_in clientaddr;
        socklen_t clientaddrlen = sizeof(clientaddr);
        int new_socket = accept(m_master_socket, (struct sockaddr *)&clientaddr, &clientaddrlen);

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

            cout << "@" << inet_ntoa(clientaddr.sin_addr) << ":" << ntohs(clientaddr.sin_port) << " (socket = " << new_socket << ") connected." << endl;

            // Create a new Logging Handler.
            PeerHandler *handler = new PeerHandler(new_socket);
        }
    }
    return 0;
}
