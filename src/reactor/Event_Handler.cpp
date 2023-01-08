#include "Event_Handler.h"

#include <netinet/tcp.h>    //TCP_KEEPCNT, TCP_KEEPIDLE, TCP_KEEPINTVL
#include <unistd.h>         //close socket
#include <string.h>         //memset
#include <fcntl.h>          // fcntl, F_SETFL, O_NONBLOCK
#include <assert.h>
#include <errno.h>      //errno
#include <iostream>     //cout

using std::cout;
using std::endl;

Discovery_PeerHandler::Discovery_PeerHandler(const int socket)
    : m_peer_socket(socket)
{
    socklen_t m_peer_address_length = sizeof(m_peer_address);
    assert( !getpeername (m_peer_socket , (struct sockaddr *)&m_peer_address , &m_peer_address_length ) );

    // Register with the dispatcher for READ/WRITE events.
    Initiation_Dispatcher::GetInstance().register_handler(this, READ_EVENT);
    Initiation_Dispatcher::GetInstance().register_handler(this, WRITE_EVENT);
    Initiation_Dispatcher::GetInstance().register_handler(this, EXCEPTION_EVENT);
}

// Hook method that handles communication with clients.
int Discovery_PeerHandler::handle_event(const Event_Type et)
{
    Event_Type ev = et;
    if(ev == READ_EVENT)
    {
        char buffer[1024];        // + 1 for the null char
        memset(buffer, 0, sizeof(buffer));
        int ret = recv(m_peer_socket, buffer, 1024, 0);

        // the errno conditions handle the exceptional case where
        // the fd was announced ready and the socket operation would hang
        assert(ret >= 0 || errno == EWOULDBLOCK || errno == EAGAIN);

        if( ret > 0 )
            cout << "@" << inet_ntoa(m_peer_address.sin_addr) << ":" << ntohs(m_peer_address.sin_port) << " (socket = " << m_peer_socket << "), receiving: " << buffer << endl;               
        else if( ret == -1 && (errno == EWOULDBLOCK || errno == EAGAIN) )
            //should be exceptionnal
            cout << "@" << inet_ntoa(m_peer_address.sin_addr) << ":" << ntohs(m_peer_address.sin_port) << ", socket " << m_peer_socket << " has error EWOULDBLOCK | EAGAIN!" << buffer << endl;                               
        else
            //if socket is in abnormal error or client hangs up
            ev = CLOSE_EVENT;
    }
    else if(ev == WRITE_EVENT)
    {
        //TODO
    }
    else if(ev == EXCEPTION_EVENT || ev == TIMEOUT_EVENT || ev == SIGNAL_EVENT)
    {
        //TODO
    }

    if(ev == CLOSE_EVENT)
    {
        Initiation_Dispatcher::GetInstance().remove_handler(this, READ_EVENT);
        Initiation_Dispatcher::GetInstance().remove_handler(this, WRITE_EVENT);
        Initiation_Dispatcher::GetInstance().remove_handler(this, EXCEPTION_EVENT);
        
        cout << "Socket: " << m_peer_socket << " has been closed." << endl;
        
        close(m_peer_socket);
        delete this;
    }
    return 0;
}

Discovery_Acceptor::Discovery_Acceptor(const uint16_t port)
{
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
    
    int connection_queue_length = 3;
    assert( !listen(m_master_socket, connection_queue_length) );

    Initiation_Dispatcher::GetInstance().register_handler(this, ACCEPT_EVENT);
}

// Factory method that accepts a new connection and creates a PeerHandler
int Discovery_Acceptor::handle_event(const Event_Type et)
{
    if(et == ACCEPT_EVENT)
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
            Discovery_PeerHandler *handler = new Discovery_PeerHandler(new_socket);
        }
    }
    return 0;
}
