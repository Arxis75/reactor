#include "InitiationDispatcher.h"
#include "SocketHandler.h"

#include <sys/epoll.h>
#include <fcntl.h>          //O_CLOEXEC
#include <assert.h>
#include <iostream>         //cout, EXIT_FAILURE, NULL

#define MAX_EVENTS 10   //max simultaneous events for a single epoll_wait

Initiation_Dispatcher::Initiation_Dispatcher()
{
    m_epoll_fd = epoll_create1(O_CLOEXEC);
    assert( m_epoll_fd > 0 );
}

// Register an Event_Handler of a particular
// Event_Type (e.g., READ_EVENT, ACCEPT_EVENT,
// etc.).
void Initiation_Dispatcher::register_handler(struct epoll_event ev)
{
    assert( !epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, static_cast<SocketHandler*>(ev.data.ptr)->getSocket(), &ev) );
}

// Remove an Event_Handler of a particular
// Event_Type.
void Initiation_Dispatcher::remove_handler(int fd)
{
    assert( !epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, fd, NULL) );
}

// Entry point into the reactive event loop.
void Initiation_Dispatcher::handle_events(const int ms_timeout)
{   
    struct epoll_event events[MAX_EVENTS];
    int nfds = epoll_wait(m_epoll_fd, events, MAX_EVENTS, ms_timeout);
    if( nfds > 0 )
        for (int n = 0; n < nfds; ++n)
            static_cast<SocketHandler*>(events[n].data.ptr)->handleEvent(events[n]);
    else if( nfds < 0 && errno != EINTR )  //error (neither a timeout nor a signal)
        exit(EXIT_FAILURE);
}

Initiation_Dispatcher& Initiation_Dispatcher::GetInstance()
{
    if (m_sInstancePtr == NULL)
        m_sInstancePtr = new Initiation_Dispatcher();

    return *m_sInstancePtr;
}

Initiation_Dispatcher *Initiation_Dispatcher::m_sInstancePtr = NULL;