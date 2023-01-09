#include "Initiation_Dispatcher.h"

#include <sys/epoll.h>
#include <fcntl.h>      //O_CLOEXEC
#include <sys/ioctl.h>  //ioctl
#include <errno.h>      //errno
#include <sys/time.h>   //struct timeval
#include <stddef.h>     //NULL
#include <assert.h>
#include <map>
#include <iostream>     //cout

using std::cout;
using std::endl;
using std::map;

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
    assert( !epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, static_cast<Event_Handler*>(ev.data.ptr)->get_handle(), &ev) );
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
            static_cast<Event_Handler*>(events[n].data.ptr)->handle_event(events[n]);
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