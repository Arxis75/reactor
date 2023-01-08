#include "Initiation_Dispatcher.h"

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

// Register an Event_Handler of a particular
// Event_Type (e.g., READ_EVENT, ACCEPT_EVENT,
// etc.).
void Initiation_Dispatcher::register_handler(Event_Handler *eh, const Event_Type et)
{
    assert(eh);
    auto it = m_eh.find(eh);
    if( it != m_eh.end() )
        it->second |= et;
    else
        m_eh[eh] = et;
}

// Remove an Event_Handler of a particular
// Event_Type.
void Initiation_Dispatcher::remove_handler(Event_Handler *eh, const Event_Type et)
{
    assert(eh);
    auto it = m_eh.find(eh);
    if( it != m_eh.end() )
    {
        it->second &= ~et;
        if(m_eh[eh] == NO_EVENT)
            m_eh.erase(eh);
    }
}

// Entry point into the reactive event loop.
void Initiation_Dispatcher::handle_events(const struct timeval& tv)
{   
    //set of socket descriptors 
    fd_set readfds, writefds, exceptionfds;

    //clear the socket set 
    FD_ZERO(&readfds);  
    FD_ZERO(&writefds);
    FD_ZERO(&exceptionfds);

    int max_sd = 0;
    for(auto it=m_eh.begin();it!=m_eh.end();it++)
    {
        int sd = it->first->get_handle();
        if(sd > 0)
        {
            if((it->second & ACCEPT_EVENT) || (it->second & READ_EVENT))
                FD_SET(sd, &readfds);
            if(it->second & WRITE_EVENT)
                //FD_SET(sd, &writefds);        //No write event needed!
            if(it->second & EXCEPTION_EVENT)
                FD_SET(sd, &exceptionfds);
        }
        //highest file descriptor number, need it for the select function 
        if(sd > max_sd)  
            max_sd = sd;  
    }

    //wait for an activity on one of the sockets , timeout is NULL , 
    //so wait indefinitely
    struct timeval tv_copy = tv;    //select modifies tv
    int retval = select(max_sd+1, &readfds, &writefds, &exceptionfds, NULL/*&tv_copy*/);
    
    if( retval < 0 && errno != EINTR )
        cout << "select error" << endl;
    else
    {
        auto it = m_eh.begin();
        while( it != m_eh.end() )
        {   
            auto next_it = it;  // Caches the iterator because a call to remove_handler by an event_handler
            next_it++;          // could invalidate it.

            Event_Handler* eh = it->first;

            if( retval == 0 )
            {
                cout << "Select: TIMEOUT_EVENT" << endl;
                eh->handle_event(Event_Type::TIMEOUT_EVENT);
            }
            else if( retval < 0  && errno == EINTR)
            {
                cout << "Select SIGNAL_EVENT" << endl;
                eh->handle_event(Event_Type::SIGNAL_EVENT);
            }
            else
            {
                int socket = eh->get_handle();

                if( FD_ISSET(socket, &readfds) )
                {
                    if( it->second & Event_Type::READ_EVENT )
                    {
                        int n = 0;
                        ioctl(socket, FIONREAD, &n);
                        if( n )
                        {
                            cout << "Select: (socket = " << socket << ") READ_EVENT" << endl;
                            eh->handle_event(Event_Type::READ_EVENT);
                        }
                        else
                        {
                            cout << "Select: (socket = " << socket << ") CLOSE_EVENT" << endl;
                            eh->handle_event(Event_Type::CLOSE_EVENT);
                        }
                    }
                    else if( it->second & Event_Type::ACCEPT_EVENT)
                    {
                        cout << "Select: (socket = " << socket << ") ACCEPT_EVENT" << endl;
                        eh->handle_event(Event_Type::ACCEPT_EVENT);
                    }
                }
                else if( FD_ISSET(socket, &writefds) && (it->second & Event_Type::WRITE_EVENT) )
                {
                    cout << "Select: (socket = " << socket << ") WRITE_EVENT" << endl;
                    eh->handle_event(Event_Type::WRITE_EVENT);
                }
                else if( FD_ISSET(socket, &exceptionfds) && (it->second & Event_Type::EXCEPTION_EVENT)  )
                {
                    cout << "Select: (socket = " << socket << ") EXCEPTION_EVENT" << endl;
                    eh->handle_event(Event_Type::EXCEPTION_EVENT);
                }
            }
        it = next_it;
        }
    }
}

Initiation_Dispatcher& Initiation_Dispatcher::GetInstance()
{
    if (m_sInstancePtr == NULL)
        m_sInstancePtr = new Initiation_Dispatcher();

    return *m_sInstancePtr;
}

Initiation_Dispatcher *Initiation_Dispatcher::m_sInstancePtr = NULL;