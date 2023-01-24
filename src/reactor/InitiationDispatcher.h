#pragma once

#include <memory>
#include <map>

using std::map;
using std::shared_ptr;

class SocketHandler;

// Demultiplex and dispatch Event_Handlers
// in response to client requests.
class Initiation_Dispatcher
{
    private:
        //private constructor
        Initiation_Dispatcher();

    public:
        static Initiation_Dispatcher& GetInstance();

        Initiation_Dispatcher(const Initiation_Dispatcher& obj) = delete;

        // Register an Event_Handler of a particular
        // Event_Type (e.g., READ_EVENT, ACCEPT_EVENT,
        // etc.).
        void registerHandler(std::shared_ptr<SocketHandler> handler, struct epoll_event &ev);
        
        // Remove an Event_Handler of a particular
        // Event_Type.
        void removeHandler(int fd);
        
        // Entry point into the reactive event loop.
        void handle_events(const int ms_timeout = -1);

        const shared_ptr<SocketHandler> getHandler(int fd) const
        {
            auto it = m_handler_list.find(fd);
            return ( it != m_handler_list.end() ? it->second : shared_ptr<SocketHandler>(nullptr) );
        }
    
    private:
        static Initiation_Dispatcher *m_sInstancePtr;
        int m_epoll_fd;
        map<int, shared_ptr<SocketHandler>> m_handler_list;
};
