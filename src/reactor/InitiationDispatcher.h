#pragma once

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
        void register_handler(struct epoll_event ev);
        
        // Remove an Event_Handler of a particular
        // Event_Type.
        void remove_handler(int fd);
        
        // Entry point into the reactive event loop.
        void handle_events(const int ms_timeout = -1);
    
    private:
        static Initiation_Dispatcher *m_sInstancePtr;
        int m_epoll_fd;
};
