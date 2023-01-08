#pragma once

#include <stdint.h>
#include <map>

using std::map;

enum Event_Type
// = TITLE
// Types of events handled by the
// Initiation_Dispatcher.
//
// = DESCRIPTION
// These values are powers of two so
// their bits can be efficiently ‘‘or’d’’
// together to form composite values.
{
    NO_EVENT = 0x00,
    ACCEPT_EVENT = 0x01,
    READ_EVENT = 0x02,
    WRITE_EVENT = 0x04,
    EXCEPTION_EVENT = 0x08,
    TIMEOUT_EVENT = 0x10,
    SIGNAL_EVENT = 0x20,
    CLOSE_EVENT = 0x40
};

class Event_Handler
// = TITLE
// Abstract base class that serves as the
// target of the Initiation_Dispatcher.
{
    public:
        // Hook methods that are called back by
        // the Initiation_Dispatcher to handle
        // particular types of events.
        virtual int handle_event(const Event_Type et) = 0;

        // Hook method that returns the underlying
        // I/O Handle.
        virtual int get_handle(void) const = 0;
};

// Demultiplex and dispatch Event_Handlers
// in response to client requests.
class Initiation_Dispatcher
{
    private:
        //private constructor
        Initiation_Dispatcher() {}

    public:
        static Initiation_Dispatcher& GetInstance();

        Initiation_Dispatcher(const Initiation_Dispatcher& obj) = delete;

        // Register an Event_Handler of a particular
        // Event_Type (e.g., READ_EVENT, ACCEPT_EVENT,
        // etc.).
        void register_handler(Event_Handler *eh, const Event_Type et);
        
        // Remove an Event_Handler of a particular
        // Event_Type.
        void remove_handler(Event_Handler *eh, const Event_Type et);
        
        // Entry point into the reactive event loop.
        void handle_events(const struct timeval& tv = {10, 0});
    
    private:
        static Initiation_Dispatcher *m_sInstancePtr;
        map<Event_Handler*, uint16_t> m_eh;
};
