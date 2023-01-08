#pragma once

#include "Initiation_Dispatcher.h"

#include <arpa/inet.h>      //IPPROTO_TCP, INADDR_ANY, htons, sockaddr_in

// Receives and processes messages
// from/to a Discv4/v5 client.
class Discovery_PeerHandler : public Event_Handler
{
    public:  
        // Initialize the client stream.
        Discovery_PeerHandler(const int socket);

        // Hook method that handles communication with clients.
        virtual int handle_event(const Event_Type et);

        // Get the I/O Handle (called by the
        // Initiation Dispatcher when
        // Discovery_PeerHandler is registered).
        virtual int get_handle(void) const { return m_peer_socket; }

    private:
        int m_peer_socket;
        struct sockaddr_in m_peer_address;
};

// Handles Discv4/v5 client connection requests.
class Discovery_Acceptor : public Event_Handler
{
    public:
        Discovery_Acceptor(const uint16_t port);

        // Factory method that accepts a new connection and creates a PeerHandler
        virtual int handle_event(const Event_Type et);

        // Get the I/O Handle (called by the
        // Initiation Dispatcher when
        // Logging_Acceptor is registered).
        virtual int get_handle(void) const { return m_master_socket; }

    private:
        // Socket factory that accepts client
        // connections.
         int m_master_socket;
};