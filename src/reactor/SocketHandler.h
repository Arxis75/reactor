#pragma once

#include "InitiationDispatcher.h"

#include <arpa/inet.h>      //IPPROTO_TCP, INADDR_ANY, htons, sockaddr_in

class SocketHandler
{
    public:
        SocketHandler(const uint16_t port, const int protocol);
        SocketHandler(const int socket);

        virtual int handleEvent(const struct epoll_event event);

        int getSocket(void) const { return m_socket; };
        int getProtocol(void) const { return m_protocol; };
        const struct sockaddr_in& getLocalAddress(void) const { return m_local_address; };
        const struct sockaddr_in& getPeerAddress(void) const { return m_peer_address; };

    private:
        int bindSocket(const uint16_t port);
        int acceptConnection();
        int cacheLocalAddress();
        int cacheRemoteAddress();
        void registerHandler();

    private:
        int m_protocol;
        int m_socket;
        struct sockaddr_in m_local_address;
        struct sockaddr_in m_peer_address;
        bool m_delete_on_close;
};