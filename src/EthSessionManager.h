#pragma once

#include <arpa/inet.h>      //IPPROTO_TCP, INADDR_ANY, htons, sockaddr_in
#include <queue>
#include <vector>
#include <condition_variable>

using std::vector;

using std::lock_guard;
using std::unique_lock;
using std::mutex;

using std::make_shared;
using std::shared_ptr;
using std::const_pointer_cast;

#include <reactor/SocketHandler.h>

class EthSessionManager: public SessionManager
{
    public:
        EthSessionManager(const uint16_t master_port, const int master_protocol);

        virtual void onNewMessage(const shared_ptr<const SocketHandlerMessage> msg_in);

    private:
        int m_master_port;
        int m_master_protocol;
        SafeQueue<shared_ptr<const SocketHandlerMessage>> m_ingress;
};