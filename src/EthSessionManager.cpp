#include "EthSessionManager.h"

#include <sys/epoll.h>
#include <fcntl.h>          //O_CLOEXEC
#include <netinet/tcp.h>    //TCP_KEEPCNT, TCP_KEEPIDLE, TCP_KEEPINTVL
#include <unistd.h>         //close socket
#include <string.h>         //memset
#include <assert.h>
#include <iostream>         //cout, EXIT_FAILURE, NULL
//#include <algorithm>

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::min;

EthSessionManager::EthSessionManager()
    : SessionManager()
{ }

void EthSessionManager::onNewMessage(const shared_ptr<const SocketHandlerMessage> msg_in) 
{
    if(msg_in)
    {
        if( auto sh_in = msg_in->getSocketHandler() )
            cout << dec << "@ " << (sh_in->getProtocol() == IPPROTO_TCP ? "TCP" : "UDP") << " socket = " << sh_in->getSocket()
                    << " => @" << inet_ntoa(msg_in->getPeerAddress().sin_addr) << ":" << ntohs(msg_in->getPeerAddress().sin_port)
                    << ", " << msg_in->data().size() << " Bytes received" << endl;
    }

    //Worker job:
    auto msg_out = msg_in; //echo server here for example
    if(msg_out)
        if( auto sh_out = msg_out->getSocketHandler() )
            if( auto sm_out = sh_out->getSessionManager() )
                const_pointer_cast<SocketHandler>(sh_out)->sendMsg(msg_out);
}