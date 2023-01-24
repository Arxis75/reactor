#include <EthSessionManager.h>
#include <reactor/InitiationDispatcher.h>

#define PORT 40404

int main(int argc , char *argv[])  
{   
    // Initialize logging server endpoint and
    // register with the Initiation_Dispatcher.

    if( shared_ptr<EthSessionManager> tcp = make_shared<EthSessionManager>(PORT, IPPROTO_TCP) )
        tcp->start();
    if( shared_ptr<EthSessionManager> udp = make_shared<EthSessionManager>(PORT, IPPROTO_UDP) )
        udp->start();

    // Main event loop that handles client
    // logging records and connection requests.
    while(true)
        Initiation_Dispatcher::GetInstance().handle_events();
         
    return 0;  
}  