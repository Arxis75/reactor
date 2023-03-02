//#include <reactor/InitiationDispatcher.h>
#include <UDP.h>
#include <TCP.h>

#define SERVER_PORT 40404

int main(int argc , char *argv[])  
{   
    if( shared_ptr<UDPSocketHandler> udp = make_shared<UDPSocketHandler>(SERVER_PORT) )
    {
        udp->start();
        if( shared_ptr<TCPSocketHandler> tcp = make_shared<TCPSocketHandler>(SERVER_PORT) )
            tcp->start();
    }

    // Main event loop that handles client
    // logging records and connection requests.
    while(true)
        Initiation_Dispatcher::GetInstance().handle_events();

    return 0;  
}  