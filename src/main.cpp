#include <reactor/SocketHandler.h>
#include <reactor/InitiationDispatcher.h>

#define PORT 40404
     
int main(int argc , char *argv[])  
{   
    // Initialize logging server endpoint and
    // register with the Initiation_Dispatcher.
    SocketHandler tcp_server(PORT, IPPROTO_TCP);
    SocketHandler udp_server(PORT, IPPROTO_UDP);

    // Main event loop that handles client
    // logging records and connection requests.
    while(true)
        Initiation_Dispatcher::GetInstance().handle_events();
         
    return 0;  
}  