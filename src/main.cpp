
#include <reactor/Initiation_Dispatcher.h>
#include <reactor/Event_Handler.h>

#define PORT 40404
     
int main(int argc , char *argv[])  
{   
    // Initialize logging server endpoint and
    // register with the Initiation_Dispatcher.
    Discovery_Acceptor da(PORT);

    // Main event loop that handles client
    // logging records and connection requests.
    while(true)
        Initiation_Dispatcher::GetInstance().handle_events();
         
    return 0;  
}  