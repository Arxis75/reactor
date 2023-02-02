//#include <reactor/InitiationDispatcher.h>
#include <Concrete.h>

#define PORT 40404

int main(int argc , char *argv[])  
{   
    int a;

    a = 1;
    // Initialize logging server endpoint and
    // register with the Initiation_Dispatcher.

    if( shared_ptr<ConcreteSocketHandler> udp = make_shared<ConcreteSocketHandler>(PORT, IPPROTO_UDP) )
    {
        udp->start();
        if( shared_ptr<ConcreteSocketHandler> tcp = make_shared<ConcreteSocketHandler>(PORT, IPPROTO_TCP) )
            tcp->start();
    }

    // Main event loop that handles client
    // logging records and connection requests.
    while(true)
        Initiation_Dispatcher::GetInstance().handle_events();

    return 0;  
}  