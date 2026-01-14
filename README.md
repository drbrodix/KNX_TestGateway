# KNX_TestGateway

The goal of this small test project is to test the KNXnet/IP Services described
in the KNX Standard. The program initialises a KNXnet/IP server running in a Windows environment.

**This project is not and will not be ready for production environment.**
**This project is developed strictly for learning and testing purposes.**

Winsock2 library is used to manage network sockets. UDP/IP is used for communication.

This is a standard C99 project, which uses the CMake 4.0 build system.
The KNXnet/IP Server is built as an Object Library, which can be imported in, and linked against an executable.

There is already a main routine set up in the repo, which is as simple as:

    #include "KNXnetIP.h"
    #include <stdio.h>
    
    int main(void) {
    
        /* Initialise socket and server entity */
        initServer();
        /* Start blocking communication state machine */
        KNXnetIPCommStateMachine();
        
        return EXIT_SUCCESS;
    }

As it is mentioned in the code comment, the KNXnet/IP Server is currently actively blocking.
I might change it into an asynchronous state machine later on,
but it doesn't really matter for this project, so I'll probably just leave it as is.