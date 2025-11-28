# KNX_TestGateway

The goal of this small test project is to test the KNXnet/IP Services described
in the KNX Standard. The program initialises a KNXnet/IP server running in a Windows environment.

**This project is not and will not be ready for production environment.**
**This project is developed strictly for learning and testing purposes.**

Winsock2 library is used to manage network sockets. UDP/IP is used for communication.

Support of the following basic KNXnet/IP services are planned:

- Core
    - Search
    - Search Extended
    - Self-Description
    - Connect
    - Disconnect
    - Connection State
- Tunneling
    - Tunneling
    - Tunneling Feature