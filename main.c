#include "KNXnetIP.h"
#include <stdio.h>

int main(void) {

  WSADATA wsaData;
  SOCKET serverSocket;
  IP_MREQ mreq;
  SOCKADDR_IN serverAddr;
  SOCKADDR_IN clientAddr;

  ZeroMemory(&wsaData, sizeof(wsaData));
  ZeroMemory(&mreq, sizeof(mreq));
  ZeroMemory(&serverAddr, sizeof(serverAddr));
  ZeroMemory(&clientAddr, sizeof(clientAddr));

  initSocket(&wsaData, &serverSocket);
  bindSocket(serverSocket, &serverAddr);
  joinMulticastGroup(serverSocket, &mreq);

  /* Vars for bidirectional communication state machine */
  int clientAddrLen     = sizeof(clientAddr);
  int recvLen           = 0;
  CommType commType     = COM_RECEIVING;
  KNXServiceType action = ST_NO_TYPE;

  /* Start blocking communication state machine */
  KNXnetIPCommStateMachine(serverSocket, &serverAddr, &clientAddr);

  return EXIT_SUCCESS;
}