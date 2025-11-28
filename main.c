#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ws2tcpip.h>

#pragma region Definitions

#define LOG_STR_BUFF_LEN          64
#define BUFF_LEN                  128
#define KNX_PORT                  3671
#define KNX_MULTICAST_ADDR        "224.0.23.12"
#define KNX_CTRL_ENDPOINT_IP_ADDR "10.56.2.122"

typedef enum CommType { COM_RECEIVING, COM_SENDING } CommType;

typedef enum KNXServiceFamily {
  FAMILY_CORE      = 0x02,
  FAMILY_DEV_MGMT  = 0x03,
  FAMILY_TUNNELING = 0x04,
  FAMILY_ROUTING   = 0x05
} KNXServiceFamily;

typedef enum KNXConnectionType {
  DEVICE_MGMT_CONNECTION = 0x03,
  TUNNEL_CONNECTION      = 0x04,
  REMLOG_CONNECTION      = 0x06,
  REMCONF_CONNECTION     = 0x07,
  OBJSVR_CONNECTION      = 0x08
} KNXConnectionType;

typedef enum KNXDescriptionType {
  DEVICE_INFO       = 0x01,
  SUPP_SVC_FAMILIES = 0x02,
  IP_CONFIG         = 0x03,
  IP_CUR_CONFIG     = 0x04,
  KNX_ADDRESSES     = 0x05
} KNXDescriptionType;

typedef enum KNXMedium {
  TP1    = 0x02,
  PL110  = 0x04,
  RF     = 0x10,
  KNX_IP = 0x20
} KNXMedium;

typedef enum DeviceStatus {
  DEVICE_STATUS_PROG_MODE_OFF = 0x00,
  DEVICE_STATUS_PROG_MODE_ON  = 0x01
} DeviceStatus;

typedef enum HostProtocol { IPV4_UDP = 0x01, IPV4_TCP = 0x02 } HostProtocol;

typedef enum TunnelingLayer {
  TUNNEL_LINKLAYER  = 0x02,
  TUNNEL_RAW        = 0x04,
  TUNNEL_BUSMONITOR = 0x80
} TunnelingLayer;

typedef enum ConnectionError {
  E_NO_ERROR            = 0x00,
  E_CONNECTION_TYPE     = 0x22,
  E_CONNECTION_OPTION   = 0x23,
  E_NO_MORE_CONNECTIONS = 0x24,
  E_TUNNELLING_LAYER    = 0x29
} ConnectionError;

typedef enum KNXServiceType {
  ST_NO_TYPE                      = 0x0000,
  ST_SEARCH_REQUEST               = 0x0201,
  ST_SEARCH_RESPONSE              = 0x0202,
  ST_DESCRIPTION_REQUEST          = 0x0203,
  ST_DESCRIPTION_RESPONSE         = 0x0204,
  ST_CONNECT_REQUEST              = 0x0205,
  ST_CONNECT_RESPONSE             = 0x0206,
  ST_CONNECTIONSTATE_REQUEST      = 0x0207,
  ST_CONNECTIONSTATE_RESPONSE     = 0x0208,
  ST_DISCONNECT_REQUEST           = 0x0209,
  ST_DISCONNECT_RESPONSE          = 0x020A,
  ST_SEARCH_REQUEST_EXTENDED      = 0x020B,
  ST_SEARCH_RESPONSE_EXTENDED     = 0x020C,
  ST_DEVICE_CONFIGURATION_REQUEST = 0x0310,
  ST_DEVICE_CONFIGURATION_ACK     = 0x0311,
  ST_TUNNELING_REQUEST            = 0x0420,
  ST_TUNNELING_ACK                = 0x0421,
  ST_ROUTING_INDICATION           = 0x0530,
  ST_ROUTING_LOST_MESSAGE         = 0x0531,
  ST_ROUTING_BUSY                 = 0x0532
} KNXServiceType;

#pragma endregion Definitions

#pragma region KNX Buffer Write Subfunctions

uint16_t writeKNXHeaderInBuff(uint8_t *buff, uint16_t *totalLen,
                              KNXServiceType action) {

  *buff = 0x06; //< Header length
  ++(*totalLen);
  *(buff + (*totalLen)) = 0x10; //< Protocol version 1.0
  ++(*totalLen);
  *(uint16_t *)(buff + (*totalLen)) = htons(action); //< Service identifier
  (*totalLen) += 2;
  /* Total length will be filled later on */
  (*totalLen) += 2;
  return (*totalLen);
}

uint16_t writeHPAIInBuff(uint8_t *buff, uint16_t *totalLen) {

  *(buff + (*totalLen)) = 0x08; //< HPAI struct length
  ++(*totalLen);
  *(buff + (*totalLen)) = IPV4_UDP; //< Host Protocol
  ++(*totalLen);
  inet_pton(AF_INET, KNX_CTRL_ENDPOINT_IP_ADDR,
            (buff + (*totalLen))); //< Control endpoint IP address
  (*totalLen) += 4;
  *(uint16_t *)(buff + (*totalLen)) =
      htons(KNX_PORT); //< Control endpoint port number
  (*totalLen) += 2;
  return (*totalLen);
}

uint16_t writeDIBDevInfoInBuff(uint8_t *buff, uint16_t *totalLen) {

  const uint8_t KNXSerialNum[6]  = {0x00, 0xc1, 0x77, 0x13, 0x52, 0x69};
  const uint8_t MacAddr[6]       = {0x00, 0x72, 0x11, 0x37, 0x28, 0x42};
  const uint8_t friendlyName[30] = "KNX IP DoggoDevice";

  *(buff + (*totalLen))          = 0x36; //< Structure length
  ++(*totalLen);
  *(buff + (*totalLen)) = DEVICE_INFO; //< Description type: Device Information
  ++(*totalLen);
  *(buff + (*totalLen)) = TP1; //< KNX medium: TP1
  ++(*totalLen);
  *(buff + (*totalLen)) = DEVICE_STATUS_PROG_MODE_OFF; //< Device status
  ++(*totalLen);
  *(uint16_t *)(buff + (*totalLen)) =
      htons(0x1132); //< KNX individual address 1.1.50
  (*totalLen) += 2;
  *(uint16_t *)(buff + (*totalLen)) =
      0x0000; //< Project installation identifier
  (*totalLen) += 2;
  memcpy((buff + (*totalLen)), KNXSerialNum, 6); //< KNX Serial Number
  (*totalLen) += 6;
  inet_pton(AF_INET, KNX_MULTICAST_ADDR,
            (buff + (*totalLen))); //< Control endpoint IP address
  (*totalLen) += 4;
  memcpy((buff + (*totalLen)), MacAddr, 6); //< MAC address
  (*totalLen) += 6;
  memcpy((buff + (*totalLen)), friendlyName, 30); //< Friendly name
  (*totalLen) += 30;
  return (*totalLen);
}

uint16_t writeCRDTunnConnInBuff(uint8_t *buff, uint16_t *totalLen) {

  *(buff + (*totalLen)) = 0x04; //< Structure length
  ++(*totalLen);
  *(buff + (*totalLen)) =
      FAMILY_TUNNELING; //< Connection type: Tunneling connection
  ++(*totalLen);
  *(uint16_t *)(buff + (*totalLen)) =
      htons(0x11FA); //< KNX tunnel individual address 1.1.250
  (*totalLen) += 2;

  return (*totalLen);
}

uint16_t writeDIBSSInBuff(uint8_t *buff, uint16_t *totalLen) {

  *(buff + (*totalLen)) = 0x06; //< Structure length
  ++(*totalLen);
  *(buff + (*totalLen)) =
      SUPP_SVC_FAMILIES; //< Description type: Supported service family
  ++(*totalLen);
  *(uint16_t *)(buff + (*totalLen)) =
      MAKEWORD(FAMILY_CORE, 0x02); //< KNXnet/IP Core v2
  (*totalLen) += 2;
  //  *(uint16_t *)(buff + (*totalLen)) =
  //      htons(0x0302); //< KNXnet/IP Device Management v2
  //  (*totalLen) += 2;
  *(uint16_t *)(buff + (*totalLen)) =
      MAKEWORD(FAMILY_TUNNELING, 0x02); //< KNXnet/IP Tunneling v2
  (*totalLen) += 2;
  return (*totalLen);
}

#pragma endregion KNX Buffer Write Subfunctions

#pragma region KNX Buffer Write Function

uint16_t writeInBuff(uint8_t *buff, KNXServiceType action, char *logStrBuff) {

  uint16_t totalLen         = 0;
  const uint8_t totalLenInd = 4;

  /*
   * Common KNXnet/IP Header,
   * which is same in each KNXnet/IP frame
   */
  writeKNXHeaderInBuff(buff, &totalLen, action);

  switch (action) {
  case ST_SEARCH_RESPONSE:
    strcpy_s(logStrBuff, LOG_STR_BUFF_LEN, "Search Response");

  case ST_SEARCH_RESPONSE_EXTENDED:

    /* HPAI Control Endpoint */
    writeHPAIInBuff(buff, &totalLen);

    /* DIB DevInfo */
    writeDIBDevInfoInBuff(buff, &totalLen);

    /* Supported Service: Tunneling */
    writeDIBSSInBuff(buff, &totalLen);

    strcpy_s(logStrBuff, LOG_STR_BUFF_LEN, "Search Response Extended");

    break;

  case ST_DESCRIPTION_RESPONSE:

    /* DIB DevInfo */
    writeDIBDevInfoInBuff(buff, &totalLen);

    /* Supported Service: Tunneling */
    writeDIBSSInBuff(buff, &totalLen);

    strcpy_s(logStrBuff, LOG_STR_BUFF_LEN, "Description Response");

    break;

  case ST_CONNECT_RESPONSE:

    *(buff + totalLen) = 0x01; //< Channel ID
    ++totalLen;
    *(buff + totalLen) = 0x00; //< Status code
    ++totalLen;

    writeHPAIInBuff(buff, &totalLen);
    writeCRDTunnConnInBuff(buff, &totalLen);

    strcpy_s(logStrBuff, LOG_STR_BUFF_LEN, "Connect Response");

    break;

  case ST_CONNECTIONSTATE_RESPONSE:
    strcpy_s(logStrBuff, LOG_STR_BUFF_LEN, "Connection State Response");
  case ST_DISCONNECT_RESPONSE:

    /*
     * Communication Channel ID.
     * Always 1, because we won't support more channels for now.
     */
    *(buff + totalLen) = 0x01;
    ++totalLen;
    *(buff + totalLen) = E_NO_ERROR; //< Status code
    ++totalLen;

    strcpy_s(logStrBuff, LOG_STR_BUFF_LEN, "Disconnect Response");

    break;

  case ST_TUNNELING_ACK:

    strcpy_s(logStrBuff, LOG_STR_BUFF_LEN, "Tunneling Acknowledgement");
    break;

  default:
    return 0;
    break;
  }

  *(uint16_t *)(buff + totalLenInd) = htons(totalLen);

  return totalLen;
}

#pragma endregion KNX Buffer Write Function

#pragma region Socket Functions

void initSocket(WSADATA *wsaData, SOCKET *serverSocket) {

  int wsaStartupResult = WSAStartup(0x22, wsaData);
  if (wsaStartupResult) {
    perror("Windows socket startup failed\n");
    exit(EXIT_FAILURE);
  }

  if ((*serverSocket = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
    perror("Socket creation failed\n");
    exit(EXIT_FAILURE);
  }
}

void bindSocket(SOCKET serverSocket, SOCKADDR_IN *serverAddr) {
  serverAddr->sin_family           = AF_INET;
  serverAddr->sin_addr.S_un.S_addr = INADDR_ANY;
  serverAddr->sin_port             = htons(KNX_PORT);

  if (bind(serverSocket, (const struct sockaddr *)serverAddr,
           sizeof(SOCKADDR_IN)) < 0) {
    fprintf(stderr, "Binding of socket failed\nError: %d", WSAGetLastError());
    exit(EXIT_FAILURE);
  }
}

void joinMulticastGroup(SOCKET serverSocket, IP_MREQ *mreq) {
  mreq->imr_interface.S_un.S_addr = htonl(INADDR_ANY);
  if (!inet_pton(AF_INET, KNX_MULTICAST_ADDR,
                 &mreq->imr_multiaddr.S_un.S_addr)) {
    fprintf(stderr, "Configuring multicast address failed\nError: %d",
            WSAGetLastError());
    exit(EXIT_FAILURE);
  }

  if (setsockopt(serverSocket, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                 (const char *)mreq, sizeof(IP_MREQ)) < 0) {
    fprintf(stderr, "Joining multicast address group failed\nError: %d",
            WSAGetLastError());
    exit(EXIT_FAILURE);
  }
}

#pragma endregion Socket Functions

int main(void) {

#pragma region Communication Preparation

  WSADATA wsaData;
  SOCKET serverSocket;
  IP_MREQ mreq;
  SOCKADDR_IN serverAddr;
  SOCKADDR_IN clientAddr;
  uint8_t rxBuff[BUFF_LEN];
  uint8_t txBuff[BUFF_LEN];

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

#pragma endregion Communication Preparation

#pragma region Communication State Machine

  /* Communication State Machine */
  while (TRUE) {

    switch (commType) {
    case COM_RECEIVING:
      recvLen = recvfrom(serverSocket, (char *)rxBuff, BUFF_LEN, 0,
                         (struct sockaddr *)&clientAddr, &clientAddrLen);
      if (recvLen < 0) {
        fprintf(stderr, "Receiving on socket failed\nError: %d",
                WSAGetLastError());
        exit(EXIT_FAILURE);
      }

      if (recvLen) {

        /*
         * The holy KNX Standard itself says,
         * this is a solid way to check KNX packets
         */
        if (*(uint16_t *)rxBuff != htons(0x0610))
          continue;

        char srvcStr[64];
        const uint16_t srvcIdentifier = htons(*(((uint16_t *)rxBuff) + 1));

        //        ST_NO_TYPE                      = 0x0000,
        //        ST_SEARCH_REQUEST               = 0x0201,
        //        ST_SEARCH_RESPONSE              = 0x0202,
        //        ST_DESCRIPTION_REQUEST          = 0x0203,
        //        ST_DESCRIPTION_RESPONSE         = 0x0204,
        //        ST_CONNECT_REQUEST              = 0x0205,
        //        ST_CONNECT_RESPONSE             = 0x0206,
        //        ST_CONNECTIONSTATE_REQUEST      = 0x0207,
        //        ST_CONNECTIONSTATE_RESPONSE     = 0x0208,
        //        ST_DISCONNECT_REQUEST           = 0x0209,
        //        ST_DISCONNECT_RESPONSE          = 0x020A,
        //        ST_SEARCH_REQUEST_EXTENDED      = 0x020B,
        //        ST_SEARCH_RESPONSE_EXTENDED     = 0x020C,
        //        ST_DEVICE_CONFIGURATION_REQUEST = 0x0310,
        //        ST_DEVICE_CONFIGURATION_ACK     = 0x0311,
        //        ST_TUNNELING_REQUEST            = 0x0420,
        //        ST_TUNNELING_ACK                = 0x0421,
        //        ST_ROUTING_INDICATION           = 0x0530,
        //        ST_ROUTING_LOST_MESSAGE         = 0x0531,
        //        ST_ROUTING_BUSY                 = 0x0532

        /* Service Identifier */
        switch ((KNXServiceType)srvcIdentifier) {

        case ST_SEARCH_REQUEST: {
          commType = COM_SENDING;
          action   = ST_SEARCH_RESPONSE;
          strcpy_s(srvcStr, 64, "Search Request");
        } break;

        case ST_DESCRIPTION_REQUEST:
          commType = COM_SENDING;
          action   = ST_DESCRIPTION_RESPONSE;
          strcpy_s(srvcStr, 64, "Description Request");
          break;

        case ST_CONNECT_REQUEST:
          commType = COM_SENDING;
          action   = ST_CONNECT_RESPONSE;
          strcpy_s(srvcStr, 64, "Connect Request");
          break;

        case ST_CONNECTIONSTATE_REQUEST:
          commType = COM_SENDING;
          action   = ST_CONNECTIONSTATE_RESPONSE;
          strcpy_s(srvcStr, 64, "Connection State Request");
          break;

        case ST_DISCONNECT_REQUEST:
          commType = COM_SENDING;
          action   = ST_DISCONNECT_RESPONSE;
          strcpy_s(srvcStr, 64, "Disconnect Request");
          break;

        case ST_SEARCH_REQUEST_EXTENDED:
          commType = COM_SENDING;
          action   = ST_SEARCH_RESPONSE_EXTENDED;
          strcpy_s(srvcStr, 64, "Search Request Extended");
          break;

        case ST_TUNNELING_REQUEST:
          commType = COM_SENDING;
          action   = ST_TUNNELING_ACK;
          strcpy_s(srvcStr, 64, "Tunneling Request");
          break;

        default:
          action = ST_NO_TYPE;
          strcpy_s(srvcStr, 64, "Message");
          break;
        }

        printf("Received %s from address %d.%d.%d.%d:\n", srvcStr,
               clientAddr.sin_addr.S_un.S_un_b.s_b1,
               clientAddr.sin_addr.S_un.S_un_b.s_b2,
               clientAddr.sin_addr.S_un.S_un_b.s_b3,
               clientAddr.sin_addr.S_un.S_un_b.s_b4);

        for (int i = 0; i < recvLen; ++i) {
          printf("0x%x ", rxBuff[i]);
        }
        printf("\n\n");
        ZeroMemory(rxBuff, BUFF_LEN);
        recvLen = 0;
      }
      break;

    case COM_SENDING: {
      char srvcStr[64];

      const uint16_t buffLen = writeInBuff(txBuff, action, srvcStr);

      if (sendto(serverSocket, (const char *)txBuff, buffLen, 0,
                 (const struct sockaddr *)&clientAddr,
                 sizeof(clientAddr)) <= 0) {
        fprintf(stderr, "Failed to send message.\nError: %d",
                WSAGetLastError());
      } else {
        printf("Sent %s to address %d.%d.%d.%d:\n", srvcStr,
               clientAddr.sin_addr.S_un.S_un_b.s_b1,
               clientAddr.sin_addr.S_un.S_un_b.s_b2,
               clientAddr.sin_addr.S_un.S_un_b.s_b3,
               clientAddr.sin_addr.S_un.S_un_b.s_b4);

        for (int i = 0; i < buffLen; ++i) {
          printf("0x%x ", txBuff[i]);
        }
        printf("\n\n");
      }
      commType = COM_RECEIVING;
    } break;
    }
  }

#pragma endregion Communication State Machine

  return EXIT_SUCCESS;
}