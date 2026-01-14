#include "KNXnetIP.h"
#include <stdio.h>
#include <stdlib.h>

///* Index in list will be used as Channel ID */
// KNXnetIPServerHandle serverList[MAX_NR_OF_SERVERS];
// uint8_t nrOfServers = 0;
WSADATA wsaData;
SOCKET serverSocket;
IP_MREQ mreq;
KNXnetIPServer server;
InterfaceFeatureSet interfaceFeatures = {
    .supportedEmiType               = {.cEMI = TRUE},
    .deviceDescriptorType           = DDT_KNXNET_IP_ROUTER_091A,
    .busConnectionStatus            = TRUE,
    .knxManufacturerCode            = KNX_MANUFACTURER_CODE,
    .activeEmiType                  = EMI_CEMI,
    .interfaceIndivAddr             = KNX_DEFAULT_TUNNEL_ADDR,
    .maxApduLength                  = MAX_APDU_LENGTH,
    .interfaceFeatureInfoServEnable = FALSE};

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
  *(uint32_t *)(buff + (*totalLen)) = server.serverAddr.sin_addr.S_un.S_addr;
  (*totalLen) += 4;
  *(uint16_t *)(buff + (*totalLen)) =
      server.serverAddr.sin_port; //< Endpoint port number
  (*totalLen) += 2;
  return (*totalLen);
}

uint16_t writeDIBInBuff(uint8_t *buff, uint16_t *totalLen,
                        DibWriteList dibWriteList) {
  if (dibWriteList.deviceInfo) {
    const uint8_t KNXSerialNum[6]  = {0x00, 0xc1, 0x77, 0x13, 0x52, 0x69};
    const uint8_t MacAddr[6]       = {0x00, 0x72, 0x11, 0x37, 0x28, 0x42};
    const uint8_t friendlyName[30] = "KNX IP DoggoDevice";

    *(buff + (*totalLen)) = 0x36; //< Structure length
    ++(*totalLen);
    *(buff + (*totalLen)) =
        DIB_DEVICE_INFO; //< Description type: Device Information
    ++(*totalLen);
    *(buff + (*totalLen)) = MED_TP1; //< KNX medium: TP1
    ++(*totalLen);
    *(buff + (*totalLen)) = DEVICE_STATUS_PROG_MODE_OFF; //< Device status
    ++(*totalLen);
    *(uint16_t *)(buff + (*totalLen)) =
        htons(KNX_DEFAULT_ROUTER_ADDR); //< KNX individual address 1.1.50
    (*totalLen) += 2;
    *(uint16_t *)(buff + (*totalLen)) =
        0x0000; //< Project installation identifier
    (*totalLen) += 2;
    memcpy((buff + (*totalLen)), KNXSerialNum, 6); //< KNX Serial Number
    (*totalLen) += 6;
    *(uint32_t *)(buff + (*totalLen)) =
        server.serverAddr.sin_addr.S_un.S_addr; //< Control endpoint IP address
    (*totalLen) += 4;
    memcpy((buff + (*totalLen)), MacAddr, 6); //< MAC address
    (*totalLen) += 6;
    memcpy((buff + (*totalLen)), friendlyName, 30); //< Friendly name
    (*totalLen) += 30;
  }
  if (dibWriteList.suppSvcFamilies) {
    *(buff + (*totalLen)) = 0x08; //< Structure length
    ++(*totalLen);
    *(buff + (*totalLen)) =
        DIB_SUPP_SVC_FAMILIES; //< Description type: Supported service family
    ++(*totalLen);
    *(uint16_t *)(buff + (*totalLen)) =
        MAKEWORD(FAMILY_CORE, 0x02); //< KNXnet/IP Core v2
    (*totalLen) += 2;
    *(uint16_t *)(buff + (*totalLen)) =
        htons(0x0302); //< KNXnet/IP Device Management v2
    (*totalLen) += 2;
    *(uint16_t *)(buff + (*totalLen)) =
        MAKEWORD(FAMILY_TUNNELLING, 0x02); //< KNXnet/IP Tunneling v2
    (*totalLen) += 2;
  }
  if (dibWriteList.ipConfig) {
  }
  if (dibWriteList.ipCurConfig) {
  }
  if (dibWriteList.knxAddresses) {
  }
  if (dibWriteList.mfrData) {
  }
  if (dibWriteList.tunnInfo) {
    *(buff + (*totalLen)) = 0x08; //< Structure length
    ++(*totalLen);
    *(buff + (*totalLen)) =
        DIB_TUNNELLING_INFO; //< Description type: Tunnelling Info
    ++(*totalLen);
    *(uint16_t *)(buff + (*totalLen)) = htons(MAX_APDU_LENGTH);
    (*totalLen) += 2;
    /* Tunnelling Slot Individual Address */
    *(uint16_t *)(buff + (*totalLen)) = htons(KNX_DEFAULT_TUNNEL_ADDR);
    (*totalLen) += 2;
    /* Tunnelling Slot Status */
    *(uint16_t *)(buff + (*totalLen)) = htons((0xFFFE) | !(server.isConnected));
    (*totalLen) += 2;
  }
  if (dibWriteList.extDvcInfo) {
  }

  return (*totalLen);
}

uint16_t writeCRDTunnConnInBuff(uint8_t *buff, uint16_t *totalLen) {

  *(buff + (*totalLen)) = 0x04; //< Structure length
  ++(*totalLen);
  *(buff + (*totalLen)) =
      FAMILY_TUNNELLING; //< Connection type: Tunnelling connection
  ++(*totalLen);
  *(uint16_t *)(buff + (*totalLen)) =
      htons(0x11FA); //< KNX tunnel individual address 1.1.250
  (*totalLen) += 2;

  return (*totalLen);
}

uint16_t writeKNXConnHeaderInBuff(uint8_t *buff, uint16_t *totalLen) {

  *(buff + (*totalLen)) = 0x04; //< Structure length
  ++(*totalLen);
  *(buff + (*totalLen)) = server.channelID; //< Channel ID
  ++totalLen;
  *(uint16_t *)(buff + (*totalLen)) =
      MAKEWORD(FAMILY_CORE, 0x02); //< KNXnet/IP Core v2
  (*totalLen) += 2;
  //  *(uint16_t *)(buff + (*totalLen)) =
  //      htons(0x0302); //< KNXnet/IP Device Management v2
  //  (*totalLen) += 2;
  *(uint16_t *)(buff + (*totalLen)) =
      MAKEWORD(FAMILY_TUNNELLING, 0x02); //< KNXnet/IP Tunneling v2
  (*totalLen) += 2;
  return (*totalLen);
}

#pragma endregion KNX Buffer Write Subfunctions

#pragma region KNX Action Handler

uint16_t prepareResponse(const uint8_t *rxBuff, uint8_t *txBuff,
                         KNXServiceType recvSrvc, char *srvcStr,
                         SOCKADDR_IN *clientAddr) {

  uint16_t totalLen         = 0;
  const uint8_t totalLenInd = 4;

  clientAddr->sin_family = AF_INET;

  uint8_t rxIdx = 0;

  KNXnetIPHeader knxNetIpHeader;
  knxNetIpHeader.headerLength = *(rxBuff + rxIdx++);
  knxNetIpHeader.protoVersion = *(rxBuff + rxIdx++);
  knxNetIpHeader.serviceCode  = ntohs(*(uint16_t *)(rxBuff + rxIdx));
  rxIdx += 2;
  knxNetIpHeader.totalLength = ntohs(*(uint16_t *)(rxBuff + rxIdx));
  rxIdx += 2;

  switch (recvSrvc) {
  case ST_SEARCH_REQUEST: {

    /* Discovery HPAI structure */
    Hpai discoveryHpai;
    discoveryHpai.structLength  = *(rxBuff + rxIdx++);
    discoveryHpai.hostProtoCode = *(rxBuff + rxIdx++);
    discoveryHpai.ipAddr        = ntohl(*(uint32_t *)(rxBuff + rxIdx));
    rxIdx += 4;
    discoveryHpai.port = ntohs(*(uint16_t *)(rxBuff + rxIdx));
    rxIdx += 2;

    clientAddr->sin_addr.S_un.S_addr = htonl(discoveryHpai.ipAddr);
    clientAddr->sin_port             = htons(discoveryHpai.port);

    /* Response: ST_SEARCH_RESPONSE */

    /*
     * Common KNXnet/IP Header,
     * which is same in each KNXnet/IP frame
     */
    writeKNXHeaderInBuff(txBuff, &totalLen, ST_SEARCH_RESPONSE);

    /* HPAI Control Endpoint */
    writeHPAIInBuff(txBuff, &totalLen);

    /* DIBs DevInfo, SupportedSvcFamilies */
    writeDIBInBuff(txBuff, &totalLen,
                   (DibWriteList){.deviceInfo = TRUE, .suppSvcFamilies = TRUE});

    strcpy_s(srvcStr, LOG_STR_BUFF_LEN, "Search Response");
  } break;

  case ST_DESCRIPTION_REQUEST: {

    /* Discovery HPAI structure */
    Hpai controlHpai;
    controlHpai.structLength  = *(rxBuff + rxIdx++);
    controlHpai.hostProtoCode = *(rxBuff + rxIdx++);
    controlHpai.ipAddr        = ntohl(*(uint32_t *)(rxBuff + rxIdx));
    rxIdx += 4;
    controlHpai.port = ntohs(*(uint16_t *)(rxBuff + rxIdx));
    rxIdx += 2;

    clientAddr->sin_addr.S_un.S_addr = htonl(controlHpai.ipAddr);
    clientAddr->sin_port             = htons(controlHpai.port);

    /* Response: ST_DESCRIPTION_RESPONSE */

    /*
     * Common KNXnet/IP Header,
     * which is same in each KNXnet/IP frame
     */
    writeKNXHeaderInBuff(txBuff, &totalLen, ST_DESCRIPTION_RESPONSE);

    /* DIBs DevInfo, SupportedSvcFamilies */
    writeDIBInBuff(txBuff, &totalLen,
                   (DibWriteList){.deviceInfo = TRUE, .suppSvcFamilies = TRUE});

    strcpy_s(srvcStr, LOG_STR_BUFF_LEN, "Description Response");
  } break;

  case ST_CONNECT_REQUEST:
    /* Response: ST_CONNECT_RESPONSE */

    /*
     * Common KNXnet/IP Header,
     * which is same in each KNXnet/IP frame
     */
    writeKNXHeaderInBuff(txBuff, &totalLen, ST_CONNECT_RESPONSE);

    *(txBuff + totalLen) = server.channelID; //< Channel ID
    ++totalLen;
    *(txBuff + totalLen) = 0x00; //< Status code
    ++totalLen;

    writeHPAIInBuff(txBuff, &totalLen);
    writeCRDTunnConnInBuff(txBuff, &totalLen);

    strcpy_s(srvcStr, LOG_STR_BUFF_LEN, "Connect Response");
    break;

  case ST_CONNECTIONSTATE_REQUEST:
    /* Response: ST_CONNECTIONSTATE_RESPONSE */

    /*
     * Common KNXnet/IP Header,
     * which is same in each KNXnet/IP frame
     */
    writeKNXHeaderInBuff(txBuff, &totalLen, ST_CONNECTIONSTATE_RESPONSE);

    /*
     * Communication Channel ID.
     * Always 1, because we won't support more channels for now.
     */
    *(txBuff + totalLen) = server.channelID;
    ++totalLen;
    *(txBuff + totalLen) = E_NO_ERROR; //< Status code
    ++totalLen;

    strcpy_s(srvcStr, LOG_STR_BUFF_LEN, "Connection State Response");
    break;

  case ST_DISCONNECT_REQUEST:
    /* Response: ST_DISCONNECT_RESPONSE */

    /*
     * Common KNXnet/IP Header,
     * which is same in each KNXnet/IP frame
     */
    writeKNXHeaderInBuff(txBuff, &totalLen, ST_DISCONNECT_RESPONSE);

    /*
     * Communication Channel ID.
     * Always 1, because we won't support more channels for now.
     */
    *(txBuff + totalLen) = server.channelID;
    ++totalLen;
    *(txBuff + totalLen) = E_NO_ERROR; //< Status code
    ++totalLen;

    strcpy_s(srvcStr, LOG_STR_BUFF_LEN, "Disconnect Response");
    break;

  case ST_SEARCH_REQUEST_EXTENDED: {
    /*
     * Init index with KNXnet/IP header length.
     * With that value, we'll practically skip to body.
     */

    /* Discovery HPAI structure */
    Hpai discoveryHpai;
    discoveryHpai.structLength  = *(rxBuff + rxIdx++);
    discoveryHpai.hostProtoCode = *(rxBuff + rxIdx++);
    discoveryHpai.ipAddr        = ntohl(*(uint32_t *)(rxBuff + rxIdx));
    rxIdx += 4;
    discoveryHpai.port = ntohs(*(uint16_t *)(rxBuff + rxIdx));
    rxIdx += 2;

    clientAddr->sin_addr.S_un.S_addr = htonl(discoveryHpai.ipAddr);
    clientAddr->sin_port             = htons(discoveryHpai.port);

    /* Response: ST_SEARCH_RESPONSE */

    /*
     * Common KNXnet/IP Header,
     * which is same in each KNXnet/IP frame
     */
    writeKNXHeaderInBuff(txBuff, &totalLen, ST_SEARCH_RESPONSE_EXTENDED);

    /* HPAI Control Endpoint */
    writeHPAIInBuff(txBuff, &totalLen);

    /* DIBs DevInfo, SupportedSvcFamilies */
    writeDIBInBuff(txBuff, &totalLen,
                   (DibWriteList){.deviceInfo      = TRUE,
                                  .suppSvcFamilies = TRUE,
                                  .tunnInfo        = TRUE});

    strcpy_s(srvcStr, LOG_STR_BUFF_LEN, "Search Response Extended");
  } break;

  case ST_TUNNELLING_REQUEST:

    break;

  case ST_TUNNELLING_FEATURE_GET:

    break;

  case ST_TUNNELLING_FEATURE_SET:

    break;

  default:
    return totalLen;
    break;
  }

  *(uint16_t *)(txBuff + totalLenInd) = htons(totalLen);

  return totalLen;
}

#pragma endregion KNX Buffer Write Function

void handleSearchRequest(const uint8_t *rxBuff, CommType *commType,
                         KNXServiceType *action) {
  *commType = COM_SENDING;
  *action   = ST_SEARCH_RESPONSE;
}
void handleDescriptionRequest(const uint8_t *rxBuff, CommType *commType,
                              KNXServiceType *action) {
  *commType = COM_SENDING;
  *action   = ST_DESCRIPTION_RESPONSE;
}
void handleConnectRequest(const uint8_t *rxBuff, CommType *commType,
                          KNXServiceType *action) {
  /*
   * Need to check what type of connection the Client wants to
   * establish, on which layer, and whether a specific tunnel address is
   * provided. For now, only Tunnelling is supported, and only on
   * LinkLayer.
   */

  /* Use first byte of header to skip to CtrlHPAI */
  uint8_t i = rxBuff[0];
  /* Use first byte of CtrlHPAI to skip to DataHPAI */
  i += rxBuff[i];
  /* Use first byte of DataHPAI to skip to Connection Request Info */
  i += rxBuff[i];

  if (rxBuff[i + 1] == FAMILY_TUNNELLING && rxBuff[i + 2] == TUNNEL_LINKLAYER) {
    /* A CRI structure of length greater than 4 suggests
     * it's an extended CRI with an individual address
     * provided by the client for the tunnel as the last element.
     * In this case, we use that address for the tunnel,
     * otherwise we assign a default address 1.1.250. */
    server.tunnelIndivAddr = rxBuff[i] > 4
                                 ? htons(*(((uint16_t *)rxBuff + i + 4)))
                                 : KNX_DEFAULT_TUNNEL_ADDR;

    //            /* Build new server entity and store it in server list
    //            */ currentServer = KNXnetIPServerFactory(
    //                KNX_ENDPOINT_IP_ADDR, KNX_ENDPOINT_IP_ADDR,
    //                KNX_DEFAULT_ROUTER_ADDR, tunnelAddr);

    *commType = COM_SENDING;
    *action   = ST_CONNECT_RESPONSE;
  }
}
void handleConnectionStateRequest(const uint8_t *rxBuff, CommType *commType,
                                  KNXServiceType *action) {
  *commType = COM_SENDING;
  *action   = ST_CONNECTIONSTATE_RESPONSE;
}
void handleDisconnectRequest(const uint8_t *rxBuff, CommType *commType,
                             KNXServiceType *action) {
  *commType = COM_SENDING;
  *action   = ST_DISCONNECT_RESPONSE;
}
void handleSearchRequestExtended(const uint8_t *rxBuff, CommType *commType,
                                 KNXServiceType *action) {
  *commType = COM_SENDING;
  *action   = ST_SEARCH_RESPONSE_EXTENDED;
}
void handleTunnellingRequest(const uint8_t *rxBuff, CommType *commType,
                             KNXServiceType *action) {
  *commType = COM_SENDING;
  *action   = ST_TUNNELLING_ACK;
}
void handleTunnellingFeatureGet(const uint8_t *rxBuff, CommType *commType,
                                KNXServiceType *action) {
  *commType = COM_SENDING;
  *action   = ST_TUNNELLING_FEATURE_RESPONSE;
}
void handleTunnellingFeatureSet(const uint8_t *rxBuff, CommType *commType,
                                KNXServiceType *action) {
  *commType = COM_SENDING;
  *action   = ST_TUNNELLING_FEATURE_RESPONSE;
}

#pragma region Socket Functions

void initServer() {
  ZeroMemory(&wsaData, sizeof(wsaData));
  ZeroMemory(&mreq, sizeof(mreq));
  ZeroMemory(&server, sizeof(KNXnetIPServer));

  initSocket();
  bindSocket();
  joinMulticastGroup();

  /* Server's own KNX individual address */
  server.serverIndivAddr = KNX_DEFAULT_ROUTER_ADDR;
  /*
   * Server - Client communication tunnel's KNX individual address.
   * Set to a default for now, will be set to Client's wish if provided.
   */
  server.tunnelIndivAddr = KNX_DEFAULT_TUNNEL_ADDR;
}

void initSocket() {

  const int wsaStartupResult = WSAStartup(0x22, &wsaData);
  if (wsaStartupResult) {
    perror("Windows socket startup failed\n");
    exit(EXIT_FAILURE);
  }

  if ((serverSocket = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
    perror("Socket creation failed\n");
    exit(EXIT_FAILURE);
  }
}

void bindSocket() {
  server.serverAddr.sin_family = AF_INET;
  server.serverAddr.sin_port   = htons(KNX_PORT);
  if (!inet_pton(AF_INET, KNX_ENDPOINT_IP_ADDR,
                 &(server.serverAddr.sin_addr.S_un.S_addr))) {
    fprintf(stderr, "Configuring server IP address failed\nError: %d",
            WSAGetLastError());
    exit(EXIT_FAILURE);
  }
  if (bind(serverSocket, (const struct sockaddr *)&(server.serverAddr),
           sizeof(SOCKADDR_IN)) < 0) {
    fprintf(stderr, "Binding of socket failed\nError: %d", WSAGetLastError());
    exit(EXIT_FAILURE);
  }
}

void joinMulticastGroup() {
  mreq.imr_interface.S_un.S_addr = htonl(INADDR_ANY);
  if (!inet_pton(AF_INET, KNX_MULTICAST_ADDR,
                 &(mreq.imr_multiaddr.S_un.S_addr))) {
    fprintf(stderr, "Configuring multicast address failed\nError: %d",
            WSAGetLastError());
    exit(EXIT_FAILURE);
  }

  if (setsockopt(serverSocket, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                 (const char *)&mreq, sizeof(IP_MREQ)) < 0) {
    fprintf(stderr, "Joining multicast address group failed\nError: %d",
            WSAGetLastError());
    exit(EXIT_FAILURE);
  }
}

#pragma endregion Socket Functions

#pragma region Communication State Machine

void KNXnetIPCommStateMachine() {

#pragma region Setup Vars for bidirectional Communication

  uint8_t rxBuff[BUFF_LEN];
  uint8_t txBuff[BUFF_LEN];
  int recvLen             = 0;
  KNXServiceType recvSrvc = ST_NO_TYPE;
  CommType commType       = COM_RECEIVING;

#pragma endregion Setup Vars for bidirectional Communication

  while (TRUE) {

    switch (commType) {
    case COM_RECEIVING:
      recvLen = recv(serverSocket, (char *)rxBuff, BUFF_LEN, 0);
      if (recvLen < 0) {
        fprintf(stderr, "Receiving on socket failed\nError: %d",
                WSAGetLastError());
        exit(EXIT_FAILURE);
      }

      if (recvLen) {

        /*
         * The holy KNX Standard itself says,
         * this is a solid way to recognise KNX datagrams
         */
        if (*(uint16_t *)rxBuff != htons(0x0610))
          continue;

        char srvcStr[64];
        recvSrvc = htons(*(((uint16_t *)rxBuff) + 1));

        /* Service Identifier */
        switch (recvSrvc) {

        case ST_SEARCH_REQUEST:
          // handleSearchRequest(rxBuff, &commType, &action);
          strcpy_s(srvcStr, 64, "Search Request");
          break;

        case ST_DESCRIPTION_REQUEST:
          // handleDescriptionRequest(rxBuff, &commType, &action);
          strcpy_s(srvcStr, 64, "Description Request");
          break;

        case ST_CONNECT_REQUEST: {
          // handleConnectRequest(rxBuff, &commType, &action);
          strcpy_s(srvcStr, 64, "Connect Request");
        } break;

        case ST_CONNECTIONSTATE_REQUEST:
          // handleConnectionStateRequest(rxBuff, &commType, &action);
          strcpy_s(srvcStr, 64, "Connection State Request");
          break;

        case ST_DISCONNECT_REQUEST:
          // handleDisconnectRequest(rxBuff, &commType, &action);
          strcpy_s(srvcStr, 64, "Disconnect Request");
          break;

        case ST_SEARCH_REQUEST_EXTENDED:
          // handleSearchRequestExtended(rxBuff, &commType, &action);
          strcpy_s(srvcStr, 64, "Search Request Extended");
          break;

        case ST_TUNNELLING_REQUEST:
          // handleTunnellingRequest(rxBuff, &commType, &action);
          strcpy_s(srvcStr, 64, "Tunneling Request");
          break;

        case ST_TUNNELLING_FEATURE_GET:
          // handleTunnellingFeatureGet(rxBuff, &commType, &action);
          strcpy_s(srvcStr, 64, "Tunneling Feature Get");
          break;

        case ST_TUNNELLING_FEATURE_SET:
          // handleTunnellingFeatureSet(rxBuff, &commType, &action);
          strcpy_s(srvcStr, 64, "Tunneling Feature Set");
          break;

        default:
          recvSrvc = ST_NO_TYPE;
          strcpy_s(srvcStr, 64, "Message");
          continue;
          break;
        }

        printf("Received %s\n", srvcStr);

        for (int i = 0; i < recvLen; ++i) {
          printf("0x%x ", rxBuff[i]);
        }
        printf("\n\n");
        commType = COM_SENDING;
        // ZeroMemory(rxBuff, BUFF_LEN);
        // recvLen = 0;
      }
      break;

    case COM_SENDING: {
      char srvcStr[64];
      SOCKADDR_IN clientAddr;
      const uint16_t buffLen =
          prepareResponse(rxBuff, txBuff, recvSrvc, srvcStr, &clientAddr);

      if (buffLen > 0) {
        if (sendto(serverSocket, (const char *)txBuff, buffLen, 0,
                   (const struct sockaddr *)&clientAddr,
                   sizeof(SOCKADDR_IN)) <= 0) {
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
      }
      commType = COM_RECEIVING;
    } break;
    }
  }
}

#pragma endregion Communication State Machine