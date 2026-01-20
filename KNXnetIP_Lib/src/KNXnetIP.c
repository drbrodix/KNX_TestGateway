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

  KNXnetIPHeader header;
  header.headerLength                = sizeof(KNXnetIPHeader);
  header.protoVersion                = 0x10;
  header.U_ServiceCode.W_ServiceCode = htons(action);
  /* Total length will be filled later on */
  memcpy((buff + *totalLen), &header, sizeof(KNXnetIPHeader));
  *totalLen += header.headerLength;

  return (*totalLen);
}

uint16_t writeHPAIInBuff(uint8_t *buff, uint16_t *totalLen, SOCKADDR_IN *addr) {

  Hpai hpai;
  hpai.structLength     = sizeof(Hpai);
  hpai.hostProtoCode    = HP_IPV4_UDP;
  hpai.ipAddr.DW_ipAddr = addr->sin_addr.S_un.S_addr;
  hpai.port.W_port      = addr->sin_port;
  memcpy((buff + *totalLen), &hpai, sizeof(Hpai));
  *totalLen += hpai.structLength;

  return (*totalLen);
}

uint16_t writeDIBInBuff(uint8_t *buff, uint16_t *totalLen,
                        DibWriteList dibWriteList) {

  if (dibWriteList.deviceInfo) {
    const uint8_t knxSerialNum[6]  = {0x00, 0xc1, 0x77, 0x13, 0x52, 0x69};
    const uint8_t macAddr[6]       = {0x00, 0x72, 0x11, 0x37, 0x28, 0x42};
    const uint8_t friendlyName[30] = "KNX IP DoggoDevice";

    Dib_DeviceInformation dib;
    dib.structLength     = sizeof(Dib_DeviceInformation);
    dib.dibTypeCode      = DIB_DEVICE_INFO;
    dib.knxMedium        = MED_TP1;
    dib.deviceStatus     = DEV_STAT_PROG_MODE_OFF;
    dib.knxIndivAddr     = htons(KNX_DEFAULT_ROUTER_ADDR);
    dib.projInstallIdent = 0x0000;
    memcpy(dib.knxDevSerialNum, knxSerialNum, 6);
    inet_pton(AF_INET, KNX_MULTICAST_ADDR, &(dib.knxDevRoutingMulticastAddr));
    memcpy(dib.knxDevMacAddr, macAddr, 6);
    memcpy(dib.knxDevFriendlyName, friendlyName, 30);

    memcpy(buff + *totalLen, &dib, sizeof(Dib_DeviceInformation));
    *totalLen += dib.structLength;
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

#pragma endregion KNX Buffer Write Subfunctions

#pragma region KNX Frame Factory

uint16_t prepareResponse(const uint8_t *rxBuff, uint8_t *txBuff,
                         KNXServiceType recvSrvc, char *srvcStr,
                         SOCKADDR_IN *clientAddr) {

  uint16_t totalLen         = 0;
  const uint8_t totalLenInd = 4;

  clientAddr->sin_family = AF_INET;

  uint8_t rxIdx = 0;

  KNXnetIPHeader knxNetIpHeader = *(KNXnetIPHeader *)rxBuff;
  rxIdx += knxNetIpHeader.headerLength;

  switch (recvSrvc) {
  case ST_SEARCH_REQUEST: {

    /* Discovery HPAI structure */
    Hpai discoveryHpai = *((Hpai *)(rxBuff + rxIdx));
    rxIdx += discoveryHpai.structLength;

    clientAddr->sin_addr.S_un.S_addr = discoveryHpai.ipAddr.DW_ipAddr;
    clientAddr->sin_port             = discoveryHpai.port.W_port;

    /* Response: ST_SEARCH_RESPONSE */

    /*
     * Common KNXnet/IP Header,
     * which is same in each KNXnet/IP frame
     */
    writeKNXHeaderInBuff(txBuff, &totalLen, ST_SEARCH_RESPONSE);

    /* HPAI Control Endpoint */
    writeHPAIInBuff(txBuff, &totalLen, &server.serverAddr);

    /* DIBs DevInfo, SupportedSvcFamilies */
    writeDIBInBuff(txBuff, &totalLen,
                   (DibWriteList){.deviceInfo = TRUE, .suppSvcFamilies = TRUE});

    strcpy_s(srvcStr, LOG_STR_BUFF_LEN, "Search Response");
  } break;

  case ST_DESCRIPTION_REQUEST: {

    /* Discovery HPAI structure */
    Hpai discoveryHpai = *((Hpai *)(rxBuff + rxIdx));
    rxIdx += discoveryHpai.structLength;

    clientAddr->sin_addr.S_un.S_addr = discoveryHpai.ipAddr.DW_ipAddr;
    clientAddr->sin_port             = discoveryHpai.port.W_port;

    /* Response: ST_DESCRIPTION_RESPONSE */

    /*
     * Common KNXnet/IP Header,
     * which is same in each KNXnet/IP frame
     */
    writeKNXHeaderInBuff(txBuff, &totalLen, ST_DESCRIPTION_RESPONSE);

    /* DIBs DevInfo, SupportedSvcFamilies */
    writeDIBInBuff(txBuff, &totalLen,
                   (DibWriteList){.deviceInfo      = TRUE,
                                  .suppSvcFamilies = TRUE,
                                  .tunnInfo        = TRUE});

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

    writeHPAIInBuff(txBuff, &totalLen, &server.serverAddr);
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

    /* Discovery HPAI structure */
    Hpai discoveryHpai = *((Hpai *)(rxBuff + rxIdx));
    rxIdx += discoveryHpai.structLength;

    clientAddr->sin_addr.S_un.S_addr = discoveryHpai.ipAddr.DW_ipAddr;
    clientAddr->sin_port             = discoveryHpai.port.W_port;

    /* Response: ST_SEARCH_RESPONSE */

    /*
     * Common KNXnet/IP Header,
     * which is same in each KNXnet/IP frame
     */
    writeKNXHeaderInBuff(txBuff, &totalLen, ST_SEARCH_RESPONSE_EXTENDED);

    /* HPAI Control Endpoint */
    writeHPAIInBuff(txBuff, &totalLen, &server.serverAddr);

    /* DIBs DevInfo, SupportedSvcFamilies */
    writeDIBInBuff(txBuff, &totalLen,
                   (DibWriteList){.deviceInfo      = TRUE,
                                  .suppSvcFamilies = TRUE,
                                  .tunnInfo        = TRUE});

    strcpy_s(srvcStr, LOG_STR_BUFF_LEN, "Search Response Extended");
  } break;

  case ST_TUNNELLING_REQUEST:

    break;

  case ST_TUNNELLING_FEATURE_GET: {

  } break;

  case ST_TUNNELLING_FEATURE_SET:

    break;

  default:
    return totalLen;
    break;
  }

  *(uint16_t *)(txBuff + totalLenInd) = htons(totalLen);

  return totalLen;
}

#pragma endregion KNX Frame Factory

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
  /* Server's physical Ethernet interface IP address */
  server.serverAddr.sin_family = AF_INET;
  server.serverAddr.sin_port   = htons(KNX_PORT);
  if (!inet_pton(AF_INET, KNX_ENDPOINT_IP_ADDR,
                 &(server.serverAddr.sin_addr.S_un.S_addr))) {
    fprintf(stderr,
            "Configuring Server Ethernet interface address failed\nError: %d",
            WSAGetLastError());
    exit(EXIT_FAILURE);
  }
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
  SOCKADDR_IN listenAddr;
  ZeroMemory(&listenAddr, sizeof(SOCKADDR_IN));
  listenAddr.sin_family           = AF_INET;
  listenAddr.sin_port             = htons(KNX_PORT);
  listenAddr.sin_addr.S_un.S_addr = INADDR_ANY;
  if (bind(serverSocket, (const struct sockaddr *)&listenAddr,
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