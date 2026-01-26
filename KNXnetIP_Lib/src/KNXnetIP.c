#include "KNXnetIP.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

///* Index in list will be used as Channel ID */
// KNXnetIPServerHandle serverList[MAX_NR_OF_SERVERS];
// uint8_t nrOfServers = 0;
WSADATA wsaData;
SOCKET serverSocket;
IP_MREQ mreq;
KNXnetIPServer server;

#pragma region KNX Buffer Write Subfunctions

uint16_t writeHPAIInBuff(uint8_t *buff, uint16_t *totalLen,
                         const SOCKADDR_IN *addr) {

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
                        const DibWriteList dibWriteList) {

  if (dibWriteList.deviceInfo) {
    Dib_DeviceInformation dib;
    dib.structLength     = sizeof(Dib_DeviceInformation);
    dib.dibTypeCode      = DIB_DEVICE_INFO;
    dib.knxMedium        = MED_TP1;
    dib.deviceStatus     = DEV_STAT_PROG_MODE_OFF;
    dib.knxIndivAddr     = htons(KNX_DEFAULT_ROUTER_ADDR);
    dib.projInstallIdent = 0x0000;
    memcpy(dib.knxDevSerialNum, server.knxSerialNum, 6);
    inet_pton(AF_INET, KNX_MULTICAST_ADDR, &(dib.knxDevRoutingMulticastAddr));
    memcpy(dib.knxDevMacAddr, server.macAddress, 6);
    memcpy(dib.knxDevFriendlyName, server.friendlyName, 30);

    memcpy(buff + *totalLen, &dib, sizeof(Dib_DeviceInformation));
    *totalLen += dib.structLength;
  }

  if (dibWriteList.suppSvcFamilies) {
    *(buff + (*totalLen)) = 10; //< Structure length
    ++(*totalLen);
    *(buff + (*totalLen)) = DIB_SUPP_SVC_FAMILIES;
    ++(*totalLen);
    *(uint16_t *)(buff + (*totalLen)) =
        MAKEWORD(FAMILY_CORE, server.svcFamilySupport[FAMILY_CORE]);
    (*totalLen) += 2;
    *(uint16_t *)(buff + (*totalLen)) =
        MAKEWORD(FAMILY_DEV_MGMT, server.svcFamilySupport[FAMILY_DEV_MGMT]);
    (*totalLen) += 2;
    *(uint16_t *)(buff + (*totalLen)) =
        MAKEWORD(FAMILY_TUNNELLING, server.svcFamilySupport[FAMILY_TUNNELLING]);
    (*totalLen) += 2;
    *(uint16_t *)(buff + (*totalLen)) =
        MAKEWORD(FAMILY_ROUTING, server.svcFamilySupport[FAMILY_ROUTING]);
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

#pragma region KNX Frame Interpreter

uint16_t prepareResponse(const uint8_t *rxBuff, uint8_t *txBuff,
                         const KNXServiceType recvSrvc, char *srvcStr,
                         SOCKADDR_IN *clientAddr) {

  clientAddr->sin_family = AF_INET;

  KNXnetIPHeader *rxKnxNetIpHeader = (KNXnetIPHeader *)rxBuff;
  rxKnxNetIpHeader->headerLength   = sizeof(KNXnetIPHeader);
  rxKnxNetIpHeader->protoVersion   = 0x10;
  uint16_t rxIdx                   = rxKnxNetIpHeader->headerLength;

  KNXnetIPHeader *txKnxNetIpHeader = (KNXnetIPHeader *)txBuff;
  txKnxNetIpHeader->headerLength   = sizeof(KNXnetIPHeader);
  txKnxNetIpHeader->protoVersion   = 0x10;
  uint16_t totalLen                = txKnxNetIpHeader->headerLength;

  switch (recvSrvc) {
  case ST_SEARCH_REQUEST: {

    /* Discovery HPAI structure */
    const Hpai discoveryHpai = *((Hpai *)(rxBuff + rxIdx));
    rxIdx += discoveryHpai.structLength;

    clientAddr->sin_addr.S_un.S_addr = discoveryHpai.ipAddr.DW_ipAddr;
    clientAddr->sin_port             = discoveryHpai.port.W_port;

    /* Response: ST_SEARCH_RESPONSE */

    /*
     * Common KNXnet/IP Header,
     * which is same in each KNXnet/IP frame
     */
    txKnxNetIpHeader->U_ServiceCode.W_ServiceCode = htons(ST_SEARCH_RESPONSE);

    /* HPAI Control Endpoint */
    writeHPAIInBuff(txBuff, &totalLen, &server.serverAddr);

    /* DIBs DevInfo, SupportedSvcFamilies */
    writeDIBInBuff(txBuff, &totalLen,
                   (DibWriteList){.deviceInfo = TRUE, .suppSvcFamilies = TRUE});

    strcpy_s(srvcStr, LOG_STR_BUFF_LEN, "Search Response");
  } break;

  case ST_DESCRIPTION_REQUEST: {

    /* Discovery HPAI structure */
    const Hpai discoveryHpai = *((Hpai *)(rxBuff + rxIdx));
    rxIdx += discoveryHpai.structLength;

    clientAddr->sin_addr.S_un.S_addr = discoveryHpai.ipAddr.DW_ipAddr;
    clientAddr->sin_port             = discoveryHpai.port.W_port;

    /* Response: ST_DESCRIPTION_RESPONSE */

    /*
     * Common KNXnet/IP Header,
     * which is same in each KNXnet/IP frame
     */
    txKnxNetIpHeader->U_ServiceCode.W_ServiceCode =
        htons(ST_DESCRIPTION_RESPONSE);

    /* DIBs DevInfo, SupportedSvcFamilies */
    writeDIBInBuff(txBuff, &totalLen,
                   (DibWriteList){.deviceInfo      = TRUE,
                                  .suppSvcFamilies = TRUE,
                                  .tunnInfo        = TRUE});

    strcpy_s(srvcStr, LOG_STR_BUFF_LEN, "Description Response");
  } break;

  case ST_CONNECT_REQUEST: {
    /* Control HPAI structure */
    const Hpai controlHpai = *((Hpai *)(rxBuff + rxIdx));
    rxIdx += controlHpai.structLength;

    /* Data HPAI structure */
    const Hpai dataHpai = *((Hpai *)(rxBuff + rxIdx));
    rxIdx += dataHpai.structLength;

    const Cri cri = *((Cri *)(rxBuff + rxIdx));

    server.clientCtrlHPAI.sin_family           = AF_INET;
    server.clientCtrlHPAI.sin_addr.S_un.S_addr = controlHpai.ipAddr.DW_ipAddr;
    server.clientCtrlHPAI.sin_port             = controlHpai.port.W_port;

    server.clientDataHPAI.sin_family           = AF_INET;
    server.clientDataHPAI.sin_addr.S_un.S_addr = dataHpai.ipAddr.DW_ipAddr;
    server.clientDataHPAI.sin_port             = dataHpai.port.W_port;

    /* Response: ST_CONNECT_RESPONSE */

    /*
     * Common KNXnet/IP Header,
     * which is same in each KNXnet/IP frame
     */

    memcpy(clientAddr, &server.clientCtrlHPAI, sizeof(SOCKADDR_IN));

    txKnxNetIpHeader->U_ServiceCode.W_ServiceCode = htons(ST_CONNECT_RESPONSE);

    *(txBuff + totalLen) = server.channelID; //< Channel ID
    ++totalLen;
    *(txBuff + totalLen) = 0x00; //< Status code
    ++totalLen;

    writeHPAIInBuff(txBuff, &totalLen, &server.serverAddr);
    writeCRDTunnConnInBuff(txBuff, &totalLen);

    server.isConnected = TRUE;

    strcpy_s(srvcStr, LOG_STR_BUFF_LEN, "Connect Response");
  } break;

  case ST_CONNECTIONSTATE_REQUEST: {
    if (rxBuff[rxIdx] != server.channelID)
      return totalLen;
    rxIdx += 2;
    /* Control HPAI structure */
    const Hpai controlHpai = *((Hpai *)(rxBuff + rxIdx));
    rxIdx += controlHpai.structLength;

    clientAddr->sin_addr.S_un.S_addr = controlHpai.ipAddr.DW_ipAddr;
    clientAddr->sin_port             = controlHpai.port.W_port;

    /* Response: ST_CONNECTIONSTATE_RESPONSE */

    /*
     * Common KNXnet/IP Header,
     * which is same in each KNXnet/IP frame
     */
    txKnxNetIpHeader->U_ServiceCode.W_ServiceCode =
        htons(ST_CONNECTIONSTATE_RESPONSE);

    /*
     * Communication Channel ID.
     * Always 1, because we won't support more channels for now.
     */
    *(txBuff + totalLen) = server.channelID;
    ++totalLen;
    *(txBuff + totalLen) = E_NO_ERROR; //< Status code
    ++totalLen;

    strcpy_s(srvcStr, LOG_STR_BUFF_LEN, "Connection State Response");
  } break;

  case ST_DISCONNECT_REQUEST: {
    if (rxBuff[rxIdx] != server.channelID)
      return totalLen;
    rxIdx += 2;
    /* Control HPAI structure */
    const Hpai controlHpai = *((Hpai *)(rxBuff + rxIdx));
    rxIdx += controlHpai.structLength;

    clientAddr->sin_addr.S_un.S_addr = controlHpai.ipAddr.DW_ipAddr;
    clientAddr->sin_port             = controlHpai.port.W_port;

    /* Response: ST_DISCONNECT_RESPONSE */

    /*
     * Common KNXnet/IP Header,
     * which is same in each KNXnet/IP frame
     */
    txKnxNetIpHeader->U_ServiceCode.W_ServiceCode =
        htons(ST_DISCONNECT_RESPONSE);

    /*
     * Communication Channel ID.
     * Always 1, because we won't support more channels for now.
     */
    *(txBuff + totalLen) = server.channelID;
    ++totalLen;
    *(txBuff + totalLen) = E_NO_ERROR; //< Status code
    ++totalLen;

    server.isConnected = FALSE;
    server.seqCntr     = 0;
    ZeroMemory(&server.clientCtrlHPAI, sizeof(SOCKADDR_IN));
    ZeroMemory(&server.clientDataHPAI, sizeof(SOCKADDR_IN));

    strcpy_s(srvcStr, LOG_STR_BUFF_LEN, "Disconnect Response");
  } break;

  case ST_SEARCH_REQUEST_EXTENDED: {

    /*
     * KNXnetIP Header is 6 bytes long, HPAI is 8 bytes long.
     * If total length is longer, there must be SRPs in the frame.
     */
    const BOOLEAN hasSrp =
        ntohs(rxKnxNetIpHeader->U_TotalLength.W_TotalLength) > 14;

    /* Discovery HPAI structure */
    Hpai discoveryHpai = *((Hpai *)(rxBuff + rxIdx));
    rxIdx += discoveryHpai.structLength;

    clientAddr->sin_addr.S_un.S_addr = discoveryHpai.ipAddr.DW_ipAddr;
    clientAddr->sin_port             = discoveryHpai.port.W_port;

    if (hasSrp) {
      const uint16_t rxTotalLen =
          ntohs(rxKnxNetIpHeader->U_TotalLength.W_TotalLength);
      while (rxIdx < rxTotalLen) {
        const uint8_t srpLen         = rxBuff[rxIdx++];
        uint8_t srpType              = rxBuff[rxIdx++];
        const BOOLEAN isSrpMandatory = srpType & 0x80;
        srpType &= 0x7F;
        switch (srpType) {

        case SRP_SELECT_BY_PROG_MODE:
          if (isSrpMandatory && !server.deviceStatus)
            return totalLen;
          break;

        case SRP_SELECT_BY_MAC_ADDR:
          if (isSrpMandatory && memcmp(rxBuff + rxIdx, &server.macAddress, 6))
            return totalLen;
          break;

        case SRP_SELECT_BY_SERVICE: {
          const uint8_t svcFamilyReq    = rxBuff[rxIdx++];
          const SrpType svcFamilyVerReq = rxBuff[rxIdx++];
          if (isSrpMandatory &&
              server.svcFamilySupport[svcFamilyReq] < svcFamilyVerReq)
            return totalLen;
        } break;

        case SRP_REQUEST_DIBS: {
          const uint8_t nrOfDibReq = srpLen - 2;
          const uint8_t lastDibIdx = rxIdx + nrOfDibReq;
          if (isSrpMandatory) {
            while (rxIdx < lastDibIdx) {
              if (rxBuff[rxIdx] > FAMILY_ROUTING)
                return totalLen;
              rxIdx++;
            }
          }
        } break;

        default:
          /* Just skip the SRP. -2, because we've already skipped 2 bytes. */
          rxIdx += (srpLen - 2);
        }
      }
    }
    /* Response: ST_SEARCH_RESPONSE */

    /*
     * Common KNXnet/IP Header,
     * which is same in each KNXnet/IP frame
     */
    txKnxNetIpHeader->U_ServiceCode.W_ServiceCode =
        htons(ST_SEARCH_RESPONSE_EXTENDED);

    /* HPAI Control Endpoint */
    writeHPAIInBuff(txBuff, &totalLen, &server.serverAddr);

    /* DIBs DevInfo, SupportedSvcFamilies */
    writeDIBInBuff(txBuff, &totalLen,
                   (DibWriteList){.deviceInfo      = TRUE,
                                  .suppSvcFamilies = TRUE,
                                  .tunnInfo        = TRUE});

    strcpy_s(srvcStr, LOG_STR_BUFF_LEN, "Search Response Extended");
  } break;

  case ST_TUNNELLING_REQUEST: {
    const ConnectionHeader rxConnHeader = *(ConnectionHeader *)(rxBuff + rxIdx);
    if (rxConnHeader.commChannelId != server.channelID)
      return totalLen;
    rxIdx += rxConnHeader.structLength;

    /* Response: ST_TUNNELLING_ACK */

    /* Common KNXnet/IP Header */
    txKnxNetIpHeader->U_ServiceCode.W_ServiceCode = htons(ST_TUNNELLING_ACK);
    /* Connection Header */
    ConnectionHeader *txConnHeader = (ConnectionHeader *)(txBuff + totalLen);
    memcpy(txConnHeader, &rxConnHeader, sizeof(ConnectionHeader));
    totalLen += txConnHeader->structLength;
    txConnHeader->seqCounter = server.seqCntr++;
    txConnHeader->status     = E_NO_ERROR;
  } break;

  case ST_TUNNELLING_FEATURE_GET:
  case ST_TUNNELLING_FEATURE_SET: {
    const ConnectionHeader rxConnHeader = *(ConnectionHeader *)(rxBuff + rxIdx);
    if (rxConnHeader.commChannelId != server.channelID)
      return totalLen;

    rxIdx += rxConnHeader.structLength;
    InterfaceFeature featureId = rxBuff[rxIdx];

    /* Response: ST_TUNNELLING_FEATURE_RESPONSE */

    /* Common KNXnet/IP Header */
    txKnxNetIpHeader->U_ServiceCode.W_ServiceCode =
        htons(ST_TUNNELLING_FEATURE_RESPONSE);
    /* Connection Header */
    ConnectionHeader *txConnHeader = (ConnectionHeader *)(txBuff + totalLen);
    memcpy(txConnHeader, &rxConnHeader, sizeof(ConnectionHeader));
    totalLen += txConnHeader->structLength;
    txConnHeader->seqCounter = server.seqCntr++;

    txBuff[totalLen++] = featureId;
    txBuff[totalLen++] = E_NO_ERROR;

    switch (recvSrvc) {
    case ST_TUNNELLING_FEATURE_GET:
      switch (featureId) {
      case IF_SUPPORTED_EMI_TYPE:
        *(uint16_t *)(txBuff + totalLen) =
            htons(*(uint16_t *)&server.InterfaceFeatureSet.supportedEmiType);
        totalLen += 2;
        break;
      case IF_DEVICE_DESCRIPTOR_TYPE_0:
        *(uint16_t *)(txBuff + totalLen) = htons(
            *(uint16_t *)&server.InterfaceFeatureSet.deviceDescriptorType);
        totalLen += 2;
        break;
      case IF_BUS_CONNECTION_STATUS:
        *(txBuff + totalLen) = server.InterfaceFeatureSet.busConnectionStatus;
        totalLen++;
        break;
      case IF_KNX_MANUFACTURER_CODE:
        *(uint16_t *)(txBuff + totalLen) =
            htons(*(uint16_t *)&server.InterfaceFeatureSet.knxManufacturerCode);
        totalLen += 2;
        break;
      case IF_ACTIVE_EMI_TYPE:
        *(txBuff + totalLen) = server.InterfaceFeatureSet.activeEmiType;
        totalLen++;
        break;
      case IF_INTERFACE_INDIVIDUAL_ADDRESS:
        *(uint16_t *)(txBuff + totalLen) =
            htons(*(uint16_t *)&server.InterfaceFeatureSet.interfaceIndivAddr);
        totalLen += 2;
        break;
      case IF_MAX_APDU_LENGTH:
        *(uint16_t *)(txBuff + totalLen) =
            htons(*(uint16_t *)&server.InterfaceFeatureSet.maxApduLength);
        totalLen += 2;
        break;
      case IF_INTERFACE_FEATURE_INFO_SERVICE_ENABLE:
        *(txBuff + totalLen) =
            server.InterfaceFeatureSet.interfaceFeatureInfoServEnable;
        totalLen++;
        break;
      default:
        txBuff[totalLen - 1] = E_ADDRESS_VOID;
        return totalLen;
        break;
      }
      break;
    case ST_TUNNELLING_FEATURE_SET:
      rxIdx += 2;
      switch (featureId) {
      case IF_INTERFACE_INDIVIDUAL_ADDRESS:
        server.InterfaceFeatureSet.interfaceIndivAddr =
            ntohs(*(uint16_t *)(rxBuff + rxIdx));
        memcpy(txBuff + totalLen, rxBuff + rxIdx, 2);
        totalLen += 2;
        rxIdx += 2;
        break;

      case IF_INTERFACE_FEATURE_INFO_SERVICE_ENABLE:
        server.InterfaceFeatureSet.interfaceFeatureInfoServEnable =
            txBuff[totalLen++] = rxBuff[rxIdx++];
        break;

      default: {
        if (featureId > IF_INTERFACE_FEATURE_INFO_SERVICE_ENABLE ||
            featureId < IF_SUPPORTED_EMI_TYPE)
          txBuff[totalLen - 1] = E_ADDRESS_VOID;
        else
          txBuff[totalLen - 1] = E_ACCESS_READ_ONLY;
      } break;
      }
      break;
    default:
      return FALSE;
      break;
    }

  } break;

  default:
    return totalLen;
    break;
  }

  txKnxNetIpHeader->U_TotalLength.W_TotalLength = htons(totalLen);

  return totalLen;
}

#pragma endregion KNX Frame Interpreter

#pragma region Socket Functions

void initServer() {
  ZeroMemory(&wsaData, sizeof(wsaData));
  ZeroMemory(&mreq, sizeof(mreq));
  ZeroMemory(&server, sizeof(KNXnetIPServer));

  initSocket();
  bindSocket();
  joinMulticastGroup();

  /* Versions of supported service families */
  server.svcFamilySupport[FAMILY_CORE]       = 2;
  server.svcFamilySupport[FAMILY_DEV_MGMT]   = 2;
  server.svcFamilySupport[FAMILY_TUNNELLING] = 2;
  server.svcFamilySupport[FAMILY_ROUTING]    = 2;
  memcpy(server.knxSerialNum, (uint8_t[6]){0x00, 0xc1, 0x77, 0x13, 0x52, 0x69},
         6);
  memcpy(server.macAddress, (uint8_t[6]){0x00, 0x72, 0x11, 0x37, 0x28, 0x42},
         6);
  memcpy(server.friendlyName, (uint8_t[30]){"KNX IP DoggoDevice"}, 30);

  server.InterfaceFeatureSet.supportedEmiType.cEMI = TRUE;
  server.InterfaceFeatureSet.deviceDescriptorType  = DDT_KNXNET_IP_ROUTER_091A;
  server.InterfaceFeatureSet.busConnectionStatus   = TRUE;
  server.InterfaceFeatureSet.knxManufacturerCode   = KNX_MANUFACTURER_CODE;
  server.InterfaceFeatureSet.activeEmiType         = EMI_CEMI;
  server.InterfaceFeatureSet.interfaceIndivAddr    = KNX_DEFAULT_TUNNEL_ADDR;
  server.InterfaceFeatureSet.maxApduLength         = MAX_APDU_LENGTH;
  server.InterfaceFeatureSet.interfaceFeatureInfoServEnable = FALSE;

  /* Server's own KNX individual address */
  server.serverIndivAddr = KNX_DEFAULT_ROUTER_ADDR;
  /*
   * Server - Client communication tunnel's KNX individual address.
   * Set to a default for now, will be set to Client's wish if provided.
   */
  server.tunnelIndivAddr = KNX_DEFAULT_TUNNEL_ADDR;

  /* Fetch local IPv4 of Ethernet interface */
#define HOST_NAME_LEN 250
  char hostName[HOST_NAME_LEN];
  ZeroMemory(hostName, HOST_NAME_LEN);
  if (gethostname(hostName, HOST_NAME_LEN)) {
    fprintf(stderr, "Fetching host name failed\nError: %d", WSAGetLastError());
    exit(EXIT_FAILURE);
  }

  ADDRINFO *addrList = NULL;
  if (getaddrinfo(hostName, NULL, NULL, &addrList)) {
    fprintf(stderr, "Fetching host name failed\nError: %d", WSAGetLastError());
    exit(EXIT_FAILURE);
  }
  ADDRINFO *sockAddr = addrList;
  while (sockAddr) {
    if (sockAddr->ai_family == AF_INET)
      break;
    sockAddr = sockAddr->ai_next;
  }
  if (!sockAddr) {
    fprintf(stderr, "Fetching local IPv4 interface address failed\nError: %d",
            WSAGetLastError());
    exit(EXIT_FAILURE);
  }
  server.serverAddr          = *(SOCKADDR_IN *)sockAddr->ai_addr;
  server.serverAddr.sin_port = htons(KNX_PORT);

#undef HOST_NAME_LEN
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