#ifndef KNX_TESTGATEWAY_KNXNETIP_H
#define KNX_TESTGATEWAY_KNXNETIP_H

#include <stdint.h>
#include <ws2tcpip.h>

#pragma region Definitions

#define LOG_STR_BUFF_LEN          64
#define BUFF_LEN                  128
#define KNX_PORT                  3671
#define KNX_MULTICAST_ADDR        "224.0.23.12"
#define KNX_CTRL_ENDPOINT_IP_ADDR "10.56.2.124"

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

#pragma region Function Declarations

uint16_t writeKNXHeaderInBuff(uint8_t *buff, uint16_t *totalLen,
                              KNXServiceType action);
uint16_t writeHPAIInBuff(uint8_t *buff, uint16_t *totalLen);
uint16_t writeDIBDevInfoInBuff(uint8_t *buff, uint16_t *totalLen);
uint16_t writeCRDTunnConnInBuff(uint8_t *buff, uint16_t *totalLen);
uint16_t writeDIBSSInBuff(uint8_t *buff, uint16_t *totalLen);
uint16_t writeKNXConnHeaderInBuff(uint8_t *buff, uint16_t *totalLen);
uint16_t writeInBuff(uint8_t *buff, KNXServiceType action, char *logStrBuff);

void initSocket(WSADATA *wsaData, SOCKET *serverSocket);
void bindSocket(SOCKET serverSocket, SOCKADDR_IN *serverAddr);
void joinMulticastGroup(SOCKET serverSocket, IP_MREQ *mreq);

void KNXnetIPCommStateMachine(SOCKET serverSocket, SOCKADDR_IN *serverAddr,
                              SOCKADDR_IN *clientAddr);

#pragma endregion Function Declarations

#endif // KNX_TESTGATEWAY_KNXNETIP_H
