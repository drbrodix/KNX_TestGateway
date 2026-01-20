#ifndef KNX_TESTGATEWAY_KNXNETIP_H
#define KNX_TESTGATEWAY_KNXNETIP_H

#include <stdint.h>
#include <ws2tcpip.h>

#pragma region Definitions

#define LOG_STR_BUFF_LEN        64
#define BUFF_LEN                128
#define KNX_PORT                3671
#define KNX_MULTICAST_ADDR      "224.0.23.12"
#define KNX_ENDPOINT_IP_ADDR    "10.56.2.123"
#define KNX_DEFAULT_ROUTER_ADDR 0xFF00
#define KNX_DEFAULT_TUNNEL_ADDR 0x11FA
#define KNX_MANUFACTURER_CODE   0x4269
#define MAX_APDU_LENGTH         50
// #define MAX_NR_OF_SERVERS       5

typedef enum CommType { COM_RECEIVING, COM_SENDING } CommType;

typedef enum KNXServiceFamily {
  FAMILY_CORE             = 0x02,
  FAMILY_DEV_MGMT         = 0x03,
  FAMILY_TUNNELLING       = 0x04,
  FAMILY_ROUTING          = 0x05,
  FAMILY_REMOTE_LOGGING   = 0x06,
  FAMILY_REMOTE_CONF_DIAG = 0x07,
  FAMILY_OBJ_SERVER       = 0x08,
  FAMILY_SECURITY         = 0x09,
} KNXServiceFamily;

typedef enum KNXConnectionType {
  DEVICE_MGMT_CONNECTION = 0x03,
  TUNNEL_CONNECTION      = 0x04,
  REMLOG_CONNECTION      = 0x06,
  REMCONF_CONNECTION     = 0x07,
  OBJSVR_CONNECTION      = 0x08
} KNXConnectionType;

typedef enum KNXDescriptionType {
  DIB_DEVICE_INFO       = 0x01,
  DIB_SUPP_SVC_FAMILIES = 0x02,
  DIB_IP_CONFIG         = 0x03,
  DIB_IP_CUR_CONFIG     = 0x04,
  DIB_KNX_ADDRESSES     = 0x05,
  DIB_TUNNELLING_INFO   = 0x07,
  DIB_EXT_DEV_INFO      = 0x08,
  DIB_MFR_DATA          = 0xFE,
} KNXDescriptionType;

typedef enum KNXMedium {
  MED_TP1    = 0x02,
  MED_PL110  = 0x04,
  MED_RF     = 0x10,
  MED_KNX_IP = 0x20
} KNXMedium;

typedef enum DeviceStatus {
  DEV_STAT_PROG_MODE_OFF = 0x00,
  DEV_STAT_PROG_MODE_ON  = 0x01
} DeviceStatus;

typedef enum HostProtocol {
  HP_IPV4_UDP = 0x01,
  HP_IPV4_TCP = 0x02
} HostProtocol;

typedef enum TunnellingLayer {
  TUNNEL_LINKLAYER  = 0x02,
  TUNNEL_RAW        = 0x04,
  TUNNEL_BUSMONITOR = 0x80
} TunnellingLayer;

typedef enum ConnectionError {
  /* Common KNXnet/IP Error Codes */

  // Operation successful
  E_NO_ERROR = 0x00,
  // The requested host protocol is not supported by the KNXnet/IP device.
  E_HOST_PROTOCOL_TYPE = 0x01,
  // The requested protocol version is not supported by the KNXnet/IP device.
  E_VERSION_NOT_SUPPORTED = 0x02,
  // The received sequence number is out of order.
  E_SEQUENCE_NUMBER = 0x04,
  // Any further undefined, possibly implementation specific error has occurred.
  E_ERROR = 0x0F,

  /* Common CONNECT_RESPONSE status codes */
  // The KNXnet/IP Server device does not support the requested connection type.
  E_CONNECTION_TYPE = 0x22,
  // The KNXnet/IP Server device does not support one or more requested
  // connection options.
  E_CONNECTION_OPTION = 0x23,
  // The KNXnet/IP Server device cannot accept the new data connection because
  // its maximum amount of concurrent connections is already used.
  E_NO_MORE_CONNECTIONS = 0x24,
  // The Client is not authorised to establish the requested connection
  // The Client is not authorised to use the requested IA in the Extended CRI.
  E_AUTHORISATION_ERROR = 0x28,
  // The IA requested in the Extended CRI is not a Tunnelling IA.
  E_NO_TUNNELLING_ADDRESS = 0x2D,
  // The IA requested for this connection is in use.
  E_CONNECTION_IN_USE = 0x2E,

  /* CONNECTIONSTATE_RESPONSE status codes */

  // The KNXnet/IP Server device cannot find an active data connection with the
  // specified ID.
  E_CONNECTION_ID = 0x21,
  // The KNXnet/IP Server device detects an error concerning the data connection
  // with the specified ID.
  E_DATA_CONNECTION = 0x26,
  // The KNXnet/IP Server device detects an error concerning the KNX connection
  // with the specified ID.
  E_KNX_CONNECTION = 0x27,

  /* Tunnelling CONNECT_ACK error codes */

  // The KNXnet/IP Server device does not support the requested KNXnet/IP
  // Tunnelling layer.
  E_TUNNELLING_LAYER = 0x29,

  /* Application Layer Error Codes */

  // memory cannot be accessed or only with fault(s)
  E_MEMORY_ERROR = 0xF1,
  // Requested data will not fit into a Frame supported by this server.
  // This shall be used for Device limitations of the maximum supported Frame
  // length by accessing resources (Properties, Function Properties, memory…)
  // of the device.
  E_LENGTH_EXCEEDS_MAX_APDU_LENGTH = 0xF4,
  // This means that one wants to write data beyond what is reserved for the
  // addressed Resource.
  E_DATA_OVERFLOW = 0xF5,
  // Write value too low.
  E_DATA_MIN = 0xF6,
  // Write value too high.
  E_DATA_MAX = 0xF7,
  // This shall mean that the service or the function (Property) is supported,
  // but the request data is not valid for this receiver. This value shall also
  // be given if the requested data contains an enumeration value that is not
  // supported, in between the supported ranges.
  E_DATA_VOID = 0xF8,
  // This shall mean that the data could in generally be written,
  // but that it is not possible at this time because
  // - another MaC is accessing the data, or
  // - the data is currently being processed by the MaS
  E_TEMPORARILY_NOT_AVAILABLE = 0xF9,
  // This shall mean that a read access is attempted to a “write only” service
  // or Resource. This shall be for Resources (Properties, Function Properties,
  // memory…) etc. that can be written, but that cannot be read.
  E_ACCESS_WRITE_ONLY = 0xFA,
  // This shall mean that a write access is attempted to a “read only” service
  // or Resource. This shall be for Resources (Properties, Function Properties,
  // memory…) etc. that can be read, but that cannot be written.
  E_ACCESS_READ_ONLY = 0xFB,
  // This shall mean that the access to the data or function is denied because
  // of authorisation reasons, A_Authorize as well as KNX Security.
  E_ACCESS_DENIED = 0xFC,
  // The Interface Object or the Property is not present,
  // or the index is out of range.
  E_ADDRESS_VOID = 0xFD,
  // Write access with a wrong datatype (Datapoint length)
  E_DATA_TYPE_CONFLICT = 0xFE

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
  ST_TUNNELLING_REQUEST           = 0x0420,
  ST_TUNNELLING_ACK               = 0x0421,
  ST_TUNNELLING_FEATURE_GET       = 0x0422,
  ST_TUNNELLING_FEATURE_RESPONSE  = 0x0423,
  ST_TUNNELLING_FEATURE_SET       = 0x0424,
  ST_TUNNELLING_FEATURE_INFO      = 0x0425,
  ST_ROUTING_INDICATION           = 0x0530,
  ST_ROUTING_LOST_MESSAGE         = 0x0531,
  ST_ROUTING_BUSY                 = 0x0532
} KNXServiceType;

typedef enum DeviceDescriptorType {
  DDT_BCU_1_SYSTEM_1_0010          = 0x0010,
  DDT_BCU_1_SYSTEM_1_0011          = 0x0011,
  DDT_BCU_1_SYSTEM_1_0012          = 0x0012,
  DDT_BCU_1_SYSTEM_1_0013          = 0x0013,
  DDT_BCU_2_SYSTEM_2_0020          = 0x0020,
  DDT_BCU_2_SYSTEM_2_0021          = 0x0021,
  DDT_BCU_2_SYSTEM_2_0025          = 0x0025,
  DDT_SYSTEM_300_0300              = 0x0300,
  DDT_TP1_USB_INTERFACE_V1_0310    = 0x0310,
  DDT_TP1_USB_INTERFACE_V2_0311    = 0x0311,
  DDT_BIM_M112_0700                = 0x0700,
  DDT_BIM_M112_0701                = 0x0701,
  DDT_BIM_M112_0705                = 0x0705,
  DDT_SYSTEM_B_07B0                = 0x07B0,
  DDT_IR_DECODER_0810              = 0x0810,
  DDT_IR_DECODER_0811              = 0x0811,
  DDT_COUPLER_1_0_0910             = 0x0910,
  DDT_COUPLER_1_1_0911             = 0x0911,
  DDT_COUPLER_1_2_0912             = 0x0912,
  DDT_KNXNET_IP_ROUTER_091A        = 0x091A,
  DDT_NONE_SEE_V06_PROFILES_0AFD   = 0x0AFD,
  DDT_NONE_SEE_V06_PROFILES_0AFE   = 0x0AFE,
  DDT_BCU_1_1012                   = 0x1012,
  DDT_BCU_1_1013                   = 0x1013,
  DDT_PL110_USB_INTERFACE_V1_1310  = 0x1310,
  DDT_PL110_USB_INTERFACE_V2_1311  = 0x1311,
  DDT_SYSTEM_B_17B0                = 0x17B0,
  DDT_MEDIA_COUPLER_PL_TP_1900     = 0x1900,
  DDT_BI_DIRECTIONAL_DEVICES_2010  = 0x2010,
  DDT_UNI_DIRECTIONAL_DEVICES_2110 = 0x2110,
  DDT_RF_USB_INTERFACE_V2_2311     = 0x2311,
  DDT_BCU_1_3012                   = 0x3012,
  DDT_BCU_1_4012                   = 0x4012,
  DDT_SYSTEM_7_5705                = 0x5705,
  DDT_SYSTEM_B_57B0                = 0x57B0
} DeviceDescriptorType;

typedef enum InterfaceFeature {
  IF_SUPPORTED_EMI_TYPE                    = 1,
  IF_DEVICE_DESCRIPTOR_TYPE_0              = 2,
  IF_BUS_CONNECTION_STATUS                 = 3,
  IF_KNX_MANUFACTURER_CODE                 = 4,
  IF_ACTIVE_EMI_TYPE                       = 5,
  IF_INTERFACE_INDIVIDUAL_ADDRESS          = 6,
  IF_MAX_APDU_LENGTH                       = 7,
  IF_INTERFACE_FEATURE_INFO_SERVICE_ENABLE = 8
} InterfaceFeature;

typedef enum ActiveEmiType {
  EMI_EMI1 = 1,
  EMI_EMI2 = 2,
  EMI_CEMI = 3
} ActiveEmiType;

typedef struct SupportedEMIType {
  uint16_t EMI1     : 1;
  uint16_t EMI2     : 1;
  uint16_t cEMI     : 1;
  uint16_t _padding : 13;
} SupportedEMIType;

typedef struct InterfaceFeatureSet {
  SupportedEMIType supportedEmiType;
  DeviceDescriptorType deviceDescriptorType;
  BOOLEAN busConnectionStatus;
  uint16_t knxManufacturerCode;
  ActiveEmiType activeEmiType;
  uint16_t interfaceIndivAddr;
  uint16_t maxApduLength;
  BOOLEAN interfaceFeatureInfoServEnable;
} InterfaceFeatureSet;

typedef struct KNXnetIPServer {
  BOOLEAN isConnected;
  uint8_t channelID;
  uint32_t seqNr;
  uint16_t serverIndivAddr;
  uint16_t tunnelIndivAddr;
  SOCKADDR_IN serverAddr;
  SOCKADDR_IN clientCtrlHPAI;
  SOCKADDR_IN clientDataHPAI;
} KNXnetIPServer;

typedef union U_IpAddr {
  uint32_t DW_ipAddr;
  struct {
    uint8_t ipAddrB1;
    uint8_t ipAddrB2;
    uint8_t ipAddrB3;
    uint8_t ipAddrB4;
  } S_B_ipAddr;
} U_IpAddr;

typedef union U_Port {
  uint16_t W_port;
  struct {
    uint8_t portB1;
    uint8_t portB2;
  } S_B_port;
} U_Port;

typedef struct __attribute__((packed)) KNXnetIPHeader {
  uint8_t headerLength;
  uint8_t protoVersion;
  union {
    uint16_t W_ServiceCode;
    struct {
      uint8_t ServiceCodeB1;
      uint8_t ServiceCodeB2;
    } S_B_ServiceCode;
  } U_ServiceCode;
  union {
    uint16_t W_TotalLength;
    struct {
      uint8_t TotalLengthB1;
      uint8_t TotalLengthB2;
    } S_B_TotalLength;
  } U_TotalLength;
} KNXnetIPHeader;

typedef struct __attribute__((packed)) Hpai {
  uint8_t structLength;
  uint8_t hostProtoCode;
  U_IpAddr ipAddr;
  U_Port port;
} Hpai;

typedef struct Cri {
  uint8_t structLength;
  uint8_t connTypeCode;
  uint8_t knxLayer;
} Cri;

typedef struct __attribute__((packed)) Dib_DeviceInformation {
  uint8_t structLength;
  uint8_t dibTypeCode;
  uint8_t knxMedium;
  uint8_t deviceStatus;
  uint16_t knxIndivAddr;
  uint16_t projInstallIdent;
  uint8_t knxDevSerialNum[6];
  uint32_t knxDevRoutingMulticastAddr;
  uint8_t knxDevMacAddr[6];
  uint8_t knxDevFriendlyName[30];
} Dib_DeviceInformation;

typedef struct FeatureGetBody {
  uint8_t structLength;
  uint8_t commChannelId;
  uint8_t knxLayer;
} FeatureGetBody;

typedef struct DibWriteList {
  uint8_t deviceInfo      : 1;
  uint8_t suppSvcFamilies : 1;
  uint8_t ipConfig        : 1;
  uint8_t ipCurConfig     : 1;
  uint8_t knxAddresses    : 1;
  uint8_t mfrData         : 1;
  uint8_t tunnInfo        : 1;
  uint8_t extDvcInfo      : 1;
} DibWriteList;

#pragma endregion Definitions

#pragma region Function Declarations

uint16_t writeKNXHeaderInBuff(uint8_t *buff, uint16_t *totalLen,
                              KNXServiceType action);
uint16_t writeHPAIInBuff(uint8_t *buff, uint16_t *totalLen, SOCKADDR_IN *addr);
uint16_t writeDIBInBuff(uint8_t *buff, uint16_t *totalLen,
                        DibWriteList dibWriteList);
uint16_t writeCRDTunnConnInBuff(uint8_t *buff, uint16_t *totalLen);
uint16_t writeKNXConnHeaderInBuff(uint8_t *buff, uint16_t *totalLen);
uint16_t prepareResponse(const uint8_t *rxBuff, uint8_t *txBuff,
                         KNXServiceType recvSrvc, char *srvcStr,
                         SOCKADDR_IN *clientAddr);

void initServer();
void initSocket();
void bindSocket();
void joinMulticastGroup();

// KNXnetIPServerHandle KNXnetIPServerFactory(char *ctrlIP, char *dataIP,
//                                            uint16_t serverIndivAddr,
//                                            uint16_t tunnelIndivAddr);
// void KNXnetIPServerDelete(KNXnetIPServerHandle server);

void KNXnetIPCommStateMachine();

#pragma endregion Function Declarations

#endif // KNX_TESTGATEWAY_KNXNETIP_H