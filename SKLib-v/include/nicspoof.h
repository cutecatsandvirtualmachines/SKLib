#pragma once

#include "ioctlhook.h"
#include <IPTypes.h>

namespace nics {
	bool Spoof(DWORD64 seed = TEST_SEED);
}

#define IOCTL_NSI_GETALLPARAM (0x0012001B)
#define IOCTL_NSI_ARP_SOMETHING (0x12000F)

#define NSI_GET_INTERFACE_INFO (1) 
#define NSI_GET_IP_NET_TABLE   (11)

#define IOCTL_NDIS_QUERY_GLOBAL_STATS \
    CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD, 0, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_TCP_QUERY_INFORMATION_EX \
	    CTL_CODE(FILE_DEVICE_NETWORK, 0, METHOD_NEITHER, FILE_ANY_ACCESS)

#define OID_802_3_PERMANENT_ADDRESS			0x01010101
#define OID_802_3_CURRENT_ADDRESS			0x01010102
#define OID_802_5_PERMANENT_ADDRESS         0x02010101
#define OID_802_5_CURRENT_ADDRESS           0x02010102
#define OID_WAN_PERMANENT_ADDRESS		   	0x04010101
#define OID_WAN_CURRENT_ADDRESS			 	0x04010102
#define OID_ARCNET_PERMANENT_ADDRESS		0x06010101
#define OID_ARCNET_CURRENT_ADDRESS		  	0x06010102
#define IF_MAX_PHYS_ADDRESS_LENGTH			32
#define MAX_PHYSADDR_SIZE					8

typedef enum _NT_NSI_PARAM_TYPE
{
	NsiUdp = 1,
	NsiTcp = 3
} NT_NSI_PARAM_TYPE;

typedef struct _NT_NSI_TCP_SUBENTRY
{
	BYTE Reserved1[2];
	USHORT Port;
	ULONG IpAddress;
	BYTE IpAddress6[16];
	BYTE Reserved2[4];
} NT_NSI_TCP_SUBENTRY, * PNT_NSI_TCP_SUBENTRY;

typedef struct _NT_NSI_TCP_ENTRY
{
	NT_NSI_TCP_SUBENTRY Local;
	NT_NSI_TCP_SUBENTRY Remote;
} NT_NSI_TCP_ENTRY, * PNT_NSI_TCP_ENTRY;

typedef struct _NT_NSI_UDP_ENTRY
{
	BYTE Reserved1[2];
	USHORT Port;
	ULONG IpAddress;
	BYTE IpAddress6[16];
	BYTE Reserved2[4];
} NT_NSI_UDP_ENTRY, * PNT_NSI_UDP_ENTRY;

typedef struct _NT_NSI_STATUS_ENTRY
{
	ULONG State;
	BYTE Reserved[8];
} NT_NSI_STATUS_ENTRY, * PNT_NSI_STATUS_ENTRY;

typedef struct _NT_NSI_PROCESS_ENTRY
{
	ULONG UdpProcessId;
	ULONG Reserved1;
	ULONG Reserved2;
	ULONG TcpProcessId;
	ULONG Reserved3;
	ULONG Reserved4;
	ULONG Reserved5;
	ULONG Reserved6;
} NT_NSI_PROCESS_ENTRY, * PNT_NSI_PROCESS_ENTRY;

typedef struct _NT_NSI_PARAM
{
	// It was really daunting to figure out the contents of this struct...
	// There are lots of examples online with "LPVOID Unknown1, Unknown2" and so on.
	// However, this should be as close to the actual structure as it gets:

	SIZE_T Reserved1;
	SIZE_T Reserved2;
	LPVOID ModuleId;
	NT_NSI_PARAM_TYPE Type;
	ULONG Reserved3;
	ULONG Reserved4;
	LPVOID Entries;
	SIZE_T EntrySize;
	LPVOID Reserved5;
	SIZE_T Reserved6;
	LPVOID StatusEntries;
	SIZE_T StatusEntrySize;
	LPVOID ProcessEntries;
	SIZE_T ProcessEntrySize;
	SIZE_T Count;
} NT_NSI_PARAM, * PNT_NSI_PARAM;

typedef struct _NSI_PARAMS {
	__int64 field_0;
	__int64 field_8;
	__int64 field_10;
	int Type;
	int field_1C;
	int field_20;
	int field_24;
	char field_42;
	__int64 AddrTable;
	int AddrEntrySize;
	int field_34;
	__int64 NeighborTable;
	int NeighborTableEntrySize;
	int field_44;
	__int64 StateTable;
	int StateTableEntrySize;
	int field_54;
	__int64 OwnerTable;
	int OwnerTableEntrySize;
	int field_64;
	int Count;
	int field_6C;
} NSI_PARAMS, * PNSI_PARAMS;

typedef struct _NIC_DRIVER {
	PDRIVER_OBJECT DriverObject;
	PDRIVER_DISPATCH Original;
} NIC_DRIVER, * PNIC_DRIVER;

struct NICS {
	DWORD Length;
	NIC_DRIVER Drivers[0xFF];
};

typedef struct _NDIS_IF_BLOCK {
	char _padding_0[0x464];
	IF_PHYSICAL_ADDRESS_LH ifPhysAddress; // 0x464
	IF_PHYSICAL_ADDRESS_LH PermanentPhysAddress; // 0x486
} NDIS_IF_BLOCK, * PNDIS_IF_BLOCK;

typedef struct _KSTRING {
	char _padding_0[0x10];
	WCHAR Buffer[1]; // 0x10 at least
} KSTRING, * PKSTRING;

typedef struct _NDIS_FILTER_BLOCK {
	char _padding_0[0x8];
	struct _NDIS_FILTER_BLOCK* NextFilter; // 0x8
	char _padding_1[0x18];
	PKSTRING FilterInstanceName; // 0x28
} NDIS_FILTER_BLOCK, * PNDIS_FILTER_BLOCK;

/* TDIObjectID.toi_class constants */
#define	INFO_CLASS_GENERIC			          0x100
#define	INFO_CLASS_PROTOCOL			          0x200
#define	INFO_CLASS_IMPLEMENTATION	        0x300

/* TDIObjectID.toi_type constants */
#define	INFO_TYPE_PROVIDER			          0x100
#define	INFO_TYPE_ADDRESS_OBJECT	        0x200
#define	INFO_TYPE_CONNECTION		          0x300
#define IF_MIB_STATS_ID                 1
#define	ENTITY_LIST_ID				            0

// TDIObjectID TCP 
#define CO_TL_ENTITY					0x400
// TDIObjectID UDP
#define CL_TL_ENTITY					0x401

typedef struct IFEntry
{
	ULONG if_index;
	ULONG if_type;
	ULONG if_mtu;
	ULONG if_speed;
	ULONG if_physaddrlen;
	UCHAR if_physaddr[MAX_PHYSADDR_SIZE];
	ULONG if_adminstatus;
	ULONG if_operstatus;
	ULONG if_lastchange;
	ULONG if_inoctets;
	ULONG if_inucastpkts;
	ULONG if_innucastpkts;
	ULONG if_indiscards;
	ULONG if_inerrors;
	ULONG if_inunknownprotos;
	ULONG if_outoctets;
	ULONG if_outucastpkts;
	ULONG if_outnucastpkts;
	ULONG if_outdiscards;
	ULONG if_outerrors;
	ULONG if_outqlen;
	ULONG if_descrlen;
	UCHAR if_descr[1];
} IFEntry;

typedef struct _TDIEntityID {
	ULONG  tei_entity;
	ULONG  tei_instance;
} TDIEntityID;

typedef struct _TDIObjectID {
	TDIEntityID  toi_entity;
	ULONG  toi_class;
	ULONG  toi_type;
	ULONG  toi_id;
} TDIObjectID;

#define	CONTEXT_SIZE				              16

typedef struct _TCP_REQUEST_QUERY_INFORMATION_EX {
	TDIObjectID  ID;
	ULONG_PTR  Context[CONTEXT_SIZE / sizeof(ULONG_PTR)];
} TCP_REQUEST_QUERY_INFORMATION_EX, * PTCP_REQUEST_QUERY_INFORMATION_EX;
