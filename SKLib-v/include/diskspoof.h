#pragma once

#include "ioctlhook.h"

#include <ntddstor.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <scsi.h>

#define MAX_HDDS 10
#define VOLUME_GUID_MAX_LENGTH (sizeof(GUID))
#define DISK_SERIAL_MAX_LENGTH 20

/*
* Enable to use hardcoded serial value
*/
//#define DUMMY_SERIAL "MyDummySerial"

#define FILE_DEVICE_SCSI                0x0000001b
#define SRB_FUNCTION_IO_CONTROL         0x02

#define IOCTL_SCSI_BASE                 FILE_DEVICE_CONTROLLER
#define IOCTL_ATA_PASS_THROUGH          CTL_CODE(IOCTL_SCSI_BASE, 0x040b, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define ATA_IDENTIFY_DEVICE             0xec
#define IOCTL_SCSI_MINIPORT             CTL_CODE(IOCTL_SCSI_BASE, 0x0402, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_SCSI_MINIPORT_IDENTIFY    ((FILE_DEVICE_SCSI << 16) + 0x0501)
#define NVME_STORPORT_DRIVER 0xe000
#define NVME_PASS_THROUGH_SRB_IO_CODE \
  CTL_CODE(NVME_STORPORT_DRIVER, 0x0800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INTEL_NVME_PASS_THROUGH CTL_CODE(0xf000, 0xA02, METHOD_BUFFERED, FILE_ANY_ACCESS)

namespace disks {
    bool Spoof(DWORD64 seed = TEST_SEED);
}

typedef struct _DISK_DRIVER_HOOK_INFO {
    PDEVICE_OBJECT DeviceObject;
    PDRIVER_DISPATCH Original;
} DISK_DRIVER_HOOK_INFO, * PDISK_DRIVER_HOOK_INFO;

struct DISK_HOOKS {
    DWORD length;
    DISK_DRIVER_HOOK_INFO hookInfo[0xFF];
};

typedef union
{
    struct
    {
        ULONG Opcode : 8;
        ULONG FUSE : 2;
        ULONG _Rsvd : 4;
        ULONG PSDT : 2;
        ULONG CID : 16;
    } DUMMYSTRUCTNAME;
    ULONG AsDWord;
} NVME_CDW0, * PNVME_CDW0;

// NVMe Command Format

// See NVMe specification 1.3c Section 4.2, Figure 10

typedef union
{
    struct
    {
        ULONG   CNS : 2;
        ULONG   _Rsvd : 30;
    } DUMMYSTRUCTNAME;
    ULONG AsDWord;
} NVME_IDENTIFY_CDW10, * PNVME_IDENTIFY_CDW10;

// NVMe Specification < 1.3

typedef union
{
    struct
    {
        ULONG   LID : 8;
        ULONG   _Rsvd1 : 8;
        ULONG   NUMD : 12;
        ULONG   _Rsvd2 : 4;
    } DUMMYSTRUCTNAME;
    ULONG   AsDWord;
} NVME_GET_LOG_PAGE_CDW10, * PNVME_GET_LOG_PAGE_CDW10;

// NVMe Specification >= 1.3

typedef union
{
    struct
    {
        ULONG   LID : 8;
        ULONG   LSP : 4;
        ULONG   Reserved0 : 3;
        ULONG   RAE : 1;
        ULONG   NUMDL : 16;
    } DUMMYSTRUCTNAME;
    ULONG   AsDWord;
} NVME_GET_LOG_PAGE_CDW10_V13, * PNVME_GET_LOG_PAGE_CDW10_V13;

typedef struct
{
    // Common fields for all commands
    NVME_CDW0           CDW0;
    ULONG               NSID;
    ULONG               _Rsvd[2];
    ULONGLONG           MPTR;
    ULONGLONG           PRP1;
    ULONGLONG           PRP2;
    // Command independent fields from CDW10 to CDW15
    union
    {
        // Admin Command: Identify (6)
        struct
        {
            NVME_IDENTIFY_CDW10 CDW10;
            ULONG   CDW11;
            ULONG   CDW12;
            ULONG   CDW13;
            ULONG   CDW14;
            ULONG   CDW15;
        } IDENTIFY;
        // Admin Command: Get Log Page (2)
        struct
        {
            NVME_GET_LOG_PAGE_CDW10 CDW10;
            //NVME_GET_LOG_PAGE_CDW10_V13 CDW10;
            ULONG   CDW11;
            ULONG   CDW12;
            ULONG   CDW13;
            ULONG   CDW14;
            ULONG   CDW15;
        } GET_LOG_PAGE;
    } u;
} NVME_CMD, * PNVME_CMD;

#pragma pack(1)
struct nvme_id_power_state {
    unsigned short  max_power; // centiwatts
    unsigned char   rsvd2;
    unsigned char   flags;
    unsigned int    entry_lat; // microseconds
    unsigned int    exit_lat;  // microseconds
    unsigned char   read_tput;
    unsigned char   read_lat;
    unsigned char   write_tput;
    unsigned char   write_lat;
    unsigned short  idle_power;
    unsigned char   idle_scale;
    unsigned char   rsvd19;
    unsigned short  active_power;
    unsigned char   active_work_scale;
    unsigned char   rsvd23[9];
};

struct nvme_id_ctrl {
    unsigned short  vid;
    unsigned short  ssvid;
    char            sn[20];
    char            mn[40];
    char            fr[8];
    unsigned char   rab;
    unsigned char   ieee[3];
    unsigned char   cmic;
    unsigned char   mdts;
    unsigned short  cntlid;
    unsigned int    ver;
    unsigned int    rtd3r;
    unsigned int    rtd3e;
    unsigned int    oaes;
    unsigned int    ctratt;
    unsigned char   rsvd100[156];
    unsigned short  oacs;
    unsigned char   acl;
    unsigned char   aerl;
    unsigned char   frmw;
    unsigned char   lpa;
    unsigned char   elpe;
    unsigned char   npss;
    unsigned char   avscc;
    unsigned char   apsta;
    unsigned short  wctemp;
    unsigned short  cctemp;
    unsigned short  mtfa;
    unsigned int    hmpre;
    unsigned int    hmmin;
    unsigned char   tnvmcap[16];
    unsigned char   unvmcap[16];
    unsigned int    rpmbs;
    unsigned short  edstt;
    unsigned char   dsto;
    unsigned char   fwug;
    unsigned short  kas;
    unsigned short  hctma;
    unsigned short  mntmt;
    unsigned short  mxtmt;
    unsigned int    sanicap;
    unsigned char   rsvd332[180];
    unsigned char   sqes;
    unsigned char   cqes;
    unsigned short  maxcmd;
    unsigned int    nn;
    unsigned short  oncs;
    unsigned short  fuses;
    unsigned char   fna;
    unsigned char   vwc;
    unsigned short  awun;
    unsigned short  awupf;
    unsigned char   nvscc;
    unsigned char   rsvd531;
    unsigned short  acwu;
    unsigned char   rsvd534[2];
    unsigned int    sgls;
    unsigned char   rsvd540[228];
    char			      subnqn[256];
    unsigned char   rsvd1024[768];
    unsigned int    ioccsz;
    unsigned int    iorcsz;
    unsigned short  icdoff;
    unsigned char   ctrattr;
    unsigned char   msdbd;
    unsigned char   rsvd1804[244];
    struct nvme_id_power_state  psd[32];
    unsigned char   vs[1024];
};

struct STORAGE_PROTOCOL_SPECIFIC_QUERY_WITH_BUFFER
{
    struct { // STORAGE_PROPERTY_QUERY without AdditionalsParameters[1]
        STORAGE_PROPERTY_ID PropertyId;
        STORAGE_QUERY_TYPE QueryType;
    } PropertyQuery;
    STORAGE_PROTOCOL_SPECIFIC_DATA ProtocolSpecific;
    BYTE DataBuffer[1];
};

typedef struct {
    ATA_PASS_THROUGH_EX apt;
    ULONG Filler;
    UCHAR ucDataBuf[32 * 512];
} ATA_PASS_THROUGH_EX_WITH_BUFFERS;

struct ata_identify_device {
    unsigned short words000_009[10];
    unsigned char  serial_no[20];
    unsigned short words020_022[3];
    unsigned char  fw_rev[8];
    unsigned char  model[40];
    unsigned short words047_079[33];
    unsigned short major_rev_num;
    unsigned short minor_rev_num;
    unsigned short command_set_1;
    unsigned short command_set_2;
    unsigned short command_set_extension;
    unsigned short cfs_enable_1;
    unsigned short word086;
    unsigned short csf_default;
    unsigned short words088_255[168];
};
#pragma pack()

typedef struct _INTEL_NVME_PAYLOAD
{
    BYTE    Version;        // 0x001C
    BYTE    PathId;         // 0x001D
    BYTE    TargetID;       // 0x001E
    BYTE    Lun;            // 0x001F
    NVME_CMD Cmd;           // 0x0020 ~ 0x005F
    DWORD   CplEntry[4];    // 0x0060 ~ 0x006F
    DWORD   QueueId;        // 0x0070 ~ 0x0073
    DWORD   ParamBufLen;    // 0x0074
    DWORD   ReturnBufferLen;// 0x0078
    BYTE    __rsvd2[0x28];  // 0x007C ~ 0xA3
} INTEL_NVME_PAYLOAD, * PINTEL_NVME_PAYLOAD;

typedef struct _INTEL_NVME_PASS_THROUGH
{
    SRB_IO_CONTROL SRB;     // 0x0000 ~ 0x001B
    INTEL_NVME_PAYLOAD Payload;
    BYTE DataBuffer[0x1000];
} INTEL_NVME_PASS_THROUGH, * PINTEL_NVME_PASS_THROUGH;

typedef struct _IEEE {
    UCHAR ieee[3];
} IEEE, *PIEEE;
//
// Define values for pass-through DataIn field.
//
#define SCSI_IOCTL_DATA_OUT          0
#define SCSI_IOCTL_DATA_IN           1
#define SCSI_IOCTL_DATA_UNSPECIFIED  2

//
// Define the SCSI pass through structure.
//

typedef struct _SCSI_PASS_THROUGH_WITH_BUFFERS {
    SCSI_PASS_THROUGH Spt;
    ULONG             Filler;      // realign buffers to double word boundary
    UCHAR             SenseBuf[32];
    UCHAR             DataBuf[4096];
} SCSI_PASS_THROUGH_WITH_BUFFERS, * PSCSI_PASS_THROUGH_WITH_BUFFERS;

typedef struct _SCSI_PASS_THROUGH_WITH_BUFFERS24 {
    SCSI_PASS_THROUGH Spt;
    UCHAR             SenseBuf[24];
    UCHAR             DataBuf[4096];
} SCSI_PASS_THROUGH_WITH_BUFFERS24, * PSCSI_PASS_THROUGH_WITH_BUFFERS24;

#define SPT_CDB_LENGTH 32
#define SPT_SENSE_LENGTH 32
#define SPTWB_DATA_LENGTH 512

typedef struct _SCSI_PASS_THROUGH_WITH_BUFFERS_EX {
    SCSI_PASS_THROUGH_EX Spt;
    UCHAR             ucCdbBuf[SPT_CDB_LENGTH - 1];       // cushion for spt.Cdb
    ULONG             Filler;      // realign buffers to double word boundary
    STOR_ADDR_BTL8    StorAddress;
    UCHAR             ucSenseBuf[SPT_SENSE_LENGTH];
    UCHAR             ucDataBuf[SPTWB_DATA_LENGTH];     // buffer for DataIn or DataOut
} SCSI_PASS_THROUGH_WITH_BUFFERS_EX, * PSCSI_PASS_THROUGH_WITH_BUFFERS_EX;

typedef struct _WWN {
    USHORT WorldWideName[4];
    USHORT ReservedForWorldWideName128[4];
} WWN, *PWWN;

#define NVME_SIG_STR "NvmeMini"
#define NVME_SIG_STR_LEN 8
#define NVME_FROM_DEV_TO_HOST 2
#define NVME_IOCTL_VENDOR_SPECIFIC_DW_SIZE 6
#define NVME_IOCTL_CMD_DW_SIZE 16
#define NVME_IOCTL_COMPLETE_DW_SIZE 4
#define NVME_PT_TIMEOUT 40

struct NVME_PASS_THROUGH_IOCTL {
    SRB_IO_CONTROL SrbIoCtrl;
    DWORD          VendorSpecific[NVME_IOCTL_VENDOR_SPECIFIC_DW_SIZE];
    DWORD          NVMeCmd[NVME_IOCTL_CMD_DW_SIZE];
    DWORD          CplEntry[NVME_IOCTL_COMPLETE_DW_SIZE];
    DWORD          Direction;
    DWORD          QueueId;
    DWORD          DataBufferLen;
    DWORD          MetaDataLen;
    DWORD          ReturnBufferLen;
    UCHAR          DataBuffer[4096];
};

typedef union _STORAGE_DEVICE_DESCRIPTOR_DATA {
    STORAGE_DEVICE_DESCRIPTOR desc;
    char raw[256];
} STORAGE_DEVICE_DESCRIPTOR_DATA, *PSTORAGE_DEVICE_DESCRIPTOR_DATA;

typedef struct _IDINFO
{
    USHORT	wGenConfig;
    USHORT	wNumCyls;
    USHORT	wReserved;
    USHORT	wNumHeads;
    USHORT	wBytesPerTrack;
    USHORT	wBytesPerSector;
    USHORT	wNumSectorsPerTrack;
    USHORT	wVendorUnique[3];
    CHAR	sSerialNumber[20];
    USHORT	wBufferType;
    USHORT	wBufferSize;
    USHORT	wECCSize;
    CHAR	sFirmwareRev[8];
    CHAR	sModelNumber[40];
    USHORT	wMoreVendorUnique;
    USHORT	wDoubleWordIO;
    struct {
        USHORT	Reserved : 8;
        USHORT	DMA : 1;
        USHORT	LBA : 1;
        USHORT	DisIORDY : 1;
        USHORT	IORDY : 1;
        USHORT	SoftReset : 1;
        USHORT	Overlap : 1;
        USHORT	Queue : 1;
        USHORT	InlDMA : 1;
    } wCapabilities;
    USHORT	wReserved1;
    USHORT	wPIOTiming;
    USHORT	wDMATiming;
    struct {
        USHORT	CHSNumber : 1;
        USHORT	CycleNumber : 1;
        USHORT	UnltraDMA : 1;
        USHORT	Reserved : 13;
    } wFieldValidity;
    USHORT	wNumCurCyls;
    USHORT	wNumCurHeads;
    USHORT	wNumCurSectorsPerTrack;
    USHORT	wCurSectorsLow;
    USHORT	wCurSectorsHigh;
    struct {
        USHORT	CurNumber : 8;
        USHORT	Multi : 1;
        USHORT	Reserved : 7;
    } wMultSectorStuff;
    ULONG	dwTotalSectors;
    USHORT	wSingleWordDMA;
    struct {
        USHORT	Mode0 : 1;
        USHORT	Mode1 : 1;
        USHORT	Mode2 : 1;
        USHORT	Reserved1 : 5;
        USHORT	Mode0Sel : 1;
        USHORT	Mode1Sel : 1;
        USHORT	Mode2Sel : 1;
        USHORT	Reserved2 : 5;
    } wMultiWordDMA;
    struct {
        USHORT	AdvPOIModes : 8;
        USHORT	Reserved : 8;
    } wPIOCapacity;
    USHORT	wMinMultiWordDMACycle;
    USHORT	wRecMultiWordDMACycle;
    USHORT	wMinPIONoFlowCycle;
    USHORT	wMinPOIFlowCycle;
    USHORT	wReserved69[11];
    struct {
        USHORT	Reserved1 : 1;
        USHORT	ATA1 : 1;
        USHORT	ATA2 : 1;
        USHORT	ATA3 : 1;
        USHORT	ATA4 : 1;
        USHORT	ATA5 : 1;
        USHORT	ATA6 : 1;
        USHORT	ATA7 : 1;
        USHORT	ATA8 : 1;
        USHORT	ATA9 : 1;
        USHORT	ATA10 : 1;
        USHORT	ATA11 : 1;
        USHORT	ATA12 : 1;
        USHORT	ATA13 : 1;
        USHORT	ATA14 : 1;
        USHORT	Reserved2 : 1;
    } wMajorVersion;
    USHORT	wMinorVersion;
    USHORT	wReserved82[6];
    struct {
        USHORT	Mode0 : 1;
        USHORT	Mode1 : 1;
        USHORT	Mode2 : 1;
        USHORT	Mode3 : 1;
        USHORT	Mode4 : 1;
        USHORT	Mode5 : 1;
        USHORT	Mode6 : 1;
        USHORT	Mode7 : 1;
        USHORT	Mode0Sel : 1;
        USHORT	Mode1Sel : 1;
        USHORT	Mode2Sel : 1;
        USHORT	Mode3Sel : 1;
        USHORT	Mode4Sel : 1;
        USHORT	Mode5Sel : 1;
        USHORT	Mode6Sel : 1;
        USHORT	Mode7Sel : 1;
    } wUltraDMA;
    USHORT	wReserved89[167];
} IDINFO, * PIDINFO;

typedef struct _DICTIONARY {
    ULONGLONG Signature;
    struct _DICTIONARY_HEADER* List;
    KSPIN_LOCK SpinLock;
} DICTIONARY, * PDICTIONARY;

typedef struct _COMMON_DEVICE_EXTENSION {
    ULONG Version;
    PDEVICE_OBJECT DeviceObject;
    PDEVICE_OBJECT LowerDeviceObject;
    struct _FUNCTIONAL_DEVICE_EXTENSION* PartitionZeroExtension;
    PVOID DriverExtension;
    LONG RemoveLock;
    KEVENT RemoveEvent;
    KSPIN_LOCK RemoveTrackingSpinlock;
    PVOID RemoveTrackingList;
    LONG RemoveTrackingUntrackedCount;
    PVOID DriverData;
    struct {
        BOOLEAN IsFdo : 1;
        BOOLEAN IsInitialized : 1;
        BOOLEAN IsSrbLookasideListInitialized : 1;
    } DUMMYSTRUCTNAME;
    UCHAR PreviousState;
    UCHAR CurrentState;
    ULONG IsRemoved;
    UNICODE_STRING DeviceName;
    struct _PHYSICAL_DEVICE_EXTENSION* ChildList;
    ULONG PartitionNumber;
    LARGE_INTEGER PartitionLength;
    LARGE_INTEGER StartingOffset;
    PVOID DevInfo;
    ULONG PagingPathCount;
    ULONG DumpPathCount;
    ULONG HibernationPathCount;
    KEVENT PathCountEvent;
#ifndef ALLOCATE_SRB_FROM_POOL
    NPAGED_LOOKASIDE_LIST SrbLookasideList;
#endif
    UNICODE_STRING MountedDeviceInterfaceName;
    ULONG GuidCount;
    PVOID GuidRegInfo;
    DICTIONARY FileObjectDictionary;
#if (NTDDI_VERSION >= NTDDI_WINXP)
    PVOID PrivateCommonData;
#else
    ULONG_PTR Reserved1;
#endif
#if (NTDDI_VERSION >= NTDDI_VISTA)
    PDRIVER_DISPATCH* DispatchTable;
#else
    ULONG_PTR Reserved2;
#endif
    ULONG_PTR Reserved3;
    ULONG_PTR Reserved4;
} COMMON_DEVICE_EXTENSION, * PCOMMON_DEVICE_EXTENSION;

typedef struct _FUNCTIONAL_DEVICE_EXTENSION {
    union {
        struct {
            ULONG Version;
            PDEVICE_OBJECT DeviceObject;
        };
        COMMON_DEVICE_EXTENSION CommonExtension;
    };
    PDEVICE_OBJECT LowerPdo;
    PSTORAGE_DEVICE_DESCRIPTOR DeviceDescriptor;
} FUNCTIONAL_DEVICE_EXTENSION, * PFUNCTIONAL_DEVICE_EXTENSION;

typedef struct _IDSECTOR
{
    USHORT  wGenConfig;
    USHORT  wNumCyls;
    USHORT  wReserved;
    USHORT  wNumHeads;
    USHORT  wBytesPerTrack;
    USHORT  wBytesPerSector;
    USHORT  wSectorsPerTrack;
    USHORT  wVendorUnique[3];
    CHAR    sSerialNumber[20];
    USHORT  wBufferType;
    USHORT  wBufferSize;
    USHORT  wECCSize;
    CHAR    sFirmwareRev[8];
    CHAR    sModelNumber[40];
    USHORT  wMoreVendorUnique;
    USHORT  wDoubleWordIO;
    USHORT  wCapabilities;
    USHORT  wReserved1;
    USHORT  wPIOTiming;
    USHORT  wDMATiming;
    USHORT  wBS;
    USHORT  wNumCurrentCyls;
    USHORT  wNumCurrentHeads;
    USHORT  wNumCurrentSectorsPerTrack;
    ULONG   ulCurrentSectorCapacity;
    USHORT  wMultSectorStuff;
    ULONG   ulTotalAddressableSectors;
    USHORT  wSingleWordDMA;
    USHORT  wMultiWordDMA;
    BYTE    bReserved[128];
} IDSECTOR, * PIDSECTOR;

typedef struct _VendorInfo
{
    char pad_0x0000[0x8];
    char Info[64];
} VendorInfo;

typedef struct _HDD_EXTENSION
{
    char pad_0x0000[0x68];
    VendorInfo* pVendorInfo;
    char pad_0x0068[0x8];
    char* pHDDSerial;
    char pad_0x0078[0x30];
} HDD_EXTENSION, * PHDD_EXTENSION;