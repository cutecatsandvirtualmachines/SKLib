#pragma once

#include "ioctlhook.h"

#ifdef _KERNEL_MODE

namespace wmi {
	bool SpoofMonitor(DWORD64 seed = TEST_SEED);
}

INIT_GUID(WmiMonitorID_GUID, 0x671a8285, 0x4edb, 0x4cae, 0x99, 0xfe, 0x69, 0xa1, 0x5c, 0x48, 0xc0, 0xbc);
INIT_GUID(MSNdis_AtmHardwareCurrentAddress_GUID, 0x791ad1a1, 0xe35c, 0x11d0, 0x96, 0x92, 0x00, 0xc0, 0x4f, 0xc3, 0x35, 0x8c);
INIT_GUID(MSNdis_EthernetCurrentAddress_GUID, 0x44795700, 0xa61b, 0x11d0, 0x8d, 0xd4, 0x00, 0xc0, 0x4f, 0xc3, 0x35, 0x8c);
INIT_GUID(MSNdis_EthernetPermanentAddress_GUID, 0x447956ff, 0xa61b, 0x11d0, 0x8d, 0xd4, 0x00, 0xc0, 0x4f, 0xc3, 0x35, 0x8c);
INIT_GUID(MSNdis_FddiLongCurrentAddress_GUID, 0xacf14036, 0xa61c, 0x11d0, 0x8d, 0xd4, 0x00, 0xc0, 0x4f, 0xc3, 0x35, 0x8c);
INIT_GUID(MSNdis_FddiLongPermanentAddress_GUID, 0xacf14035, 0xa61c, 0x11d0, 0x8d, 0xd4, 0x00, 0xc0, 0x4f, 0xc3, 0x35, 0x8c);
INIT_GUID(MSNdis_TokenRingCurrentAddress_GUID, 0x44795708, 0xa61b, 0x11d0, 0x8d, 0xd4, 0x00, 0xc0, 0x4f, 0xc3, 0x35, 0x8c);
INIT_GUID(MSNdis_TokenRingPermanentAddress_GUID, 0x44795707, 0xa61b, 0x11d0, 0x8d, 0xd4, 0x00, 0xc0, 0x4f, 0xc3, 0x35, 0x8c);

INIT_GUID(MSNdis_EthernetMulticastList_GUID, 0x44795701, 0xa61b, 0x11d0, 0x8d, 0xd4, 0x00, 0xc0, 0x4f, 0xc3, 0x35, 0x8c);
INIT_GUID(MSNdis_FddiLongMulticastList_GUID, 0xacf14037, 0xa61c, 0x11d0, 0x8d, 0xd4, 0x00, 0xc0, 0x4f, 0xc3, 0x35, 0x8c);

typedef struct _MSNdis_NetworkAddress {
    UCHAR Address[6];
} MSNdis_NetworkAddress, * PMSNdis_NetworkAddress;

typedef struct _MSNdis_EthernetPermanentAddress {
    MSNdis_NetworkAddress NdisPermanentAddress;
} MSNdis_EthernetPermanentAddress, * PMSNdis_EthernetPermanentAddress;

typedef struct _MSNdis_EthernetCurrentAddress {
    MSNdis_NetworkAddress NdisCurrentAddress;
} MSNdis_EthernetCurrentAddress, * PMSNdis_EthernetCurrentAddress;

typedef struct _MSNdis_EthernetMulticastList {
    ULONG NumberElements;
    MSNdis_NetworkAddress NdisMulticastList[1];
} MSNdis_EthernetMulticastList, * PMSNdis_EthernetMulticastList;

typedef struct _MSNdis_TokenRingPermanentAddress {
    MSNdis_NetworkAddress NdisPermanentAddress;
} MSNdis_TokenRingPermanentAddress, * PMSNdis_TokenRingPermanentAddress;

typedef struct _MSNdis_TokenRingCurrentAddress {
    MSNdis_NetworkAddress NdisCurrentAddress;
} MSNdis_TokenRingCurrentAddress, * PMSNdis_TokenRingCurrentAddress;

typedef struct _MSNdis_FddiLongPermanentAddress {
    MSNdis_NetworkAddress NdisPermanentAddress;
} MSNdis_FddiLongPermanentAddress, * PMSNdis_FddiLongPermanentAddress;

typedef struct _MSNdis_FddiLongCurrentAddress {
    MSNdis_NetworkAddress NdisCurrentAddress;
} MSNdis_FddiLongCurrentAddress, * PMSNdis_FddiLongCurrentAddress;

typedef struct _MSNdis_FddiLongMulticastList {
    ULONG NumberElements;
    MSNdis_NetworkAddress NdisMulticastList[1];
} MSNdis_FddiLongMulticastList, * PMSNdis_FddiLongMulticastList;

typedef struct _MSNdis_AtmHardwareCurrentAddress {
    MSNdis_NetworkAddress NdisAtmHardwareCurrentAddress;
} MSNdis_AtmHardwareCurrentAddress, * PMSNdis_AtmHardwareCurrentAddress;

#define WNODE_FLAG_FIXED_INSTANCE_SIZE  0x00000010
#define MONITOR_SERIAL_LENGTH 16

typedef struct _WNODE_HEADER
{
    ULONG BufferSize;
    ULONG ProviderId;
    union
    {
        ULONG64 HistoricalContext;
        struct
        {
            ULONG Version;
            ULONG Linkage;
        };
    };
    union
    {
        ULONG CountLost;
        HANDLE KernelHandle;
        LARGE_INTEGER TimeStamp;
    };
    GUID Guid;
    ULONG ClientContext;
    ULONG Flags;
} WNODE_HEADER, * PWNODE_HEADER;

typedef struct
{
    ULONG OffsetInstanceData;
    ULONG LengthInstanceData;
} OFFSETINSTANCEDATAANDLENGTH, * POFFSETINSTANCEDATAANDLENGTH;

typedef struct tagWNODE_ALL_DATA
{
    struct _WNODE_HEADER WnodeHeader;
    ULONG DataBlockOffset;
    ULONG InstanceCount;
    ULONG OffsetInstanceNameOffsets;
    union
    {
        ULONG FixedInstanceSize;
        OFFSETINSTANCEDATAANDLENGTH OffsetInstanceDataAndLength[1];
    };
} WNODE_ALL_DATA, * PWNODE_ALL_DATA;

typedef struct WmiMonitorID {
    USHORT ProductCodeID[16];
    USHORT SerialNumberID[16];
    USHORT ManufacturerName[16];
    UCHAR WeekOfManufacture;
    USHORT YearOfManufacture;
    USHORT UserFriendlyNameLength;
    USHORT UserFriendlyName[1];
} WmiMonitorID, * PWmiMonitorID;

typedef struct tagWNODE_SINGLE_INSTANCE
{
    struct _WNODE_HEADER WnodeHeader;
    ULONG OffsetInstanceName;
    ULONG InstanceIndex;
    ULONG DataBlockOffset;
    ULONG SizeDataBlock;
    UCHAR VariableData[1];
} WNODE_SINGLE_INSTANCE, * PWNODE_SINGLE_INSTANCE;

typedef struct _REGENTRY
{
    LIST_ENTRY InUseEntryList;    // Node in list of in use entries

    union
    {
        PDEVICE_OBJECT DeviceObject;    // Device object of registered device
        PVOID WmiEntry;         // Pointer to a pointer to Callback function
    };
    LONG RefCount;                      // Reference Count
    LONG Flags;                         // Registration flags
    PDEVICE_OBJECT PDO;                 // PDO associated with device
    ULONG MaxInstanceNames;             // # instance names for device
    LONG IrpCount;                      // Count of IRPs currently active
    ULONG ProviderId;                   // Provider Id
    struct tagDATASOURCE* DataSource;   // Datasource associated with regentry
    KEVENT Event;                       // Event used to synchronize unloading
} REGENTRY, * PREGENTRY;

typedef struct _WMI_LOGGER_INFORMATION {
    WNODE_HEADER Wnode;       // Had to do this since wmium.h comes later
    //
    // data provider by caller
    ULONG BufferSize;                   // buffer size for logging (in kbytes)
    ULONG MinimumBuffers;               // minimum to preallocate
    ULONG MaximumBuffers;               // maximum buffers allowed
    ULONG MaximumFileSize;              // maximum logfile size (in MBytes)
    ULONG LogFileMode;                  // sequential, circular
    ULONG FlushTimer;                   // buffer flush timer, in seconds
    ULONG EnableFlags;                  // trace enable flags
    LONG  AgeLimit;                     // aging decay time, in minutes
    ULONG Wow;                          // TRUE if the logger started under WOW64
    union {
        HANDLE  LogFileHandle;          // handle to logfile
        ULONG64 LogFileHandle64;
    };

    // data returned to caller
    // end_wmikm
    union {
        // begin_wmikm
        ULONG NumberOfBuffers;          // no of buffers in use
        // end_wmikm
        ULONG InstanceCount;            // Number of Provider Instances
    };
    union {
        // begin_wmikm
        ULONG FreeBuffers;              // no of buffers free
        // end_wmikm
        ULONG InstanceId;               // Current Provider's Id for UmLogger
    };
    union {
        // begin_wmikm
        ULONG EventsLost;               // event records lost
        // end_wmikm
        ULONG NumberOfProcessors;       // Passed on to UmLogger
    };
    // begin_wmikm
    ULONG BuffersWritten;               // no of buffers written to file
    ULONG LogBuffersLost;               // no of logfile write failures
    ULONG RealTimeBuffersLost;          // no of rt delivery failures
    union {
        HANDLE  LoggerThreadId;         // thread id of Logger
        ULONG64 LoggerThreadId64;       // thread is of Logger
    };
    union {
        UNICODE_STRING LogFileName;     // used only in WIN64
        UNICODE_STRING64 LogFileName64; // Logfile name: only in WIN32
    };

    // mandatory data provided by caller
    union {
        UNICODE_STRING LoggerName;      // Logger instance name in WIN64
        UNICODE_STRING64 LoggerName64;  // Logger Instance name in WIN32
    };

    // private
    union {
        PVOID   Checksum;
        ULONG64 Checksum64;
    };
    union {
        PVOID   LoggerExtension;
        ULONG64 LoggerExtension64;
    };
} WMI_LOGGER_INFORMATION, * PWMI_LOGGER_INFORMATION;

typedef struct
{
    LIST_ENTRY ChunkList;        // Node in list of chunks
    LIST_ENTRY FreeEntryHead;    // Head of list of free entries in chunk
    ULONG EntriesInUse;            // Count of entries being used
} CHUNKHEADER, * PCHUNKHEADER;

typedef struct tagGUIDENTRY
{
    union
    {
        // Entry in list of all guids registered with WMI
        LIST_ENTRY MainGEList;

        // Entry in list of free guid entry blocks
        LIST_ENTRY FreeGEList;
    };
    PCHUNKHEADER Chunk;            // Chunk in which entry is located
    ULONG Flags;

    // Count of number of data sources using this guid
    ULONG RefCount;

    // Signature to identify entry
    ULONG Signature;

    // Head of list of open objects to this guid
    LIST_ENTRY ObjectHead;

    // Count of InstanceSets headed by this guid
    ULONG ISCount;

    // Head of list of all instances for guid
    LIST_ENTRY ISHead;

    // Guid that represents data block
    GUID Guid;

    ULONG EventRefCount;                // Global count of event enables
    ULONG CollectRefCount;              // Global count of collection enables

    ULONG64 LoggerContext;              // Logger context handle

    PWMI_LOGGER_INFORMATION LoggerInfo; // LoggerInfo. Used in case of Ntdll tracing

    PKEVENT CollectInProgress;          // Event set when all collect complete

} GUIDENTRY, * PGUIDENTRY, * PBGUIDENTRY;

typedef struct
{
    PUCHAR Buffer;               // Buffer that holds events waiting
    PWNODE_HEADER LastWnode;     // Last event so we can link to next
    ULONG MaxBufferSize;         // Max size of events that can be held
    ULONG NextOffset;             // Offset in buffer to next place to store
    ULONG EventsLost;            // # events lost
} WMIEVENTQUEUE, * PWMIEVENTQUEUE;

struct _WMIGUIDOBJECT;
#define MAXREQREPLYSLOTS  4

typedef struct
{
    struct _WMIGUIDOBJECT* ReplyObject;
    LIST_ENTRY RequestListEntry;
} MBREQUESTS, * PMBREQUESTS;

typedef struct _WMIGUIDOBJECT
{
    KEVENT Event;

    union
    {
        GUID Guid;
        PREGENTRY RegEntry;
    };

    // Entry in linked list of objects for this guid
    LIST_ENTRY GEObjectList;
    PBGUIDENTRY GuidEntry;
    ULONG Type;              // Type of object

    union
    {
        //
        // Kernel mode event receiver - all we need is a callback &
        // context
        //
        struct
        {
            WMI_NOTIFICATION_CALLBACK Callback;
            PVOID CallbackContext;
        };

        struct
        {
            //
            // User mode Queued up event management
            //

            //
            // Info on how to startup a new pump thread
            //
            LIST_ENTRY ThreadObjectList;
            HANDLE UserModeProcess;
            PVOID UserModeCallback;
            SIZE_T StackSize;
            SIZE_T StackCommit;

            //
            // Info for request waiting to be completed
            //
            PIRP Irp;   // Irp waiting for event from this object

            // Entry in list objects associated with an irp
            LIST_ENTRY IrpObjectList;

            // What to do when an event is queued
            ULONG EventQueueAction;

            WMIEVENTQUEUE HiPriority;// Hi priority event queue
            WMIEVENTQUEUE LoPriority;// Lo priority event queue
        };
    };


    BOOLEAN EnableRequestSent;

    //
    // MB management
    //
    union
    {
        LIST_ENTRY RequestListHead; // Head of request list (reply object)
        // (request object)
        MBREQUESTS MBRequests[MAXREQREPLYSLOTS];
    };
    ULONG Cookie;

    ULONG Flags;

} WMIGUIDOBJECT, * PWMIGUIDOBJECT;

#endif