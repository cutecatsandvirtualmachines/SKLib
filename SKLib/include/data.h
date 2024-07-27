#pragma once

#ifdef _KERNEL_MODE
#ifndef _WDMDDK_
#include <ntifs.h>
#endif
#include <ntdef.h>
#endif

#include "ListEx.h"
#include "eventlogger.h"
#include "ioctl.h"
#include "power.h"
#include "sharedpool.h"
#include "RandEx.h"

#pragma warning (disable:4458)
#pragma warning (disable:4101)
#pragma warning (disable:4238)


struct OffsetDump;
struct _CLEANUP_DATA;

extern OffsetDump offsets;
extern _CLEANUP_DATA cleanupData;

#define VALID_OFFSET(offset) (offset && (offset != MAXULONG64))

#pragma pack(push, 1)
struct OffsetDump {
	/*
	* RAID
	*/
	ULONG64 RaidIdentity;
	ULONG64 RaidSerialNumber;
	ULONG64 RaidUnitRegInterface;

	ULONG64 ScsiSerialNumber;

	/*
	* NIC
	*/
	ULONG64 NdisGlobalFilterList;
	ULONG64 FilterBlockNextFilter;
	ULONG64 FilterBlockMiniport;
	ULONG64 FilterBlockInstanceName;
	ULONG64 FilterBlockIfBlock;

	ULONG64 MiniportBlockInterfaceGuid;
	ULONG64 MiniportBlockLowestFilter;
	ULONG64 MiniportBlockHighestFilter;

	ULONG64 IfBlockPhy;
	ULONG64 IfBlockPermanentPhy;

	/*
	* SMBIOS
	*/
	ULONG64 WmipSMBiosTableLength;

	/*
	* TEB
	*/
	ULONG64 ClientInfo;
	ULONG64 HwndCache;

	/*
	* ci.dll
	*/
	ULONG64 g_KernelHashBucketList;
	ULONG64 g_HashCacheLock;

	/*
	* Functions
	*/
	ULONG64 PsEnumProcesses;
	ULONG64 PsEnumProcessThreads;
	ULONG64 WmipSMBiosVersionInfo;
	ULONG64 PspInsertProcess;
	ULONG64 PspInsertThread;
	ULONG64 PspTerminateProcess;
	ULONG64 MmQueryVirtualMemory;
	ULONG64 NtResumeThread;
	ULONG64 BgpFwQueryBootGraphicsInformation;
	ULONG64 MiniportPendingMacAddress;
	ULONG64 PspCreateThread;
	ULONG64 PspSetQuotaLimits;
	ULONG64 MmQueryWorkingSetInformation;
	ULONG64 MmAdjustWorkingSetSizeEx;
	ULONG64 MiniportIfBlock;
	ULONG64 PspRundownSingleProcess;
	ULONG64 PspGetContextThreadInternal;
	ULONG64 WmipQueryAllData;
	ULONG64 ZwSetInformationProcess;
	ULONG64 PsQueryFullProcessImageName;

	ULONG64 ExpBootEnvironmentInformation;
	ULONG64 WmipSMBiosTablePhysicalAddress;
	ULONG64 PiDDBLock;
	ULONG64 PiDDBCacheTable;
	ULONG64 KiNmiInterruptStart;
};

typedef struct _CLEANUP_DATA {
	HANDLE hDevice;
	DWORD32 dwTimestamp;
	char pDriverName[0x100];
	PVOID pPreHv;
} CLEANUP_DATA, * PCLEANUP_DATA;

typedef struct _USERMODE_INFO {
	//Usermode to kernel
	DWORD64 vmcallKey;
	PVOID driverBase;
	ULONG64 driverSize;
	ULONG32 loaderProcId;

	//Kernel to usermode
	ULONG64 callbackAddress;
	FILETIME callTime;

	//Shared
	OffsetDump offsets;
	CLEANUP_DATA cleanupData;
	DWORD64 spooferSeed;

	//Pre-to-hv
	PVOID pIdtCopy;
	ULONG64 cpuIdx;
	PVOID pDetectionCallback;
} USERMODE_INFO, * PUSERMODE_INFO;
#pragma pack(pop)

#ifdef _KERNEL_MODE

namespace SKLib {
	extern wchar_t UniHideKeysPath[];
	extern wchar_t CurrentDriverName[];
	extern bool IsInitialized;

	//Logging
	namespace Log {
		extern EventLogger evLogger;
	}

	extern PUSERMODE_INFO pUserInfo;

	void Init(PDRIVER_OBJECT pDevice = nullptr);
	void InitName(wchar_t* pDriverName = nullptr);
	void Dispose();
}

#endif