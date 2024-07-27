#pragma once

struct OffsetDump;
struct _CLEANUP_DATA;

#ifdef _KERNEL_MODE

#else
#include <Windows.h>
#include <filesystem>

#include "pdbparse.h"
#endif

#ifndef _KERNEL_MODE
#include <data.h>

namespace setup {
	__forceinline bool InitOffsets(OffsetDump& offsets) {
		EzPdbDownload("C:\\Windows\\System32\\ci.dll");
		EzPdbDownload("C:\\Windows\\System32\\ntdll.dll");
		EzPdbDownload("C:\\Windows\\System32\\ntoskrnl.exe");
		EzPdbDownload("C:\\Windows\\System32\\drivers\\storport.sys");
		EzPdbDownload("C:\\Windows\\System32\\drivers\\ndis.sys");

#pragma region "ci"
		{
			auto parser = PdbParser(L".\\ci.pdb");
			ULONG64 g_KernelHashBucketList = parser.GetSymbolRVA(L"g_KernelHashBucketList");
			ULONG64 g_HashCacheLock = parser.GetSymbolRVA(L"g_HashCacheLock");
			if (g_KernelHashBucketList == INVALID_OFFSET) {
				printf("[-] ci offsets invalid!\n");
#ifdef BUILD_SPOOFER
				return false;
#endif
			}
			offsets.g_KernelHashBucketList = g_KernelHashBucketList;
			offsets.g_HashCacheLock = g_HashCacheLock;
		}
#pragma endregion

#pragma region "Ntdll"
		{
			auto parser = PdbParser(L".\\ntdll.pdb");
			ULONG64 Win32ClientInfoOffset = parser.GetStructMemberOffset(L"_TEB", L"Win32ClientInfo");
			if (Win32ClientInfoOffset == INVALID_OFFSET) {
				printf("[-] ntdll offsets invalid!\n");
#ifdef BUILD_SPOOFER
				return false;
#endif
			}
			offsets.ClientInfo = Win32ClientInfoOffset;
			offsets.HwndCache = 8;
		}
#pragma endregion

#pragma region "Ntoskrnl"
		{
			auto parser = PdbParser(L".\\ntoskrnl.pdb");
			ULONG64 WmipSMBiosTableLength = parser.GetSymbolRVA(L"WmipSMBiosTableLength");
			ULONG64 PsEnumProcesses = parser.GetSymbolRVA(L"PsEnumProcesses");
			ULONG64 PspInsertProcess = parser.GetSymbolRVA(L"PspInsertProcess");
			ULONG64 PspTerminateProcess = parser.GetSymbolRVA(L"PspTerminateProcess");
			ULONG64 MmQueryVirtualMemory = parser.GetSymbolRVA(L"MmQueryVirtualMemory");
			ULONG64 NtResumeThread = parser.GetSymbolRVA(L"NtResumeThread");
			ULONG64 BgpFwQueryBootGraphicsInformation = parser.GetSymbolRVA(L"BgpFwQueryBootGraphicsInformation");
			ULONG64 PsEnumProcessThreads = parser.GetSymbolRVA(L"PsEnumProcessThreads");
			ULONG64 KeResumeThread = parser.GetSymbolRVA(L"KeResumeThread");
			ULONG64 PspCreateThread = parser.GetSymbolRVA(L"PspCreateThread");
			ULONG64 PspSetQuotaLimits = parser.GetSymbolRVA(L"PspSetQuotaLimits");
			ULONG64 MmQueryWorkingSetInformation = parser.GetSymbolRVA(L"MmQueryWorkingSetInformation");
			ULONG64 MmAdjustWorkingSetSizeEx = parser.GetSymbolRVA(L"MmAdjustWorkingSetSizeEx");
			ULONG64 MiAllocateVirtualMemoryPrepare = parser.GetSymbolRVA(L"MiAllocateVirtualMemoryPrepare");
			ULONG64 ExpBootEnvironmentInformation = parser.GetSymbolRVA(L"ExpBootEnvironmentInformation");
			ULONG64 PspRundownSingleProcess = parser.GetSymbolRVA(L"PspRundownSingleProcess");
			ULONG64 PspGetContextThreadInternal = parser.GetSymbolRVA(L"PspGetContextThreadInternal");
			ULONG64 WmipSMBiosTablePhysicalAddress = parser.GetSymbolRVA(L"WmipSMBiosTablePhysicalAddress");
			ULONG64 WmipQueryAllData = parser.GetSymbolRVA(L"WmipQueryAllData");
			ULONG64 PiDDBLock = parser.GetSymbolRVA(L"PiDDBLock");
			ULONG64 PiDDBCacheTable = parser.GetSymbolRVA(L"PiDDBCacheTable");
			ULONG64 PspInsertThread = parser.GetSymbolRVA(L"PspInsertThread");
			ULONG64 ZwSetInformationProcess = parser.GetSymbolRVA(L"ZwSetInformationProcess");
			ULONG64 PsQueryFullProcessImageName = parser.GetSymbolRVA(L"PsQueryFullProcessImageName");
			ULONG64 KiNmiInterruptStart = parser.GetSymbolRVA(L"KiNmiInterruptStart");
			ULONG64 WmipSMBiosVersionInfo = parser.GetSymbolRVA(L"WmipSMBiosVersionInfo");
			if (WmipSMBiosTableLength == INVALID_OFFSET
				|| PsEnumProcesses == INVALID_OFFSET
				|| PspInsertProcess == INVALID_OFFSET
				|| PspTerminateProcess == INVALID_OFFSET
				|| MmQueryVirtualMemory == INVALID_OFFSET
				|| NtResumeThread == INVALID_OFFSET
				|| BgpFwQueryBootGraphicsInformation == INVALID_OFFSET
				|| PsEnumProcessThreads == INVALID_OFFSET
				|| KeResumeThread == INVALID_OFFSET
				|| PspCreateThread == INVALID_OFFSET
				|| PspSetQuotaLimits == INVALID_OFFSET
				|| MmQueryWorkingSetInformation == INVALID_OFFSET
				|| MmAdjustWorkingSetSizeEx == INVALID_OFFSET
				|| MiAllocateVirtualMemoryPrepare == INVALID_OFFSET
				|| ExpBootEnvironmentInformation == INVALID_OFFSET
				|| PspRundownSingleProcess == INVALID_OFFSET
				|| PspGetContextThreadInternal == INVALID_OFFSET
				|| WmipSMBiosTablePhysicalAddress == INVALID_OFFSET
				|| WmipQueryAllData == INVALID_OFFSET
				|| PiDDBLock == INVALID_OFFSET
				|| PiDDBCacheTable == INVALID_OFFSET
				|| PspInsertThread == INVALID_OFFSET
				|| ZwSetInformationProcess == INVALID_OFFSET
				|| PsQueryFullProcessImageName == INVALID_OFFSET
				|| KiNmiInterruptStart == INVALID_OFFSET
				|| WmipSMBiosVersionInfo == INVALID_OFFSET
				) {
				printf("[-] ntoskrnl offsets invalid!\n");
#ifdef BUILD_SPOOFER
				return false;
#endif
			}
			offsets.WmipSMBiosTableLength = WmipSMBiosTableLength;
			offsets.PsEnumProcesses = PsEnumProcesses;
			offsets.PspInsertProcess = PspInsertProcess;
			offsets.PspTerminateProcess = PspTerminateProcess;
			offsets.MmQueryVirtualMemory = MmQueryVirtualMemory;
			offsets.NtResumeThread = NtResumeThread;
			offsets.BgpFwQueryBootGraphicsInformation = BgpFwQueryBootGraphicsInformation;
			offsets.PsEnumProcessThreads = PsEnumProcessThreads;
			offsets.PspCreateThread = PspCreateThread;
			offsets.PspSetQuotaLimits = PspSetQuotaLimits;
			offsets.MmQueryWorkingSetInformation = MmQueryWorkingSetInformation;
			offsets.MmAdjustWorkingSetSizeEx = MmAdjustWorkingSetSizeEx;
			offsets.ExpBootEnvironmentInformation = ExpBootEnvironmentInformation;
			offsets.PspRundownSingleProcess = PspRundownSingleProcess;
			offsets.PspGetContextThreadInternal = PspGetContextThreadInternal;
			offsets.WmipSMBiosTablePhysicalAddress = WmipSMBiosTablePhysicalAddress;
			offsets.WmipQueryAllData = WmipQueryAllData;
			offsets.PiDDBLock = PiDDBLock;
			offsets.PiDDBCacheTable = PiDDBCacheTable;
			offsets.PspInsertThread = PspInsertThread;
			offsets.ZwSetInformationProcess = ZwSetInformationProcess;
			offsets.PsQueryFullProcessImageName = PsQueryFullProcessImageName;
			offsets.KiNmiInterruptStart = KiNmiInterruptStart;
			offsets.WmipSMBiosVersionInfo = WmipSMBiosVersionInfo;
		}
#pragma endregion

#pragma region "Raid"
		{
			auto parser = PdbParser(L".\\storport.pdb");
			size_t RaidUnitRegisterInterfaces = parser.GetSymbolRVA(L"RaidUnitRegisterInterfaces");
			size_t dwIdentityOffset = parser.GetStructMemberOffset(L"_RAID_UNIT_EXTENSION", L"Identity");
			size_t dwRaidSerialNumberOffset = parser.GetStructMemberOffset(L"_RAID_UNIT_EXTENSION", L"SerialNumber");
			size_t dwSerialNumberOffset = parser.GetStructMemberOffset(L"_STOR_SCSI_IDENTITY", L"SerialNumber");
			if (INVALID_OFFSET == RaidUnitRegisterInterfaces
				|| INVALID_OFFSET == dwIdentityOffset
				|| INVALID_OFFSET == dwRaidSerialNumberOffset) {
				printf("[-] storport offsets invalid!\n");
#ifdef BUILD_SPOOFER
				return false;
#endif
			}

			offsets.RaidUnitRegInterface = RaidUnitRegisterInterfaces;
			offsets.RaidIdentity = dwIdentityOffset;
			offsets.RaidSerialNumber = dwRaidSerialNumberOffset;
			offsets.ScsiSerialNumber = dwSerialNumberOffset;
		}
#pragma endregion

#pragma region "Ndis"
		{
			auto parser = PdbParser(L".\\ndis.pdb");
			size_t dwNdisGlobalFilterListOffset = parser.GetSymbolRVA(L"ndisGlobalFilterList");
			size_t dwNextFilterOffset = parser.GetStructMemberOffset(L"_NDIS_FILTER_BLOCK", L"NextFilter");
			size_t dwMiniportOffset = parser.GetStructMemberOffset(L"_NDIS_FILTER_BLOCK", L"Miniport");
			size_t dwFilterInstanceNameOffset = parser.GetStructMemberOffset(L"_NDIS_FILTER_BLOCK", L"FilterInstanceName");
			size_t dwIfBlockOffset = parser.GetStructMemberOffset(L"_NDIS_FILTER_BLOCK", L"IfBlock");
			size_t dwIfBlockMiniportOffset = parser.GetStructMemberOffset(L"_NDIS_MINIPORT_BLOCK", L"IfBlock");
			size_t dwInterfaceGuidOffset = parser.GetStructMemberOffset(L"_NDIS_MINIPORT_BLOCK", L"InterfaceGuid");
			size_t dwLowestFilterOffset = parser.GetStructMemberOffset(L"_NDIS_MINIPORT_BLOCK", L"LowestFilter");
			size_t dwHighestFilterOffset = parser.GetStructMemberOffset(L"_NDIS_MINIPORT_BLOCK", L"HighestFilter");
			size_t dwPendingMacAddressOffset = parser.GetStructMemberOffset(L"_NDIS_MINIPORT_BLOCK", L"PendingMacAddress");
			size_t dwNdiNsiInterfaceOffset = parser.GetStructMemberOffset(L"_NDIS_IF_BLOCK", L"_NDIS_NSI_INTERFACE_ENUM_ROD");
			size_t dwIfPhyAddressOffset = dwNdiNsiInterfaceOffset;
			dwIfPhyAddressOffset += parser.GetStructMemberOffset(L"_NDIS_NSI_INTERFACE_ENUM_ROD", L"ifPhysAddress");
			size_t dwPermanentPhysAddressOffset = dwNdiNsiInterfaceOffset;
			dwPermanentPhysAddressOffset += parser.GetStructMemberOffset(L"_NDIS_NSI_INTERFACE_ENUM_ROD", L"PermanentPhysAddress");

			if (dwNdisGlobalFilterListOffset == INVALID_OFFSET
				|| dwNextFilterOffset == INVALID_OFFSET
				|| dwMiniportOffset == INVALID_OFFSET
				|| dwFilterInstanceNameOffset == INVALID_OFFSET
				|| dwIfBlockOffset == INVALID_OFFSET
				|| dwIfPhyAddressOffset == INVALID_OFFSET
				|| dwPermanentPhysAddressOffset == INVALID_OFFSET
				|| dwPendingMacAddressOffset == INVALID_OFFSET
				|| dwLowestFilterOffset == INVALID_OFFSET
				|| dwHighestFilterOffset == INVALID_OFFSET
				|| dwIfBlockMiniportOffset == INVALID_OFFSET
				) {
				printf("[-] ndis offsets invalid!\n");
#ifdef BUILD_SPOOFER
				return false;
#endif
			}

			offsets.NdisGlobalFilterList = dwNdisGlobalFilterListOffset;
			offsets.FilterBlockNextFilter = dwNextFilterOffset;
			offsets.FilterBlockMiniport = dwMiniportOffset;
			offsets.FilterBlockInstanceName = dwFilterInstanceNameOffset;
			offsets.FilterBlockIfBlock = dwIfBlockOffset;

			offsets.MiniportBlockInterfaceGuid = dwInterfaceGuidOffset;
			offsets.MiniportBlockLowestFilter = dwLowestFilterOffset;
			offsets.MiniportBlockHighestFilter = dwHighestFilterOffset;

			offsets.IfBlockPhy = dwIfPhyAddressOffset;
			offsets.IfBlockPermanentPhy = dwPermanentPhysAddressOffset;
			offsets.MiniportIfBlock = dwIfBlockMiniportOffset;
			offsets.MiniportPendingMacAddress = dwPendingMacAddressOffset;
		}
#pragma endregion

		return true;
	}
}

#endif