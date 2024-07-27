#pragma once

#include "cpp.h"
#include "PE.h"
#include "winternlex.h"

#ifdef _KERNEL_MODE
#include <intrin.h>
#include <ia32.h>

typedef struct _SYSTEM_BASIC_INFORMATION
{
	ULONG Reserved;
	ULONG TimerResolution;
	ULONG PageSize;
	ULONG NumberOfPhysicalPages;
	ULONG LowestPhysicalPageNumber;
	ULONG HighestPhysicalPageNumber;
	ULONG AllocationGranularity;
	ULONG_PTR MinimumUserModeAddress;
	ULONG_PTR MaximumUserModeAddress;
	KAFFINITY ActiveProcessorsAffinityMask;
	CHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, * PSYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_MODULE   // Information Class 11
{
	ULONG_PTR Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION   // Information Class 11
{
	ULONG_PTR ulModuleCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_THREADS {
	LARGE_INTEGER  KernelTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  CreateTime;
	ULONG          WaitTime;
	PVOID          StartAddress;
	CLIENT_ID      ClientId;
	KPRIORITY      Priority;
	KPRIORITY      BasePriority;
	ULONG          ContextSwitchCount;
	LONG           State;
	LONG           WaitReason;
} SYSTEM_THREADS, * PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES {
	ULONG            NextEntryDelta;
	ULONG            ThreadCount;
	ULONG            Reserved1[6];
	LARGE_INTEGER    CreateTime;
	LARGE_INTEGER    UserTime;
	LARGE_INTEGER    KernelTime;
	UNICODE_STRING   ProcessName;
	KPRIORITY        BasePriority;
	SIZE_T           ProcessId;
	SIZE_T           InheritedFromProcessId;
	ULONG            HandleCount;
	ULONG            Reserved2[2];
	VM_COUNTERS      VmCounters;
	IO_COUNTERS      IoCounters;
	SYSTEM_THREADS   Threads[1];
} SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

typedef struct _MTRR_RANGE_DESCRIPTOR
{
	SIZE_T PhysicalBaseAddress;
	SIZE_T PhysicalEndAddress;
	UCHAR  MemoryType;
} MTRR_RANGE_DESCRIPTOR, * PMTRR_RANGE_DESCRIPTOR;

extern "C"
NTSTATUS ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

namespace paging {
	PVOID MapToGuest(PVOID pa);
	PVOID MapManually(PVOID pa);
	void RestoreMapPage();
}

namespace Memory {
	NTSTATUS ReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size);
	NTSTATUS WriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size);
	NTSTATUS CopyPhysicalMemory(PVOID pSrc, PVOID pDst, SIZE_T length);

	NTSTATUS VirtualProtect(PVOID pMemory, ULONG size, ULONG flags);

	UINT64 VirtToPhy(PVOID Va);
	UINT64 PhyToVirt(UINT64 Pa);

	PVOID GetKernelAddress(PCHAR name);
	PSYSTEM_PROCESSES GetProcess(PCHAR name);
	char* GetDriverNameForAddress(char* pAddress);
	PUNICODE_STRING GetDriverNameForProcess(PEPROCESS pErocess);
	PVOID FindFunctionStart(PVOID function);
	PVOID FindPatternImage(PVOID pImageBase, PCHAR pPattern, PCHAR pMask);
	PVOID FindPattern(PCHAR base, ULONG length, PCHAR pattern, PCHAR mask);
	PVOID FindSection(PCHAR base, PCHAR pSectionName);
	PVOID FindByteSeries(PVOID pBase, SIZE_T length, UCHAR byte);
	PVOID FindByteSeriesSafe(PVOID pBase, SIZE_T length, UCHAR byte);
	PVOID FindDriverBase(PVOID pMemory);
	MTRR_RANGE_DESCRIPTOR* GetMemoryRangeDescriptors();
	DWORD64 GetMemoryRangeDescriptorsLength();
	BOOLEAN IsInMemoryRanges(PVOID pBase);

	template<typename F>
	BOOLEAN ForEachBytePattern(char* pBase, char* pPattern, size_t maxLen, size_t szPattern, F fnCallback) {
		if (maxLen <= szPattern) {
			return FALSE;
		}
		for (size_t i = 0; i < (maxLen - 1 - szPattern); i++) {
			if (!memcmp(pBase + i, pPattern, szPattern)) {
				fnCallback(pBase + i);
			}
		}
		return TRUE;
	}

	template<typename F>
	BOOLEAN ForEachBytePatternInPhy(char* pPattern, size_t szPattern, F fnCallback) {
		if (!szPattern) {
			return FALSE;
		}
		if (PAGE_SIZE <= szPattern) {
			return FALSE;
		}

		PPHYSICAL_MEMORY_RANGE pMttr = MmGetPhysicalMemoryRanges();
		auto phyMemRanges = 0;

		for (size_t mttrIndex = 0; (pMttr[mttrIndex].BaseAddress.QuadPart || pMttr[mttrIndex].NumberOfBytes.QuadPart);
			mttrIndex++)
		{
			//DbgMsg("[MEMORY] Pattern scan 0x%llx bytes from 0x%llx", pMttr[mttrIndex].NumberOfBytes.QuadPart, pMttr[mttrIndex].BaseAddress.QuadPart);
			for (LONGLONG pageIndex = 0; pageIndex < pMttr[mttrIndex].NumberOfBytes.QuadPart / PAGE_SIZE; pageIndex++) {
				UINT64 currAddress = pMttr[mttrIndex].BaseAddress.QuadPart + (pageIndex * PAGE_SIZE);
				PVOID pCurrPage = paging::MapToGuest((PVOID)currAddress);
				if (winternl::IsDriverAddress((DWORD64)pCurrPage)) {
					continue;
				}
				for (size_t i = 0; i < (PAGE_SIZE - 1 - szPattern); i++) {
					if (!memcmp((char*)pCurrPage + i, pPattern, szPattern)) {
						fnCallback((char*)pCurrPage + i);
					}
				}
			}
			phyMemRanges++;
		}

		return TRUE;
	}

	template<typename F>
	BOOLEAN ForEachBytePatternInPhyDevice(char* pPattern, size_t szPattern, F fnCallback) {
		if (!szPattern) {
			return FALSE;
		}
		if (PAGE_SIZE <= szPattern) {
			return FALSE;
		}

		MTRR_RANGE_DESCRIPTOR* pMttr = GetMemoryRangeDescriptors();
		auto phyMemRanges = 0;

		for (size_t mttrIndex = 0; mttrIndex < GetMemoryRangeDescriptorsLength(); mttrIndex++)
		{
			SIZE_T mttrLen = pMttr[mttrIndex].PhysicalEndAddress - pMttr[mttrIndex].PhysicalBaseAddress;
			for (SIZE_T pageIndex = 0; pageIndex < mttrLen / PAGE_SIZE; pageIndex++) {
				UINT64 currAddress = pMttr[mttrIndex].PhysicalBaseAddress + (pageIndex * PAGE_SIZE);
				if (currAddress > SIZE_2_MB * 0x10)
					return TRUE;
				PVOID pCurrPage = paging::MapToGuest((PVOID)currAddress);
				if (winternl::IsDriverAddress((DWORD64)pCurrPage)) {
					continue;
				}
				for (size_t i = 0; i < (PAGE_SIZE - 1 - szPattern); i++) {
					if (!memcmp((char*)pCurrPage + i, pPattern, szPattern)) {
						fnCallback((char*)pCurrPage + i);
					}
				}
			}
			phyMemRanges++;
		}

		return TRUE;
	}

	template<typename F>
	BOOLEAN ForEachBytePatternInPhyUncached(char* pPattern, size_t szPattern, F fnCallback) {
		if (!szPattern) {
			return FALSE;
		}
		if (PAGE_SIZE <= szPattern) {
			return FALSE;
		}

		MTRR_RANGE_DESCRIPTOR* pMttr = GetMemoryRangeDescriptors();
		auto phyMemRanges = 0;

		for (size_t mttrIndex = 0; mttrIndex < GetMemoryRangeDescriptorsLength(); mttrIndex++)
		{
			SIZE_T mttrLen = pMttr[mttrIndex].PhysicalEndAddress - pMttr[mttrIndex].PhysicalBaseAddress;
			DbgMsg("[MTRR] Iterating range from 0x%llx with length 0x%llx", pMttr[mttrIndex].PhysicalBaseAddress, mttrLen);
			for (SIZE_T pageIndex = 0; pageIndex < mttrLen / PAGE_SIZE; pageIndex++) {
				UINT64 currAddress = pMttr[mttrIndex].PhysicalBaseAddress + (pageIndex * PAGE_SIZE);
				PVOID pCurrPage = paging::MapToGuest((PVOID)currAddress);
				if (winternl::IsDriverAddress((DWORD64)pCurrPage)) {
					continue;
				}
				for (size_t i = 0; i < (PAGE_SIZE - 1 - szPattern); i++) {
					if (!memcmp((char*)pCurrPage + i, pPattern, szPattern)) {
						fnCallback((char*)pCurrPage + i);
					}
				}
			}
			phyMemRanges++;
		}

		return TRUE;
	}

	template<typename F>
	BOOLEAN ForEachPageMapped(F fnCallback) {
		SYSTEM_BASIC_INFORMATION Sbi;
		NTSTATUS ntStatus = ZwQuerySystemInformation(SystemBasicInformation, &Sbi, sizeof(Sbi), NULL);
		if (!NT_SUCCESS(ntStatus)) {
			DbgMsg("[EPT] Could not get physical memory size!");
			return FALSE;
		}

		for (size_t pfn = Sbi.LowestPhysicalPageNumber; pfn < Sbi.HighestPhysicalPageNumber; pfn++) {
			PVOID pCurrPage = (PVOID)Memory::PhyToVirt(pfn * PAGE_SIZE);
			if (!cpp::IsKernelAddress((PVOID)pCurrPage))
				continue;
			pCurrPage = paging::MapToGuest((PVOID)(pfn * PAGE_SIZE));

			fnCallback(pCurrPage);
		}

		return TRUE;

	}

	template<typename F>
	BOOLEAN ForEachPageInPhy(F fnCallback) {
		PPHYSICAL_MEMORY_RANGE pMttr = MmGetPhysicalMemoryRanges();
		auto phyMemRanges = 0;

		for (size_t mttrIndex = 0; (pMttr[mttrIndex].BaseAddress.QuadPart || pMttr[mttrIndex].NumberOfBytes.QuadPart);
			mttrIndex++)
		{
			for (LONGLONG pageIndex = 0; pageIndex <= pMttr[mttrIndex].NumberOfBytes.QuadPart / PAGE_SIZE; pageIndex++) {
				UINT64 currAddress = pMttr[mttrIndex].BaseAddress.QuadPart + (pageIndex * PAGE_SIZE);
				PVOID pCurrPage = paging::MapToGuest((PVOID)currAddress);
				fnCallback(pCurrPage);
			}
			phyMemRanges++;
		}

		return TRUE;
	}

	template<typename F>
	BOOLEAN ForEachPageInPhyPassPhy(F fnCallback) {
		PPHYSICAL_MEMORY_RANGE pMttr = MmGetPhysicalMemoryRanges();
		auto phyMemRanges = 0;

		for (size_t mttrIndex = 0; (pMttr[mttrIndex].BaseAddress.QuadPart || pMttr[mttrIndex].NumberOfBytes.QuadPart);
			mttrIndex++)
		{
			for (LONGLONG pageIndex = 0; pageIndex <= pMttr[mttrIndex].NumberOfBytes.QuadPart / PAGE_SIZE; pageIndex++) {
				UINT64 currAddress = pMttr[mttrIndex].BaseAddress.QuadPart + (pageIndex * PAGE_SIZE);
				PVOID pCurrPage = paging::MapToGuest((PVOID)currAddress);
				fnCallback(pCurrPage, currAddress);
			}
			phyMemRanges++;
		}

		return TRUE;
	}

	template<typename F>
	BOOLEAN ForEachPageUncachedInPhy(F fnCallback) {
		MTRR_RANGE_DESCRIPTOR* pMttr = GetMemoryRangeDescriptors();
		auto phyMemRanges = 0;

		for (size_t mttrIndex = 0; mttrIndex < GetMemoryRangeDescriptorsLength(); mttrIndex++)
		{
			SIZE_T mttrLen = pMttr[mttrIndex].PhysicalEndAddress - pMttr[mttrIndex].PhysicalBaseAddress;
			for (SIZE_T pageIndex = 0; pageIndex < mttrLen / PAGE_SIZE; pageIndex++) {
				UINT64 currAddress = pMttr[mttrIndex].PhysicalBaseAddress + (pageIndex * PAGE_SIZE);
				PVOID pCurrPage = paging::MapToGuest((PVOID)currAddress);
				fnCallback(pCurrPage);
			}
			phyMemRanges++;
		}

		return TRUE;
	}

	template<typename F>
	BOOLEAN ForEachPageInPhyDevice(F fnCallback) {
		MTRR_RANGE_DESCRIPTOR* pMttr = GetMemoryRangeDescriptors();
		auto phyMemRanges = 0;

		for (size_t mttrIndex = 0; mttrIndex < GetMemoryRangeDescriptorsLength(); mttrIndex++)
		{
			SIZE_T mttrLen = pMttr[mttrIndex].PhysicalEndAddress - pMttr[mttrIndex].PhysicalBaseAddress;
			for (SIZE_T pageIndex = 0; pageIndex < mttrLen / PAGE_SIZE; pageIndex++) {
				UINT64 currAddress = pMttr[mttrIndex].PhysicalBaseAddress + (pageIndex * PAGE_SIZE);
				if (currAddress > SIZE_2_MB * 0x10)
					return TRUE;
				PVOID pCurrPage = paging::MapToGuest((PVOID)currAddress);
				fnCallback(pCurrPage);
			}
			phyMemRanges++;
		}

		return TRUE;
	}

	PVOID AttachToProcessId(DWORD32 procId);
	VOID DetachFromProcess(PVOID pRkapcState);

	VOID WriteProtected(PVOID dst, PVOID src, SIZE_T sz);
}
#endif