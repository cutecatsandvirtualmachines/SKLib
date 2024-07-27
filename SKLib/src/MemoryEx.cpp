#pragma warning (disable : 4047 4024 )
#include "MemoryEx.h"

NTSTATUS Memory::ReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PSIZE_T Bytes;

	return MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(), TargetAddress, Size, KernelMode, reinterpret_cast<PSIZE_T>(&Bytes));
}

NTSTATUS Memory::WriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PSIZE_T Bytes;

	return MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process, TargetAddress, Size, KernelMode, reinterpret_cast<PSIZE_T>(&Bytes));
}

NTSTATUS Memory::CopyPhysicalMemory(PVOID pSrc, PVOID pDst, SIZE_T length)
{
	MM_COPY_ADDRESS mmAddress = { 0 };
	PHYSICAL_ADDRESS phy = { 0 };
	phy.QuadPart = (ULONGLONG)pSrc;
	mmAddress.PhysicalAddress = phy;

	SIZE_T out = 0;
	return MmCopyMemory(pDst, mmAddress, length, MM_COPY_MEMORY_PHYSICAL, &out);
}

NTSTATUS Memory::VirtualProtect(PVOID pMemory, ULONG size, ULONG flags)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PHYSICAL_ADDRESS lowAddress = { 0 };
	PHYSICAL_ADDRESS highAddress = { 0 };
	highAddress.QuadPart = ~0ull;
	PHYSICAL_ADDRESS skipAddress = { 0 };
	PMDL mdl = MmAllocatePagesForMdl
	(
		lowAddress,
		highAddress,
		skipAddress,
		size
	);

	PMDL guard_mdl = IoAllocateMdl
	(
		pMemory,
		size,
		FALSE,
		FALSE,
		NULL
	);

	if (guard_mdl)
	{
		IoBuildPartialMdl
		(
			mdl,
			guard_mdl,
			nullptr,  // **offset** from the beginning of allocated memory ptr
			size
		);

		status = MmProtectMdlSystemAddress
		(
			guard_mdl,
			flags
		);
	}
	else {
		DbgMsg("[MEMORY] Virtual protect failed in allocating MDL!");
	}

	IoFreeMdl(mdl);
	return status;
}

UINT64 Memory::VirtToPhy(PVOID Va)
{
	return MmGetPhysicalAddress(Va).QuadPart;
}

UINT64 Memory::PhyToVirt(UINT64 Pa)
{
	PHYSICAL_ADDRESS PhysicalAddr;
	PhysicalAddr.QuadPart = Pa;

	return (UINT64)MmGetVirtualForPhysical(PhysicalAddr);
}

PVOID Memory::GetKernelAddress(PCHAR name)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG neededSize = 0;

	ZwQuerySystemInformation(
		SystemModuleInformation,
		&neededSize,
		0,
		&neededSize
	);

	PSYSTEM_MODULE_INFORMATION pModuleList;

	pModuleList = (PSYSTEM_MODULE_INFORMATION)cpp::kMalloc(neededSize, PAGE_READWRITE);
	if (pModuleList == NULL)
	{
		return FALSE;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation,
		pModuleList,
		neededSize,
		0
	);
	ULONG i = 0;

	PVOID address = 0;

	bool bFound = false;
	for (i = 0; i < (ULONG)pModuleList->ulModuleCount; i++)
	{
		SYSTEM_MODULE mod = pModuleList->Modules[i];

		address = pModuleList->Modules[i].Base;
		
		if (strstr((char*)&mod.ImageName, name) != NULL) {
			bFound = true;
			break;
		}
	}

	cpp::kFree(pModuleList);

	return bFound ? address : nullptr;
}

PSYSTEM_PROCESSES Memory::GetProcess(PCHAR name)
{
	PSYSTEM_PROCESSES pProc = nullptr;
	NTSTATUS ntStatus = 0;
	ULONG bufferSize = 0;

	if (ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize) != STATUS_INFO_LENGTH_MISMATCH) {
		return nullptr;
	}
	if (!bufferSize) {
		return nullptr;
	}
	PVOID memory = ExAllocatePoolWithTag(PagedPool, bufferSize, 'enoN');

	if (!memory) {
		return nullptr;
	}
	ntStatus = ZwQuerySystemInformation(SystemProcessInformation, memory, bufferSize, &bufferSize);
	if (NT_SUCCESS(ntStatus)) {
		PSYSTEM_PROCESSES processEntry = (PSYSTEM_PROCESSES)memory;

		string procName(name);
		do {
			if (processEntry->ProcessName.Length
				&& RtlCompareUnicodeString(&procName.unicode(), &processEntry->ProcessName, TRUE)) {
				pProc = processEntry;
				break;
			}
			processEntry = (PSYSTEM_PROCESSES)((BYTE*)processEntry + processEntry->NextEntryDelta);
		} while (processEntry->NextEntryDelta);
	}
	ExFreePoolWithTag(memory, 'enoN');

	return pProc;
}

char* Memory::GetDriverNameForAddress(char* pAddress)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG neededSize = 0;

	ZwQuerySystemInformation(
		SystemModuleInformation,
		&neededSize,
		0,
		&neededSize
	);

	PSYSTEM_MODULE_INFORMATION pModuleList;

	pModuleList = (PSYSTEM_MODULE_INFORMATION)cpp::kMalloc(neededSize, PAGE_READWRITE);
	if (pModuleList == NULL)
	{
		return FALSE;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation,
		pModuleList,
		neededSize,
		0
	);
	ULONG i = 0;

	char* address = 0;
	char* end = 0;

	char* pName = nullptr;
	for (i = 0; i < (ULONG)pModuleList->ulModuleCount; i++)
	{
		SYSTEM_MODULE mod = pModuleList->Modules[i];

		address = (char*)pModuleList->Modules[i].Base;
		end = address + pModuleList->Modules[i].Size;

		if (pAddress >= address && pAddress < end) {
			pName = (char*)cpp::kMalloc(strlen(pModuleList->Modules[i].ImageName) + 1, PAGE_READWRITE);
			strcpy(pName, pModuleList->Modules[i].ImageName);
			break;
		}
	}

	cpp::kFree(pModuleList);

	return pName;
}

typedef NTSTATUS (*fnZwQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
);
fnZwQueryInformationProcess pZwQueryInformationProcess;

PUNICODE_STRING Memory::GetDriverNameForProcess(PEPROCESS pErocess)
{
	PUNICODE_STRING ProcessImageName = nullptr;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG returnedLength;
	HANDLE hProcess = NULL;

	PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process

	if (pErocess == NULL)
	{
		return nullptr;
	}

	status = ObOpenObjectByPointer(pErocess,
		0, NULL, 0, 0, KernelMode, &hProcess);
	if (!NT_SUCCESS(status))
	{
		DbgMsg("[MEMORY] ObOpenObjectByPointer Failed: 0x%x\n", status);
		return nullptr;
	}

	if (pZwQueryInformationProcess == NULL)
	{
		UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");

		pZwQueryInformationProcess =
			(fnZwQueryInformationProcess)MmGetSystemRoutineAddress(&routineName);

		if (pZwQueryInformationProcess == NULL)
		{
			DbgMsg("[MEMORY] Cannot resolve ZwQueryInformationProcess\n");
			status = STATUS_UNSUCCESSFUL;
			goto cleanUp;
		}
	}

	/* Query the actual size of the process path */
	status = pZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		NULL, // buffer
		0,    // buffer size
		&returnedLength);

	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		DbgMsg("[MEMORY] ZwQueryInformationProcess status = %x\n", status);
		goto cleanUp;
	}

	ProcessImageName = (PUNICODE_STRING)cpp::kMalloc(returnedLength, PAGE_READWRITE);

	if (ProcessImageName == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanUp;
	}

	/* Retrieve the process path from the handle to the process */
	status = pZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		ProcessImageName,
		returnedLength,
		&returnedLength);

	if (!NT_SUCCESS(status)) {
		cpp::kFree(ProcessImageName);
		ProcessImageName = nullptr;
	}

cleanUp:

	ZwClose(hProcess);

	return ProcessImageName;
}

BOOLEAN CheckMask(PCHAR base, PCHAR pattern, PCHAR mask) {
	for (; *mask; ++base, ++pattern, ++mask) {
		if ('x' == *mask && *base != *pattern) {
			return FALSE;
		}
	}

	return TRUE;
}

PVOID Memory::FindPattern(PCHAR base, ULONG length, PCHAR pattern, PCHAR mask) {
	length -= (ULONG)strlen(mask);
	for (ULONG i = 0; i <= length; ++i) {
		PVOID addr = &base[i];
		if (CheckMask((PCHAR)addr, pattern, mask)) {
			return addr;
		}
	}

	return 0;
}

PVOID Memory::FindSection(PCHAR pImageBase, PCHAR pSectionName)
{
	PVOID match = 0;

	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)((DWORD64)pImageBase + ((PIMAGE_DOS_HEADER)pImageBase)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD32 i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (memcmp(section->Name, pSectionName, strlen(pSectionName)) == 0) {
			match = (PCHAR)(pImageBase + section->VirtualAddress);
			break;
		}
	}

	return match;
}

PVOID Memory::FindFunctionStart(PVOID function) {
	char* currPtr = (char*)function;
	while (*(WORD*)currPtr != 0xcccc) {
		currPtr--;
	}

	return currPtr + 2;
}

PVOID Memory::FindPatternImage(PVOID pImageBase, PCHAR pPattern, PCHAR pMask)
{
	PVOID match = 0;

	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)((DWORD64)pImageBase + ((PIMAGE_DOS_HEADER)pImageBase)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD32 i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (memcmp(section->Name, "PAGE", 4) == 0 || memcmp(section->Name, ".text", 5) == 0) {
			match = FindPattern((PCHAR)pImageBase + section->VirtualAddress, section->Misc.VirtualSize, pPattern, pMask);
			if (match) {
				break;
			}
		}
	}

	return match;
}

PVOID Memory::FindByteSeries(PVOID pBase, SIZE_T length, UCHAR byte)
{
	SIZE_T szFound = 0;
	SIZE_T i = 0;
	PVOID pNewBase = 0;

	while (1) {
		if (szFound == length)
			break;
		if (((UCHAR*)pBase)[i++] == byte) {
			szFound++;
			continue;
		}
		else {
			szFound = 0;
			pNewBase = (PVOID)((SIZE_T)pBase + i);
		}
	}

	return pNewBase;
}

PVOID Memory::FindByteSeriesSafe(PVOID pBase, SIZE_T length, UCHAR byte)
{
	SIZE_T szFound = 0;
	SIZE_T i = 0;
	PVOID pNewBase = 0;

	while (1) {
		if (!MmIsAddressValid((UCHAR*)pBase + i)) {
			return nullptr;
		}

		if (szFound == length)
			break;
		if (((UCHAR*)pBase)[i++] == byte) {
			szFound++;
			continue;
		}
		else {
			szFound = 0;
			pNewBase = (PVOID)((SIZE_T)pBase + i);
		}
	}

	return pNewBase;
}

PVOID Memory::FindDriverBase(PVOID pMemory)
{
	DWORD64 currPage = (DWORD64)PAGE_ALIGN(pMemory);
	while (*(WORD*)currPage != 0x5a4d) {
		currPage -= PAGE_SIZE;
	}

	return (PVOID)currPage;
}

PVOID Memory::AttachToProcessId(DWORD32 procId) {
	PEPROCESS pEproc = nullptr;
	if (PsLookupProcessByProcessId((HANDLE)procId, &pEproc) != STATUS_SUCCESS) {
		return nullptr;
	}
	PRKAPC_STATE pRkapcState = (PRKAPC_STATE)cpp::kMalloc(sizeof(*pRkapcState), PAGE_READWRITE);
	KeStackAttachProcess(pEproc, pRkapcState);
	return pRkapcState;
}

VOID Memory::DetachFromProcess(PVOID pRkapcState) {
	KeUnstackDetachProcess((PRKAPC_STATE)pRkapcState);
	cpp::kFree(pRkapcState);
}

VOID Memory::WriteProtected(PVOID dst, PVOID src, SIZE_T sz)
{
	CPU::DisableInterrupts();
	bool bEnableCET = CPU::DisableWriteProtection();
	RtlCopyMemory(dst, src, sz);
	CPU::EnableWriteProtection(bEnableCET);
	CPU::EnableInterrupts();
}

MTRR_RANGE_DESCRIPTOR MemoryRanges[9] = { 0 };
DWORD64 NumberOfEnabledMemoryRanges = 0;

VOID BuildMemoryRanges() {
	IA32_MTRR_CAPABILITIES_REGISTER MTRRCap;
	IA32_MTRR_PHYSBASE_REGISTER CurrentPhysBase;
	IA32_MTRR_PHYSMASK_REGISTER CurrentPhysMask;
	PMTRR_RANGE_DESCRIPTOR Descriptor;
	ULONG CurrentRegister;
	ULONG NumberOfBitsInMask;

	MTRRCap.Flags = __readmsr(MSR_IA32_MTRR_CAPABILITIES);

	for (CurrentRegister = 0; CurrentRegister < MTRRCap.VariableRangeCount; CurrentRegister++)
	{
		// For each dynamic register pair
		CurrentPhysBase.Flags = __readmsr(MSR_IA32_MTRR_PHYSBASE0 + (CurrentRegister * 2));
		CurrentPhysMask.Flags = __readmsr(MSR_IA32_MTRR_PHYSMASK0 + (CurrentRegister * 2));

		// Is the range enabled?
		if (CurrentPhysMask.Valid)
		{
			// We only need to read these once because the ISA dictates that MTRRs are to be synchronized between all processors
			// during BIOS initialization.
			Descriptor = &MemoryRanges[NumberOfEnabledMemoryRanges++];

			// Calculate the base address in bytes
			Descriptor->PhysicalBaseAddress = CurrentPhysBase.PageFrameNumber * PAGE_SIZE;

			// Calculate the total size of the range
			// The lowest bit of the mask that is set to 1 specifies the size of the range
			_BitScanForward64(&NumberOfBitsInMask, CurrentPhysMask.PageFrameNumber * PAGE_SIZE);

			// Size of the range in bytes + Base Address
			Descriptor->PhysicalEndAddress = Descriptor->PhysicalBaseAddress + ((1ULL << NumberOfBitsInMask) - 1ULL);

			// Memory Type (cacheability attributes)
			Descriptor->MemoryType = (UCHAR)CurrentPhysBase.Type;

			if (Descriptor->MemoryType != MEMORY_TYPE_UNCACHEABLE)
			{
				NumberOfEnabledMemoryRanges--;
			}
		}
	}
}

BOOLEAN IsUncached(DWORD64 pa) {
	if (!MemoryRanges[0].PhysicalEndAddress) {
		BuildMemoryRanges();
	}

	for (DWORD64 CurrentMtrrRange = 0; CurrentMtrrRange < NumberOfEnabledMemoryRanges; CurrentMtrrRange++)
	{
		if (pa <= MemoryRanges[CurrentMtrrRange].PhysicalEndAddress
			&& (pa + SIZE_2_MB - 1) >= MemoryRanges[CurrentMtrrRange].PhysicalBaseAddress)
		{
			if (MemoryRanges[CurrentMtrrRange].MemoryType == MEMORY_TYPE_UNCACHEABLE)
			{
				return TRUE;
			}
		}
	}

	return FALSE;
}

MTRR_RANGE_DESCRIPTOR* Memory::GetMemoryRangeDescriptors() {
	if (!NumberOfEnabledMemoryRanges) {
		BuildMemoryRanges();
	}

	return MemoryRanges;
}

DWORD64 Memory::GetMemoryRangeDescriptorsLength() {
	return NumberOfEnabledMemoryRanges;
}

BOOLEAN Memory::IsInMemoryRanges(PVOID pBase)
{
	MTRR_RANGE_DESCRIPTOR* pMttr = GetMemoryRangeDescriptors();

	for (size_t mttrIndex = 0; mttrIndex < GetMemoryRangeDescriptorsLength(); mttrIndex++)
	{
		SIZE_T mttrLen = pMttr[mttrIndex].PhysicalEndAddress - pMttr[mttrIndex].PhysicalBaseAddress;
		if (((SIZE_T)pBase >= pMttr[mttrIndex].PhysicalBaseAddress) && ((SIZE_T)pBase < pMttr[mttrIndex].PhysicalEndAddress))
			return true;
	}
	return false;
}
