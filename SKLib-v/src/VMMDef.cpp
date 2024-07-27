#include "VMMDef.h"

#include "Vmcall.h"
#include "Vmexit.h"
#include "Vmoperations.h"
#include <identity.h>
#include <threading.h>

PVM_STATE vmm::vGuestStates = nullptr;
EPT_STATE* vmm::eptShadow = nullptr;
DWORD64 vmm::dwCores = 0;
ULONG vmm::ulProcessorMask = 0;
Spinlock vmm::lock;
vector<HOOK_DATA>* vmm::vHooks = nullptr;
CR3 vmm::hostCR3 = { 0 };
CR3 vmm::guestCR3 = { 0 };
PVOID vmm::pIdentityMap = 0;
DWORD64 vmm::tscDeltaTimeout = 0;
DWORD64 vmm::oldestValidTsc = 0;
bool vmmInitialised = false;

list<PVOID>* vPageTablesPools = nullptr;
char* pIdentity = nullptr;

#define MY_ENTRY 256

inline const PPML4T vmxrootPml4 = reinterpret_cast<PPML4T>(0xffff800000000000);
//inline const PPML4T vmxrootPml4 = reinterpret_cast<PPML4T>(0x0000000000000000);
PPML4T pPML4Table1 = nullptr;
__declspec(align(4096)) PDPTE_64 vmxRootPdpte;
__declspec(align(4096)) PDE_64 vmxRootPde;
__declspec(align(4096)) PTE_64 vmxRootPte[PT_ENTRIES];

__declspec(align(4096)) char test[0x1000];

void vmm::Init()
{
    if (vmmInitialised) {
        DbgMsg("[VMM] Already initialised");
        return;
    }
    DbgMsg("[VMM] Initializing VMM...");

    vmm::dwCores = CPU::GetCPUCount();

    DbgMsg("[VMM] Initialising guest states");
    if (!vmm::vGuestStates) {
        vmm::vGuestStates = (PVM_STATE)cpp::kMalloc(sizeof(VM_STATE) * vmm::dwCores, PAGE_READWRITE);
        RtlZeroMemory(vmm::vGuestStates, sizeof(VM_STATE) * vmm::dwCores);
    }
    DbgMsg("[VMM] Initialising hooks");
	if (!MmIsAddressValid(vmm::vHooks)) {
		vmm::vHooks = (vector<HOOK_DATA>*)cpp::kMallocTryAll(sizeof(*vmm::vHooks));
		RtlZeroMemory(vmm::vHooks, sizeof(*vmm::vHooks));
		vmm::vHooks->Init();
		vmm::vHooks->reserve(128);
		vmm::vHooks->DisableLock();
	}

    DbgMsg("[VMM] Initialising EPT");

    if (!EPT::Init()) {
        DbgMsg("[VMM] Error: failed to initialize EPT!");
    }

    DbgMsg("[VMM] Initialising VMCALL handlers");
    if (!vmcall::Init()) {
        DbgMsg("[VMM] Error: failed to initialize VMCALL handlers, unexpected crashes may occurr if dynamic vmcalls are invoked");
    }

    DbgMsg("[VMM] Initialising VMEXIT handlers");
    vmexit::Init();

    DbgMsg("[VMM] Initialising VM operations");
    vmoperations::Init();

    DbgMsg("[VMM] Initialising custom bugcheck");
    bugcheck::Init();

	DbgMsg("[VMM] Initialising EAC bypasses");
	eac::Init();

    PEPROCESS ntoskrnl = PsInitialSystemProcess;
	vmm::guestCR3.Flags = *(DWORD64*)((DWORD64)ntoskrnl + 0x28);

	PoRegisterSystemState(NULL, ES_SYSTEM_REQUIRED | ES_CONTINUOUS);
	DbgMsg("[VMM] Blocked power state to S0");

	DWORD64 tsc1 = __rdtsc();
	threading::Sleep(CLOCK_TIMEOUT_MS / 100);
	DWORD64 tsc2 = __rdtsc();
	vmm::tscDeltaTimeout = (tsc2 - tsc1) * 100;

    DbgMsg("[VMM] Done");
    vmmInitialised = true;
}

void vmm::Virtualise()
{
    if (CPU::bIntelCPU)
        VTx::VirtualizeSystem();
    else
        SVM::VirtualiseAllCores();
}

bool vmm::IsTimeoutExpired()
{
#ifndef ENABLE_CLOCK_TIMEOUT
	return false;
#else
	DWORD dwCore = CPU::GetCPUIndex(true);

	if (
		vmm::vGuestStates[dwCore].lastCr3Tsc
		&& (__rdtsc() - vmm::vGuestStates[dwCore].lastCr3Tsc) > vmm::tscDeltaTimeout
		&& !vmm::vGuestStates[dwCore].bTimeoutExpired
		) {
		vmm::vGuestStates[dwCore].bTimeoutExpired = true;
		return true;
	}
	return false;
#endif
}

EXIT_ERRORS paging::vmmhost::ReadPhyMemory(PVOID pOut, PVOID pTargetPa, SIZE_T size)
{
	CR3 guestCr3 = vmm::GetGuestCR3();

	while (size) {
		DWORD64 destSize = PAGE_SIZE - VIRT_ADD{ (DWORD64)pOut }.offset_4kb;
		if (size < destSize)
			destSize = size;

		DWORD64 srcSize = PAGE_SIZE - VIRT_ADD{ (DWORD64)pTargetPa }.offset_4kb;
		if (size < srcSize)
			srcSize = size;

		PVOID pMappedTarget = paging::vmmhost::MapGuestToHost(
			guestCr3.Flags,
			(PVOID)pOut,
			MAP_TYPE::dest);
		if (!pMappedTarget)
		{
			return EXIT_ERRORS::ERROR_CANNOT_MAP_DST;
		}

		PVOID pMappedIn = paging::vmmhost::MapToHost(
			(PVOID)pTargetPa,
			MAP_TYPE::src);
		if (!pMappedIn)
		{
			return EXIT_ERRORS::ERROR_CANNOT_MAP_SRC;
		}

		DWORD64 currentSize = min(destSize, srcSize);
		__try {
			__movsb((PUCHAR)pMappedTarget, (PUCHAR)pMappedIn, currentSize);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return EXIT_ERRORS::ERROR_PAGE_FAULT;
		}

		pTargetPa = (PVOID)((DWORD64)pTargetPa + currentSize);
		pOut = (PVOID)((DWORD64)pOut + currentSize);
		size -= currentSize;
	}

	return EXIT_ERRORS::ERROR_SUCCESS;
}

EXIT_ERRORS paging::vmmhost::WritePhyMemory(PVOID pTargetPa, PVOID pIn, SIZE_T size)
{
	CR3 guestCr3 = vmm::GetGuestCR3();
	while (size) {
		DWORD64 destSize = PAGE_SIZE - VIRT_ADD{ (DWORD64)pTargetPa }.offset_4kb;
		if (size < destSize)
			destSize = size;

		DWORD64 srcSize = PAGE_SIZE - VIRT_ADD{ (DWORD64)pIn }.offset_4kb;
		if (size < srcSize)
			srcSize = size;

		PVOID pMappedIn = paging::vmmhost::MapGuestToHost(
			guestCr3.Flags,
			(PVOID)pIn,
			MAP_TYPE::src);
		if (!pMappedIn)
		{
			return EXIT_ERRORS::ERROR_CANNOT_MAP_SRC;
		}

		PVOID pMappedTarget = paging::vmmhost::MapToHost(
			(PVOID)pTargetPa,
			MAP_TYPE::dest);
		if (!pMappedTarget)
		{
			return EXIT_ERRORS::ERROR_CANNOT_MAP_DST;
		}

		DWORD64 currentSize = min(destSize, srcSize);
		__try {
			__movsb((PUCHAR)pMappedTarget, (PUCHAR)pMappedIn, currentSize);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return EXIT_ERRORS::ERROR_PAGE_FAULT;
		}

		pTargetPa = (PVOID)((DWORD64)pTargetPa + currentSize);
		pIn = (PVOID)((DWORD64)pIn + currentSize);
		size -= currentSize;
	}

	return EXIT_ERRORS::ERROR_SUCCESS;
}

EXIT_ERRORS paging::vmmhost::ReadVirtMemory(PVOID pOut, PVOID pTarget, SIZE_T size, CR3 cr3) {
	return ReadVirtMemoryEx(pOut, pTarget, size, vmm::GetGuestCR3(), cr3);
}

EXIT_ERRORS paging::vmmhost::ReadVirtMemoryEx(PVOID pOut, PVOID pTarget, SIZE_T size, CR3 cr3, CR3 targetCr3) {
	while (size) {
		DWORD64 destSize = PAGE_SIZE - VIRT_ADD{ (DWORD64)pOut }.offset_4kb;
		if (size < destSize)
			destSize = size;

		DWORD64 srcSize = PAGE_SIZE - VIRT_ADD{ (DWORD64)pTarget }.offset_4kb;
		if (size < srcSize)
			srcSize = size;

		PVOID pMappedOut = paging::vmmhost::MapGuestToHost(
			cr3.Flags,
			(PVOID)pOut,
			MAP_TYPE::dest);
		if (!pMappedOut)
		{
			return EXIT_ERRORS::ERROR_CANNOT_MAP_DST;
		}

		PVOID pMappedTarget = paging::vmmhost::MapGuestToHost(
			targetCr3.Flags,
			(PVOID)pTarget,
			MAP_TYPE::src);
		if (!pMappedTarget)
		{
			return EXIT_ERRORS::ERROR_CANNOT_MAP_SRC;
		}

		DWORD64 currentSize = min(destSize, srcSize);
		__try {
			__movsb((PUCHAR)pMappedOut, (PUCHAR)pMappedTarget, currentSize);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return EXIT_ERRORS::ERROR_PAGE_FAULT;
		}

		pTarget = (PVOID)((DWORD64)pTarget + currentSize);
		pOut = (PVOID)((DWORD64)pOut + currentSize);
		size -= currentSize;
	}

	return EXIT_ERRORS::ERROR_SUCCESS;
}

EXIT_ERRORS paging::vmmhost::WriteVirtMemory(PVOID pTarget, PVOID pIn, SIZE_T size, CR3 cr3)
{
	return WriteVirtMemoryEx(pTarget, pIn, size, cr3, vmm::GetGuestCR3());
}

EXIT_ERRORS paging::vmmhost::WriteVirtMemoryEx(PVOID pTarget, PVOID pIn, SIZE_T size, CR3 cr3, CR3 inCr3)
{
	while (size) {
		DWORD64 destSize = PAGE_SIZE - VIRT_ADD{ (DWORD64)pTarget }.offset_4kb;
		if (size < destSize)
			destSize = size;

		DWORD64 srcSize = PAGE_SIZE - VIRT_ADD{ (DWORD64)pIn }.offset_4kb;
		if (size < srcSize)
			srcSize = size;

		PVOID pMappedIn = paging::vmmhost::MapGuestToHost(
			inCr3.Flags,
			(PVOID)pIn,
			MAP_TYPE::src);
		if (!pMappedIn)
		{
			return EXIT_ERRORS::ERROR_CANNOT_MAP_SRC;
		}

		PVOID pMappedTarget = paging::vmmhost::MapGuestToHost(
			cr3.Flags,
			(PVOID)pTarget,
			MAP_TYPE::dest);
		if (!pMappedTarget)
		{
			return EXIT_ERRORS::ERROR_CANNOT_MAP_DST;
		}

		DWORD64 currentSize = min(destSize, srcSize);
		__try {
			__movsb((PUCHAR)pMappedTarget, (PUCHAR)pMappedIn, currentSize);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return EXIT_ERRORS::ERROR_PAGE_FAULT;
		}

		pTarget = (PVOID)((DWORD64)pTarget + currentSize);
		pIn = (PVOID)((DWORD64)pIn + currentSize);
		size -= currentSize;
	}

	return EXIT_ERRORS::ERROR_SUCCESS;
}

PVOID paging::vmmhost::GuestVirtToPhy(PVOID va, PVOID pGuestPml4tPa, MAP_TYPE mapType, bool* pIsLargePage)
{
	__try {
		PPML4T pPml4t = (PPML4T)MapToHost(pGuestPml4tPa, mapType);
		VIRT_ADD virtAdd{ (DWORD64)va };

		if (!pPml4t->entry[virtAdd.pml4_index].Present) {
			return nullptr;
		}

		PML4E_64 pml4 = pPml4t->entry[virtAdd.pml4_index];
		PPDPT pPdpt = (PPDPT)MapToHost((PVOID)(pPml4t->entry[virtAdd.pml4_index].PageFrameNumber * PAGE_SIZE), mapType);
		if (!pPdpt->entry[virtAdd.pdpt_index].Present) {
			return nullptr;
		}

		PDPTE_1GB_64* pPdpte = (PDPTE_1GB_64*)&pPdpt->entry[virtAdd.pdpt_index];
		PDPTE_64 pdpt = pPdpt->entry[virtAdd.pdpt_index];
		if (pPdpt->entry[virtAdd.pdpt_index].LargePage) {
			if (pIsLargePage)
				*pIsLargePage = true;
			return (PVOID)((pPdpte->PageFrameNumber * PAGE_SIZE * 0x200 * 0x200) + virtAdd.offset_1gb);
		}

		PPDT pPdt = (PPDT)MapToHost((PVOID)(pPdpt->entry[virtAdd.pdpt_index].PageFrameNumber * PAGE_SIZE), mapType);
		if (!pPdt->entry[virtAdd.pdt_index].Present) {
			return nullptr;
		}

		PDE_2MB_64* pPde = (PDE_2MB_64*)&pPdt->entry[virtAdd.pdt_index];
		PDE_64 pde = pPdt->entry[virtAdd.pdt_index];
		if (pPdt->entry[virtAdd.pdt_index].LargePage) {
			if (pIsLargePage)
				*pIsLargePage = true;
			return (PVOID)((pPde->PageFrameNumber * PAGE_SIZE * 0x200) + virtAdd.offset_2mb);
		}

		PPT pPt = (PPT)MapToHost((PVOID)(pPdt->entry[virtAdd.pdt_index].PageFrameNumber * PAGE_SIZE), mapType);
		PTE_64 pte = pPt->entry[virtAdd.pt_index];
		if (!pPt->entry[virtAdd.pt_index].Present) {
			return nullptr;
		}

		if (pIsLargePage)
			*pIsLargePage = false;
		return (PVOID)((pPt->entry[virtAdd.pt_index].PageFrameNumber * PAGE_SIZE) + virtAdd.offset_4kb);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return 0;
	}
}

PVOID paging::vmmhost::MapToHost(PVOID pa, MAP_TYPE mapType)
{
	identity::PhysicalAccess phy(vmm::pIdentityMap, vmm::hostCR3.Flags);
	return phy.phys2virt((DWORD64)pa);
}

PVOID paging::vmmhost::MapGuestToHost(DWORD64 cr3, PVOID va, MAP_TYPE mapType)
{
	CR3 guestCR3;
	guestCR3.Flags = cr3;

	identity::PhysicalAccess phy(vmm::pIdentityMap, cr3);
	return phy.VirtToIdentityVirt((uintptr_t)va);
}

PVOID AllocAndTrack(size_t size) {
	PVOID pMem = cpp::kMallocContinuous(size);
	return pMem;
}

void SetupPT(PDE_64* pPDTable, PDE_64* pTemplate) {
	PTE_64* originalSmallPageTable = (PTE_64*)(pIdentity + (pTemplate->PageFrameNumber * PAGE_SIZE));

	PTE_64* smallPageTable = 0;
	for (int i = 0; i < PT_ENTRIES; i++) {
		if (!originalSmallPageTable[i].Present
			|| !originalSmallPageTable[i].Write)
			continue;

		if (!smallPageTable) {
			smallPageTable = (PTE_64*)AllocAndTrack(sizeof(PTE_64) * PT_ENTRIES);
			pPDTable->Flags = pTemplate->Flags;
			pPDTable->PageFrameNumber = (SIZE_T)Memory::VirtToPhy(smallPageTable) / PAGE_SIZE;
		}
		smallPageTable[i].Flags = originalSmallPageTable[i].Flags;
	}
}

void SetupPDPTable(PDPTE_64* pPDPTable, PPDPT pOriginalPDPTable) {
	for (DWORD64 EntryGroupIndex = 0; EntryGroupIndex < PT_ENTRIES; EntryGroupIndex++) {
		PDPTE_64& currPDPT = pOriginalPDPTable->entry[EntryGroupIndex];
		if (!currPDPT.Present
			|| !currPDPT.PageFrameNumber
			|| !currPDPT.Write
			|| currPDPT.LargePage
			)
			continue;
		PDE_64* currPDT = (PDE_64*)(pIdentity + (currPDPT.PageFrameNumber * PAGE_SIZE));

		PDE_64* pPDTable = 0;

		for (DWORD64 EntryIndex = 0; EntryIndex < PT_ENTRIES; EntryIndex++) {
			if (currPDT[EntryIndex].LargePage
				|| !currPDT[EntryIndex].Present
				|| !currPDT[EntryIndex].Write
				) {
				continue;
			}

			if (!pPDTable) {
				pPDTable = (PDE_64*)AllocAndTrack(sizeof(PDE_64) * PT_ENTRIES);
				RtlZeroMemory(pPDTable, PAGE_SIZE);
				pPDPTable[EntryGroupIndex].Flags = currPDPT.Flags;
				pPDPTable[EntryGroupIndex].PageFrameNumber = (SIZE_T)Memory::VirtToPhy(pPDTable) / PAGE_SIZE;
			}

			SetupPT(&pPDTable[EntryIndex], &currPDT[EntryIndex]);
		}
	}
}

void SetupVmxRootMapping(PPML4T pPML4Table) {
	RtlZeroMemory(test, PAGE_SIZE);

	pPML4Table->entry[MY_ENTRY].Flags = 0;
	pPML4Table->entry[MY_ENTRY].PageFrameNumber = Memory::VirtToPhy(&vmxRootPdpte) / PAGE_SIZE;
	pPML4Table->entry[MY_ENTRY].Write = true;
	pPML4Table->entry[MY_ENTRY].Present = true;
	pPML4Table->entry[MY_ENTRY].PageLevelCacheDisable = true;

	vmxRootPdpte.Flags = 0;
	vmxRootPdpte.PageFrameNumber = Memory::VirtToPhy(&vmxRootPde) / PAGE_SIZE;
	vmxRootPdpte.Write = true;
	vmxRootPdpte.Present = true;
	vmxRootPdpte.PageLevelCacheDisable = true;

	vmxRootPde.Flags = 0;
	vmxRootPde.PageFrameNumber = Memory::VirtToPhy(vmxRootPte) / PAGE_SIZE;
	vmxRootPde.Write = true;
	vmxRootPde.Present = true;
	vmxRootPde.PageLevelCacheDisable = true;

	for (int i = 0; i < 512; i++) {
		vmxRootPte[i].Flags = 0;
		vmxRootPte[i].Present = true;
		vmxRootPte[i].Write = true;
		vmxRootPte[i].PageLevelCacheDisable = true;
		vmxRootPte[i].PageFrameNumber = Memory::VirtToPhy(test) / PAGE_SIZE;
	}
}

PPML4T paging::CopyPML4Mapping(CR3 cr3)
{
	PML4E_64* pOriginalPML4 = (PML4E_64*)paging::GetPML4Base(cr3);
	vPageTablesPools = (list<PVOID>*)cpp::kMalloc(sizeof(*vPageTablesPools), PAGE_READWRITE);
	RtlZeroMemory(vPageTablesPools, sizeof(*vPageTablesPools));
	vPageTablesPools->Init();

	pPML4Table1 = (PPML4T)AllocAndTrack(sizeof(PML4T));
	RtlZeroMemory(pPML4Table1, sizeof(PML4T));

	CR3 currCr3 = { 0 };
	currCr3.Flags = __readcr3();
	pIdentity = (char*)identity::MapIdentityUntracked(currCr3);

	for (DWORD32 PML4Index = 256; PML4Index < PT_ENTRIES; PML4Index++) {
		if (!pOriginalPML4[PML4Index].Present)
			continue;

		pPML4Table1->entry[PML4Index].Flags = pOriginalPML4[PML4Index].Flags;

		PDPTE_64* pOriginalPDPT = (PDPTE_64*)(pIdentity + (pOriginalPML4[PML4Index].PageFrameNumber * PAGE_SIZE));

		PDPTE_64* pPDPTable = (PDPTE_64*)AllocAndTrack(sizeof(PDPTE_64) * PT_ENTRIES);
		RtlZeroMemory(pPDPTable, PAGE_SIZE);
		SetupPDPTable(pPDPTable, (PPDPT)pOriginalPDPT);
		pPML4Table1->entry[PML4Index].PageFrameNumber = (SIZE_T)Memory::VirtToPhy(pPDPTable) / PAGE_SIZE;
	}

	SetupVmxRootMapping(pPML4Table1);

	return pPML4Table1;
}
