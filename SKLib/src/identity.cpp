#include "identity.h"

identity::IDENTITY_MAPPING* mapping = nullptr;

bool bIdentityCreated = false;
DWORD64 pLastEprocess = 0;
DWORD64 lastMappedIndex = INVALID_PML4_INDEX;
CR3 lastMappedCR3 = { 0 };

PTE_64* pDynamicMappingBuffer = nullptr;
PPML4T pml4 = nullptr;

void identity::Init()
{
	if (bIdentityCreated)
		return;

	mapping = (identity::IDENTITY_MAPPING*)cpp::kMalloc(sizeof(*mapping));
	if (!mapping) {
		DbgMsg("[IDENTITY] Failed allocating mapping structures!");
		return;
	}
	RtlZeroMemory(mapping, sizeof(*mapping));

	mapping->pml4[0].Present = true;
	mapping->pml4[0].Write = true;
	mapping->pml4[0].Supervisor = true;
	mapping->pml4[0].PageFrameNumber = Memory::VirtToPhy(&mapping->pdpt[0]) / PAGE_SIZE;

	for (DWORD64 EntryIndex = 0; EntryIndex < 512; EntryIndex++)
	{
		mapping->pdpt[EntryIndex].Present = true;
		mapping->pdpt[EntryIndex].Write = true;
		mapping->pdpt[EntryIndex].Supervisor = true;
		mapping->pdpt[EntryIndex].PageFrameNumber = (SIZE_T)Memory::VirtToPhy(&mapping->pdt[EntryIndex][0]) / PAGE_SIZE;
	}

	for (DWORD64 EntryGroupIndex = 0; EntryGroupIndex < 512; EntryGroupIndex++)
	{
		for (DWORD64 EntryIndex = 0; EntryIndex < 512; EntryIndex++)
		{
			mapping->pdt[EntryGroupIndex][EntryIndex].Present = true;
			mapping->pdt[EntryGroupIndex][EntryIndex].Write = true;
			mapping->pdt[EntryGroupIndex][EntryIndex].LargePage = true;
			mapping->pdt[EntryGroupIndex][EntryIndex].Supervisor = true;
			mapping->pdt[EntryGroupIndex][EntryIndex].PageFrameNumber = (EntryGroupIndex * 512) + EntryIndex;
		}
	}

	bIdentityCreated = true;

	DbgMsg("[IDENTITY] Saved identity mapping for future usage");
}

void identity::Dispose()
{

}

PVOID identity::MapIdentity(CR3 cr3)
{
	if (!bIdentityCreated) {
		DbgMsg("[IDENTITY] Not initialized yet!");
		return (PVOID)MAXULONG64;
	}

	PTE_64 origPte = { 0 };
	pml4 = (PPML4T)cpp::kMalloc(PAGE_SIZE, PAGE_READWRITE);
	RtlZeroMemory(pml4, PAGE_SIZE);
	pDynamicMappingBuffer = paging::GetPPTE(paging::GetPML4Base(), pml4);
	origPte = *pDynamicMappingBuffer;
	pDynamicMappingBuffer->PageLevelCacheDisable = true;
	pDynamicMappingBuffer->PageFrameNumber = cr3.AddressOfPageDirectory;
	__invlpg(pml4);

	DbgMsg("[IDENTITY] PML4 at: %p - 0x%llx", pml4, mapping->pml4[0].PageFrameNumber * PAGE_SIZE);

	bool bEntryFound = false;
	int pml4Idx = 0x80;

	pml4->entry[pml4Idx].Flags = mapping->pml4[0].Flags;

	lastMappedIndex = pml4Idx;
	lastMappedCR3.Flags = cr3.Flags;
	pLastEprocess = (DWORD64)PsGetThreadProcess(PsGetCurrentThread());

	VIRT_ADD_MAP virtAddMap = { 0 };
	virtAddMap.Level4 = pml4Idx;

	DbgMsg("[IDENTITY] Mapped at: 0x%llx", virtAddMap.Flags);
	*pDynamicMappingBuffer = origPte;
	__invlpg(pml4);

	return (PVOID)virtAddMap.Flags;
}

PVOID identity::MapIdentityUntracked(CR3 cr3)
{
	if (!bIdentityCreated) {
		DbgMsg("[IDENTITY] Not initialized yet!");
		return (PVOID)MAXULONG64;
	}

	PTE_64 origPte = { 0 };
	auto ppml4 = (PPML4T)cpp::kMalloc(PAGE_SIZE, PAGE_READWRITE);
	RtlZeroMemory(ppml4, PAGE_SIZE);
	auto pMappingBuffer = paging::GetPPTE(paging::MapPML4Base(), ppml4);
	origPte = *pMappingBuffer;
	pMappingBuffer->PageLevelCacheDisable = true;
	pMappingBuffer->PageFrameNumber = cr3.AddressOfPageDirectory;
	__invlpg(ppml4);

	DbgMsg("[IDENTITY] PML4 at: %p - 0x%llx", ppml4, mapping->pml4[0].PageFrameNumber * PAGE_SIZE);

	bool bEntryFound = false;
	int pml4Idx = 0x80;
	for (; pml4Idx < 255; pml4Idx++) {
		if (ppml4->entry[pml4Idx].Flags == 0) {
			DbgMsg("[IDENTITY] Mapping identity to pml4 entry %d", pml4Idx);
			bEntryFound = true;
			break;
		}
	}
	if (!bEntryFound) {
		DbgMsg("[IDENTITY] Could not find a valid entry to map into!");
		return (PVOID)MAXULONG64;
	}

	ppml4->entry[pml4Idx].Flags = mapping->pml4[0].Flags;
	ppml4->entry[pml4Idx].Supervisor = false;
	*pMappingBuffer = origPte;
	__invlpg(pml4);
	cpp::kFree(ppml4);

	VIRT_ADD_MAP virtAddMap = { 0 };
	virtAddMap.Level4 = pml4Idx;
	return (PVOID)virtAddMap.Flags;
}

void identity::ResetCache(bool bVmxRoot)
{
	if (!pLastEprocess)
		return;

	//PTE_64 origPte = *pDynamicMappingBuffer;
	//pDynamicMappingBuffer->PageLevelCacheDisable = true;
	//pDynamicMappingBuffer->PageFrameNumber = lastMappedCR3.AddressOfPageDirectory;
	//__invlpg(pml4);
	//pml4->entry[lastMappedIndex].Flags = 0;
	//*pDynamicMappingBuffer = origPte;
	//__invlpg(pml4);
	//
	//pLastEprocess = 0;
	//lastMappedIndex = INVALID_PML4_INDEX;
	//lastMappedCR3 = { 0 };
}

void identity::ResetCacheUntracked(CR3 cr3)
{
	if (!bIdentityCreated) {
		DbgMsg("[IDENTITY] Not initialized yet!");
		return;
	}

	PTE_64 origPte = { 0 };
	auto ppml4 = (PPML4T)cpp::kMalloc(PAGE_SIZE, PAGE_READWRITE);
	RtlZeroMemory(ppml4, PAGE_SIZE);
	auto pMappingBuffer = paging::GetPPTE(paging::MapPML4Base(), ppml4);
	origPte = *pMappingBuffer;
	pMappingBuffer->PageLevelCacheDisable = true;
	pMappingBuffer->PageFrameNumber = cr3.AddressOfPageDirectory;
	__invlpg(ppml4);

	int pml4Idx = 0x80;
	for (; pml4Idx < 255; pml4Idx++) {
		if (ppml4->entry[pml4Idx].Ignored2 == 0
			&& ppml4->entry[pml4Idx].PageFrameNumber) {
			break;
		}
	}

	ppml4->entry[pml4Idx].Flags = 0;
	*pMappingBuffer = origPte;
	__invlpg(ppml4);

	cpp::kFree(ppml4);
}

identity::PhysicalAccess::PhysicalAccess()
{
	cr3.Flags = __readcr3();
	pIdentity = (char*)MapIdentity(cr3);
	bAllocated = false;
}

identity::PhysicalAccess::PhysicalAccess(DWORD64 cr3)
{
	this->cr3.Flags = cr3;
	pIdentity = (char*)MapIdentityUntracked(this->cr3);
	bAllocated = true;
}

identity::PhysicalAccess::PhysicalAccess(PVOID identity, DWORD64 _cr3)
{
	cr3.Flags = _cr3;
	pIdentity = (char*)identity;
	bAllocated = false;
}

identity::PhysicalAccess::~PhysicalAccess()
{
	if (bAllocated)
		ResetCacheUntracked(cr3);
}
