#include "paging.h"
#include "identity.h"

PPML4T paging::GetPML4Base(CR3 cr3)
{
	CR3 currCR3 = { 0 };
	if (cr3.Flags) {
		currCR3 = cr3;
	}
	else {
		currCR3.Flags = __readcr3();
	}
	return (PPML4T)Memory::PhyToVirt(currCR3.AddressOfPageDirectory << 12);
}

PPML4T paging::MapPML4Base(CR3 cr3)
{
	CR3 currCR3 = { 0 };
	if (cr3.Flags) {
		currCR3 = cr3;
	}
	else {
		currCR3.Flags = __readcr3();
	}
	return (PPML4T)MapToGuest((PVOID)(currCR3.AddressOfPageDirectory << 12));
}

VOID paging::SetPML4Base(PVOID pPML4Table)
{
	CR3 newCR3 = { 0 };
	newCR3.Flags = __readcr3();
	newCR3.AddressOfPageDirectory = Memory::VirtToPhy(pPML4Table) >> 12;
	__writecr3(newCR3.Flags);
}

vector<MANUAL_PAGED_TABLES> paging::CopyMapRegion(CR3 toCr3, vector<TARGET_TRANSLATION>& translations)
{
	vector<MANUAL_PAGED_TABLES> manualMapTracking;

	for (auto& translation : translations) {
		MANUAL_PAGED_TABLES tracking = { 0 };
		tracking = CopyMapPage(toCr3, translation);

		if (!tracking.pPte) {
			DbgMsg("[PAGING] Mapping failed for 0x%llx", translation.va);
			manualMapTracking.Clean();
			break;
		}

		manualMapTracking.Append(tracking);
	}

	if (manualMapTracking.length()) {
		DbgMsg("[PAGING] Cloned 0x%llx pages", manualMapTracking.length());
	}
	return manualMapTracking;
}

MANUAL_PAGED_TABLES paging::CopyMapPage(CR3 toCr3, TARGET_TRANSLATION translations)
{
	MANUAL_PAGED_TABLES manualMapTracking = { 0 };

	PPML4T toPml4t = GetPML4Base(toCr3);

	BOOL bSuccess = paging::MapPage(toPml4t, translations.va, translations.pa, &manualMapTracking);

	if (!bSuccess) {
		DbgMsg("[PAGING] Failed copying page: 0x%llx", translations.va);
		manualMapTracking = { 0 };
	}

	return manualMapTracking;
}

PVOID paging::MapPhysical(DWORD64 pa, DWORD64 sz, ULONG protect)
{
	PHYSICAL_ADDRESS PA = { 0 };
	PA.QuadPart = pa;
	return MmMapIoSpaceEx(PA, sz, protect);
}

BOOLEAN paging::IsMapped(PPML4T ppml4t, PVOID va) {
	if (!ppml4t) {
		return FALSE;
	}

	VIRT_ADD_MAP virtAddMap = { 0 };
	virtAddMap.Flags = (DWORD64)va;

	PPDPT pOrigPdpt = (PPDPT)Memory::PhyToVirt(ppml4t->entry[virtAddMap.Level4].PageFrameNumber * PAGE_SIZE);
	if (!pOrigPdpt)
		return FALSE;

	PPDT pOrigPdt = (PPDT)Memory::PhyToVirt(pOrigPdpt->entry[virtAddMap.Level3].PageFrameNumber * PAGE_SIZE);
	if (!pOrigPdt)
		return FALSE;

	PPT pOrigPt = (PPT)Memory::PhyToVirt(pOrigPdt->entry[virtAddMap.Level2].PageFrameNumber * PAGE_SIZE);
	if (!pOrigPt)
		return FALSE;

	PVOID pOrigPage = nullptr;

	if (pOrigPdt->entry[virtAddMap.Level3].LargePage) {
		pOrigPage = pOrigPt;
	}
	else {
		pOrigPage = (PVOID)Memory::PhyToVirt(pOrigPt->entry[virtAddMap.Level1].PageFrameNumber * PAGE_SIZE);
	}

	return pOrigPage != nullptr;
}

BOOLEAN paging::MapPage(PPML4T pTargetPml4t, DWORD64 va, DWORD64 pa, MANUAL_PAGED_TABLES* manualMapTracking)
{
	if (!pTargetPml4t || !pa) {
		return FALSE;
	}

	VIRT_ADD_MAP virtAddMap = { 0 };
	virtAddMap.Flags = (DWORD64)va;

	PPDPT pNewPdpt = nullptr;
	PPDT pNewPdt = nullptr;
	PPT pNewPt = nullptr;

#pragma region level4
	DWORD64 pdptVa = Memory::PhyToVirt(pTargetPml4t->entry[virtAddMap.Level4].PageFrameNumber * PAGE_SIZE);
	if (MmIsAddressValid((PVOID)pdptVa)) {
		pNewPdpt = (PPDPT)pdptVa;
	}
	else {
		pNewPdpt = (PPDPT)cpp::kMallocTryAll(sizeof(*pNewPdpt));
		RtlZeroMemory(pNewPdpt, sizeof(*pNewPdpt));
		pTargetPml4t->entry[virtAddMap.Level4].PageFrameNumber = (SIZE_T)Memory::VirtToPhy(pNewPdpt) / PAGE_SIZE;
		pTargetPml4t->entry[virtAddMap.Level4].Write = true;
		pTargetPml4t->entry[virtAddMap.Level4].Supervisor = true;
		pTargetPml4t->entry[virtAddMap.Level4].Present = true;
	}
#pragma endregion

#pragma region level3
	DWORD64 pdtVa = Memory::PhyToVirt(pNewPdpt->entry[virtAddMap.Level3].PageFrameNumber * PAGE_SIZE);
	if (MmIsAddressValid((PVOID)pdtVa)) {
		pNewPdt = (PPDT)pdtVa;
	}
	else {
		pNewPdt = (PPDT)cpp::kMallocTryAll(sizeof(*pNewPdt));
		RtlZeroMemory(pNewPdt, sizeof(*pNewPdt));
		pNewPdpt->entry[virtAddMap.Level3].PageFrameNumber = (SIZE_T)Memory::VirtToPhy(pNewPdt) / PAGE_SIZE;
		pNewPdpt->entry[virtAddMap.Level3].Write = true;
		pNewPdpt->entry[virtAddMap.Level3].Supervisor = true;
		pNewPdpt->entry[virtAddMap.Level3].Present = true;
	}
#pragma endregion

#pragma region level2
	DWORD64 ptVa = Memory::PhyToVirt(pNewPdt->entry[virtAddMap.Level2].PageFrameNumber * PAGE_SIZE);
	if (MmIsAddressValid((PVOID)ptVa)) {
		pNewPt = (PPT)ptVa;
	}
	else {
		pNewPt = (PPT)cpp::kMallocTryAll(sizeof(*pNewPt));
		RtlZeroMemory(pNewPt, sizeof(*pNewPt));
		pNewPdt->entry[virtAddMap.Level2].PageFrameNumber = (SIZE_T)Memory::VirtToPhy(pNewPt) / PAGE_SIZE;
		pNewPdt->entry[virtAddMap.Level2].Write = true;
		pNewPdt->entry[virtAddMap.Level2].Supervisor = true;
		pNewPdt->entry[virtAddMap.Level2].Present = true;
	}
#pragma endregion

#pragma region level1
	PTE_64 pteOrig = pNewPt->entry[virtAddMap.Level1];
	if (!pNewPt->entry[virtAddMap.Level1].Present) {
		pNewPt->entry[virtAddMap.Level1].Write = true;
		pNewPt->entry[virtAddMap.Level1].Supervisor = true;
		pNewPt->entry[virtAddMap.Level1].Present = true;
	}
	pNewPt->entry[virtAddMap.Level1].PageFrameNumber = pa / PAGE_SIZE;
#pragma endregion

	if (manualMapTracking) {
		manualMapTracking->pPml4e = &pTargetPml4t->entry[virtAddMap.Level4];
		manualMapTracking->pPdpte = &pNewPdpt->entry[virtAddMap.Level3];
		manualMapTracking->pPde = &pNewPdt->entry[virtAddMap.Level2];
		manualMapTracking->pPte = &pNewPt->entry[virtAddMap.Level1];
		manualMapTracking->pteOrig = pteOrig;
	}

	return TRUE;
}

BOOLEAN paging::MapRegion(PPML4T ppml4t, PVOID va, size_t size) {
	DWORD64 pages = size / PAGE_SIZE;
	pages += size % PAGE_SIZE ? 1 : 0;

	for (DWORD64 i = 0; i < pages; i++) {
		bool bRes = paging::MapPage(
			ppml4t,
			((DWORD64)va + i * PAGE_SIZE),
			Memory::VirtToPhy((PVOID)((DWORD64)va + i * PAGE_SIZE))
		);

		if (!bRes) {
			return FALSE;
		}
	}
	return TRUE;
}

PTE_64* paging::GetPPTE(PPML4T ppml4t, PVOID va, BOOLEAN bMap)
{
	if (!ppml4t) {
		return nullptr;
	}

	VIRT_ADD_MAP virtAddMap = { 0 };
	virtAddMap.Flags = (DWORD64)va;

	PPDPT pOrigPdpt = 0;
	if (!bMap) {
		pOrigPdpt = (PPDPT)Memory::PhyToVirt(ppml4t->entry[virtAddMap.Level4].PageFrameNumber * PAGE_SIZE);
		if (!pOrigPdpt)
			return nullptr;
	}
	else {
		pOrigPdpt = (PPDPT)MapToGuest((PVOID)(ppml4t->entry[virtAddMap.Level4].PageFrameNumber * PAGE_SIZE));
	}

	PPDT pOrigPdt = 0;
	if (!bMap) {
		pOrigPdt = (PPDT)Memory::PhyToVirt(pOrigPdpt->entry[virtAddMap.Level3].PageFrameNumber * PAGE_SIZE);
		if (!pOrigPdt)
			return nullptr;
	}
	else {
		pOrigPdt = (PPDT)MapToGuest((PVOID)(pOrigPdpt->entry[virtAddMap.Level3].PageFrameNumber * PAGE_SIZE));
	}

	PPT pOrigPt = 0;
	if (!bMap) {
		pOrigPt = (PPT)Memory::PhyToVirt(pOrigPdt->entry[virtAddMap.Level2].PageFrameNumber * PAGE_SIZE);
		if (!pOrigPt)
			return nullptr;
	}
	else {
		pOrigPt = (PPT)MapToGuest((PVOID)(pOrigPdt->entry[virtAddMap.Level2].PageFrameNumber * PAGE_SIZE));
	}

	return &pOrigPt->entry[virtAddMap.Level1];
}

BOOLEAN paging::IsAddressValid(PVOID va) {
	return GetPPTE(paging::GetPML4Base(), va) != 0;
}

PMDL paging::LockRange(PVOID pBase, size_t size)
{
	PMDL pMdl = IoAllocateMdl(
		pBase,
		(ULONG)size,
		FALSE,
		FALSE,
		NULL
	);

	MmProbeAndLockPages(
		pMdl,
		KernelMode,
		IoModifyAccess
	);

	MmBuildMdlForNonPagedPool(pMdl);

	return pMdl;
}

VOID paging::UnlockRange(PMDL pMdl)
{
	MmUnlockPages(pMdl);
	IoFreeMdl(pMdl);
}

PVOID paging::MapNonPaged(PVOID pa, size_t size, MODE allocationMode)
{
	PHYSICAL_ADDRESS phyAdd = { 0 };
	phyAdd.QuadPart = (ULONGLONG)pa;

	if (!phyAdd.QuadPart)
		return 0;
	PVOID pMappedBase = MmMapIoSpace(phyAdd, size, MmCached);
	if (!MmIsAddressValid(pMappedBase))
		return 0;
	PMDL pNonPagedMdl = IoAllocateMdl(
		pMappedBase,
		(ULONG)size,
		FALSE,
		FALSE,
		NULL
	);

	if (!MmIsAddressValid(pNonPagedMdl))
		return nullptr;

	MmBuildMdlForNonPagedPool(pNonPagedMdl);

	PVOID pKernelAddress = MmMapLockedPagesSpecifyCache(
		pNonPagedMdl,
		(KPROCESSOR_MODE)allocationMode,
		MmCached,
		NULL,
		FALSE,
		NormalPagePriority
	);
	if (!MmIsAddressValid(pKernelAddress))
		return 0;
	MmUnmapIoSpace(pMappedBase, size);

	return pKernelAddress;
}

PVOID paging::GuestVirtToPhy(PVOID va, PVOID pGuestPml4tPa, bool* pIsLargePage)
{
	if (!va) {
		DbgMsg("[PAGING] Passed NULL virtual address!");
		return 0;
	}
	if (pGuestPml4tPa == nullptr) {
		CR3 currCr3 = { 0 };
		currCr3.Flags = __readcr3();
		pGuestPml4tPa = (PVOID)(currCr3.AddressOfPageDirectory * PAGE_SIZE);
	}
	VIRT_ADD virtAdd{ (DWORD64)va };

	identity::PhysicalAccess pa;
	_disable();
	PML4E_64 pml4e = pa.Read<PML4E_64>((DWORD64)pGuestPml4tPa + (8 * virtAdd.pml4_index));

	if (!pml4e.Present) {
		_enable();
		return nullptr;
	}

	PDPTE_64 pdpte = pa.Read<PDPTE_64>(pml4e.PageFrameNumber * PAGE_SIZE + (8 * virtAdd.pdpt_index));
	if (!pdpte.Present) {
		DbgMsg("[PAGING] PDPT entry not present: 0x%llx", pdpte.Flags);
		_enable();
		return nullptr;
	}

	PDPTE_1GB_64* pPdpte1GB = (PDPTE_1GB_64*)&pdpte;
	if (pdpte.LargePage) {
		if (pIsLargePage)
			*pIsLargePage = true;
		_enable();
		return (PVOID)((pPdpte1GB->PageFrameNumber * PAGE_SIZE * 0x200 * 0x200) + virtAdd.offset_1gb);
	}

	PDE_64 pde = pa.Read<PDE_64>(pdpte.PageFrameNumber * PAGE_SIZE + (8 * virtAdd.pdt_index));
	if (!pde.Present) {
		DbgMsg("[PAGING] PDT entry not present: 0x%llx", pde.Flags);
		_enable();
		return nullptr;
	}

	PDE_2MB_64* pPde2MB = (PDE_2MB_64*)&pde;
	if (pde.LargePage) {
		if (pIsLargePage)
			*pIsLargePage = true;
		_enable();
		return (PVOID)((pPde2MB->PageFrameNumber * PAGE_SIZE * 0x200) + virtAdd.offset_2mb);
	}

	PTE_64 pte = pa.Read<PTE_64>(pde.PageFrameNumber * PAGE_SIZE + (8 * virtAdd.pt_index));
	if (!pte.Present) {
		DbgMsg("[PAGING] PT entry not present: 0x%llx", &pte);
		_enable();
		return nullptr;
	}

	if (pIsLargePage)
		*pIsLargePage = false;
	_enable();
	return (PVOID)((pte.PageFrameNumber * PAGE_SIZE) + virtAdd.offset_4kb);
}

DWORD64 paging::ProcessVirtToPhy(PEPROCESS pEprocess, PVOID va)
{
	DWORD64 cr3Flags = PsProcessDirBase(pEprocess);
	CR3 cr3 = { 0 };
	cr3.Flags = cr3Flags;
	auto ppte = GetPPTE(MapPML4Base(cr3), va, true);
	if (ppte) {
		return ppte->PageFrameNumber * PAGE_SIZE;
	}
	return 0;
}

DWORD64 paging::CurrProcessVirtToPhy(PVOID va)
{
	return ProcessVirtToPhy(PsGetCurrentProcess(), va);
}

DWORD64 paging::VirtToPhy(PVOID va)
{
	//if (cpp::IsKernelAddress(va))
	//	return Memory::VirtToPhy(va);

	identity::PhysicalAccess pa;
	return pa.getPhysicalAddress((uintptr_t)va);
}

PVOID pBufPage = nullptr;
PTE_64* pGuestPageToSwap = nullptr;
PTE_64 pgOrig = { 0 };
Spinlock pageLock;

PVOID paging::MapToGuest(PVOID pa)
{
	if (!pGuestPageToSwap) {
		pBufPage = cpp::kMalloc(PAGE_SIZE);
		RtlZeroMemory(pBufPage, PAGE_SIZE);
		pGuestPageToSwap = paging::GetPPTE(paging::GetPML4Base(), pBufPage);
		pgOrig = *pGuestPageToSwap;
		pGuestPageToSwap->Write = 1;
		pGuestPageToSwap->ExecuteDisable = 0;
		pGuestPageToSwap->PageLevelWriteThrough = 0;
		pageLock.Init();
	}

	VIRT_ADD result{ (DWORD64)pBufPage };

	pGuestPageToSwap->PageFrameNumber = (DWORD64)pa >> 12;
	pGuestPageToSwap->Write = 1;
	pGuestPageToSwap->ExecuteDisable = 0;
	pGuestPageToSwap->PageLevelWriteThrough = 0;
	__invlpg((void*)result.value);
	result.offset_4kb = VIRT_ADD{ (DWORD64)pa }.offset_4kb;

	return (PVOID)result.value;
}

PVOID paging::MapManually(PVOID pa)
{
	auto pBufPageLocal = cpp::kMalloc(PAGE_SIZE);
	RtlZeroMemory(pBufPageLocal, PAGE_SIZE);
	auto pGuestPageToSwapLocal = paging::GetPPTE(paging::GetPML4Base(), pBufPageLocal);
	pGuestPageToSwapLocal->Write = 1;
	pGuestPageToSwapLocal->ExecuteDisable = 0;
	pGuestPageToSwapLocal->PageLevelWriteThrough = 0;

	VIRT_ADD result{ (DWORD64)pBufPageLocal };

	pGuestPageToSwapLocal->PageFrameNumber = (DWORD64)pa >> 12;
	pGuestPageToSwapLocal->Write = 1;
	pGuestPageToSwapLocal->ExecuteDisable = 0;
	pGuestPageToSwapLocal->PageLevelWriteThrough = 0;
	__invlpg((void*)result.value);
	result.offset_4kb = VIRT_ADD{ (DWORD64)pa }.offset_4kb;

	return (PVOID)result.value;
}

void paging::RestoreMapPage()
{
	if (pGuestPageToSwap) {
		*pGuestPageToSwap = pgOrig;
	}
}
