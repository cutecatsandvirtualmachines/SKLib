#include "EPT.h"

#include "winternlex.h"
#include "Vmcall.h"
#include "iommu.h"
#include "identity.h"

bool EPT::bInit = false;

UINT64 maxPhysicalRAM = 0;
PVOID pTrampolinePage = nullptr;
DWORD64 dwCurrTrampolineOffset = 0;

NTSTATUS EptSetup(EPT_STATE* pEptState, PML2E pml2Template) {
    PVMM_EPT_PAGE_TABLE PageTable;
    EPTP EPTP;
    DWORD dwCore = CPU::GetCPUIndex();
    if (!pEptState) {
        pEptState = &vmm::vGuestStates[dwCore].eptState;
        vmm::vGuestStates[dwCore].bRestoreHook = false;
    }
    else {
        //if (dwCore) {
        //    pEptState[dwCore] = *pEptState;
        //    return STATUS_SUCCESS;
        //}
        pEptState = &pEptState[dwCore];
    }

    if (!EPT::IsMTRRSupported()) {
        DbgMsg("[VMX] MTRR is not supported on this machine !");
        return STATUS_UNSUCCESSFUL;
    }

    if (!EPT::BuildMtrrMap(pEptState)) {
        DbgMsg("[VMX] Error: failed to build MTRR map!");
        return STATUS_UNSUCCESSFUL;
    }

    /* Allocate the identity mapped page table*/
    PML2E_2MB tbl;
    tbl.Flags = pml2Template.Flags;
    PageTable = EPT::CreatePageTable(pEptState, tbl);
    if (!PageTable)
    {
        DbgMsg("[EPT] Error: Unable to allocate memory for EPT");
        return STATUS_UNSUCCESSFUL;
    }
    pEptState->EptPageTable[0] = PageTable;

    for (int i = 1; i < 2; i++) {
        auto PageTableX = EPT::CreatePageTable(pEptState, tbl, i);
        PageTable->PML4[i] = PageTableX->PML4[0];
        pEptState->EptPageTable[i] = PageTableX;
    }
    
    //auto PageTableX = EPT::CreatePageTable(pEptState, tbl, 1);
    //for (int i = 1; i < 512; i++) {
    //    PageTable->PML4[i] = PageTableX->PML4[0];
    //    pEptState->EptPageTable[i] = PageTableX;
    //}

    if (!CPU::bIntelCPU) {
        pEptState->nCR3.Flags = 0;
        pEptState->nCR3.AddressOfPageDirectory = Memory::VirtToPhy(&PageTable->PML4) / PAGE_SIZE;
    }

    EPTP.Flags = 0;
    // For performance, we let the processor know it can cache the EPT.
    EPTP.MemoryType = MEMORY_TYPE_WRITE_BACK;

    // We are not utilizing the 'access' and 'dirty' flag features. 
    EPTP.EnableAccessAndDirtyFlags = FALSE;

    /*
      Bits 5:3 (1 less than the EPT page-walk length) must be 2, indicating an EPT page-walk length of 3
      see Section 28.2.2
     */
    EPTP.PageWalkLength = 3;

    // The physical page number of the page table we will be using 
    EPTP.PageFrameNumber = (SIZE_T)Memory::VirtToPhy(&PageTable->PML4) / PAGE_SIZE;

    // We will write the EPTP to the VMCS later 
    pEptState->EptPointer = EPTP;

    return STATUS_SUCCESS;
}

bool EPT::Init()
{
    if (bInit) {
        DbgMsg("[EPT] Was already initialized");
        return TRUE;
    }
    pTrampolinePage = cpp::kMallocZero(PAGE_SIZE, PAGE_EXECUTE_READWRITE);
    if (!vmm::InitAllocator()) {
        DbgMsg("[EPT] Could not initialize vmm allocator!");
        return FALSE;
    }

    PROCESSOR_RUN_INFO procInfo;
    procInfo.Flags = ~0ull;
    procInfo.bHighIrql = FALSE;
    PML2E pml2Template = { 0 };
    pml2Template.SetReadWrite(true);
    pml2Template.SetExecute(true);
    pml2Template.SetValid(true);

    if (!NT_SUCCESS(CPU::RunOnAllCPUs(EptSetup, procInfo, nullptr, pml2Template)))
        return FALSE;

    DbgMsg("[EPT] EPT Setup done");
    pml2Template.SetExecute(false);
    vmm::eptShadow = (EPT_STATE*)cpp::kMallocZero(sizeof(*vmm::eptShadow) * CPU::GetCPUCount(), PAGE_READWRITE);
    if (!NT_SUCCESS(CPU::RunOnAllCPUs(EptSetup, procInfo, vmm::eptShadow, pml2Template)))
        return FALSE;

    //for (DWORD core = 1; core < CPU::GetCPUCount(); core++) {
    //    vmm::eptShadow[core] = vmm::eptShadow[0];
    //    vmm::vGuestStates[core].eptState = vmm::vGuestStates[0].eptState;
    //}

    DbgMsg("[EPT] EPT Setup for Shadow done");

    SIZE_T pTrampolinePa = Memory::VirtToPhy(PAGE_ALIGN(pTrampolinePage));
    auto pTrampolinePageCopy = cpp::kMallocZero(PAGE_SIZE, PAGE_EXECUTE_READWRITE);
    for (DWORD dwCore = 0; dwCore < CPU::GetCPUCount(); dwCore++) {
        HOOK_SECONDARY_INFO hkSecondaryInfo = { 0 };
        hkSecondaryInfo.pSubstitutePage = pTrampolinePageCopy;
        PAGE_PERMISSIONS pgPermissions = { 0 };
        pgPermissions.Exec = true;
        if (!Hook(pTrampolinePage, pTrampolinePageCopy, hkSecondaryInfo, pgPermissions)) {
            DbgMsg("[EPT] Hook on trampoline failed: 0x%x - %p - %p", dwCore, pTrampolinePage, pTrampolinePageCopy);
            return FALSE;
        }
    }

    DbgMsg("[EPT] Ready");
    bInit = true;
    return TRUE;
}

bool EPT::IsMTRRSupported()
{
    IA32_MTRR_DEF_TYPE_REGISTER MTRRDefType;

    MTRRDefType.Flags = __readmsr(MSR_IA32_MTRR_DEF_TYPE);

    if (!MTRRDefType.MtrrEnable)
    {
        return false;
    }
    return true;
}

bool EPT::IsExecOnlySupported()
{
    IA32_VMX_EPT_VPID_CAP_REGISTER VpidRegister;
    VpidRegister.Flags = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);

    return VpidRegister.ExecuteOnlyPages;
}

BOOLEAN EPT::BuildMtrrMap(EPT_STATE* pEptState)
{
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
            Descriptor = &pEptState->MemoryRanges[pEptState->NumberOfEnabledMemoryRanges++];

            // Calculate the base address in bytes
            Descriptor->PhysicalBaseAddress = CurrentPhysBase.PageFrameNumber * PAGE_SIZE;

            // Calculate the total size of the range
            // The lowest bit of the mask that is set to 1 specifies the size of the range
            _BitScanForward64(&NumberOfBitsInMask, CurrentPhysMask.PageFrameNumber * PAGE_SIZE);

            // Size of the range in bytes + Base Address
            Descriptor->PhysicalEndAddress = Descriptor->PhysicalBaseAddress + ((1ULL << NumberOfBitsInMask) - 1ULL);

            // Memory Type (cacheability attributes)
            Descriptor->MemoryType = (UCHAR)CurrentPhysBase.Type;

            if (Descriptor->MemoryType == MEMORY_TYPE_WRITE_BACK)
            {
                /* This is already our default, so no need to store this range.
                 * Simply 'free' the range we just wrote. */
                pEptState->NumberOfEnabledMemoryRanges--;
            }
            DbgMsg("[EPT] MTRR Range: Base=0x%llx End=0x%llx Type=0x%x", Descriptor->PhysicalBaseAddress, Descriptor->PhysicalEndAddress, Descriptor->MemoryType);
        }
    }

    DbgMsg("[EPT] Total MTRR Ranges Committed: %d", pEptState->NumberOfEnabledMemoryRanges);

    return TRUE;
}

VOID SetupPML2Entry(EPT_STATE* pEptState, PPML2E_2MB NewEntry, SIZE_T PageFrameNumber)
{
    SIZE_T AddressOfPage;
    SIZE_T CurrentMtrrRange;
    SIZE_T TargetMemoryType;

    /*
      Each of the 512 collections of 512 PML2 entries is setup here.
      This will, in total, identity map every physical address from 0x0 to physical address 0x8000000000 (512GB of memory)

      ((EntryGroupIndex * VMM_EPT_PML2E_COUNT) + EntryIndex) * 2MB is the actual physical address we're mapping
     */
    NewEntry->SetPFN(PageFrameNumber);
    NewEntry->SetValid(true);
    NewEntry->SetReadWrite(true);
    NewEntry->SetUser(true);

    // Size of 2MB page * PageFrameNumber == AddressOfPage (physical memory). 
    AddressOfPage = PageFrameNumber * SIZE_2_MB;

    /* To be safe, we will map the first page as UC as to not bring up any kind of undefined behavior from the
      fixed MTRR section which we are not formally recognizing (typically there is MMIO memory in the first MB).

      I suggest reading up on the fixed MTRR section of the manual to see why the first entry is likely going to need to be UC.
     */
    if (PageFrameNumber == 0)
    {
        NewEntry->SetPATWriteback(false);
        return;
    }

    // Default memory type is always WB for performance. 
    TargetMemoryType = MEMORY_TYPE_WRITE_BACK;

    // For each MTRR range 
    for (CurrentMtrrRange = 0; CurrentMtrrRange < pEptState->NumberOfEnabledMemoryRanges; CurrentMtrrRange++)
    {
        // If this page's address is below or equal to the max physical address of the range 
        // And this page's last address is above or equal to the base physical address of the range 
        if (AddressOfPage <= pEptState->MemoryRanges[CurrentMtrrRange].PhysicalEndAddress
            && (AddressOfPage + SIZE_2_MB - 1) >= pEptState->MemoryRanges[CurrentMtrrRange].PhysicalBaseAddress)
        {
            /* If we're here, this page fell within one of the ranges specified by the variable MTRRs
               Therefore, we must mark this page as the same cache type exposed by the MTRR
            */
            TargetMemoryType = pEptState->MemoryRanges[CurrentMtrrRange].MemoryType;

            // 11.11.4.1 MTRR Precedences 
            if (TargetMemoryType == MEMORY_TYPE_UNCACHEABLE)
            {
                // If this is going to be marked uncacheable, then we stop the search as UC always takes precedent. 
                break;
            }
        }
    }

    // Finally, commit the memory type to the entry. 
    NewEntry->SetPATWriteback(TargetMemoryType == MEMORY_TYPE_WRITE_BACK);
}

PVMM_EPT_PAGE_TABLE EPT::CreatePageTable(EPT_STATE* pEptState, PML2E_2MB PML2EntryTemplate, ULONG pml4Index)
{
    PVMM_EPT_PAGE_TABLE PageTable;
    PML3E RWXTemplate;
    SIZE_T EntryGroupIndex;
    SIZE_T EntryIndex;

    PageTable = (PVMM_EPT_PAGE_TABLE)cpp::kMalloc((size_t)sizeof(VMM_EPT_PAGE_TABLE));

    if (PageTable == NULL)
    {
        DbgMsg("[EPT] Failed to allocate memory for PageTable");
        return NULL;
    }

    // Zero out all entries to ensure all unused entries are marked Not Present 
    RtlZeroMemory(PageTable, (size_t)sizeof(VMM_EPT_PAGE_TABLE));

    // Mark the first 512GB PML4 entry as present, which allows us to manage up to 512GB of discrete paging structures. 
    PageTable->PML4[0].SetPFN((SIZE_T)Memory::VirtToPhy(&PageTable->PML3[0]) / PAGE_SIZE);
    PageTable->PML4[0].SetReadWrite(true);
    PageTable->PML4[0].SetExecute(true);
    PageTable->PML4[0].SetValid(true);
    PageTable->PML4[0].SetUser(true);

    /* Now mark each 1GB PML3 entry as RWX and map each to their PML2 entry */

    // Ensure stack memory is cleared
    RWXTemplate.Flags = 0;

    // Set up one 'template' RWX PML3 entry and copy it into each of the 512 PML3 entries 
    // Using the same method as SimpleVisor for copying each entry using intrinsics. 
    RWXTemplate.SetReadWrite(true);
    RWXTemplate.SetExecute(true);
    RWXTemplate.SetValid(true);
    RWXTemplate.SetUser(true);

    // Copy the template into each of the 512 PML3 entry slots 
    __stosq((SIZE_T*)&PageTable->PML3[0], RWXTemplate.Flags, VMM_EPT_PML3E_COUNT);

    // For each of the 512 PML3 entries 
    for (EntryIndex = 0; EntryIndex < VMM_EPT_PML3E_COUNT; EntryIndex++)
    {
        // Map the 1GB PML3 entry to 512 PML2 (2MB) entries to describe each large page.
        // NOTE: We do *not* manage any PML1 (4096 byte) entries and do not allocate them.
        PageTable->PML3[EntryIndex].SetPFN((SIZE_T)Memory::VirtToPhy(&PageTable->PML2[EntryIndex][0]) / PAGE_SIZE);
    }

    PML2EntryTemplate.SetLarge(true);
    PML2EntryTemplate.SetValid(true);
    PML2EntryTemplate.SetReadWrite(true);

    PML2EntryTemplate.SetUser(true);
    /* For each collection of 512 PML2 entries (512 collections * 512 entries per collection), mark it RWX using the same template above.
       This marks the entries as "Present" regardless of if the actual system has memory at this region or not. We will cause a fault in our
       EPT handler if the guest access a page outside a usable range, despite the EPT frame being present here.
     */
    __stosq((SIZE_T*)&PageTable->PML2[0], PML2EntryTemplate.Flags, VMM_EPT_PML3E_COUNT * VMM_EPT_PML2E_COUNT);

    // For each of the 512 collections of 512 2MB PML2 entries 
    for (EntryGroupIndex = 0; EntryGroupIndex < VMM_EPT_PML3E_COUNT; EntryGroupIndex++)
    {
        // For each 2MB PML2 entry in the collection 
        for (EntryIndex = 0; EntryIndex < VMM_EPT_PML2E_COUNT; EntryIndex++)
        {
            // Setup the memory type and frame number of the PML2 entry. 
            SetupPML2Entry(pEptState, (PPML2E_2MB)&PageTable->PML2[EntryGroupIndex][EntryIndex], (((pml4Index * 512) + EntryGroupIndex) * VMM_EPT_PML2E_COUNT) + EntryIndex);
        }
    }

    return PageTable;
}

PPML2E EPT::GetPml2Entry(PVMM_EPT_PAGE_TABLE pEpt, SIZE_T pa)
{
    PPML2E PML2;
    VIRT_ADD_MAP virtMap = { 0 };
    virtMap.Flags = pa;

    PML2 = &pEpt->PML2[virtMap.Level3][virtMap.Level2];
    return PML2;
}

PPML1E EPT::GetPml1Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress)
{
    PPML2E_2MB PML2;
    PPML1E PML1;
    PPML2E PML2Pointer;

    PML2 = (PPML2E_2MB)GetPml2Entry(EptPageTable, PhysicalAddress);

    // Check to ensure the page is split 
    if (!PML2 || PML2->GetLarge())
    {
        DbgMsg("[EPT] Invalid pml2 or already large: %p", PML2);
        return NULL;
    }

    // Conversion to get the right PageFrameNumber.
    // These pointers occupy the same place in the table and are directly convertable.
    PML2Pointer = (PPML2E)PML2;

    // If it is, translate to the PML1 pointer 
    PML1 = (PPML1E)Memory::PhyToVirt(PML2Pointer->GetPFN() * PAGE_SIZE);
    if (!PML1)
    {
        PHYSICAL_ADDRESS phyAdd = { 0 };
        phyAdd.QuadPart = PML2Pointer->GetPFN() * PAGE_SIZE;
        DbgMsg("[EPT] Invalid pml1: %p - 0x%llx", PML1, PML2Pointer->GetPFN() * PAGE_SIZE);
        PML1 = (PPML1E)MmMapIoSpace(phyAdd, PAGE_SIZE, MmCached);
        //return NULL;
    }

    // Index into PML1 for that address 
    PML1 = &PML1[ADDRMASK_EPT_PML1_INDEX(PhysicalAddress)];

    return PML1;
}

PPML1E EPT::MapPml1Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress)
{
    PPML2E_2MB PML2;
    PPML1E PML1;
    PPML2E PML2Pointer;

    PML2 = (PPML2E_2MB)GetPml2Entry(EptPageTable, PhysicalAddress);

    // Check to ensure the page is split 
    if (!PML2 || PML2->GetLarge())
    {
        return NULL;
    }

    // Conversion to get the right PageFrameNumber.
    // These pointers occupy the same place in the table and are directly convertable.
    PML2Pointer = (PPML2E)PML2;

    // If it is, translate to the PML1 pointer 
    PML1 = (PPML1E)paging::MapPhysical(PML2Pointer->GetPFN() * PAGE_SIZE, PAGE_SIZE);

    // Index into PML1 for that address 
    PML1 = &PML1[ADDRMASK_EPT_PML1_INDEX(PhysicalAddress)];

    return PML1;
}

BOOLEAN EPT::SplitLargePage(PVMM_EPT_PAGE_TABLE pEpt, PVOID PBuf, SIZE_T pa, BOOLEAN bVmxRoot)
{
    __try {
        PVMM_EPT_DYNAMIC_SPLIT NewSplit;
        PML1E EntryTemplate = { 0 };
        SIZE_T EntryIndex;
        PPML2E_2MB TargetEntry;
        PPML2E Target;
        PML2E NewPointer = { 0 };
        DWORD64 dwCore = CPU::GetCPUIndex(true);

        // Find the PML2 entry that's currently used
        TargetEntry = (PPML2E_2MB)GetPml2Entry(pEpt, pa);
        if (!TargetEntry)
        {
            return FALSE;
        }

        Target = (PPML2E)TargetEntry;
        // If this large page is not marked a large page, that means it's a pointer already.
        // That page is therefore already split.
        if (!TargetEntry->GetLarge())
        {
            return TRUE;
        }

        // Allocate the PML1 entries 
        NewSplit = (PVMM_EPT_DYNAMIC_SPLIT)PBuf;
        if (!NewSplit)
        {
            return FALSE;
        }
        RtlZeroMemory(NewSplit, sizeof(VMM_EPT_DYNAMIC_SPLIT));

        // Make a template for RWX 
        EntryTemplate.SetReadWrite(true);
        EntryTemplate.SetExecute(true);
        EntryTemplate.SetPATWriteback(true);
        EntryTemplate.SetValid(true);
        // Set the page frame numbers for identity mapping.
        for (EntryIndex = 0; EntryIndex < VMM_EPT_PML1E_COUNT; EntryIndex++)
        {
            EntryTemplate.SetPFN(((TargetEntry->GetPFN() * SIZE_2_MB) / PAGE_SIZE) + EntryIndex);
            NewSplit->PML1[EntryIndex].Flags = EntryTemplate.Flags;
        }

        // Allocate a new pointer which will replace the 2MB entry with a pointer to 512 4096 byte entries. 
        NewPointer.Flags = 0;
        NewPointer.SetReadWrite(true);
        NewPointer.SetValid(true);
        NewPointer.SetExecute(true);
        if (bVmxRoot) {
            CR3 guestCR3 = vmm::GetGuestCR3();
            NewPointer.SetPFN((SIZE_T)paging::vmmhost::GuestVirtToPhy(&NewSplit->PML1[0], (PVOID)(guestCR3.AddressOfPageDirectory * PAGE_SIZE)) / PAGE_SIZE);
        }
        else {
            NewPointer.SetPFN((SIZE_T)Memory::VirtToPhy(&NewSplit->PML1[0]) / PAGE_SIZE);
        }

        // Now, replace the entry in the page table with our new split pointer.
        RtlCopyMemory(TargetEntry, &NewPointer, sizeof(NewPointer));

        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

VOID EnableShadowExecute(PVOID pTarget) {
    auto dwCore = CPU::GetCPUIndex(true);
    __try {
        CR3 guestCR3 = vmm::GetGuestCR3();
        SIZE_T pNextPagePa = (SIZE_T)paging::vmmhost::GuestVirtToPhy(pTarget, (PVOID)(guestCR3.AddressOfPageDirectory * PAGE_SIZE));
        if (!pNextPagePa)
            return;

        PPML2E_2MB PML2;
        PPML1E pNextPagePML1;
        PPML2E PML2Pointer;

        PML2 = (PPML2E_2MB)EPT::GetPml2Entry(vmm::eptShadow[dwCore].EptPageTable[ADDRMASK_EPT_PML4_INDEX(pNextPagePa)], pNextPagePa);

        // Check to ensure the page is split 
        if (PML2->GetLarge())
        {
            if (!EPT::SplitLargePage(vmm::eptShadow[dwCore].EptPageTable[ADDRMASK_EPT_PML4_INDEX(pNextPagePa)], nullptr, pNextPagePa, true)) {
                PVMM_EPT_DYNAMIC_SPLIT pNextPageBuf = (PVMM_EPT_DYNAMIC_SPLIT)vmm::malloc(sizeof(VMM_EPT_DYNAMIC_SPLIT));
                EPT::SplitLargePage(vmm::eptShadow[dwCore].EptPageTable[ADDRMASK_EPT_PML4_INDEX(pNextPagePa)], pNextPageBuf, pNextPagePa, true);
                for (SIZE_T i = 0; i < PT_ENTRIES; i++) {
                    pNextPageBuf->PML1[i].SetExecute(false);
                }
            }
        }

        // Conversion to get the right PageFrameNumber.
        // These pointers occupy the same place in the table and are directly convertable.
        PML2Pointer = (PPML2E)PML2;

        // If it is, translate to the PML1 pointer 
        pNextPagePML1 = (PPML1E)paging::vmmhost::MapToHost((PVOID)(PML2Pointer->GetPFN() * PAGE_SIZE));

        // Index into PML1 for that address 
        pNextPagePML1 = &pNextPagePML1[ADDRMASK_EPT_PML1_INDEX(pNextPagePa)];

        pNextPagePML1->SetExecute(true);
        pNextPagePML1->SetPATWriteback(true);
        pNextPagePML1->SetValid(true);

        EPT::InvalidateEPT(dwCore);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {

    }
}

BOOLEAN IsActiveInShadow(PVOID pTarget) {
    __try {
        CR3 guestCR3 = vmm::GetGuestCR3();
        SIZE_T pNextPagePa = (SIZE_T)paging::vmmhost::GuestVirtToPhy(pTarget, (PVOID)(guestCR3.AddressOfPageDirectory * PAGE_SIZE));
        if (!pNextPagePa)
            return false;

        PPML2E_2MB PML2;
        PPML1E pNextPagePML1;
        PPML2E PML2Pointer;

        auto dwCore = CPU::GetCPUIndex(true);
        PML2 = (PPML2E_2MB)EPT::GetPml2Entry(vmm::eptShadow[dwCore].EptPageTable[ADDRMASK_EPT_PML4_INDEX(pNextPagePa)], pNextPagePa);

        // Check to ensure the page is split 
        if (PML2->GetLarge())
        {
            return false;
        }

        // Conversion to get the right PageFrameNumber.
        // These pointers occupy the same place in the table and are directly convertable.
        PML2Pointer = (PPML2E)PML2;

        // If it is, translate to the PML1 pointer 
        pNextPagePML1 = (PPML1E)paging::vmmhost::MapToHost((PVOID)(PML2Pointer->GetPFN() * PAGE_SIZE));

        // Index into PML1 for that address 
        pNextPagePML1 = &pNextPagePML1[ADDRMASK_EPT_PML1_INDEX(pNextPagePa)];
        return pNextPagePML1->GetExecute();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

BOOLEAN EPT::HandlePageHookExit(UINT64 GuestPhysicalAddr)
{
    BOOLEAN bIncRIP = FALSE;
    DWORD64 dwCore = CPU::GetCPUIndex(true);
    PVM_STATE pState = &vmm::vGuestStates[dwCore];

    if (IsShadowEPTActive(dwCore)) {
        SIZE_T currentRIP = 0;
        SIZE_T instSize = 0;
        bool bCpl0 = false;

        if (CPU::bIntelCPU) {
            Vmx::SegmentAccessRights ssAttrib;
            __vmx_vmread(GUEST_SS_AR_BYTES, (size_t*)&ssAttrib);
            __vmx_vmread(GUEST_RIP, &currentRIP);
            __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &instSize);
            bCpl0 = ssAttrib.fields.DPL == 0;
        }
        else {
            currentRIP = pState->SvmState->GuestVmcb->StateSaveArea.Rip;
            instSize = pState->SvmState->GuestVmcb->ControlArea.NextRip - currentRIP;
            bCpl0 = pState->SvmState->GuestVmcb->StateSaveArea.Cpl == 0;
        }
        bool crossBoundaryInstruction = ((currentRIP / PAGE_SIZE) != ((currentRIP + ZYDIS_MAX_INSTRUCTION_LENGTH) / PAGE_SIZE));

        if (crossBoundaryInstruction && bCpl0) {
            if(IsActiveInShadow((PVOID)(currentRIP + ZYDIS_MAX_INSTRUCTION_LENGTH)))
                EnableShadowExecute((PVOID)currentRIP);
            if(IsActiveInShadow((PVOID)currentRIP))
                EnableShadowExecute((PVOID)(currentRIP + ZYDIS_MAX_INSTRUCTION_LENGTH));
        }

        EPT::ExitShadow(dwCore);
        pState->bRestoreHook = false;
    }
    else {
        EPT::EnterShadow(dwCore);
        pState->bRestoreHook = true;
    }

    return bIncRIP;
}

BOOLEAN EPT::HideDriver()
{
#ifdef ENABLE_EPT_PROTECTION
    if (!bInit) {
        return FALSE;
    }

    PAGE_PERMISSIONS pgPermissions = { 0 };
    pgPermissions.Exec = true;
    pgPermissions.Read = false;
    pgPermissions.Write = false;
    HOOK_SECONDARY_INFO hkSecondaryInfo;

    BOOLEAN bRes = TRUE;

    DWORD64 pages = winternl::szDriver / PAGE_SIZE;
    pages += winternl::szDriver % PAGE_SIZE ? 1 : 0;

    for (DWORD dwPageIdx = 0; dwPageIdx < pages; dwPageIdx++) {
        PVOID pSubstitute = cpp::kMallocZero(PAGE_SIZE);
        hkSecondaryInfo.pSubstitutePage = pSubstitute;
        for (DWORD pageOffset = 0; pageOffset < (PAGE_SIZE / 8); pageOffset++) {
            random::rnd.setSecLevel(random::SecurityLevel::SECURE);
            ((DWORD64*)pSubstitute)[pageOffset] = (pageOffset * 8) + (dwPageIdx * PAGE_SIZE) + (random::Next(0, 0xffffffffffffffff) & 0xffffffff00000000);
            char* pBaseSection = (char*)&((DWORD64*)pSubstitute)[pageOffset];
            *(pBaseSection + 3) = BUILD_FLAGS;
        }
        bRes = Hook((PVOID)((DWORD64)winternl::pDriverBase + (PAGE_SIZE * dwPageIdx)), pSubstitute, hkSecondaryInfo, pgPermissions);
        if (!bRes) {
            DbgMsg("[EPT] Could not EPT hook driver");
            return false;
        }
        bRes = iommu::HidePage((PVOID)((DWORD64)winternl::pDriverBase + (PAGE_SIZE * dwPageIdx)), pSubstitute);
        if (!bRes) {
            DbgMsg("[EPT] Could not DMA hook driver");
            return false;
        }
    }

    DbgMsg("[EPT] Successfully hidden driver from DMA reads!");

    return bRes;
#else
    DbgMsg("[EPT] Warning: driver hiding disabled during build!");
    return true;
#endif
}

BOOLEAN EPT::HandleEptViolation(ULONG ExitQualification, UINT64 GuestPhysicalAddr)
{
    VMX_EXIT_QUALIFICATION_EPT_VIOLATION ViolationQualification;

    ViolationQualification.Flags = ExitQualification;

    return HandlePageHookExit(GuestPhysicalAddr);
}

VOID EPT::HandleMisconfiguration(UINT64 GuestAddress)
{
    DebugBreak();
}

/// <summary>
/// Do not call this function directly. The hook page is swapped in only when necessary, then
/// the original is swapped back, this to account for r/w only hooks
/// </summary>
/// <returns>TRUE if succeeds</returns>
BOOLEAN EPT::PageHook(HOOK_DATA& hkData, HOOK_SECONDARY_INFO hkSecondaryInfo, ULONG dwCore)
{
    PVOID pTarget = PAGE_ALIGN(hkData.pTarget);
    EPT_TARGET_DATA& eptTargetData = hkData.vTargetData.at(dwCore);
    PPML1E pTargetPage = eptTargetData.pOrigEPTPage;

    PML1E eptTemplate = *pTargetPage;
    eptTargetData.OrigEPTFlags = eptTemplate;

    PAGE_PERMISSIONS pgPermissions = hkData.pgPermissions;

    if (!pgPermissions.Exec
        && dwCore + 1 == CPU::GetCPUCount()
        ) {
        RtlCopyMemory(hkData.pPage, pTarget, PAGE_SIZE);
        if (!InsertTrampoline(hkData, hkSecondaryInfo.pOrigFn)) {
            return FALSE;
        }
    }
    eptTemplate = *pTargetPage;
    eptTemplate.SetPFN(hkData.PFN);

    eptTemplate.SetExecute(false);
    eptTemplate.SetReadWrite(true);
    eptTemplate.SetUser(true);

    eptTargetData.NewEPTPage = eptTemplate;

    pTargetPage->Flags = eptTargetData.NewEPTPage.Flags;

    return TRUE;
}

BOOLEAN EPT::PageHook2MB(HOOK_DATA& hkData, HOOK_SECONDARY_INFO hkSecondaryInfo, ULONG dwCore)
{
    PVOID pTarget = PAGE_ALIGN(hkData.pTarget);
    EPT_TARGET_DATA& eptTargetData = hkData.vTargetData.at(dwCore);
    auto pTargetPage = eptTargetData.pOrigEPTPage2MB;

    auto eptTemplate = *pTargetPage;
    eptTargetData.OrigEPTFlags2MB = eptTemplate;

    PAGE_PERMISSIONS pgPermissions = hkData.pgPermissions;

    if (!pgPermissions.Exec
        && dwCore + 1 == CPU::GetCPUCount()
        ) {
        RtlCopyMemory(hkData.pPage, pTarget, SIZE_2MB);
        if (!InsertTrampoline(hkData, hkSecondaryInfo.pOrigFn)) {
            return FALSE;
        }
    }
    eptTemplate = *pTargetPage;
    eptTemplate.SetPFN(hkData.PFN);

    eptTemplate.SetExecute(false);
    eptTemplate.SetReadWrite(true);
    eptTemplate.SetUser(true);

    eptTargetData.NewEPTPage2MB = eptTemplate;

    pTargetPage->Flags = eptTargetData.NewEPTPage2MB.Flags;

    return TRUE;
}

BOOLEAN EPT::PageHookRange(int startIndex, int endIndex, HOOK_SECONDARY_INFO hkSecondaryInfo, BOOLEAN bVmxLaunched, ULONG dwCore)
{
    if (startIndex < 0) {
        return FALSE;
    }
    if (startIndex >= endIndex) {
        return FALSE;
    }

    for (int i = startIndex; i < endIndex; i++) {
        if (i >= vmm::vHooks->length())
            break;
        HOOK_DATA& hkData = vmm::vHooks->at(i);

        bool bSuccess = EPT::PageHook(hkData, hkSecondaryInfo, dwCore);
        if (!bSuccess)
            return FALSE;
    }
    return TRUE;
}

BOOLEAN EPT::AddToShadow(PVOID pFn)
{
    auto pShadowPagePa = Memory::VirtToPhy(PAGE_ALIGN(pFn));
    if (!pShadowPagePa)
        return false;

    for (DWORD dwCore = 0; dwCore < CPU::GetCPUCount(); dwCore++) {
        PVMM_EPT_DYNAMIC_SPLIT pShadowTargetBuf = 0;

        if (!EPT::SplitLargePage(vmm::eptShadow[dwCore].EptPageTable[ADDRMASK_EPT_PML4_INDEX(pShadowPagePa)], nullptr, pShadowPagePa)) {
            pShadowTargetBuf = (PVMM_EPT_DYNAMIC_SPLIT)cpp::kMallocTryAll(sizeof(VMM_EPT_DYNAMIC_SPLIT));
            if (!EPT::SplitLargePage(vmm::eptShadow[dwCore].EptPageTable[ADDRMASK_EPT_PML4_INDEX(pShadowPagePa)], pShadowTargetBuf, pShadowPagePa)) {
                DbgMsg("[EPT] Could not split shadow 4kb page, aborting...");
                return false;
            }
        }
        auto pShadowPage = EPT::GetPml1Entry(vmm::eptShadow[dwCore].EptPageTable[ADDRMASK_EPT_PML4_INDEX(pShadowPagePa)], pShadowPagePa);
        if (!MmIsAddressValid(pShadowPage)) {
            pShadowPage = EPT::MapPml1Entry(vmm::eptShadow[dwCore].EptPageTable[ADDRMASK_EPT_PML4_INDEX(pShadowPagePa)], pShadowPagePa);
            if (!pShadowPage) {
                DbgMsg("[EPT] Could not get shadow pml1 entry, aborting...");
                return false;
            }
        }
        if (pShadowTargetBuf) {
            for (SIZE_T i = 0; i < PT_ENTRIES; i++) {
                pShadowTargetBuf->PML1[i].SetExecute(false);
            }
        }

        pShadowPage->SetExecute(true);
    }

    return true;
}

BOOLEAN EPT::AddToShadowRange(PVOID pFn, SIZE_T sz) {
    DWORD64 pages = sz / PAGE_SIZE;
    pages += sz % PAGE_SIZE ? 1 : 0;

    for (DWORD64 i = 0; i < pages; i++) {
        PVOID pTarget = (PVOID)((DWORD64)pFn + i * PAGE_SIZE);
        BOOLEAN bRes = AddToShadow(
            pTarget
        );

        if (!bRes)
            return FALSE;
    }

    return TRUE;
}

#define TRAMPOLINE_SIZE (sizeof("\x68\xAD\xDE\xAD\xDE\xC7\x44\x24\x04\xDA\xDA\xDA\xDA\xC3") - 1)
#define MAX_TRAMPOLINE_SIZE TRAMPOLINE_SIZE + ZYDIS_MAX_INSTRUCTION_LENGTH

PVOID GetTrampolinePointer() {
    dwCurrTrampolineOffset += MAX_TRAMPOLINE_SIZE * 2;
    PVOID pTrampoline = (PVOID)((DWORD64)pTrampolinePage + dwCurrTrampolineOffset);
    return pTrampoline;
}

#pragma warning (disable:4702)
int PrepareHook(PVOID pTarget, PVOID pHook, HOOK_SECONDARY_INFO hkSecondaryInfo, PAGE_PERMISSIONS& pgPermissions, DWORD64 dwCore) {
    if (!pTarget) {
        DbgMsg("[EPT] Target is not a valid address: %p", pTarget);
        return INVALID_HOOK_INDEX;
    }
    BOOLEAN bLaunched = false;
    SIZE_T pPagePa = 0;
    SIZE_T pShadowPagePa = 0;
    PVMM_EPT_DYNAMIC_SPLIT pTargetBuf = 0;
    PVMM_EPT_DYNAMIC_SPLIT pShadowTargetBuf = 0;
    PPML2E pPml2Shadow = nullptr;
    int index = vmm::vHooks->emplace_back();
    HOOK_DATA& hkData = vmm::vHooks->at(index);
    EPT_STATE* pEptState = &vmm::vGuestStates[dwCore].eptState;

    hkData.vTargetData.reserve(CPU::GetCPUCount());
    hkData.vTargetData.DisableLock();
    EPT_TARGET_DATA& eptTargetData = hkData.vTargetData.at(dwCore);

    hkData.pTarget = pTarget;

    pPagePa = Memory::VirtToPhy(PAGE_ALIGN(hkData.pTarget));
    pShadowPagePa = pPagePa;
    if (!pPagePa|| 
        !pShadowPagePa
        ) {
        DbgMsg("[EPT] Virt to phy failed");
        return INVALID_HOOK_INDEX;
    }

    if (!pgPermissions.Exec) {
        if (!pHook) {
            DbgMsg("[EPT] Hook pointer is null");
            return INVALID_HOOK_INDEX;
        }

        PVOID pPageVa = cpp::kMallocZero(PAGE_SIZE, PAGE_EXECUTE_READWRITE);
        //if (!iommu::HidePage(pTarget, pPageVa)) {
        //    return INVALID_HOOK_INDEX;
        //}
        hkData.pPage = pPageVa;
        hkData.PFN = Memory::VirtToPhy(pPageVa) / PAGE_SIZE;

        //Use out param as tmp buffer for trampoline memory
        hkData.pTrampoline = GetTrampolinePointer();
    }
    else {
        hkData.PFN = Memory::VirtToPhy(hkSecondaryInfo.pSubstitutePage) / PAGE_SIZE;
        hkData.pPage = hkSecondaryInfo.pSubstitutePage;
        hkData.pTarget = PAGE_ALIGN(pTarget);
    }
    if (!hkData.PFN) {
        return INVALID_HOOK_INDEX;
    }
    if (!EPT::SplitLargePage(pEptState->EptPageTable[ADDRMASK_EPT_PML4_INDEX(pPagePa)], nullptr, pPagePa)) {
        pTargetBuf = (PVMM_EPT_DYNAMIC_SPLIT)cpp::kMallocTryAll(sizeof(VMM_EPT_DYNAMIC_SPLIT));
        if (!EPT::SplitLargePage(pEptState->EptPageTable[ADDRMASK_EPT_PML4_INDEX(pPagePa)], pTargetBuf, pPagePa)) {
            DbgMsg("[EPT] Could not split 4kb page, aborting...");
            return INVALID_HOOK_INDEX;
        }
    }
    if (!EPT::SplitLargePage(vmm::eptShadow[dwCore].EptPageTable[ADDRMASK_EPT_PML4_INDEX(pShadowPagePa)], nullptr, pShadowPagePa)) {
        pShadowTargetBuf = (PVMM_EPT_DYNAMIC_SPLIT)cpp::kMallocTryAll(sizeof(VMM_EPT_DYNAMIC_SPLIT));
        if (!EPT::SplitLargePage(vmm::eptShadow[dwCore].EptPageTable[ADDRMASK_EPT_PML4_INDEX(pShadowPagePa)], pShadowTargetBuf, pShadowPagePa)) {
            DbgMsg("[EPT] Could not split shadow 4kb page, aborting...");
            return INVALID_HOOK_INDEX;
        }
    }

    eptTargetData.pTargetPage = EPT::GetPml1Entry(pEptState->EptPageTable[ADDRMASK_EPT_PML4_INDEX(pPagePa)], pPagePa);
    if (!eptTargetData.pTargetPage) {
        DbgMsg("[EPT] Could not get pml1 entry, aborting...");
        return INVALID_HOOK_INDEX;
    }
    eptTargetData.pShadowPage = EPT::GetPml1Entry(vmm::eptShadow[dwCore].EptPageTable[ADDRMASK_EPT_PML4_INDEX(pShadowPagePa)], pShadowPagePa);
    if (!MmIsAddressValid(eptTargetData.pShadowPage)) {
        eptTargetData.pShadowPage = EPT::MapPml1Entry(vmm::eptShadow[dwCore].EptPageTable[ADDRMASK_EPT_PML4_INDEX(pShadowPagePa)], pShadowPagePa);
        if (!eptTargetData.pShadowPage) {
            DbgMsg("[EPT] Could not get shadow pml1 entry, aborting...");
            return INVALID_HOOK_INDEX;
        }
    }
    if (pShadowTargetBuf) {
        for (SIZE_T i = 0; i < PT_ENTRIES; i++) {
            pShadowTargetBuf->PML1[i].SetExecute(false);
        }
    }

    eptTargetData.pShadowPage->SetExecute(true);

    pPml2Shadow = EPT::GetPml2Entry(vmm::eptShadow[dwCore].EptPageTable[ADDRMASK_EPT_PML4_INDEX(pShadowPagePa)], pShadowPagePa);
    pPml2Shadow->SetExecute(true);

    eptTargetData.pOrigEPTPage = eptTargetData.pTargetPage;

    hkData.pHook = pHook;
    hkData.pgPermissions = pgPermissions;

    return index;
}

int PrepareHook2MB(PVOID pTarget, PVOID pHook, HOOK_SECONDARY_INFO hkSecondaryInfo, PAGE_PERMISSIONS& pgPermissions, DWORD64 dwCore) {
    if (!pTarget) {
        DbgMsg("[EPT] Target is not a valid address: %p", pTarget);
        return INVALID_HOOK_INDEX;
    }
    BOOLEAN bLaunched = false;
    SIZE_T pPagePa = 0;
    SIZE_T pShadowPagePa = 0;
    PVMM_EPT_DYNAMIC_SPLIT pTargetBuf = 0;
    PVMM_EPT_DYNAMIC_SPLIT pShadowTargetBuf = 0;
    PPML2E pPml2Shadow = nullptr;
    int index = vmm::vHooks->emplace_back();
    HOOK_DATA& hkData = vmm::vHooks->at(index);
    EPT_STATE* pEptState = &vmm::vGuestStates[dwCore].eptState;

    hkData.vTargetData.reserve(CPU::GetCPUCount());
    hkData.vTargetData.DisableLock();
    EPT_TARGET_DATA& eptTargetData = hkData.vTargetData.at(dwCore);

    hkData.pTarget = pTarget;

    pPagePa = Memory::VirtToPhy(PAGE_ALIGN(hkData.pTarget));
    pShadowPagePa = pPagePa;
    if (!pPagePa ||
        !pShadowPagePa
        ) {
        return INVALID_HOOK_INDEX;
    }

    if (!pgPermissions.Exec) {
        if (!pHook) {
            DbgMsg("[EPT] Hook pointer is null");
            return INVALID_HOOK_INDEX;
        }

        PVOID pPageVa = cpp::kMallocZero(SIZE_2MB, PAGE_EXECUTE_READWRITE);
        //if (!iommu::HidePage(pTarget, pPageVa)) {
        //    return INVALID_HOOK_INDEX;
        //}
        hkData.pPage = pPageVa;
        hkData.PFN = Memory::VirtToPhy(pPageVa) / SIZE_2MB;

        //Use out param as tmp buffer for trampoline memory
        hkData.pTrampoline = GetTrampolinePointer();
    }
    else {
        hkData.PFN = Memory::VirtToPhy(hkSecondaryInfo.pSubstitutePage) / SIZE_2MB;
        hkData.pPage = hkSecondaryInfo.pSubstitutePage;
        hkData.pTarget = PAGE_ALIGN(pTarget);
    }
    if (!hkData.PFN) {
        return INVALID_HOOK_INDEX;
    }

    eptTargetData.pTargetPage2MB = (PPML2E_2MB)EPT::GetPml2Entry(pEptState->EptPageTable[ADDRMASK_EPT_PML4_INDEX(pPagePa)], pPagePa);
    if (!eptTargetData.pTargetPage) {
        DbgMsg("[EPT] Could not get pml1 entry, aborting...");
        return INVALID_HOOK_INDEX;
    }
    eptTargetData.pShadowPage2MB = (PPML2E_2MB)EPT::GetPml2Entry(vmm::eptShadow[dwCore].EptPageTable[ADDRMASK_EPT_PML4_INDEX(pShadowPagePa)], pShadowPagePa);

    if (pShadowTargetBuf) {
        for (SIZE_T i = 0; i < PT_ENTRIES; i++) {
            pShadowTargetBuf->PML1[i].SetExecute(false);
        }
    }

    eptTargetData.pShadowPage2MB->SetExecute(true);

    eptTargetData.pOrigEPTPage2MB = eptTargetData.pTargetPage2MB;

    hkData.pHook = pHook;
    hkData.pgPermissions = pgPermissions;

    return index;
}

/// <summary>
/// Apply an EPT hook to the selected page
/// </summary>
/// <param name="pTarget">For exec hooks, the target function. For other hooks this is a pointer to the virtual memory to spoof</param>
/// <param name="pHook">For exec hooks, the callback function. For other hooks this is unused</param>
/// <param name="pOrigFn">For exec hooks, a pointer to the new address of the hooked function. For other hooks this is a pointer to the virtual memory to insert in the page</param>
/// <param name="pgPermissions">Permissions to set on the page. TRUE allows the specified operation</param>
/// <returns></returns>

NTSTATUS HookCore(int hookIndex, EPT_TARGET_DATA& eptDataTemplate, PVOID pTarget, PVOID pHook, HOOK_SECONDARY_INFO hkSecondaryInfo, PAGE_PERMISSIONS& pgPermissions, bool bSetPages) {
    if (pgPermissions.Write && !pgPermissions.Read) {
        return STATUS_UNSUCCESSFUL;
    }

    BOOLEAN bLaunched = false;
    DWORD dwCore = CPU::GetCPUIndex();

    HOOK_DATA& hkData = vmm::vHooks->at(hookIndex);
    EPT_STATE* pEptState = &vmm::vGuestStates[dwCore].eptState;
    EPT_STATE* pShadowEptState = &vmm::eptShadow[dwCore];

    EPT_TARGET_DATA& eptTargetData = hkData.vTargetData.at(dwCore);
    eptTargetData = eptDataTemplate;
    SIZE_T pagePa = Memory::VirtToPhy(hkData.pTarget);
    if (!pagePa) {
        return INVALID_HOOK_INDEX;
    }
    eptTargetData.pTargetPage = EPT::GetPml1Entry(pEptState->EptPageTable[ADDRMASK_EPT_PML4_INDEX(pagePa)], pagePa);
    if (!EPT::SplitLargePage(pEptState->EptPageTable[ADDRMASK_EPT_PML4_INDEX(pagePa)], nullptr, pagePa)) {
        //This page is on one of the other cores and hasn't been split yet
        PVOID pTargetBuf = cpp::kMallocTryAllZero(sizeof(VMM_EPT_DYNAMIC_SPLIT));
        if (!EPT::SplitLargePage(pEptState->EptPageTable[ADDRMASK_EPT_PML4_INDEX(pagePa)], pTargetBuf, pagePa)) {
            DbgMsg("[EPT] Could not split 4kb page, aborting...");
            return STATUS_UNSUCCESSFUL;
        }
        if (bLaunched) {
            bool bRes = paging::MapRegion(
                (PPML4T)paging::GetPML4Base(vmm::hostCR3),
                pTargetBuf,
                sizeof(VMM_EPT_DYNAMIC_SPLIT)
            );

            if (!bRes) {
                DbgMsg("[EPT] Could not map dynamic split page to host, aborting...");
                return INVALID_HOOK_INDEX;
            }
        }
        eptTargetData.pTargetPage = EPT::GetPml1Entry(pEptState->EptPageTable[ADDRMASK_EPT_PML4_INDEX(pagePa)], pagePa);
    }
    eptTargetData.pShadowPage = EPT::GetPml1Entry(pShadowEptState->EptPageTable[ADDRMASK_EPT_PML4_INDEX(pagePa)], pagePa);
    if (!EPT::SplitLargePage(pShadowEptState->EptPageTable[ADDRMASK_EPT_PML4_INDEX(pagePa)], nullptr, pagePa)) {
        //This page is on one of the other cores and hasn't been split yet
        VMM_EPT_DYNAMIC_SPLIT* pTargetBuf = (VMM_EPT_DYNAMIC_SPLIT*)cpp::kMallocTryAllZero(sizeof(VMM_EPT_DYNAMIC_SPLIT));
        if (!EPT::SplitLargePage(pShadowEptState->EptPageTable[ADDRMASK_EPT_PML4_INDEX(pagePa)], pTargetBuf, pagePa)) {
            DbgMsg("[EPT] Could not split 4kb page, aborting...");
            return STATUS_UNSUCCESSFUL;
        }
        if (bLaunched) {
            bool bRes = paging::MapRegion(
                (PPML4T)paging::GetPML4Base(vmm::hostCR3),
                pTargetBuf,
                sizeof(VMM_EPT_DYNAMIC_SPLIT)
            );

            if (!bRes) {
                DbgMsg("[EPT] Could not map dynamic split page to host, aborting...");
                return INVALID_HOOK_INDEX;
            }
        }
        for (SIZE_T i = 0; i < PT_ENTRIES; i++) {
            pTargetBuf->PML1[i].SetExecute(false);
        }

        eptTargetData.pShadowPage = EPT::GetPml1Entry(pShadowEptState->EptPageTable[ADDRMASK_EPT_PML4_INDEX(pagePa)], pagePa);
    }
    eptTargetData.pShadowPage->SetExecute(true);
    eptTargetData.pOrigEPTPage = eptTargetData.pTargetPage;

    NTSTATUS ntResult = STATUS_UNSUCCESSFUL;
    if (bLaunched) {
        bool bRes = paging::MapRegion(
            (PPML4T)paging::GetPML4Base(vmm::hostCR3),
            &vmm::vHooks->at(0),
            sizeof(HOOK_DATA) * vmm::vHooks->size()
        );
        if (!bRes) {
            DbgMsg("[EPT] Could not map hook data page to host, aborting...");
            return STATUS_UNSUCCESSFUL;
        }
    }
    if (bSetPages) {
        if (EPT::PageHook(hkData, hkSecondaryInfo, dwCore)) {
            ntResult = STATUS_SUCCESS;
        }
    }
    else {
        ntResult = STATUS_SUCCESS;
    }

    return ntResult;
}

NTSTATUS HookCore2MB(int hookIndex, EPT_TARGET_DATA& eptDataTemplate, PVOID pTarget, PVOID pHook, HOOK_SECONDARY_INFO hkSecondaryInfo, PAGE_PERMISSIONS& pgPermissions, bool bSetPages) {
    if (pgPermissions.Write && !pgPermissions.Read) {
        return STATUS_UNSUCCESSFUL;
    }

    BOOLEAN bLaunched = false;
    DWORD dwCore = CPU::GetCPUIndex();

    HOOK_DATA& hkData = vmm::vHooks->at(hookIndex);
    EPT_STATE* pEptState = &vmm::vGuestStates[dwCore].eptState;
    EPT_STATE* pShadowEptState = &vmm::eptShadow[dwCore];

    EPT_TARGET_DATA& eptTargetData = hkData.vTargetData.at(dwCore);
    eptTargetData = eptDataTemplate;
    SIZE_T pagePa = Memory::VirtToPhy(hkData.pTarget);
    if (!pagePa) {
        return INVALID_HOOK_INDEX;
    }
    eptTargetData.pTargetPage2MB = (PPML2E_2MB)EPT::GetPml2Entry(pEptState->EptPageTable[ADDRMASK_EPT_PML4_INDEX(pagePa)], pagePa);

    eptTargetData.pShadowPage2MB = (PPML2E_2MB)EPT::GetPml2Entry(pShadowEptState->EptPageTable[ADDRMASK_EPT_PML4_INDEX(pagePa)], pagePa);

    eptTargetData.pShadowPage->SetExecute(true);
    eptTargetData.pOrigEPTPage = eptTargetData.pTargetPage;

    NTSTATUS ntResult = STATUS_UNSUCCESSFUL;
    if (bLaunched) {
        bool bRes = paging::MapRegion(
            (PPML4T)paging::GetPML4Base(vmm::hostCR3),
            &vmm::vHooks->at(0),
            sizeof(HOOK_DATA) * vmm::vHooks->size()
        );
        if (!bRes) {
            DbgMsg("[EPT] Could not map hook data page to host, aborting...");
            return STATUS_UNSUCCESSFUL;
        }
    }
    if (bSetPages) {
        if (EPT::PageHook2MB(hkData, hkSecondaryInfo, dwCore)) {
            ntResult = STATUS_SUCCESS;
        }
    }
    else {
        ntResult = STATUS_SUCCESS;
    }

    return ntResult;
}

BOOLEAN EPT::Hook2MB(PVOID pTarget, PVOID pHook, HOOK_SECONDARY_INFO hkSecondaryInfo, PAGE_PERMISSIONS& pgPermissions, bool bSetPages, int* pIndex)
{
    PROCESSOR_RUN_INFO procInfo;
    procInfo.Flags = ~0ull;
    procInfo.bHighIrql = FALSE;
    DWORD dwCore = 0;

    int index = 0;
    for (auto& hook : *vmm::vHooks) {
        if (PAGE_ALIGN(hook.pTarget) == PAGE_ALIGN(pTarget)) {
            DbgMsg("[EPT] Warning: hook already placed at: %p", pTarget);
            if (!hook.pgPermissions.Exec)
                *hkSecondaryInfo.pOrigFn = hook.pTrampoline;
            if (pIndex)
                *pIndex = index;
            return true;
        }
        index++;
    }

    index = PrepareHook2MB(pTarget, pHook, hkSecondaryInfo, pgPermissions, dwCore);
    if (index == INVALID_HOOK_INDEX) {
        DbgMsg("[EPT] Hook preparation failed!");
        return FALSE;
    }
    if (pIndex)
        *pIndex = index;
    HOOK_DATA& hkData = vmm::vHooks->at(index);

    NTSTATUS status = CPU::RunOnAllCPUs(HookCore2MB, procInfo, index, hkData.vTargetData.at(dwCore), pTarget, pHook, hkSecondaryInfo, pgPermissions, bSetPages);

    if (NT_SUCCESS(status)) {
        DbgMsg("[EPT] Hooked at %p", hkData.pTarget);
    }
    else {
        DbgMsg("[EPT] Error: could not hook at %p", hkData.pTarget);
    }

    return NT_SUCCESS(status);
}

BOOLEAN EPT::Hook(PVOID pTarget, PVOID pHook, HOOK_SECONDARY_INFO hkSecondaryInfo, PAGE_PERMISSIONS& pgPermissions, bool bSetPages, int* pIndex)
{
    PROCESSOR_RUN_INFO procInfo;
    procInfo.Flags = ~0ull;
    procInfo.bHighIrql = FALSE;
    DWORD dwCore = 0;

    int index = 0;
    for (auto& hook : *vmm::vHooks) {
        if (PAGE_ALIGN(hook.pTarget) == PAGE_ALIGN(pTarget)) {
            DbgMsg("[EPT] Warning: hook already placed at: %p", pTarget);
            if(!hook.pgPermissions.Exec)
                *hkSecondaryInfo.pOrigFn = hook.pTrampoline;
            if (pIndex)
                *pIndex = index;
            return true;
        }
        index++;
    }

    index = PrepareHook(pTarget, pHook, hkSecondaryInfo, pgPermissions, dwCore);
    if (index == INVALID_HOOK_INDEX) {
        DbgMsg("[EPT] Hook preparation failed!");
        return FALSE;
    }
    if (pIndex)
        *pIndex = index;
    HOOK_DATA& hkData = vmm::vHooks->at(index);

    NTSTATUS status = CPU::RunOnAllCPUs(HookCore, procInfo, index, hkData.vTargetData.at(dwCore), pTarget, pHook, hkSecondaryInfo, pgPermissions, bSetPages);

    if (NT_SUCCESS(status)) {
        DbgMsg("[EPT] Hooked at %p", hkData.pTarget);
    }
    else {
        DbgMsg("[EPT] Error: could not hook at %p", hkData.pTarget);
    }

    return NT_SUCCESS(status);
}

BOOLEAN EPT::HookExec(PVOID pTarget, PVOID pHook, HOOK_SECONDARY_INFO hkSecondaryInfo)
{
    PAGE_PERMISSIONS pgPermissions = { 0 };
    return Hook(pTarget, pHook, hkSecondaryInfo, pgPermissions);
}

BOOLEAN EPT::HookIf(PVOID pFn, PVOID pHook, HOOK_SECONDARY_INFO hkSecondaryInfo, PAGE_PERMISSIONS& pgPermissions, fnHookCallback callback, bool bSetPages)
{
    PTE_64* pTargetPage = paging::GetPPTE(paging::GetPML4Base(), pFn);
    if (callback(pTargetPage)) {
        return Hook(pFn, pHook, hkSecondaryInfo, pgPermissions, bSetPages);
    }
    return false;
}

BOOLEAN EPT::HookRange(PVOID pBase, size_t size, PVOID pHook, HOOK_SECONDARY_INFO hkSecondaryInfo, PAGE_PERMISSIONS& pgPermissions, bool bSetPages, int* pIndex)
{
    if (!pgPermissions.Exec) {
        return FALSE;
    }
    BOOLEAN bLaunched = false;

    DWORD64 pages = size / PAGE_SIZE;
    pages += size % PAGE_SIZE ? 1 : 0;
    vmm::vHooks->reserve(pages);

    int startIndex = vmm::vHooks->length();
    if (pIndex)
        *pIndex = startIndex;

    for (DWORD64 i = 0; i < pages; i++) {
        PVOID pTarget = (PVOID)((DWORD64)pBase + i * PAGE_SIZE);
        BOOLEAN bRes = Hook(
            pTarget,
            pHook,
            hkSecondaryInfo,
            pgPermissions,
            bSetPages,
            nullptr
        );

        if (!bRes)
            return FALSE;
    }

    return TRUE;
}

BOOLEAN EPT::HookRangeIf(PVOID pBase, size_t size, PVOID pHook, HOOK_SECONDARY_INFO hkSecondaryInfo, PAGE_PERMISSIONS& pgPermissions, fnHookCallback callback, bool bSetPages)
{
    DWORD64 pages = size / PAGE_SIZE;
    pages += size % PAGE_SIZE ? 1 : 0;
    vmm::vHooks->reserve(pages);

    for (DWORD64 i = 0; i < pages; i++) {
        PVOID pTarget = (PVOID)((DWORD64)PAGE_ALIGN(pBase) + i * PAGE_SIZE);
        PTE_64* pTargetPage = paging::GetPPTE(paging::GetPML4Base(), pTarget);
        if (!callback(pTargetPage)) {
            continue;
        }
        bool bRes = Hook(
            pTarget,
            pHook,
            hkSecondaryInfo,
            pgPermissions,
            bSetPages
        );

        if (!bRes) {
            return FALSE;
        }
    }
    return TRUE;
}

BOOLEAN EPT::HookSubstitute(PVOID pTarget, HOOK_SECONDARY_INFO hkSecondaryInfo, PAGE_PERMISSIONS& pgPermissions, bool bSetPages, int* pIndex)
{
    if (pgPermissions.Write && !pgPermissions.Read) {
        return FALSE;
    }

    BOOLEAN bLaunched = false;
    DWORD dwCore = CPU::GetCPUIndex();

    int index = PrepareHook(pTarget, hkSecondaryInfo.pSubstitutePage, hkSecondaryInfo, pgPermissions, dwCore);
    if (index == INVALID_HOOK_INDEX)
        return FALSE;

    HOOK_DATA& hkData = vmm::vHooks->at(index);
    if (pIndex)
        *pIndex = index;
    EPT_TARGET_DATA& eptTargetData = hkData.vTargetData.at(dwCore);

    eptTargetData.NewEPTPage.Flags = eptTargetData.pTargetPage->Flags;
    eptTargetData.NewEPTPage.SetPFN(hkData.PFN);

    bool bRes = FALSE;
    if (bLaunched) {
        DbgMsg("[EPT] Mapping hooks vector to host");
        bRes = paging::MapRegion(
            (PPML4T)paging::GetPML4Base(vmm::hostCR3),
            &vmm::vHooks->at(0),
            sizeof(HOOK_DATA) * vmm::vHooks->size()
        );
        if (!bRes) {
            DbgMsg("[EPT] Could not map hook data page to host, aborting...");
            return FALSE;
        }
    }
    eptTargetData.pTargetPage->Flags = eptTargetData.NewEPTPage.Flags;
    eptTargetData.pShadowPage->Flags = eptTargetData.NewEPTPage.Flags;
    bRes = TRUE;

    if (bRes) {
        DbgMsg("[EPT] Substituted at %p - 0x%llx", hkData.pTarget, hkData.PFN);
    }
    else {
        DbgMsg("[EPT] Error: could not substitute at %p - 0x%llx", hkData.pTarget, hkData.PFN);
    }
    return bRes;
}

BOOLEAN EPT::HookSubstituteRange(PVOID pBase, size_t size, HOOK_SECONDARY_INFO hkSecondaryInfo, PAGE_PERMISSIONS& pgPermissions, bool bSetPages, int* pIndex)
{
    DWORD64 pages = size / PAGE_SIZE;
    pages += size % PAGE_SIZE ? 1 : 0;
    vmm::vHooks->reserve(pages);

    for (DWORD64 i = 0; i < pages; i++) {
        PVOID pTarget = (PVOID)((DWORD64)PAGE_ALIGN(pBase) + i * PAGE_SIZE);
        bool bRes = HookSubstitute(
            pTarget,
            hkSecondaryInfo,
            pgPermissions,
            bSetPages
        );

        if (!bRes) {
            return FALSE;
        }
    }
    return TRUE;
}

BOOLEAN EPT::InsertTrampoline(HOOK_DATA& hkData, PVOID* pOrigFn)
{
    if (hkData.szTrampoline
        || 0xad68 == *(WORD*)hkData.pTarget) {
        //Trampoline already set
        return TRUE;
    }
    PVOID pTrampoline = hkData.pTrampoline;
    if (pOrigFn)
        *pOrigFn = pTrampoline;

    SIZE_T OffsetIntoPage = 0;
    size_t pageSize = 0;
    OffsetIntoPage = ADDRMASK_EPT_PML1_OFFSET((SIZE_T)hkData.pTarget);
    pageSize = PAGE_SIZE;

    if ((OffsetIntoPage + TRAMPOLINE_SIZE) > pageSize - 1)
    {
        PAGE_PERMISSIONS pgPermissions = { 0 };
        pgPermissions.Exec = true;
        HOOK_SECONDARY_INFO hkSecondaryInfo = { 0 };
        hkSecondaryInfo.pSubstitutePage = cpp::kMallocZero(PAGE_SIZE);
        RtlCopyMemory(hkSecondaryInfo.pSubstitutePage, PAGE_ALIGN((DWORD64)hkData.pTarget + PAGE_SIZE), PAGE_SIZE);
        auto success = EPT::Hook((PVOID)((DWORD64)hkData.pTarget + PAGE_SIZE), hkSecondaryInfo.pSubstitutePage, hkSecondaryInfo, pgPermissions);
        if (!success)
            return false;
    }
    SIZE_T shiftBytes = 0;
    SIZE_T SizeOfHookedInstructions = disassembler::GetInstrBoundaryLen(hkData.pTarget, TRAMPOLINE_SIZE);
    if (SizeOfHookedInstructions < TRAMPOLINE_SIZE) {
        //A near jmp/call was found, need to move the bytes
        shiftBytes = TRAMPOLINE_SIZE - SizeOfHookedInstructions;

        DWORD64 pNewTarget = (DWORD64)Memory::FindByteSeriesSafe((PVOID)((DWORD64)hkData.pTarget + SizeOfHookedInstructions), shiftBytes, (BYTE)'\xcc');
        if (!pNewTarget)
            return FALSE;

        _disable();
        bool bEnableCET = CPU::DisableWriteProtection();

        //Shift the bytes up
        for (LONG64 i = pNewTarget - (DWORD64)hkData.pTarget - SizeOfHookedInstructions - 1; i >= 0; i--) {
            ((PBYTE)hkData.pTarget + SizeOfHookedInstructions)[i + shiftBytes] = ((PBYTE)hkData.pTarget + SizeOfHookedInstructions)[i];
        }
        //Fill with NOP
        for (ULONG i = 0; i < shiftBytes; i++) {
            ((PBYTE)hkData.pTarget + SizeOfHookedInstructions)[i] = 0x90;
        }
        //Adjust near jmp/call operand
        DWORD32 operand = *(DWORD32*)((DWORD64)hkData.pTarget + SizeOfHookedInstructions + shiftBytes + 1);
        operand -= (DWORD32)shiftBytes;
        *(DWORD32*)((DWORD64)hkData.pTarget + SizeOfHookedInstructions + shiftBytes + 1) = operand;

        CPU::EnableWriteProtection(bEnableCET);
        _enable();

        SizeOfHookedInstructions = TRAMPOLINE_SIZE;
    }

    RtlCopyMemory(pTrampoline, hkData.pTarget, SizeOfHookedInstructions);

    _disable();
    bool bEnableCET = CPU::DisableWriteProtection();
    CPU::WriteAbsJmp((PCHAR)pTrampoline + SizeOfHookedInstructions, (size_t)hkData.pTarget + SizeOfHookedInstructions);
    CPU::WriteAbsJmp((PCHAR)PAGE_ALIGN(hkData.pTarget) + OffsetIntoPage, (size_t)hkData.pHook);
    CPU::EnableWriteProtection(bEnableCET);
    _enable();

    hkData.szTrampoline = SizeOfHookedInstructions;

    return TRUE;
}

BOOLEAN EPT::IsShadowEPTActive(ULONG dwCore) {
    EPT_STATE* pEptState = &vmm::vGuestStates[dwCore].eptState;
    if (CPU::bIntelCPU) {
        DWORD64 currEPT = 0;
        __vmx_vmread(EPT_POINTER_LOW, &currEPT);
        return pEptState->EptPointer.Flags != currEPT;
    }
    
    return pEptState->nCR3.Flags != vmm::vGuestStates[dwCore].SvmState->GuestVmcb->ControlArea.NestedPageTableCr3;
}

NTSTATUS EPT::ExitShadow(ULONG dwCore)
{
    EPT_STATE* pEptState = &vmm::vGuestStates[dwCore].eptState;
    if (CPU::bIntelCPU) {
        __vmx_vmwrite(EPT_POINTER_LOW, pEptState->EptPointer.Flags);
        INVEPT_DESCRIPTOR Descriptor = { pEptState->EptPointer.Flags, 0 };
        CPU::InveptContext(InveptAllContext, &Descriptor);
    }
    else {
        vmm::vGuestStates[dwCore].SvmState->GuestVmcb->ControlArea.NestedPageTableCr3 = pEptState->nCR3.Flags;
        SVM::ClearEntireTLB(vmm::vGuestStates[dwCore].SvmState);
    }

    return STATUS_SUCCESS;
}

NTSTATUS EPT::EnterShadow(ULONG dwCore)
{
    EPT_STATE* pEptState = &vmm::vGuestStates[dwCore].eptState;
    if (CPU::bIntelCPU) {
        __vmx_vmwrite(EPT_POINTER_LOW, vmm::eptShadow[dwCore].EptPointer.Flags);
        INVEPT_DESCRIPTOR Descriptor = { vmm::eptShadow[dwCore].EptPointer.Flags, 0 };
        CPU::InveptContext(InveptAllContext, &Descriptor);
    }
    else {
        vmm::vGuestStates[dwCore].SvmState->GuestVmcb->ControlArea.NestedPageTableCr3 = vmm::eptShadow[dwCore].nCR3.Flags;
        SVM::ClearEntireTLB(vmm::vGuestStates[dwCore].SvmState);
    }

    return STATUS_SUCCESS;
}

NTSTATUS EPT::Unhook(PVOID pFn)
{
    bool bFound = false;
    int i = 0;
    NTSTATUS ntStatus = STATUS_SUCCESS;

    for (; i < vmm::vHooks->length(); i++) {
        HOOK_DATA& hkData = vmm::vHooks->at(i);

        if (hkData.pTarget != pFn
            || hkData.pTarget == (PVOID)MAXULONG64) {
            continue;
        }

        DbgMsg("[EPT] Unhooking page at: %p", hkData.pTarget);

        PROCESSOR_RUN_INFO procInfo;
        procInfo.Flags = ~0ull;
        procInfo.bHighIrql = FALSE;

        if (!hkData.pgPermissions.Exec) {
            //Restore the original page bytes
            Memory::WriteProtected(hkData.pTarget, hkData.pTrampoline, hkData.szTrampoline);
        }

        ntStatus = CPU::RunOnAllCPUs([&](HOOK_DATA& hkData) {
            DWORD dwCore = CPU::GetCPUIndex();

            if (hkData.vTargetData[dwCore].pTargetPage) {
                hkData.vTargetData[dwCore].pTargetPage->Flags = hkData.vTargetData[dwCore].OrigEPTFlags.Flags;
                hkData.vTargetData[dwCore].pTargetPage->SetReadWrite(true);
                hkData.vTargetData[dwCore].pShadowPage->SetExecute(false);
            }

            return STATUS_SUCCESS;
        }, procInfo, hkData);

        bFound = true;
        hkData.pTarget = (PVOID)MAXULONG64;
        break;
    }

    if (bFound) {
        DbgMsg("[EPT] Removed hook %d at: %p", i, pFn);
    }
    else {
        DbgMsg("[EPT] Could not find any hook to remove at: %p", pFn);
    }
    return ntStatus;
}

NTSTATUS EPT::UnhookRange(PVOID pFn, SIZE_T sz)
{
    int i = 0;
    NTSTATUS ntStatus = STATUS_SUCCESS;
    DWORD64 startRange = (DWORD64)pFn;
    DWORD64 endRange = startRange + sz - 1;

    for (; i < vmm::vHooks->length(); i++) {
        HOOK_DATA& hkData = vmm::vHooks->at(i);

        if (!cpp::IsInRange(hkData.pTarget, startRange, endRange)
            || hkData.pTarget == (PVOID)MAXULONG64) {
            continue;
        }

        DbgMsg("[EPT] Unhooking page at: %p", hkData.pTarget);

        PROCESSOR_RUN_INFO procInfo;
        procInfo.Flags = ~0ull;
        procInfo.bHighIrql = FALSE;

        if (!hkData.pgPermissions.Exec) {
            //Restore the original page bytes
            Memory::WriteProtected(hkData.pTarget, hkData.pTrampoline, hkData.szTrampoline);
        }

        ntStatus = CPU::RunOnAllCPUs([&](HOOK_DATA& hkData) {
            DWORD dwCore = CPU::GetCPUIndex();

            if (hkData.vTargetData[dwCore].pTargetPage) {
                hkData.vTargetData[dwCore].pTargetPage->Flags = hkData.vTargetData[dwCore].OrigEPTFlags.Flags;
                hkData.vTargetData[dwCore].pTargetPage->SetReadWrite(true);
                hkData.vTargetData[dwCore].pShadowPage->SetExecute(false);
            }

            return STATUS_SUCCESS;
        }, procInfo, hkData);

        hkData.pTarget = (PVOID)MAXULONG64;
        if (ntStatus != STATUS_SUCCESS)
            break;
    }

    if (ntStatus == STATUS_SUCCESS) {
        DbgMsg("[EPT] Successfully unhooked range at %p for 0x%llx bytes", pFn, sz);
    }
    else {
        DbgMsg("[EPT] Could not unhook range at %p for 0x%llx bytes", pFn, sz);
    }
    return ntStatus;
}

VMX_ERROR EPT::SetPMLAndInvalidateTLB(PVOID pEntry, DWORD64 Flags, INVEPT_TYPE type, ULONG dwCore)
{
    if (!pEntry) {
        return VMX_ERROR::VMX_ERROR_CODE_FAILED;
    }

    *(DWORD64*)pEntry = Flags;

    VMX_ERROR res = VMX_ERROR::VMX_ERROR_CODE_SUCCESS;
    if (CPU::bIntelCPU) {
        EPT_STATE* pEptState = &vmm::vGuestStates[dwCore].eptState;

        INVEPT_DESCRIPTOR Descriptor = { pEptState->EptPointer.Flags, 0 };

        if (type == InveptAllContext) {
            Descriptor.EptPointer = 0;
        }
        res = CPU::InveptContext(type, &Descriptor);
    }

    return res;
}

VMX_ERROR EPT::InvalidateEPT(DWORD dwCore)
{
    if (CPU::bIntelCPU) {
        VMX_ERROR res;
        INVEPT_DESCRIPTOR Descriptor = { 0, 0 };
        res = CPU::InveptContext(InveptAllContext, &Descriptor);
        return res;
    }
    else {
        SVM::ClearEntireTLB(vmm::vGuestStates[dwCore].SvmState);
        return VMX_ERROR::VMX_ERROR_CODE_SUCCESS;
    }
}

VMX_ERROR EPT::InvalidateEPTShadow(DWORD dwCore)
{
    if (CPU::bIntelCPU) {
        VMX_ERROR res;
        INVEPT_DESCRIPTOR Descriptor = { 0, 0 };
        res = CPU::InveptContext(InveptAllContext, &Descriptor);
        return res;
    }
    else {
        SVM::ClearEntireTLB(vmm::vGuestStates[dwCore].SvmState);
        return VMX_ERROR::VMX_ERROR_CODE_SUCCESS;
    }
}
