#include "VTx.h"

#include "Vmcall.h"
#include "Vmexit.h"
#include "Vmoperations.h"

#include <intrin.h>
#include <Arch/Cpuid.h>
#include <identity.h>

bool bVmxInit = false;
int powIndex = -1;

DWORD32 cpuFreq = 0;

//Avoid backwards counter reads
DWORD64 lastReadTSC = 0;
DWORD64 lastReadAPERF = 0;
DWORD64 lastReadMPERF = 0;

// VMWRITE instruction
inline void vmx_vmwrite(DWORD64 const field, DWORD64 const value) {
    __vmx_vmwrite(field, value);
}

// VMREAD instruction
inline DWORD64 vmx_vmread(DWORD64 const field) {
    DWORD64 value;
    __vmx_vmread(field, &value);
    return value;
}

// get the value of CR0 that the guest believes is active.
// this is a mixture of the guest CR0 and the CR0 read shadow.
inline CR0 read_effective_guest_cr0() {
    // TODO: cache this value
    auto const mask = vmx_vmread(VMCS_CTRL_CR0_GUEST_HOST_MASK);

    // bits set to 1 in the mask are read from CR0, otherwise from the shadow
    CR0 cr0;
    cr0.Flags = (vmx_vmread(VMCS_CTRL_CR0_READ_SHADOW) & mask)
        | (vmx_vmread(VMCS_GUEST_CR0) & ~mask);

    return cr0;
}

// get the value of CR4 that the guest believes is active.
// this is a mixture of the guest CR4 and the CR4 read shadow.
inline CR4 read_effective_guest_cr4() {
    // TODO: cache this value
    auto const mask = vmx_vmread(VMCS_CTRL_CR4_GUEST_HOST_MASK);

    // bits set to 1 in the mask are read from CR4, otherwise from the shadow
    CR4 cr4;
    cr4.Flags = (vmx_vmread(VMCS_CTRL_CR4_READ_SHADOW) & mask)
        | (vmx_vmread(VMCS_GUEST_CR4) & ~mask);

    return cr4;
}

void PowerCallback(PVOID pContext, PVOID arg1, PVOID arg2) {
    DbgMsg("[POWER] Callback called: arg1=%p, arg2=%p", arg1, arg2);

    if (arg1 != reinterpret_cast<void*>(PO_CB_SYSTEM_STATE_LOCK)) {
        return;
    }

    if (arg2) {
        // the computer has just reentered S0.
        if (CPU::IsHypervOn()) {
            DbgMsg("[POWER] Hypervisor is already on, skipping resume...");
            return;
        }
        DbgMsg("[POWER] Resuming virtualization...");
        NTSTATUS ntStatus = VTx::VirtualizeSystem();
        if (ntStatus == STATUS_SUCCESS) {
            DbgMsg("[POWER] Successfully virtualized system!");
        }
        else {
            DbgMsg("[POWER] Error: Could not virtualize system!");
        }
    }
    else {
        // the computer is about to exit system power state S0
        DbgMsg("[POWER] Suspending virtualization...");
        if (VTx::DevirtualizeSystem() == STATUS_SUCCESS) {
            DbgMsg("[POWER] Successfully suspended hypervisor!");
        }
        else {
            DbgMsg("[POWER] Error: could not suspend hypervisor!");
        }
    }
}

bool VTx::Init()
{
    vmm::Init();
#ifndef _USERMODE_LOGS
    logging::Init(LOG_FILE_PATH);
#endif
    KAFFINITY AffinityMask;

    for (size_t i = 0; i < vmm::dwCores; i++)
    {
        AffinityMask = 1 << i;
        vmm::ulProcessorMask |= AffinityMask;

        KeSetSystemAffinityThread(AffinityMask);

        //
        // Enabling VMX Operation
        //
        auto msr = __readmsr(IA32_FEATURE_CONTROL);
        CPU::EnableVmx();
        if (!CPU::IsVmxEnabled()) {
            DbgMsg("[VMX] Error: could not enable VMX for processor: %llx", i);
            goto _error;
        }
        if (!bitmap::GetBit(&msr, 2)) {
            if (!bitmap::GetBit(&msr, 0)) {
                bitmap::SetBit(&msr, 0, true);
                bitmap::SetBit(&msr, 1, true);
                bitmap::SetBit(&msr, 2, true);
                __writemsr(IA32_FEATURE_CONTROL, msr);
            }
            else {
                goto _error;
            }
        }

        DbgMsg("[VMX] VMX Operation Enabled for logical processor: %llx", i);

        vmm::vGuestStates[i].pContext = (PREGS)cpp::kMalloc(sizeof(REGS), PAGE_READWRITE);
        vmm::vGuestStates[i].pRetContext = (PREGS)cpp::kMalloc(sizeof(REGS), PAGE_READWRITE);

        if (!AllocVmxonRegion(&vmm::vGuestStates[i]) || !AllocVmcsRegion(&vmm::vGuestStates[i])) {
            DbgMsg("[VMX] Failed to allocate region for logical processor: %llx! Aborting initialization...", i);
            goto _error;
        }
        if (!VTx::AllocVmmStack(&vmm::vGuestStates[i])) {
            DbgMsg("[VMX] Error: failed to allocate VMM Stack");
            goto _error;
        }
        if (!VTx::AllocIOBitmap(&vmm::vGuestStates[i])) {
            DbgMsg("[VMX] Error: failed to allocate IO Bitmap");
            goto _error;
        }
        if (!VTx::AllocMsrBitmap(&vmm::vGuestStates[i])) {
            DbgMsg("[VMX] Error: failed to allocate MSR Bitmap");
            goto _error;
        }
        if (!VTx::AllocMsrState(&vmm::vGuestStates[i])) {
            DbgMsg("[VMX] Error: failed to allocate MSR State");
            goto _error;
        }

        continue;
    _error:
        vmm::ulProcessorMask &= ~AffinityMask;
    }
    KeRevertToUserAffinityThread();

#ifndef _KDMAPPED
    if (powIndex == -1) {
        NTSTATUS ntStatus = Power::RegisterCallback(PowerCallback, &powIndex);
        if (ntStatus != STATUS_SUCCESS) {
            DbgMsg("[VMX] Could not register power callback: 0x%x", ntStatus);
        }
    }
    else {
        DbgMsg("[VMX] Power callback already registered at: %d", powIndex);
    }
#endif

    DbgMsg("[VMX] Successfully initialized VMX");

    bVmxInit = true;

    return TRUE;
}

NTSTATUS VTx::Dispose()
{
    DbgMsg("[VMX] Turning off VMX for all cores...");

#ifndef _USERMODE_LOGS
    logging::Dispose();
#endif
    NTSTATUS ntStatus = VTx::DevirtualizeSystem();

#ifndef _KDMAPPED
    if (powIndex != -1) {
        Power::UnregisterCallback(powIndex);
    }
#endif

    vmm::vHooks->Dispose();

    cpp::kFree(vmm::vGuestStates);
    cpp::kFree(vmm::vHooks);

    DbgMsg("[VMX] All resources have been released");
    return ntStatus;
}

bool VTx::VmxOn(PVOID pRegion)
{
    DbgMsg("[VMX] VMXON called...");

    char bStatus = __vmx_on((ULONGLONG*)pRegion);
    if (bStatus && bStatus != 2 /*Status 2 means that Vmx was already ON*/)
    {
        DbgMsg("[VMX] VMXON failed with status %x", bStatus);
        return FALSE;
    }
    return TRUE;
}

void VTx::VmxOff(ULONG dwCore) {
    UINT64 GuestRSP; 	// Save a pointer to guest rsp for times that we want to return to previous guest stateS
    UINT64 GuestRIP; 	// Save a pointer to guest rip for times that we want to return to previous guest state
    UINT64 GuestCr3;
    UINT64 ExitInstructionLength;


    // Initialize the variables
    ExitInstructionLength = 0;
    GuestRIP = 0;
    GuestRSP = 0;

    /*
    According to SimpleVisor :
        Our callback routine may have interrupted an arbitrary user process,
        and therefore not a thread running with a system-wide page directory.
        Therefore if we return back to the original caller after turning off
        VMX, it will keep our current "host" CR3 value which we set on entry
        to the PML4 of the SYSTEM process. We want to return back with the
        correct value of the "guest" CR3, so that the currently executing
        process continues to run with its expected address space mappings.
    */

    __vmx_vmread(GUEST_CR3, &GuestCr3);
    __writecr3(GuestCr3);

    // Read guest rsp and rip
    __vmx_vmread(GUEST_RIP, &GuestRIP);
    __vmx_vmread(GUEST_RSP, &GuestRSP);

    // Read instruction length
    __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);
    GuestRIP += ExitInstructionLength;

    // Set the previous register states
    PVM_STATE pState = &vmm::vGuestStates[dwCore];
    pState->VmxoffState.IsVmxoffExecuted = true;
    vmm::vGuestStates[dwCore].VmxoffState.GuestRip = GuestRIP;
    vmm::vGuestStates[dwCore].VmxoffState.GuestRsp = GuestRSP;
    // Execute Vmxoff
    __vmx_off();

    //CPU::SetGdt(&pState->originalGdt.Limit);
    //CPU::SetIdt(&pState->originalIdt.Limit);

    vmm::ulProcessorMask &= ~(1 << dwCore);
}

void VTx::Vmptrst()
{
    DbgMsg("[VMX] VMPTRST called...");

    PHYSICAL_ADDRESS vmcspa;
    vmcspa.QuadPart = 0;
    __vmx_vmptrst((unsigned __int64*)&vmcspa);

    DbgMsg("[VMX] VMPTRST %llx", vmcspa.QuadPart);
}

bool VTx::VmClear(PVM_STATE pState)
{
    // Clear the state of the VMCS to inactive
    int status = __vmx_vmclear(&pState->pVmcsRegion);

    DbgMsg("[VMX] VMCLEAR Status is : %d", status);
    if (status)
    {
        // Otherwise, terminate the VMX
        DbgMsg("[VMX] VMCLEAR failed with status %d", status);
        __vmx_off();
        pState->VmxoffState.IsVmxoffExecuted = true;
        return FALSE;
    }
    return TRUE;
}

bool VTx::VmPtrld(PVM_STATE pState)
{
    int status = __vmx_vmptrld(&pState->pVmcsRegion);
    if (status)
    {
        DbgMsg("[VMX] VMCS failed with status %d", status);
        return FALSE;
    }
    return TRUE;
}

bool VTx::AllocVmmStack(PVM_STATE pState) {
    UINT64 VMM_STACK_VA = (UINT64)cpp::kMalloc(VMM_STACK_SIZE, PAGE_READWRITE);
    pState->pVmmStack = VMM_STACK_VA;

    if (pState->pVmmStack == NULL)
    {
        DbgMsg("[VMX] Error in allocating VMM Stack!");
        return FALSE;
    }
    RtlZeroMemory((PVOID)pState->pVmmStack, VMM_STACK_SIZE);
    return TRUE;
}

bool VTx::AllocMsrBitmap(PVM_STATE pState) {
    pState->vaMsrBitmap = (UINT64)cpp::kMalloc(PAGE_SIZE, PAGE_READWRITE); // should be aligned
    if (pState->vaMsrBitmap == NULL)
    {
        DbgMsg("[VMX] Error in allocating MSRBitMap!");
        return FALSE;
    }
    RtlZeroMemory((PVOID)pState->vaMsrBitmap, PAGE_SIZE);
    pState->paMsrBitmap = (UINT64)Memory::VirtToPhy((PVOID)pState->vaMsrBitmap);

#ifdef FAKE_COUNTERS
    //VMEXIT on TSC read/write
    bitmap::SetBit((PVOID)pState->vaMsrBitmap, IA32_TIME_STAMP_COUNTER, 1);
    bitmap::SetBit((PVOID)pState->vaMsrBitmap, 0xc00 + IA32_TIME_STAMP_COUNTER, 1);
    //VMEXIT on MPERF/APERF read
    bitmap::SetBit((PVOID)pState->vaMsrBitmap, IA32_APERF, 1);
    bitmap::SetBit((PVOID)pState->vaMsrBitmap, IA32_MPERF, 1);
#endif
    bitmap::SetBit((PVOID)pState->vaMsrBitmap, IA32_FEATURE_CONTROL, 1);
    bitmap::SetBit((PVOID)pState->vaMsrBitmap, 0xc00 + IA32_FEATURE_CONTROL, 1);
    VIRTUALIZER_FISH_WHITE_END

        return TRUE;
}

bool VTx::AllocMsrState(PVM_STATE pState)
{
    pState->pMsrGuestExitState = (PMSR_STATE)cpp::kMalloc(PAGE_SIZE * 2, PAGE_READWRITE);
    if (pState->pMsrGuestExitState == NULL)
    {
        DbgMsg("[VMX] Error in allocating MSRState!");
        return FALSE;
    }
    RtlZeroMemory((PVOID)pState->pMsrGuestExitState, PAGE_SIZE * 2);

    pState->pMsrGuestEntryState = (PMSR_STATE)cpp::kMalloc(PAGE_SIZE * 2, PAGE_READWRITE);
    if (pState->pMsrGuestEntryState == NULL)
    {
        DbgMsg("[VMX] Error in allocating MSRState!");
        return FALSE;
    }
    RtlZeroMemory((PVOID)pState->pMsrGuestEntryState, PAGE_SIZE * 2);

    pState->pMsrHostState = (PMSR_STATE)cpp::kMalloc(PAGE_SIZE * 2, PAGE_READWRITE);
    if (pState->pMsrHostState == NULL)
    {
        DbgMsg("[VMX] Error in allocating MSRState!");
        return FALSE;
    }
    RtlZeroMemory((PVOID)pState->pMsrHostState, PAGE_SIZE * 2);

    return TRUE;
}

bool VTx::AllocIOBitmap(PVM_STATE pState)
{
    pState->vaIOBitmapA = cpp::kMalloc(PAGE_SIZE, PAGE_READWRITE); // should be aligned
    if (pState->vaIOBitmapA == NULL)
    {
        DbgMsg("[VMX] Error in allocating IOBitMap!");
        return FALSE;
    }
    RtlZeroMemory((PVOID)pState->vaIOBitmapA, PAGE_SIZE);
    pState->paIOBitmapA = (UINT64)Memory::VirtToPhy((PVOID)pState->vaIOBitmapA);

#ifdef FAKE_COUNTERS
    //VMEXIT on RTC and 8253 timer read
    bitmap::SetBit(pState->vaIOBitmapA, IO_TIMER1_PORT, TRUE);
    bitmap::SetBit(pState->vaIOBitmapA, IO_RTC, TRUE);
#endif

    pState->vaIOBitmapB = cpp::kMalloc(PAGE_SIZE, PAGE_READWRITE); // should be aligned
    if (pState->vaIOBitmapB == NULL)
    {
        DbgMsg("[VMX] Error in allocating IOBitMap!");
        return FALSE;
    }
    RtlZeroMemory((PVOID)pState->vaIOBitmapB, PAGE_SIZE);
    pState->paIOBitmapB = (UINT64)Memory::VirtToPhy((PVOID)pState->vaIOBitmapB);

    return TRUE;
}

void VTx::VmxLaunch(PVOID GuestStack)
{
    ULONG ulProcessor = CPU::GetCPUIndex();
    DbgMsg("[VMX] Launching VM for processor: 0x%x", ulProcessor);
    PVM_STATE pState = &vmm::vGuestStates[ulProcessor];

    if (!VmxOn(&pState->pVmxonRegion))
    {
        DbgMsg("[VMX] Error: VMXON failed!");
        return;
    }

    //
    // Clear the VMCS State
    //

    if (!VmClear(pState)) {
        goto _error;
    }

    //
    // Load VMCS (Set the Current VMCS)
    //
    if (!VmPtrld(pState)) {
        goto _error;
    }

    if (!VmcsSetup(pState, GuestStack)) {
        goto _error;
    }

    DbgMsg("[VMX] Calling VMLAUNCH...");
    VmxSaveAndLaunch(pState->pRetContext);
    lastReadTSC = __rdtsc();

    //
    // VMLAUNCH will return here if a breaking VMEXIT case occurs
    //
    if (CPU::IsVmxEnabled() && !pState->VmxoffState.IsVmxoffExecuted) {
        //There was an error launching VM
        ULONG64 ErrorCode = 0;
        __vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
        DbgMsg("[VMX] VMRESUME Error : 0x%llx", ErrorCode);

        __vmx_off();
        pState->VmxoffState.IsVmxoffExecuted = true;

        DebugBreak();
    }

    return;

_error:
    DbgMsg("[VMX] There was an error starting the VM on logical processor: 0x%x", ulProcessor);
}

bool VTx::GetSegmentDescriptor(PSEG_SELECTOR SegmentSelector, USHORT Selector, PUCHAR GdtBase)
{
    PSEG_DESCRIPTOR SegDesc;

    if (!SegmentSelector)
        return FALSE;

    if (Selector & 0x4) {
        return FALSE;
    }

    SegDesc = (PSEG_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

    SegmentSelector->SEL = Selector;
    SegmentSelector->BASE = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
    SegmentSelector->LIMIT = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
    SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

    if (!(SegDesc->ATTR0 & 0x10)) { // LA_ACCESSED
        ULONG64 tmp;
        // this is a TSS or callgate etc, save the base high part
        tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
        SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (tmp << 32);
    }

    if (SegmentSelector->ATTRIBUTES.Fields.G) {
        // 4096-bit granularity is enabled for this segment, scale the limit
        SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
    }

    return TRUE;
}

void VTx::FillGuestSelectorData(PVOID GdtBase, ULONG SegmentRegister, USHORT Selector)
{
    SEG_SELECTOR SegmentSelector = { 0 };
    ULONG AccessRights;

    GetSegmentDescriptor(&SegmentSelector, Selector, (PUCHAR)GdtBase);
    AccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

    if (!Selector)
        AccessRights |= 0x10000;

    __vmx_vmwrite(GUEST_ES_SELECTOR + SegmentRegister * 2, Selector);
    __vmx_vmwrite(GUEST_ES_LIMIT + SegmentRegister * 2, SegmentSelector.LIMIT);
    __vmx_vmwrite(GUEST_ES_AR_BYTES + SegmentRegister * 2, AccessRights);
    __vmx_vmwrite(GUEST_ES_BASE + SegmentRegister * 2, SegmentSelector.BASE);

}

NTSTATUS VTx::VirtualizeSystem()
{
    if (!Init())
        return STATUS_UNSUCCESSFUL;

    PROCESSOR_RUN_INFO procInfo;
    procInfo.Flags = ~0ull;
    procInfo.bHighIrql = FALSE;

    auto startingTSCRate = CPU::GetTSCRate();
    DbgMsg("[VMX] Starting with TSC rate: 0x%llx", startingTSCRate);

    vmm::hostCR3.Flags = __readcr3();

#ifdef PROPRIETARY_PAGE_TABLES
    PVOID pPML4 = paging::CopyPML4Mapping();
    vmm::hostCR3.AddressOfPageDirectory = Memory::VirtToPhy(pPML4) >> 12;

    vmm::pIdentityMap = identity::MapIdentityUntracked(vmm::hostCR3);
    DbgMsg("[VMM] Mapped vmx host identity mapping");
#endif
    KeIpiGenericCall((PKIPI_BROADCAST_WORKER)VTx::AsmVmxSaveState, 0);

    auto startingTSCRate1 = CPU::GetTSCRate();
    DbgMsg("[VMX] Post start TSC rate: 0x%llx", startingTSCRate1);

    return STATUS_SUCCESS;
}

NTSTATUS VTx::DevirtualizeSystem()
{
    if (!CPU::IsHypervOn()) {
        DbgMsg("[VMX] Hypervisor is not active, cannot devirtualize!");
        return STATUS_UNSUCCESSFUL;
    }

    bVmxInit = false;
    PROCESSOR_RUN_INFO procInfo;
    procInfo.Flags = ~0ull;
    procInfo.bHighIrql = FALSE;
    NTSTATUS ntStatus = CPU::RunOnAllCPUs(CPU::VmxVMCALL, procInfo, vmcall::VMCALL_VMXOFF, 0, 0, 0);

    return ntStatus;
}

bool VTx::VmcsSetup(PVM_STATE pState, PVOID GuestStack)
{
    ULONG64      GdtBase = 0;
    SEG_SELECTOR SegmentSelector = { 0 };
    ULONG        CpuBasedVmExecControls;
    ULONG        SecondaryProcBasedVmExecControls;
    DWORD64 dwCore = CPU::GetCPUIndex();
    EPT_STATE* pEptState = &vmm::vGuestStates[dwCore].eptState;

    __vmx_vmwrite(HOST_ES_SELECTOR, CPU::GetEs() & 0xF8);
    __vmx_vmwrite(HOST_CS_SELECTOR, CPU::GetCs() & 0xF8);
    __vmx_vmwrite(HOST_SS_SELECTOR, CPU::GetSs() & 0xF8);
    __vmx_vmwrite(HOST_DS_SELECTOR, CPU::GetDs() & 0xF8);
    __vmx_vmwrite(HOST_FS_SELECTOR, CPU::GetFs() & 0xF8);
    __vmx_vmwrite(HOST_GS_SELECTOR, CPU::GetGs() & 0xF8);
    __vmx_vmwrite(HOST_TR_SELECTOR, CPU::GetTr() & 0xF8);

    // Setting the link pointer to the required value for 4KB VMCS.
    __vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL);

    __vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
    __vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);

    /* Time-stamp counter control */
    __vmx_vmwrite(TSC_OFFSET, 0);
    __vmx_vmwrite(TSC_MULTIPLIER, 1.0f);
    __vmx_vmwrite(GUEST_PREEMPTION_TIMER_VALUE, MAXINT32);

    __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
    __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

    //Load-Store MSRS at VMEXIT-VMENTRY
    __vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, VMX_SAVE_MSRS);
    __vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, VMX_LOAD_MSRS);
    __vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);

    __vmx_vmwrite(VM_EXIT_MSR_STORE_ADDR, Memory::VirtToPhy(pState->pMsrGuestExitState));
    __vmx_vmwrite(VM_EXIT_MSR_LOAD_ADDR, Memory::VirtToPhy(pState->pMsrHostState));
    __vmx_vmwrite(VM_ENTRY_MSR_LOAD_ADDR, Memory::VirtToPhy(pState->pMsrGuestEntryState));

    __vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

    GdtBase = CPU::GetGdtBase();

    FillGuestSelectorData((PVOID)GdtBase, ES, CPU::GetEs());
    FillGuestSelectorData((PVOID)GdtBase, CS, CPU::GetCs());
    FillGuestSelectorData((PVOID)GdtBase, SS, CPU::GetSs());
    FillGuestSelectorData((PVOID)GdtBase, DS, CPU::GetDs());
    FillGuestSelectorData((PVOID)GdtBase, FS, CPU::GetFs());
    FillGuestSelectorData((PVOID)GdtBase, GS, CPU::GetGs());
    FillGuestSelectorData((PVOID)GdtBase, LDTR, CPU::GetLdtr());
    FillGuestSelectorData((PVOID)GdtBase, TR, CPU::GetTr());

    __vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
    __vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));

    CpuBasedVmExecControls = CPU::AdjustControls(CPU_BASED_ACTIVATE_SECONDARY_CONTROLS
#ifdef FAKE_COUNTERS
        | CPU_BASED_ACTIVATE_MSR_BITMAP
        | CPU_BASED_ACTIVATE_IO_BITMAP
        | CPU_BASED_RDTSC_EXITING
#endif
        //| CPU_BASED_USE_TSC_OFFSETING
        , MSR_IA32_VMX_PROCBASED_CTLS);

    /*
    When exiting if the guest sets cr3 to an invalid value
    After the vm resumes execution a triple fault will be issued (unless VPID is used).
    Check out https://www.unknowncheats.me/forum/anti-cheat-bypass/572387-cr3-trashing.html.
    Working for VMWare Workstation 17.0.1 build-21139696
    */

    //CpuBasedVmExecControls &= ~CPU_BASED_CR3_LOAD_EXITING;
    //CpuBasedVmExecControls &= ~CPU_BASED_CR3_STORE_EXITING;

    __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, CpuBasedVmExecControls);

    SecondaryProcBasedVmExecControls = CPU::AdjustControls(
        CPU_BASED_CTL2_RDTSCP
        | CPU_BASED_CTL2_ENABLE_EPT
        | CPU_BASED_CTL2_ENABLE_INVPCID
        | CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS
        | CPU_BASED_CTL2_ENABLE_VPID
        , MSR_IA32_VMX_PROCBASED_CTLS2);

    __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, SecondaryProcBasedVmExecControls);

    __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, CPU::AdjustControls(
#ifndef VMX_ROOT_BREAKPOINTS
        0
        //IA32_VMX_PINBASED_CTLS_VIRTUAL_NMI_FLAG
        //| IA32_VMX_PINBASED_CTLS_NMI_EXITING_FLAG
#else
        0
#endif
        , MSR_IA32_VMX_PINBASED_CTLS));
    __vmx_vmwrite(VM_EXIT_CONTROLS, CPU::AdjustControls(VM_EXIT_IA32E_MODE, MSR_IA32_VMX_EXIT_CTLS));
    __vmx_vmwrite(VM_ENTRY_CONTROLS, CPU::AdjustControls(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));

    __vmx_vmwrite(CR3_TARGET_COUNT, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE0, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE1, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE2, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE3, 0);

    __vmx_vmwrite(CR0_GUEST_HOST_MASK, 0);
    //__vmx_vmwrite(CR0_GUEST_HOST_MASK, CPU::bCETSupported ? BIT(16) /*Write-protect*/ : 0);
    __vmx_vmwrite(CR4_GUEST_HOST_MASK, 0);

    __vmx_vmwrite(CR0_READ_SHADOW, __readcr0());
    __vmx_vmwrite(CR4_READ_SHADOW, 0);

    __vmx_vmwrite(GUEST_CR0, __readcr0());
    __vmx_vmwrite(GUEST_CR3, __readcr3());
    __vmx_vmwrite(GUEST_CR4, __readcr4());

    __vmx_vmwrite(GUEST_DR7, 0x400);

    __vmx_vmwrite(HOST_CR0, __readcr0());
    __vmx_vmwrite(HOST_CR4, __readcr4());

    /*
    Because we may be executing in an arbitrary user-mode, process as part
    of the DPC interrupt we execute in We have to save Cr3, for HOST_CR3
    */
#ifdef PROPRIETARY_PAGE_TABLES
    __vmx_vmwrite(HOST_CR3, vmm::hostCR3.Flags);
#else
    __vmx_vmwrite(HOST_CR3, __readcr3());
#endif

    __vmx_vmwrite(GUEST_GDTR_BASE, CPU::GetGdtBase());
    __vmx_vmwrite(GUEST_IDTR_BASE, CPU::GetIdtBase());
    __vmx_vmwrite(GUEST_GDTR_LIMIT, CPU::GetGdtLimit());
    __vmx_vmwrite(GUEST_IDTR_LIMIT, CPU::GetIdtLimit());

    __vmx_vmwrite(GUEST_RFLAGS, CPU::GetRflags());

    __vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    __vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

    GetSegmentDescriptor(&SegmentSelector, CPU::GetTr(), (PUCHAR)CPU::GetGdtBase());
#ifdef PROPRIETARY_GDT
    RtlCopyMemory(&pState->hostTss, (PVOID)SegmentSelector.BASE, sizeof(pState->hostTss));
#endif
    __vmx_vmwrite(HOST_TR_BASE, SegmentSelector.BASE);

    __vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
    __vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));

#ifdef PROPRIETARY_GDT
    RtlCopyMemory(pState->hostGdt, (PVOID)CPU::GetGdtBase(), PAGE_SIZE);
    const auto trIndex = SEGMENT_SELECTOR{ CPU::GetTr() }.Index;
    segment_descriptor_addr_t tss{ &pState->hostTss };
    pState->hostGdt[trIndex].BaseAddressUpper = tss.upper;
    pState->hostGdt[trIndex].BaseAddressHigh = tss.high;
    pState->hostGdt[trIndex].BaseAddressMiddle = tss.middle;
    pState->hostGdt[trIndex].BaseAddressLow = tss.low;
    __vmx_vmwrite(HOST_GDTR_BASE, (size_t)pState->hostGdt);
#else
    __vmx_vmwrite(HOST_GDTR_BASE, CPU::GetGdtBase());
#endif

#ifdef PROPRIETARY_IDT
    //Setup custom NMI handler
    pState->idt.setup();
    SetupIDTVm(pState->idt);
    pState->idt.setup_entry(EXCEPTION_VECTOR_NMI, true, __nmi_handler_vm);
    pState->idt.setup_entry(EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT, true, __gp_handler_vm);
    pState->idt.setup_entry(EXCEPTION_VECTOR_PAGE_FAULT, true, __pf_handler_vm);
    pState->idt.setup_entry(EXCEPTION_VECTOR_DIVIDE_ERROR, true, __de_handler_vm);
    __vmx_vmwrite(HOST_IDTR_BASE, (size_t)pState->idt.get_address());
#else
    __vmx_vmwrite(HOST_IDTR_BASE, CPU::GetIdtBase());
#endif
    __vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    __vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

    // Set MSR Bitmaps
    __vmx_vmwrite(MSR_BITMAP, pState->paMsrBitmap);
    __vmx_vmwrite(IO_BITMAP_A, pState->paIOBitmapA);
    __vmx_vmwrite(IO_BITMAP_B, pState->paIOBitmapB);

    // Set up EPT
    __vmx_vmwrite(EPT_POINTER_LOW, pEptState->EptPointer.Flags);

    __vmx_vmwrite(VIRTUAL_PROCESSOR_ID, CPU::GetCPUIndex() + 1);

    // setup guest rsp
    __vmx_vmwrite(GUEST_RSP, (ULONG64)GuestStack);

    // setup guest rip
    __vmx_vmwrite(GUEST_RIP, (ULONG64)AsmVmxRestoreState);

    __vmx_vmwrite(HOST_RSP, ((ULONG64)pState->pVmmStack + VMM_STACK_SIZE - 1));
    __vmx_vmwrite(HOST_RIP, (ULONG64)VmExitWrapper);

    lastReadTSC = __rdtsc();
    lastReadAPERF = __readmsr(IA32_APERF);
    lastReadMPERF = __readmsr(IA32_MPERF);

    return TRUE;
}

//https://howtohypervise.blogspot.com/2019/01/a-common-missight-in-most-hypervisors.html
void InjectPendingExceptions() {
    DWORD dwCore = CPU::GetCPUIndex(true);
    RFLAGS rFlags = { 0 };
    IA32_DEBUGCTL_REGISTER dbgCtl = { 0 };
    __vmx_vmread(GUEST_RFLAGS, &rFlags.Flags);
    __vmx_vmread(GUEST_IA32_DEBUGCTL, &dbgCtl.Flags);
    //When BTF is active a trap exception is delivered only on branches
    if (rFlags.TrapFlag && !dbgCtl.Btf) {
        DR6 dr6 = { 0 };
        __vmx_vmread(GUEST_PENDING_DBG_EXCEPTIONS, &dr6.Flags);
        dr6.SingleInstruction = 1;
        __vmx_vmwrite(GUEST_PENDING_DBG_EXCEPTIONS, dr6.Flags);

        VMX_INTERRUPTIBILITY_STATE vmxIntState = { 0 };
        __vmx_vmread(GUEST_INTERRUPTIBILITY_INFO, (size_t*)&vmxIntState.Flags);
        vmxIntState.BlockingByMovSs = false;
        vmxIntState.BlockingByNmi = false;
        vmxIntState.BlockingBySmi = false;
        __vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, vmxIntState.Flags);
    }
}

void VTx::VmExitHandler(PREGS pContext)
{
#ifdef FAKE_COUNTERS
    DWORD64 firstTSC = __rdtsc();
    INT64 TSCOffset = firstTSC - pState->lastTSC - VM_TRANSITION_CYCLES;
#endif

    DWORD32 dwCore = CPU::GetCPUIndex(true);

    PVM_STATE pState = &vmm::vGuestStates[dwCore];
    pState->bVmxRoot = TRUE;
    pState->bIncRip = TRUE;
    pState->pContext = pContext;

    ULONG ExitReason = 0;
    __vmx_vmread(VM_EXIT_REASON, (size_t*)&ExitReason);
    ExitReason &= 0xffff;

    ULONG ExitQualification = 0;
    __vmx_vmread(EXIT_QUALIFICATION, (size_t*)&ExitQualification);

    size_t guestRIP;
    __vmx_vmread(GUEST_RIP, &guestRIP);

    InjectPendingExceptions();

    bool bSetTSC = false;

    if (ExitReason != EXIT_REASON_CR_ACCESS
        && ExitReason != EXIT_REASON_EPT_VIOLATION)
        vmoperations::ExecuteOperations(pContext);
    if (!vmexit::OnVmexit(ExitReason, pContext)) {
        switch (ExitReason)
        {
            //
            // 25.1.2  Instructions That Cause VM Exits Unconditionally
            // The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
            // INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID,
            // VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
            //
        case EXIT_REASON_TRIPLE_FAULT:
        {
            DebugBreak();
            Exceptions::ApHardReset();
            break;
        }
        case EXIT_REASON_VMXON:
        {
            Exceptions::InjectException(EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT); //GPF since we pretend VMX is not enabled in BIOS with the feature controls MSR.
            pState->bIncRip = false;
            break;
        }
        case EXIT_REASON_VMXOFF:
        {
            Exceptions::InjectException(EXCEPTION_VECTOR_UNDEFINED_OPCODE);
            pState->bIncRip = false;
            break;
        }
        case EXIT_REASON_VMCLEAR:
        {
            Exceptions::InjectException(EXCEPTION_VECTOR_UNDEFINED_OPCODE);
            pState->bIncRip = false;
            break;
        }
        case EXIT_REASON_VMPTRLD:
        {
            Exceptions::InjectException(EXCEPTION_VECTOR_UNDEFINED_OPCODE);
            pState->bIncRip = false;
            break;
        }
        case EXIT_REASON_VMPTRST:
        {
            Exceptions::InjectException(EXCEPTION_VECTOR_UNDEFINED_OPCODE);
            pState->bIncRip = false;
            break;
        }
        case EXIT_REASON_VMREAD:
        {
            Exceptions::InjectException(EXCEPTION_VECTOR_UNDEFINED_OPCODE);
            pState->bIncRip = false;
            break;
        }
        case EXIT_REASON_VMRESUME:
        {
            Exceptions::InjectException(EXCEPTION_VECTOR_UNDEFINED_OPCODE);
            pState->bIncRip = false;
            break;
        }
        case EXIT_REASON_VMWRITE:
        {
            Exceptions::InjectException(EXCEPTION_VECTOR_UNDEFINED_OPCODE);
            pState->bIncRip = false;
            break;
        }
        case EXIT_REASON_VMLAUNCH:
        {
            Exceptions::InjectException(EXCEPTION_VECTOR_UNDEFINED_OPCODE);
            pState->bIncRip = false;
            break;
        }
        case EXIT_REASON_INVEPT:
        {
            Exceptions::InjectException(EXCEPTION_VECTOR_UNDEFINED_OPCODE);
            pState->bIncRip = false;
            break;
        }
        case EXIT_REASON_INVVPID:
        {
            Exceptions::InjectException(EXCEPTION_VECTOR_UNDEFINED_OPCODE);
            pState->bIncRip = false;
            break;
        }
        case EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED:
        {
            __vmx_vmwrite(GUEST_PREEMPTION_TIMER_VALUE, MAXUINT64);
            pState->bIncRip = false;
            break;
        }
        case EXIT_REASON_PENDING_VIRT_NMI:
        {
            Exceptions::InjectException(EXCEPTION_VECTOR_NMI);

            // turn off NMI window exiting since we handled the NMI...
            IA32_VMX_PROCBASED_CTLS_REGISTER procbased_ctls;
            __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &procbased_ctls.Flags);

            procbased_ctls.NmiWindowExiting = false;
            __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, procbased_ctls.Flags);

            pState->bIncRip = false;
            break;
        }
        case EXIT_REASON_EXCEPTION_NMI:
        {
            IA32_VMX_PROCBASED_CTLS_REGISTER procbased_ctls;
            __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &procbased_ctls.Flags);

            procbased_ctls.NmiWindowExiting = false;
            __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, procbased_ctls.Flags);
            pState->bIncRip = false;
            break;
        }
        case EXIT_REASON_CPUID:
        {
#ifdef LOG_CPUID
            vmLogInfo.info = pContext->rax;
            logging::SendLog(vmLogInfo);
#endif
            VMExitHandlers::HandleCPUID(pContext);

            //Avoid CPUID taking less than ~80 cycles to execute
#ifdef FAKE_COUNTERS
            pState->apparentTSC += random::NextHardware(0x10, 0x20);
#endif
            break;
        }
        case EXIT_REASON_VMCALL:
        {
            if (!vmcall::ValidateCommunicationKey(pContext->rax)) {
                Exceptions::InjectException(EXCEPTION_VECTOR_UNDEFINED_OPCODE);
                pState->bIncRip = false;
                break;
            }

            pContext->rax = vmcall::HandleVmcall(pContext->rcx, pContext->rdx, pContext->r8, pContext->r9);
            break;
        }
        case EXIT_REASON_CR_ACCESS:
        {
            PMOV_CR_QUALIFICATION data = (PMOV_CR_QUALIFICATION)&ExitQualification;
            if (VMExitHandlers::HandleCR(pContext)) {
                Exceptions::InjectException(EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT);
                pState->bIncRip = false;
            }
            break;
        }
        case EXIT_REASON_RDTSC:
        {
            bSetTSC = true;
            break;
        }
        case EXIT_REASON_RDTSCP:
        {
            pContext->rcx = dwCore;
            bSetTSC = true;
            break;
        }
        case EXIT_REASON_MSR_READ:
        {
#ifdef FAKE_COUNTERS
            if (pContext->rcx == IA32_TIME_STAMP_COUNTER
                || pContext->rcx == IA32_APERF
                || pContext->rcx == IA32_MPERF)
            {
                bSetTSC = true;
                break;
            }
#endif

            if (VMExitHandlers::HandleRDMSR(pContext)) {
                pState->bIncRip = false;
            }
            break;
        }
        case EXIT_REASON_MSR_WRITE:
        {
            if (VMExitHandlers::HandleWRMSR(pContext)) {
                pState->bIncRip = false;
            }
            break;
        }
        case EXIT_REASON_XSETBV:
        {
            if (VMExitHandlers::HandleXSetBv(pContext)) {
                Exceptions::InjectException(EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT);
                pState->bIncRip = false;
            }
            break;
        }
        case EXIT_REASON_EPT_VIOLATION:
        {
            size_t GuestPhysicalAddr = 0;
            __vmx_vmread(GUEST_PHYSICAL_ADDRESS, &GuestPhysicalAddr);
            pState->bIncRip = EPT::HandleEptViolation(ExitQualification, GuestPhysicalAddr);
            break;
        }
        case EXIT_REASON_EPT_MISCONFIG:
        {
            size_t GuestPhysicalAddr = 0;
            __vmx_vmread(GUEST_PHYSICAL_ADDRESS, &GuestPhysicalAddr);

            DebugBreak();

            Exceptions::InjectException(EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT, MAXDWORD32);
            pState->bIncRip = false;

            __vmx_vmwrite(GUEST_RIP, (ULONG64)KeBugCheckEx);
            break;
        }
        case EXIT_REASON_INVALID_GUEST_STATE:
        {
            Checks::CheckGuestVmcsFieldsForVmEntry();
            break;
        }
        case EXIT_REASON_INVPCID:
        {
            pState->bIncRip = VMExitHandlers::HandleInvpcid(pContext);
            break;
        }
        case EXIT_REASON_INVD:
        {
            __wbinvd();
            pState->bIncRip = true;
            break;
        }
        default:
        {
            DebugBreak();
            break;
        }
        }
    }

    //if (vmm::IsTimeoutExpired()) {
    //    pContext->rcx = vmm::tscDeltaTimeout;
    //    pContext->rdx = vmm::vGuestStates[dwCore].lastCr3Tsc;
    //    pContext->r8 = (__rdtsc() - vmm::vGuestStates[dwCore].lastCr3Tsc);
    //    Exceptions::InjectException(EXCEPTION_VECTOR_PAGE_FAULT, MAXULONG32);
    //}

    if (!pState->VmxoffState.IsVmxoffExecuted) {
        if (pState->bIncRip) {
            guestRIP = MoveRip();
        }

#ifdef FAKE_COUNTERS
        TSCOffset = TSCOffset > 0 ?
            TSCOffset / 10                  //Divide to make counter drift between cores negligible
            : random::NextHardware(1, 20);  //Fallback value when TSCOffset is negative (don't know why it happens yet)

        pState->apparentTSC += TSCOffset;

        if (bSetTSC) {
            MSR msr = { 0 };
            //If the TSC read comes from system address space return the real TSC
            if (CPU::IsNtoskrnlAddress(guestRIP)   //Ntsoskrnl
                || CPU::IsNtdllAddress(guestRIP)   //Usermode system modules
                || !CPU::ntdllBase   //Return true TSC until we have ntdll base to avoid system freeze at first start
                ) {
                msr.Content = __rdtsc();
            }
            //Otherwise return a faked TSC
            else {
                if (pState->apparentTSC < lastReadTSC)
                    pState->apparentTSC = lastReadTSC;
                msr.Content = pState->apparentTSC;
                lastReadTSC = pState->apparentTSC;
            }
            pContext->rax = msr.Low;
            pContext->rdx = msr.High;
        }

        pState->lastTSC = __rdtsc();
#endif
    }

    pState->bVmxRoot = FALSE;
}

PPML4T VTx::GetHostPml4t() {
    return paging::GetPML4Base(vmm::hostCR3);
}

void VTx::VmResumeExec()
{
    ULONG64 ErrorCode;

    __vmx_vmresume();

    // if VMRESUME succeeds will never be here !

    ErrorCode = 0;
    __vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);

    DbgMsg("[VMX] VMRESUME Error : 0x%llx", ErrorCode);
#ifndef VMX_ROOT_BREAKPOINTS
    KeBugCheck(0xaaaabbbb);
#endif 
}

ULONG64 VTx::MoveRip(size_t szInst)
{
    PVOID ResumeRIP = NULL;
    size_t CurrentRIP = NULL;

    __vmx_vmread(GUEST_RIP, &CurrentRIP);
    //DbgMsg("[VMX] Moving RIP from current instruction: 0x%llx", CurrentRIP);
    if (szInst == 0) {
        __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &szInst);
        //DbgMsg("[VMX] Moving RIP by instruction length: 0x%llx", szInst);
    }

    ResumeRIP = (PCHAR)CurrentRIP + szInst;

    __vmx_vmwrite(GUEST_RIP, (ULONG64)ResumeRIP);
    return (ULONG64)ResumeRIP;
}

bool VTx::AllocVmxonRegion(PVM_STATE pState)
{
    DbgMsg("[MEM] Allocating VMXON Region...");

    int VMXONSize = 2 * VMXON_SIZE;
    BYTE* Buffer = (BYTE*)cpp::kMallocContinuous(VMXONSize + ALIGNMENT_PAGE_SIZE); // Allocating a 4-KByte Contigous Memory region

    PHYSICAL_ADDRESS Highest = { 0 };
    Highest.QuadPart = ~0;

    if (Buffer == NULL)
    {
        DbgMsg("[MEM] Error : Couldn't Allocate Buffer for VMXON Region.");
        return FALSE; // ntStatus = STATUS_INSUFFICIENT_RESOURCES;
    }
    UINT64 PhysicalBuffer = (UINT64)Memory::VirtToPhy(Buffer);

    // zero-out memory
    RtlZeroMemory(Buffer, VMXONSize + ALIGNMENT_PAGE_SIZE);
    UINT64 AlignedPhysicalBuffer = (ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1);

    UINT64 AlignedVirtualBuffer = (ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1);

    // get IA32_VMX_BASIC_MSR RevisionId
    IA32_VMX_BASIC_MSR basic = { 0 };
    basic.All = __readmsr(MSR_IA32_VMX_BASIC);

    // Changing Revision Identifier
    *(UINT64*)AlignedVirtualBuffer = basic.Fields.RevisionIdentifier;
    pState->pVmxonRegion = AlignedPhysicalBuffer;

    pState->VmxoffState.IsVmxoffExecuted = false;
    return TRUE;
}

bool VTx::AllocVmcsRegion(PVM_STATE pState)
{
    DbgMsg("[MEM] Allocating VMCS Region...");

    int VMCSSize = 2 * VMCS_SIZE;
    BYTE* Buffer = (BYTE*)cpp::kMallocContinuous(VMCSSize + ALIGNMENT_PAGE_SIZE); // Allocating a 4-KByte Contigous Memory region

    PHYSICAL_ADDRESS Highest = { 0 };
    Highest.QuadPart = ~0;

    UINT64 PhysicalBuffer = (UINT64)Memory::VirtToPhy(Buffer);
    if (Buffer == NULL)
    {
        DbgMsg("Error : Couldn't Allocate Buffer for VMCS Region.");
        return FALSE;
    }
    // zero-out memory
    RtlZeroMemory(Buffer, VMCSSize + ALIGNMENT_PAGE_SIZE);
    UINT64 AlignedPhysicalBuffer = (ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1);

    UINT64 AlignedVirtualBuffer = (ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1);

    // get IA32_VMX_BASIC_MSR RevisionId
    IA32_VMX_BASIC_MSR basic = { 0 };
    basic.All = __readmsr(MSR_IA32_VMX_BASIC);

    // Changing Revision Identifier
    *(UINT64*)AlignedVirtualBuffer = basic.Fields.RevisionIdentifier;
    pState->pVmcsRegion = AlignedPhysicalBuffer;

    return TRUE;
}