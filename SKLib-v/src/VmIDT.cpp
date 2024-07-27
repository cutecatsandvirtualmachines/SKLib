#include "VmIDT.h"

#include <VMMDef.h>
#include <VTxException.h>

/*
* IMPORTANT:
* Exception handling will work only for the current stack frame, which means
* that if an exception happens inside a function being called
* from a try block, then that won't be catchable
*/
void seh_handler_ecode_vm(PIDT_REGS_ECODE regs)
{
    vmm::vGuestStates[CPU::GetCPUIndex(true)].lastErrorCode = regs->error_code;
    const auto rva = regs->rip - reinterpret_cast<DWORD64>(winternl::pDriverBase);
    const auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS64*>(
        reinterpret_cast<DWORD64>(winternl::pDriverBase) +
        reinterpret_cast<IMAGE_DOS_HEADER*>(winternl::pDriverBase)->e_lfanew);

    const auto exception =
        &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    const auto functions =
        reinterpret_cast<RUNTIME_FUNCTION*>(
            reinterpret_cast<DWORD64>(winternl::pDriverBase) + exception->VirtualAddress);

    for (auto idx = 0; idx < exception->Size / sizeof(RUNTIME_FUNCTION); ++idx)
    {
        const auto function = &functions[idx];
        if (!(rva >= function->BeginAddress && rva < function->EndAddress))
            continue;

        const auto unwind_info =
            reinterpret_cast<UNWIND_INFO*>(
                reinterpret_cast<DWORD64>(winternl::pDriverBase) + function->UnwindData);

        if (!(unwind_info->Flags & UNW_FLAG_EHANDLER))
            continue;

        const auto scope_table =
            reinterpret_cast<SCOPE_TABLE*>(
                reinterpret_cast<DWORD64>(&unwind_info->UnwindCode[
                    (unwind_info->CountOfCodes + 1) & ~1]) + sizeof(DWORD32));

        for (DWORD32 entry = 0; entry < scope_table->Count; ++entry)
        {
            const auto scope_record = &scope_table->ScopeRecords[entry];
            if (rva >= scope_record->BeginAddress && rva < scope_record->EndAddress)
            {
                regs->rip = reinterpret_cast<DWORD64>(winternl::pDriverBase) + scope_record->JumpTarget;
                return;
            }
        }
    }
    if (CPU::bIntelCPU) {
        VTx::Exceptions::InjectException(EXCEPTION_VECTOR_SIMD_FLOATING_POINT_NUMERIC_ERROR, regs->error_code);
        __vmx_vmwrite(GUEST_RIP, regs->rip);
        __vmx_vmresume();
    }
    else {
        SVM::InjectEvent(vmm::vGuestStates[CPU::GetCPUIndex(true)].SvmState, SVM::e_Exception, InterruptVector::SimdFloatingPointException, 0, false);
        Seg::DescriptorTableRegister<Seg::Mode::longMode> gdt;
        CPU::GetGdt(&gdt);

        vmm::vGuestStates[CPU::GetCPUIndex(true)].SvmState->GuestState.vg_rip = regs->rip;
        vmm::vGuestStates[CPU::GetCPUIndex(true)].SvmState->GuestVmcb->StateSaveArea.Rip = regs->rip;
        svm_enter_guest(vmm::vGuestStates[CPU::GetCPUIndex(true)].SvmState->GuestVmcbPhysicalAddress, &vmm::vGuestStates[CPU::GetCPUIndex(true)].SvmState->GuestState, &gdt);
    }
}


void NmiHandler() {
    if (CPU::bIntelCPU) {
        VTx::Exceptions::InjectException(EXCEPTION_VECTOR_NMI);
    }
    else {
        SVM::InjectNMI(vmm::vGuestStates[CPU::GetCPUIndex(true)].SvmState);
    }
}

void SetupIDTVm(IDT& idt)
{
    idt.setup(generic_interrupt_handler_vm, generic_interrupt_handler_ecode_vm);
}

void seh_handler_vm(PIDT_REGS regs)
{
    vmm::vGuestStates[CPU::GetCPUIndex(true)].lastErrorCode = 0;
    const auto rva = regs->rip - reinterpret_cast<DWORD64>(winternl::pDriverBase);
    const auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS64*>(
        reinterpret_cast<DWORD64>(winternl::pDriverBase) +
        reinterpret_cast<IMAGE_DOS_HEADER*>(winternl::pDriverBase)->e_lfanew);

    const auto exception =
        &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    const auto functions =
        reinterpret_cast<RUNTIME_FUNCTION*>(
            reinterpret_cast<DWORD64>(winternl::pDriverBase) + exception->VirtualAddress);

    for (auto idx = 0; idx < exception->Size / sizeof(RUNTIME_FUNCTION); ++idx)
    {
        const auto function = &functions[idx];
        if (!(rva >= function->BeginAddress && rva < function->EndAddress))
            continue;

        const auto unwind_info =
            reinterpret_cast<UNWIND_INFO*>(
                reinterpret_cast<DWORD64>(winternl::pDriverBase) + function->UnwindData);

        if (!(unwind_info->Flags & UNW_FLAG_EHANDLER))
            continue;

        const auto scope_table =
            reinterpret_cast<SCOPE_TABLE*>(
                reinterpret_cast<DWORD64>(&unwind_info->UnwindCode[
                    (unwind_info->CountOfCodes + 1) & ~1]) + sizeof(DWORD32));

        for (DWORD32 entry = 0; entry < scope_table->Count; ++entry)
        {
            const auto scope_record = &scope_table->ScopeRecords[entry];
            if (rva >= scope_record->BeginAddress && rva < scope_record->EndAddress)
            {
                regs->rip = reinterpret_cast<DWORD64>(winternl::pDriverBase) + scope_record->JumpTarget;
                return;
            }
        }
    }

    if (CPU::bIntelCPU) {
        VTx::Exceptions::InjectException(EXCEPTION_VECTOR_DIVIDE_ERROR, 0);
        __vmx_vmwrite(GUEST_RIP, regs->rip);
        __vmx_vmresume();
    }
    else {
        SVM::InjectEvent(vmm::vGuestStates[CPU::GetCPUIndex(true)].SvmState, SVM::e_Exception, InterruptVector::DivideError, 0, false);
        Seg::DescriptorTableRegister<Seg::Mode::longMode> gdt;
        CPU::GetGdt(&gdt);

        vmm::vGuestStates[CPU::GetCPUIndex(true)].SvmState->GuestState.vg_rip = regs->rip;
        vmm::vGuestStates[CPU::GetCPUIndex(true)].SvmState->GuestVmcb->StateSaveArea.Rip = regs->rip;
        svm_enter_guest(vmm::vGuestStates[CPU::GetCPUIndex(true)].SvmState->GuestVmcbPhysicalAddress, &vmm::vGuestStates[CPU::GetCPUIndex(true)].SvmState->GuestState, &gdt);
    }
}
