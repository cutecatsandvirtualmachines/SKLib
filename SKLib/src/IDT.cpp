#include "IDT.h"
#include <MemoryEx.h>

IDTGateDescriptor64* pIDT = nullptr;

void IDTGateDescriptor64::setup(void* handler, bool present, DWORD32 selector, DWORD32 type)
{
    const auto handler_address = uintptr_t(handler);
    
    bits.offset0_15 = bitmap::bits<DWORD32>(handler_address, 0, 15);
    bits.offset16_31 = bitmap::bits<DWORD32>(handler_address, 16, 31);
    bits.offset32_63 = bitmap::bits<DWORD32>(handler_address, 32, 63);
    bits.cs_selector = selector;
    bits.type = type;
    bits.present = present;
    bits.must_be_zero1 = 0;
    bits.ist = 0;
    bits.dpl = 0;
    bits.reserved = 0;
}

void IDTGateDescriptor64::setup(void* handler)
{
    const auto handler_address = uintptr_t(handler);

    bits.offset0_15 = bitmap::bits<DWORD32>(handler_address, 0, 15);
    bits.offset16_31 = bitmap::bits<DWORD32>(handler_address, 16, 31);
    bits.offset32_63 = bitmap::bits<DWORD32>(handler_address, 32, 63);
}

DWORD64 IDTGateDescriptor64::getAddress()
{
    return (DWORD64)bits.offset32_63 << 32 | (DWORD64)bits.offset16_31 << 16 | (DWORD64)bits.offset0_15;
}

void IDT::setup(void(*handler)(), void (*handler_ecode)())
{
    setup_entry(0, true, handler);
    setup_entry(1, true, handler);
    setup_entry(3, true, handler);
    setup_entry(4, true, handler);
    setup_entry(5, true, handler);
    setup_entry(6, true, handler);
    setup_entry(7, true, handler);
    setup_entry(8, true, handler_ecode);
    setup_entry(9, true, handler);
    setup_entry(10, true, handler_ecode);
    setup_entry(11, true, handler_ecode);
    setup_entry(12, true, handler_ecode);
    setup_entry(13, true, handler_ecode);
    setup_entry(14, true, handler_ecode);
    setup_entry(15, false);
    setup_entry(16, true, handler);
    setup_entry(17, true, handler_ecode);
    setup_entry(18, true, handler);
    setup_entry(19, true, handler);
    setup_entry(20, true, handler);
    setup_entry(21, false);
    setup_entry(22, false);
    setup_entry(23, false);
    setup_entry(24, false);
    setup_entry(25, false);
    setup_entry(26, false);
    setup_entry(27, false);
    setup_entry(28, false);
    setup_entry(29, false);
    setup_entry(30, false);
    setup_entry(31, false);
}

void IDT::setup()
{
    RtlZeroMemory(descriptor, sizeof(descriptor));
    setup(generic_interrupt_handler, generic_interrupt_handler_ecode);
}

void IDT::setup(IDTGateDescriptor64* pOrigIDT)
{
    pIDT = pOrigIDT;
    RtlCopyMemory(descriptor, pOrigIDT, sizeof(descriptor));
}

void IDT::save()
{
    Memory::WriteProtected(pIDT, descriptor, 20 * sizeof(IDTGateDescriptor64));
}

/*
* IMPORTANT:
* Exception handling will work only for the current stack frame, which means
* that if an exception happens inside a function being called
* from a try block, then that won't be catchable
*/
void seh_handler_ecode(PIDT_REGS_ECODE regs)
{
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
}

void seh_handler(PIDT_REGS regs)
{
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
}
