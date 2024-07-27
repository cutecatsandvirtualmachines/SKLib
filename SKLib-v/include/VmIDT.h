#pragma once
#include <IDT.h>

#ifdef _KERNEL_MODE

extern "C" void generic_interrupt_handler_vm();
extern "C" void generic_interrupt_handler_ecode_vm();
extern "C" void __nmi_handler_vm();
extern "C" void __gp_handler_vm();
extern "C" void __pf_handler_vm();
extern "C" void __de_handler_vm();

extern "C" void seh_handler_ecode_vm(PIDT_REGS_ECODE regs);
extern "C" void seh_handler_vm(PIDT_REGS regs);

extern "C" void NmiHandler();

void SetupIDTVm(IDT& idt);

#endif