#include "VTxException.h"

void InjectInterrupt(INTERRUPTION_TYPE intType, EXCEPTION_VECTOR exVec, bool bDeliverCode, ULONG32 dwErCode)
{
	INTERRUPT_INFO intInfo = { 0 };

	intInfo.Valid = true;
	intInfo.InterruptType = intType;
	intInfo.Vector = exVec;
	intInfo.DeliverCode = bDeliverCode;
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, intInfo.Flags);

	if (bDeliverCode)
		__vmx_vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, dwErCode);
}

bool VTx::Exceptions::InjectException(EXCEPTION_VECTOR ex, DWORD32 eCode)
{
	size_t ExitInstrLength;
	INTERRUPTION_TYPE intType = HardwareException;
	bool bDeliverCode = false;
	ULONG32 dwErCode = eCode;

	switch (ex) {
	case EXCEPTION_VECTOR_DEBUG_BREAKPOINT:
	{
		intType = SoftwareException;
		break;
	}
	case EXCEPTION_VECTOR_NMI:
	{
		intType = NonMaskableInterrupt;
		break;
	}
	case EXCEPTION_VECTOR_BREAKPOINT:
	{
		intType = SoftwareException;
		break;
	}
	case EXCEPTION_VECTOR_OVERFLOW:
	{
		intType = SoftwareException;
		break;
	}
	case EXCEPTION_VECTOR_DOUBLE_FAULT:
	{
		bDeliverCode = true;
		break;
	}
	case EXCEPTION_VECTOR_ALIGNMENT_CHECK:
	{
		bDeliverCode = true;
		break;
	}
	}

	if (ex >= EXCEPTION_VECTOR_INVALID_TASK_SEGMENT_SELECTOR && ex <= EXCEPTION_VECTOR_PAGE_FAULT) {
		bDeliverCode = true;
	}

	InjectInterrupt(intType, ex, bDeliverCode, dwErCode);

	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstrLength);
	__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, ExitInstrLength);
	return true;
}

void VTx::Exceptions::ApHardReset()
{
	union __reset_control_register reset_register;
	reset_register.flags = __inbyte(RST_CNT_IO_PORT);

	//
	// Reset CPU bit set, determines type of reset based on:
	//        - System Reset = 0; soft reset by activating INIT# for 16 PCI clocks.
	//        - System Reset = 1; then hard reset by activating PLTRST# and SUS_STAT#.
	//        - System Reset = 1; main power well reset.
	//
	reset_register.reset_cpu = 1;
	reset_register.system_reset = 1;

	__outbyte(RST_CNT_IO_PORT, reset_register.flags);
}