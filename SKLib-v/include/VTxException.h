#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#endif

#include <intrin.h>

#include "cpp.h"
#include "cpu.h"
#include "VMMDef.h"

#define RST_CNT_IO_PORT                        (USHORT)0xCF9

#define DUMP_SECTION_NAME "SKLibDump"

#ifdef _KERNEL_MODE
namespace VTx {
	namespace Exceptions {
		extern "C" bool InjectException(EXCEPTION_VECTOR ex, DWORD32 eCode = 0);
		void ApHardReset();
	}
}
#endif