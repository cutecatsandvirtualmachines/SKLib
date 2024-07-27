#pragma once

#ifdef _KERNEL_MODE

#define ZYDIS_DISABLE_FORMATTER

#include <Zydis/Zydis.h>

#include "cpp.h"

namespace disassembler {
	size_t GetInstrBoundaryLen(PVOID pBase, size_t targetLen);
}

#endif