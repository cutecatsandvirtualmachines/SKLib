#pragma once

#pragma warning (disable:4353)

#ifdef _KERNEL_MODE
#include <ntdef.h>
#endif

#include "VMMDef.h"
#include "ia32.h"
#include "cpp.h"
#include "cpu.h"
#include "MemoryEx.h"
#include "ListEx.h"
#include "VectorEx.h"
#include "spinlock.h"
#include "IDT.h"
#include "paging.h"
#include "disassembler.h"
#include "VTxException.h"
#include "PE.h"
#include "VMMAllocator.h"
