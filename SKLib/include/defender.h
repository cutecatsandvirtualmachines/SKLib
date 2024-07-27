#pragma once

#ifdef _KERNEL_MODE
#include "winternlex.h"
#include "MemoryEx.h"

namespace defender {
	bool CleanFilterList(string driverName);
}
#endif