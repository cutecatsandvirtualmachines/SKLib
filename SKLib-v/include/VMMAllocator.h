#pragma once

#include "cpp.h"

namespace vmm {
	BOOLEAN InitAllocator();

	PVOID malloc(SIZE_T sz);
	VOID free(PVOID pMem);
}