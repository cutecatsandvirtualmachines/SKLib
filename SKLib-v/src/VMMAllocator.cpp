#include "VMMAllocator.h"

PVOID pPreallocatedBuffer = nullptr;
constexpr SIZE_T szBuffer = 0x800000; //8MB
SIZE_T szAllocated = 0;

BOOLEAN vmm::InitAllocator()
{
	pPreallocatedBuffer = cpp::kMallocZero(szBuffer, PAGE_READWRITE);
	if (!pPreallocatedBuffer)
		return FALSE;
	return TRUE;
}

PVOID vmm::malloc(SIZE_T sz)
{
	PVOID retValue = 0;
	if (szAllocated + sz <= szBuffer) {
		retValue = (PVOID)((SIZE_T)pPreallocatedBuffer + szAllocated + sz);
	}
	else {
		return nullptr;
	}

	szAllocated += sz;
	return retValue;
}

VOID vmm::free(PVOID pMem)
{
	return VOID();
}
