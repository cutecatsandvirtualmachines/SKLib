#include "sharedpool.h"

#include "MemoryEx.h"
#include "paging.h"

list<SHARED_POOL>* sharedpool::vPools = nullptr;
bool sharedpool::bInit = false;

bool sharedpool::Init()
{
	if (bInit) {
		DbgMsg("[SHAREDPOOL] Warning: namespace was already initialized!");
		return true;
	}
	bInit = true;

	sharedpool::vPools = (list<SHARED_POOL>*)cpp::kMalloc(sizeof(*sharedpool::vPools), PAGE_READWRITE);
	sharedpool::vPools->Init();

	return true;
}

bool sharedpool::Dispose()
{
	bInit = false;

	for(SHARED_POOL poolData : (*sharedpool::vPools))
	{
		cpp::kFree((PVOID)poolData.baseAddr);
	}

	sharedpool::vPools->Dispose();
	cpp::kFree(sharedpool::vPools);
	return true;
}

PVOID sharedpool::Create(size_t size, OUT PPOOL_HANDLE pHandle)
{
	if (!bInit) {
		DbgMsg("[SHAREDPOOL] Error: sharedpool not initialized");
		return 0;
	}
	
	PVOID pBase = cpp::kMalloc(size, PAGE_READWRITE);
	SHARED_POOL sharedPool;
	sharedPool.baseAddr = (size_t)pBase;
	sharedPool.size = size;
	sharedPool.bMapped = true;

	POOL_HANDLE hPool = vPools->Append(sharedPool);
	if (pHandle)
		*pHandle = hPool;

	DbgMsg("[SHAREDPOOL] Created and mapped section: %p", pBase);
	return pBase;
}

void sharedpool::Delete(POOL_HANDLE poolHandle)
{
	if (!bInit) {
		DbgMsg("[SHAREDPOOL] Error: sharedpool not initialized");
		return;
	}

	SHARED_POOL& sharedPool = vPools->at(poolHandle);
	if (!sharedPool.bMapped) {
		DbgMsg("[SHAREDPOOL] Warning: cannot unmap already unmapped view of section!");
		return;
	}

	cpp::kFree((PVOID)sharedPool.baseAddr);
	vPools->RemoveAt(poolHandle);
}

PVOID sharedpool::MapUserData(PVOID pUsermodeBuffer, DWORD32 procId) {
	PVOID pBase = nullptr;
	if (!procId) {
		return nullptr;
	}

	DWORD64 guestPa = 0;
	while (!guestPa) {
		PRKAPC_STATE pRkapcState = (PRKAPC_STATE)Memory::AttachToProcessId(procId);
		if (!pRkapcState) {
			return nullptr;
		}

		guestPa = Memory::VirtToPhy(pUsermodeBuffer);

		Memory::DetachFromProcess(pRkapcState);
	}

	LARGE_INTEGER pa = { 0 };
	pa.QuadPart = guestPa;
	pBase = MmMapIoSpace(pa, sizeof(USERMODE_INFO), MmCached);
	return pBase;
}

PVOID sharedpool::PoolBase(POOL_HANDLE hPool)
{
	SHARED_POOL& sharedPool = vPools->at(hPool);
	return (PVOID)sharedPool.baseAddr;
}

bool _SHARED_POOL::operator==(_SHARED_POOL rhs)
{
	return !memcmp(this, &rhs, sizeof(rhs));
}

bool _SHARED_POOL::operator!=(_SHARED_POOL rhs)
{
	return !(*this == rhs);
}
