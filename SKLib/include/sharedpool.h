#pragma once

#pragma warning (disable:4244)

#include "cpp.h"
#include "ListEx.h"
#include "RandEx.h"
#include "StringEx.h"
#include "acl.h"

#define INVALID_POOL_HANDLE ~0ul;

typedef DWORD64 POOL_HANDLE;
typedef POOL_HANDLE* PPOOL_HANDLE;

typedef struct _SHARED_POOL {
	size_t baseAddr;
	size_t size;

	bool bMapped;

	bool operator==(_SHARED_POOL rhs);
	bool operator!=(_SHARED_POOL rhs);
} SHARED_POOL, *PSHARED_POOL;

enum POOL_REQUEST {
	REQUEST_NONE,
	REQUEST_VTX_START,
	REQUEST_VTX_STOP,
	REQUEST_DRIVER_STOP
};

enum POOL_RESULT {
	RESULT_AWAIT,
	RESULT_OK,
	RESULT_ERROR
};

typedef struct _COMMUNICATION_POOL {
	Spinlock lock;
	POOL_REQUEST request;
	POOL_RESULT result;
	PVOID pParam;
	size_t szParam;
} COMMUNICATION_POOL, * PCOMMUNICATION_POOL;

#ifdef _KERNEL_MODE

namespace sharedpool {
	extern list<SHARED_POOL>* vPools;
	extern bool bInit;
	
	bool Init();
	bool Dispose();

	PVOID Create(size_t size, OUT PPOOL_HANDLE pHandle = nullptr);
	void Delete(POOL_HANDLE poolHandle);

	PVOID MapUserData(PVOID pUsermodeBuffer, DWORD32 procId);

	PVOID PoolBase(POOL_HANDLE hPool);
}

#endif