#pragma once

#include "ListEx.h"
#include "MemoryEx.h"

#ifdef _KERNEL_MODE

struct MemoryAddress {
	cpp::MemoryType type;
	PVOID pMemory;
	size_t szMemory;	// If 0 it means the size is not important for this type of memory 
	PMDL pMdl;			// If 0 no MDL is associated with the memory type

	bool operator==(MemoryAddress& mAddress) {
		return this->pMemory == mAddress.pMemory;
	}
	bool operator==(PVOID pMem) {
		return this->pMemory == pMem;
	}
	bool operator!=(MemoryAddress& mAddress) {
		return !(mAddress== this->pMemory);
	}
	bool operator!=(PVOID pMem) {
		return !(this == pMem);
	}
};

//Implements shit for disposing of unused memory
struct Collector {
private:
	static list<MemoryAddress>* myGarbage;
public:
	static void Init();
	static void Add(void* p, cpp::MemoryType type, size_t sz = 0, PMDL pMdl = 0);
	static void Remove(void* p);
	static void Remove(MemoryAddress& pMem);
	static void Clean();
	static void Clean(void* pMemory);
	static void FreeMemory(MemoryAddress& memAddr);
	static void Dispose();
	static MemoryAddress GetMemoryInfo(void* pMemory);
	static void Lock();
	static void Unlock();
};
#endif