#include "collector.h"

list<MemoryAddress>* Collector::myGarbage = nullptr;
Spinlock garbageLock;

void Collector::Init()
{
	myGarbage = (list<MemoryAddress>*)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*myGarbage), NULL);
	myGarbage->Init(false);
}

void Collector::Add(void* p, cpp::MemoryType type, size_t sz, PMDL pMdl)
{
	MemoryAddress mAddy = {
		type,
		p,
		sz,
		pMdl
	};

	garbageLock.Lock();
	myGarbage->Append(mAddy);
	garbageLock.Unlock();
}

void Collector::Remove(void* p)
{
	auto fnDeleteWhere = [p](MemoryAddress mObj) {
		return mObj.pMemory == p;
	};

	garbageLock.Lock();
	myGarbage->RemoveWhere(fnDeleteWhere);
	garbageLock.Unlock();
}

void Collector::Remove(MemoryAddress& pMem) {
	garbageLock.Lock();
	myGarbage->Remove(pMem);
	garbageLock.Unlock();
}

void Collector::Clean()
{
	DbgMsg("[COLLECTOR] Number of leaked memory pools: %d", myGarbage->Length());
	//Dispose of pointers stored inside node's objects
	node<MemoryAddress>* curNode = myGarbage->FirstNode();
	for (int i = 0; i < myGarbage->Length(); i++) {
		auto nextNode = curNode->fLink;
		FreeMemory(curNode->obj);
		curNode = nextNode;
	}
	DbgMsg("[COLLECTOR] Disposed of leaked memory");

	myGarbage->Dispose();
	DbgMsg("[COLLECTOR] Disposed of collector nodes");
}

void Collector::FreeMemory(MemoryAddress& memAddr) {
	switch (memAddr.type) {
	case cpp::NonPaged:
		MmUnmapLockedPages(memAddr.pMemory, memAddr.pMdl);
		MmFreePagesFromMdl(memAddr.pMdl);
		ExFreePool(memAddr.pMdl);
		break;
	case cpp::NonCached:
		MmFreeNonCachedMemory(memAddr.pMemory, memAddr.szMemory);
		break;
	case cpp::Continuous:
		MmFreeContiguousMemory(memAddr.pMemory);
		break;
	case cpp::Pooled:
		ExFreePool(memAddr.pMemory);
		break;
	}
}

void Collector::Dispose()
{
	if (!myGarbage)
		return;

	Clean();
	ExFreePool(myGarbage);
}

MemoryAddress Collector::GetMemoryInfo(void* pMemory)
{
	Lock();
	node<MemoryAddress>* curNode = myGarbage->LastNode();
	for (int i = myGarbage->Length() - 1; i >= 0; i--) {
		auto nextNode = curNode->bLink;
		if (pMemory == curNode->obj.pMemory) {
			Unlock();
			return curNode->obj;
		}
		curNode = nextNode;
	}
	Unlock();
	return MemoryAddress();
}

void Collector::Lock()
{
	garbageLock.Lock();
}

void Collector::Unlock()
{
	garbageLock.Unlock();
}

void Collector::Clean(void* pMemory)
{
	//Dispose of pointers stored inside node's objects
	bool bFound = false;

	for(int i = myGarbage->Length() - 1; i >= 0; i--) {
		auto curNode = myGarbage->at(i);
		if (curNode.pMemory == pMemory) {
			bFound = true;
			//Dispose of nodes and list object
			FreeMemory(curNode);
			break;
		}
	}

	// Remove from linked list
	Remove(pMemory);

	if (!bFound) {
		DbgMsg("[COLLECTOR] Warning: %p not found in garbage!", pMemory);
		return;
	}
}
