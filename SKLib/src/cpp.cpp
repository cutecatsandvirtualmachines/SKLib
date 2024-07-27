#include "cpp.h"
#include "collector.h"

void* operator new(size_t /* ignored */, void* where) { return where; };

void* cpp::uMalloc(size_t size, ULONG protect)
{
    LARGE_INTEGER LowAddress, HighAddress;
    LowAddress.QuadPart = 0;
    HighAddress.QuadPart = MAXULONG64;

    PMDL pMdl = MmAllocatePagesForMdl(LowAddress, HighAddress, LowAddress, size);
    if (pMdl == nullptr) {
        DbgMsg("Failed to allocate %d bytes", (int)size);
        return nullptr;
    }
    if (pMdl->ByteCount < size) {
        DbgMsg("Not enough memory to allocate %d bytes", (int)size);
        MmFreePagesFromMdl(pMdl);
        ExFreePool(pMdl);
        return nullptr;
    }
    void* p = MmMapLockedPagesSpecifyCache(pMdl, UserMode, MEMORY_CACHING_TYPE::MmCached, NULL, FALSE, HighPagePriority);
    NTSTATUS ntStatus = MmProtectMdlSystemAddress(pMdl, protect);
    if (!NT_SUCCESS(ntStatus)) {
        DbgMsg("Failed to change protection for %d bytes: 0x%x", (int)size, ntStatus);
        MmUnmapLockedPages(p, pMdl);
        MmFreePagesFromMdl(pMdl);
        ExFreePool(pMdl);
        return nullptr;
    }
    Collector::Add(p, NonPaged, size, pMdl);
    if (!p) {
        KeBugCheckEx(0xaabbccdd, (ULONG_PTR)_ReturnAddress(), size, 1, (ULONG_PTR)winternl::pDriverBase);
    }
    return p;
}

void* cpp::kMallocTryAll(size_t size)
{
    void* p = cpp::kMallocContinuous(size);
    if (!p) {
        p = cpp::kMallocAligned(size, PAGE_SIZE);
        if (!p) {
            p = cpp::kMalloc(size);
        }
    }
    if (!p) {
        KeBugCheckEx(0xaabbccdd, (ULONG_PTR)_ReturnAddress(), size, 0, (ULONG_PTR)winternl::pDriverBase);
    }
    return p;
}

void* cpp::kMallocTryAllZero(size_t size)
{
    void* p = cpp::kMallocContinuousZero(size);
    if (!p) {
        p = cpp::kMallocZero(size);
    }
    return p;
}

void* cpp::kMalloc(size_t size, ULONG protect)
{
    LARGE_INTEGER LowAddress, HighAddress;
    LowAddress.QuadPart = 0;
    HighAddress.QuadPart = MAXULONG64;

    PMDL pMdl = MmAllocatePagesForMdl(LowAddress, HighAddress, LowAddress, size);
    if (pMdl == nullptr) {
        DbgMsg("Failed to allocate %d bytes", (int)size);
        return nullptr;
    }
    if (pMdl->ByteCount < size) {
        DbgMsg("Not enough memory to allocate %d bytes", (int)size);
        MmFreePagesFromMdl(pMdl);
        ExFreePool(pMdl);
        return nullptr;
    }
    void* p = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MEMORY_CACHING_TYPE::MmCached, NULL, FALSE, HighPagePriority);
    NTSTATUS ntStatus = MmProtectMdlSystemAddress(pMdl, protect);
    if (!NT_SUCCESS(ntStatus)) {
        DbgMsg("Failed to change protection for %d bytes: 0x%x", (int)size, ntStatus);
        MmUnmapLockedPages(p, pMdl);
        MmFreePagesFromMdl(pMdl);
        ExFreePool(pMdl);
        return nullptr;
    }
    Collector::Add(p, NonPaged, size, pMdl);
    if (!p) {
        KeBugCheckEx(0xaabbccdd, (ULONG_PTR)_ReturnAddress(), size, 2, (ULONG_PTR)winternl::pDriverBase);
    }
    return p;
}

void* cpp::kMallocZero(size_t size, ULONG protect) {
    PVOID p = kMalloc(size, protect);
    if (p)
        RtlZeroMemory(p, size);
    return p;
}

void* cpp::kMallocPool(size_t size) {
    PVOID p = ExAllocatePoolWithTag(POOL_TYPE::NonPagedPool, size, 0);
    Collector::Add(p, Pooled, size);
    if (!p) {
        KeBugCheckEx(0xaabbccdd, (ULONG_PTR)_ReturnAddress(), size, 3, (ULONG_PTR)winternl::pDriverBase);
    }
    return p;
}

void* cpp::kMallocContinuous(size_t size)
{
    void* p;
    PHYSICAL_ADDRESS boundary, lowest, highest;

    boundary.QuadPart = lowest.QuadPart = 0;
    highest.QuadPart = -1;
    cpp::MemoryType memType = Continuous;
    if (size > 4096) {
        p = MmAllocateContiguousMemorySpecifyCacheNode(size,
            lowest,
            highest,
            boundary,
            MmCached,
            MM_ANY_NODE_OK);
    }
    else {
        p = ExAllocatePoolWithTag(NonPagedPool, size, 0);
        memType = NonPaged;
    }

    if (p == nullptr) {
        DbgMsg("Failed to allocate %d continuous bytes", (int)size);
    }
    Collector::Add(p, memType);

    if (!p) {
        KeBugCheckEx(0xaabbccdd, (ULONG_PTR)_ReturnAddress(), size, 4, (ULONG_PTR)winternl::pDriverBase);
    }
    return p;
}

void* cpp::kMallocContinuousZero(size_t size)
{
    PVOID p = kMallocContinuous(size);
    if(p)
        RtlZeroMemory(p, size);
    return p;
}

void* cpp::kMallocNonCached(size_t size)
{
    void* p;
    p = MmAllocateNonCachedMemory(size);

    if (p == nullptr) {
        DbgMsg("Failed to allocate %d non cached bytes", (int)size);
    }
    Collector::Add(p, NonCached, size);
    if (!p) {
        KeBugCheckEx(0xaabbccdd, (ULONG_PTR)_ReturnAddress(), size, 5, (ULONG_PTR)winternl::pDriverBase);
    }
    return p;
}

void* cpp::kMallocAligned(size_t size, size_t alignment, ULONG protection)
{
    void* p;
    PHYSICAL_ADDRESS PhysicalMin = { 0 };
    PHYSICAL_ADDRESS PhysicalMax = { 0 };
    PhysicalMax.QuadPart = MAXULONG64;
    PHYSICAL_ADDRESS BoundaryAlignment = { 0 };
    BoundaryAlignment.QuadPart = alignment;
    cpp::MemoryType memType = Continuous;
    if (size > 4096 && alignment < 4096) {
        p = ExAllocatePoolWithTag(NonPagedPool, size, 0);
        memType = NonPaged;
    }
    else {
        p = MmAllocateContiguousNodeMemory(
            size,
            PhysicalMin,
            PhysicalMax,
            BoundaryAlignment,
            protection,
            MM_ANY_NODE_OK
        );
    }

    if (p == nullptr) {
        DbgMsg("Failed to allocate %d continuously aligned bytes", (int)size);
    }
    Collector::Add(p, memType);
    if (!p) {
        KeBugCheckEx(0xaabbccdd, (ULONG_PTR)_ReturnAddress(), size, 6, (ULONG_PTR)winternl::pDriverBase);
    }
    return p;
}

void* cpp::kMap(size_t pa, size_t size, ULONG protection)
{
    MM_PHYSICAL_ADDRESS_LIST paList = { 0 };
    paList.NumberOfBytes = size;
    paList.PhysicalAddress.QuadPart = pa;

    PMDL pMdl = 0;
    NTSTATUS ntStatus = MmAllocateMdlForIoSpace(&paList, 1, &pMdl);
    if (!NT_SUCCESS(ntStatus)) {
        DbgMsg("[CPP] Failed mapping pa: 0x%llx - 0x%llx", pa, size);
        return nullptr;
    }
    if (pMdl->ByteCount < size) {
        DbgMsg("Not enough memory to allocate %d bytes", (int)size);
        ExFreePool(pMdl);
        return nullptr;
    }

    void* p = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MEMORY_CACHING_TYPE::MmCached, NULL, FALSE, HighPagePriority);
    ntStatus = MmProtectMdlSystemAddress(pMdl, protection);
    if (!NT_SUCCESS(ntStatus)) {
        DbgMsg("Failed to change protection for %d bytes: 0x%x", (int)size, ntStatus);
        MmUnmapLockedPages(p, pMdl);
        ExFreePool(pMdl);
        return nullptr;
    }

    if (!p) {
        KeBugCheckEx(0xaabbccdd, (ULONG_PTR)_ReturnAddress(), size, 7, (ULONG_PTR)winternl::pDriverBase);
    }
    return p;
}

void cpp::kFree(void* pObj)
{
    if (!cpp::IsKernelAddress(pObj)) {
        DbgMsg("[CPP] Error: attempting to free non kernel memory %p", pObj);
        return;
    }
    if(pObj)
        Collector::Clean(pObj);
}

bool cpp::kProtect(void* pObj, ULONG protect)
{
    auto memInfo = Collector::GetMemoryInfo(pObj);
    if (!memInfo.szMemory) {
        return false;
    }

    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

    if (!memInfo.pMdl) {
        ntStatus = Memory::VirtualProtect(pObj, (ULONG)memInfo.szMemory, protect);
        if (!NT_SUCCESS(ntStatus)) {
            DbgMsg("Failed to change protection for 0x%llx bytes: 0x%x", memInfo.szMemory, ntStatus);
            return false;
        }
        return true;
    }

    ntStatus = MmProtectMdlSystemAddress(memInfo.pMdl, protect);
    if (!NT_SUCCESS(ntStatus)) {
        DbgMsg("Failed to change mdl protection for 0x%llx bytes: 0x%x", memInfo.szMemory, ntStatus);
        return false;
    }
    return true;
}

bool cpp::kProtect(void* pObj, SIZE_T sz, ULONG protect)
{
    NTSTATUS ntStatus = Memory::VirtualProtect(pObj, (ULONG)sz, protect);
    if (!NT_SUCCESS(ntStatus)) {
        DbgMsg("Failed to change protection for 0x%llx bytes: 0x%x", sz, ntStatus);
        return false;
    }
    return true;
}
