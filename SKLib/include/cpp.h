#pragma once

#pragma warning (disable: 4100 4996)

#ifdef _KERNEL_MODE
#ifndef _WDMDDK_
#include <ntifs.h>
#endif

#include "VirtualizerSDKMacros.h"
#endif

#include "macros.h"
#include "std.h"
#include "exception.h"

#define forEach(iterator, collection) for(auto iterator = collection.begin(); iterator != collection.end(); ++iterator)

#ifdef _KERNEL_MODE

// Integer 2MB
#define SIZE_2_MB ((SIZE_T)(512 * PAGE_SIZE))
// Integer 1GB
#define SIZE_1_GB ((SIZE_T)(512 * SIZE_2_MB))

void* operator new(size_t /* ignored */, void* where);

namespace cpp {
    enum MemoryType {
        NonPaged,
        NonCached,
        Continuous,
        Pooled
    };

    void* uMalloc(size_t size, ULONG protect = PAGE_READWRITE);
    void* kMallocTryAll(size_t size);
    void* kMallocTryAllZero(size_t size);
    void* kMalloc(size_t size, ULONG protect = PAGE_READWRITE);
    void* kMallocZero(size_t size, ULONG protect = PAGE_READWRITE);
    void* kMallocPool(size_t size);
    void* kMallocContinuous(size_t size);
    void* kMallocContinuousZero(size_t size);
    void* kMallocNonCached(size_t size);
    void* kMallocAligned(size_t size, size_t alignment, ULONG protection = PAGE_READWRITE);
    void* kMap(size_t pa, size_t size, ULONG protection = PAGE_READWRITE);
    void kFree(void* pObj);

    bool kProtect(void* pObj, ULONG protect);
    bool kProtect(void* pObj, SIZE_T sz, ULONG protect);
}
#endif