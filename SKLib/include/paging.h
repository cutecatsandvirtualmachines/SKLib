#pragma once

#include "cpp.h"
#include "MemoryEx.h"
#include "winternlex.h"

#include <intrin.h>
#include <ia32.h>

#ifdef _KERNEL_MODE

#define PT_ENTRIES 512

typedef enum _EXIT_ERRORS : ULONG {
    ERROR_SUCCESS = 0,
    ERROR_CANNOT_MAP_PARAM,
    ERROR_CANNOT_MAP_SRC,
    ERROR_CANNOT_MAP_DST,
    ERROR_CANNOT_READ,
    ERROR_CANNOT_WRITE,
    ERROR_INVALID_PARAM,
    ERROR_PAGE_FAULT
} EXIT_ERRORS, * PEXIT_ERRORS;

typedef struct _PML4T {
    PML4E_64 entry[512];
} PML4T, *PPML4T;

typedef struct _PDPT {
    PDPTE_64 entry[512];
} PDPT, * PPDPT;

typedef struct _PDT {
    PDE_64 entry[512];
} PDT, * PPDT;

typedef struct _PT {
    PTE_64 entry[512];
} PT, * PPT;

enum MAP_TYPE {
    src = 0,
    dest
};

typedef union {
    struct {
        DWORD64 Offset : 12;
        DWORD64 Level1 : 9;
        DWORD64 Level2 : 9;
        DWORD64 Level3 : 9;
        DWORD64 Level4 : 9;
        DWORD64 SignExt : 16;
    };

    DWORD64 Flags;
} VIRT_ADD_MAP, * PVIRT_ADD_MAP;

typedef union _VIRT_ADD
{
    DWORD64 value;
    struct
    {
        DWORD64 offset_4kb : 12;
        DWORD64 pt_index : 9;
        DWORD64 pdt_index : 9;
        DWORD64 pdpt_index : 9;
        DWORD64 pml4_index : 9;
        DWORD64 reserved : 16;
    };

    struct
    {
        DWORD64 offset_2mb : 21;
        DWORD64 pdt_index : 9;
        DWORD64 pdpt_index : 9;
        DWORD64 pml4_index : 9;
        DWORD64 reserved : 16;
    };

    struct
    {
        DWORD64 offset_1gb : 30;
        DWORD64 pdpt_index : 9;
        DWORD64 pml4_index : 9;
        DWORD64 reserved : 16;
    };

} VIRT_ADD, * PVIRT_ADD;

typedef struct _MANUAL_PAGED_TABLES {
    PML4E_64* pPml4e;
    PDPTE_64* pPdpte;
    PDE_64* pPde;
    PTE_64* pPte;
    PTE_64 pteOrig;

    __forceinline bool operator==(_MANUAL_PAGED_TABLES& rhs) {
        return !memcmp(&rhs, this, sizeof(rhs));
    }
    __forceinline bool operator!=(_MANUAL_PAGED_TABLES& rhs) {
        return !(*this == rhs);
    }
} MANUAL_PAGED_TABLES, *PMANUAL_PAGED_TABLES;

typedef struct _TARGET_TRANSLATION {
    DWORD64 va;
    DWORD64 pa;

    __forceinline bool operator==(_TARGET_TRANSLATION& rhs) {
        return !memcmp(&rhs, this, sizeof(rhs));
    }
    __forceinline bool operator!=(_TARGET_TRANSLATION& rhs) {
        return !(*this == rhs);
    }
} TARGET_TRANSLATION, * PTARGET_TRANSLATION;

namespace paging {
    BOOLEAN IsMapped(PPML4T ppml4t, PVOID va);
    BOOLEAN MapPage(PPML4T pTargetPml4t, DWORD64 va, DWORD64 pa, MANUAL_PAGED_TABLES* manualMapTracking = nullptr);
    BOOLEAN MapRegion(PPML4T ppml4t, PVOID va, size_t size);
    PTE_64* GetPPTE(PPML4T ppml4t, PVOID va, BOOLEAN bMap = false);
    BOOLEAN IsAddressValid(PVOID va);

    PMDL LockRange(PVOID pBase, size_t size);
    VOID UnlockRange(PMDL pMdl);

    PVOID MapNonPaged(PVOID pa, size_t size, MODE allocationMode);

    PPML4T GetPML4Base(CR3 cr3 = { 0 });
    PPML4T MapPML4Base(CR3 cr3 = { 0 });
    VOID SetPML4Base(PVOID pPML4Table);

    PVOID GuestVirtToPhy(PVOID va, PVOID pGuestPml4tPa = nullptr, bool* pIsLargePage = nullptr);
    DWORD64 ProcessVirtToPhy(PEPROCESS pEprocess, PVOID va);
    DWORD64 CurrProcessVirtToPhy(PVOID va);

    DWORD64 VirtToPhy(PVOID va);

    vector<MANUAL_PAGED_TABLES> CopyMapRegion(CR3 toCr3, vector<TARGET_TRANSLATION>& translations);
    MANUAL_PAGED_TABLES CopyMapPage(CR3 toCr3, TARGET_TRANSLATION translations);

    PVOID MapPhysical(DWORD64 pa, DWORD64 sz, ULONG protect = PAGE_READWRITE);
}

#endif