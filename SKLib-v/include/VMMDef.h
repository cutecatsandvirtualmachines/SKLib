#pragma once

#ifdef _KERNEL_MODE
#include "VectorEx.h"
#include "ia32.h"
#include "cpu.h"
#include "Arch/Vmx.h"
#include "Arch/Svm.h"
#include "Arch/Pte.h"
#include "Arch/Segmentation.h"
#include "Arch/Interrupts.h"
#include <data.h>
#include <paging.h>
#include "eac.h"
#include "VmIDT.h"
#endif

/*
* Disable logging invalid MSR usage
*/
//#define MSR_RESERVED_NO_LOG

/*
* Fake TSC, APERF and MPERF
*/
//#define FAKE_COUNTERS

/*
* Using system IDT/GDT enables the usage of kernel breakpoints in vmx root
* as well as for attaching a kernel debugger
*/
//#define VMX_ROOT_BREAKPOINTS

/*
* Use proprietary page tables for vmx-root (recommended)
*/
#define PROPRIETARY_PAGE_TABLES

/*
* Do not use custom IDT to be able to place breakpoints in VMX root
*/
#ifndef VMX_ROOT_BREAKPOINTS

/*
* Use proprietary IDT for vmx-root (recommended)
*/
#define PROPRIETARY_IDT

/*
* Use proprietary GDT for vmx-root (recommended)
*/
#define PROPRIETARY_GDT

#endif

#pragma warning (disable:4267)

#define INVALID_POOL_HANDLE ~0ul;

#define PT_ENTRIES 512

#define TARGET_CR3_SYSTEM   0

#define TARGET_CR3_CURRENT  1

#define PAGE_SIZE 0x1000

#define EPT_SIZE 100 * PAGE_SIZE

// Offset into the 1st paging structure (4096 byte)
#define ADDRMASK_EPT_PML1_OFFSET(_VAR_) (((DWORD64)_VAR_) & 0xFFFULL)
// Offset into the 2nd paging structure (2MB)
#define ADDRMASK_EPT_PML2_OFFSET(_VAR_) (((DWORD64)_VAR_) & 0x1FFFFFULL)
// Index of the 1st paging structure (4096 byte)
#define ADDRMASK_EPT_PML1_INDEX(_VAR_) ((((DWORD64)_VAR_) & 0x1FF000ULL) >> 12)
// Index of the 2nd paging structure (2MB)
#define ADDRMASK_EPT_PML2_INDEX(_VAR_) ((((DWORD64)_VAR_) & 0x3FE00000ULL) >> 21)
// Index of the 3rd paging structure (1GB)
#define ADDRMASK_EPT_PML3_INDEX(_VAR_) ((((DWORD64)_VAR_) & 0x7FC0000000ULL) >> 30)
// Index of the 4th paging structure (512GB)
#define ADDRMASK_EPT_PML4_INDEX(_VAR_) ((((DWORD64)_VAR_) & 0xFF8000000000ULL) >> 39)

#define INVALID_HOOK_INDEX ((DWORD32)(-1))

#define PAGE_ALIGN_2MB(_VAR_) (((DWORD64)_VAR_) & 0xFFFFFFFFFFE00000ULL)

#define VMXON_SIZE                  4096
#define VMCS_SIZE                   4096
#define ALIGNMENT_PAGE_SIZE         4096
#define VMM_STACK_SIZE              0x8000
#define VM_INSTRUCTION_ERROR_MASK	0x4000

#define VMX_SAVE_MSRS               0
#define VMX_LOAD_MSRS               0
#define VM_TRANSITION_CYCLES                1500
#define PREDEFINED_COUNTER_OFFSET_VALUE     1

#define CLOCK_TIMEOUT_MS 10000

enum VTX_BUG_CHECK_CODE : ULONG64 {
    BC_TRIPLE_FAULT = 0
};

// VM-entry Control Bits 
enum VM_ENTRY_BITS : ULONG {
    VM_ENTRY_IA32E_MODE = 0x00000200,
    VM_ENTRY_SMM = 0x00000400,
    VM_ENTRY_DEACT_DUAL_MONITOR = 0x00000800,
    VM_ENTRY_LOAD_GUEST_PAT = 0x00004000
};

// VM-exit Control Bits 
enum VM_EXIT_BITS : ULONG {
    VM_EXIT_IA32E_MODE = 0x00000200,
    VM_EXIT_ACK_INTR_ON_EXIT = 0x00008000,
    VM_EXIT_SAVE_GUEST_PAT = 0x00040000,
    VM_EXIT_LOAD_HOST_PAT = 0x00080000,
    VM_EXIT_SAVE_PREEMPT_TIMER = 0x00400000
};

// Pin based execution controls
enum PIN_BASED_CTLS : ULONG {
    PIN_BASED_VM_EXECUTION_CONTROLS_EXTERNAL_INTERRUPT = 0x00000001,
    PIN_BASED_VM_EXECUTION_CONTROLS_NMI_EXITING = 0x00000008,
    PIN_BASED_VM_EXECUTION_CONTROLS_VIRTUAL_NMI = 0x00000020,
    PIN_BASED_VM_EXECUTION_CONTROLS_ACTIVE_PREEMPT_TIMER = 0x00000040,
    PIN_BASED_VM_EXECUTION_CONTROLS_PROCESS_POSTED_INTERRUPTS = 0x00000080
};

// VM exit reasons
enum VMEXIT_REASONS : ULONG {
    EXIT_REASON_EXCEPTION_NMI = 0,
    EXIT_REASON_EXTERNAL_INTERRUPT = 1,
    EXIT_REASON_TRIPLE_FAULT = 2,
    EXIT_REASON_INIT = 3,
    EXIT_REASON_SIPI = 4,
    EXIT_REASON_IO_SMI = 5,
    EXIT_REASON_OTHER_SMI = 6,
    EXIT_REASON_PENDING_VIRT_INTR = 7,
    EXIT_REASON_PENDING_VIRT_NMI = 8,
    EXIT_REASON_TASK_SWITCH = 9,
    EXIT_REASON_CPUID = 10,
    EXIT_REASON_GETSEC = 11,
    EXIT_REASON_HLT = 12,
    EXIT_REASON_INVD = 13,
    EXIT_REASON_INVLPG = 14,
    EXIT_REASON_RDPMC = 15,
    EXIT_REASON_RDTSC = 16,
    EXIT_REASON_RSM = 17,
    EXIT_REASON_VMCALL = 18,
    EXIT_REASON_VMCLEAR = 19,
    EXIT_REASON_VMLAUNCH = 20,
    EXIT_REASON_VMPTRLD = 21,
    EXIT_REASON_VMPTRST = 22,
    EXIT_REASON_VMREAD = 23,
    EXIT_REASON_VMRESUME = 24,
    EXIT_REASON_VMWRITE = 25,
    EXIT_REASON_VMXOFF = 26,
    EXIT_REASON_VMXON = 27,
    EXIT_REASON_CR_ACCESS = 28,
    EXIT_REASON_DR_ACCESS = 29,
    EXIT_REASON_IO_INSTRUCTION = 30,
    EXIT_REASON_MSR_READ = 31,
    EXIT_REASON_MSR_WRITE = 32,
    EXIT_REASON_INVALID_GUEST_STATE = 33,
    EXIT_REASON_MSR_LOADING = 34,
    EXIT_REASON_MWAIT_INSTRUCTION = 36,
    EXIT_REASON_MONITOR_TRAP_FLAG = 37,
    EXIT_REASON_MONITOR_INSTRUCTION = 39,
    EXIT_REASON_PAUSE_INSTRUCTION = 40,
    EXIT_REASON_MCE_DURING_VMENTRY = 41,
    EXIT_REASON_TPR_BELOW_THRESHOLD = 43,
    EXIT_REASON_APIC_ACCESS = 44,
    EXIT_REASON_ACCESS_GDTR_OR_IDTR = 46,
    EXIT_REASON_ACCESS_LDTR_OR_TR = 47,
    EXIT_REASON_EPT_VIOLATION = 48,
    EXIT_REASON_EPT_MISCONFIG = 49,
    EXIT_REASON_INVEPT = 50,
    EXIT_REASON_RDTSCP = 51,
    EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED = 52,
    EXIT_REASON_INVVPID = 53,
    EXIT_REASON_WBINVD = 54,
    EXIT_REASON_XSETBV = 55,
    EXIT_REASON_APIC_WRITE = 56,
    EXIT_REASON_RDRAND = 57,
    EXIT_REASON_INVPCID = 58,
    EXIT_REASON_RDSEED = 61,
    EXIT_REASON_PML_FULL = 62,
    EXIT_REASON_XSAVES = 63,
    EXIT_REASON_XRSTORS = 64,
    EXIT_REASON_PCOMMIT = 65
};

enum SEGREGS
{
    ES = 0,
    CS,
    SS,
    DS,
    FS,
    GS,
    LDTR,
    TR
};

typedef union _IA32_VMX_BASIC_MSR
{
    ULONG64 All;
    struct
    {
        ULONG32 RevisionIdentifier : 31;  // [0-30]
        ULONG32 Reserved1 : 1;            // [31]
        ULONG32 RegionSize : 12;          // [32-43]
        ULONG32 RegionClear : 1;          // [44]
        ULONG32 Reserved2 : 3;            // [45-47]
        ULONG32 SupportedIA64 : 1;        // [48]
        ULONG32 SupportedDualMoniter : 1; // [49]
        ULONG32 MemoryType : 4;           // [50-53]
        ULONG32 VmExitReport : 1;         // [54]
        ULONG32 VmxCapabilityHint : 1;    // [55]
        ULONG32 Reserved3 : 8;            // [56-63]
    } Fields;
} IA32_VMX_BASIC_MSR, * PIA32_VMX_BASIC_MSR;

typedef union SEGMENT_ATTRIBUTES
{
    USHORT UCHARs;
    struct
    {
        USHORT TYPE : 4; /* 0;  Bit 40-43 */
        USHORT S : 1;    /* 4;  Bit 44 */
        USHORT DPL : 2;  /* 5;  Bit 45-46 */
        USHORT P : 1;    /* 7;  Bit 47 */

        USHORT AVL : 1; /* 8;  Bit 52 */
        USHORT L : 1;   /* 9;  Bit 53 */
        USHORT DB : 1;  /* 10; Bit 54 */
        USHORT G : 1;   /* 11; Bit 55 */
        USHORT GAP : 4;

    } Fields;
} SEGMENT_ATTRIBUTES;

typedef struct SEG_SELECTOR
{
    USHORT             SEL;
    SEGMENT_ATTRIBUTES ATTRIBUTES;
    ULONG32            LIMIT;
    ULONG64            BASE;
} SEG_SELECTOR, * PSEG_SELECTOR;

typedef struct _SEG_DESCRIPTOR
{
    USHORT LIMIT0;
    USHORT BASE0;
    UCHAR  BASE1;
    UCHAR  ATTR0;
    UCHAR  LIMIT1ATTR1;
    UCHAR  BASE2;
} SEG_DESCRIPTOR, * PSEG_DESCRIPTOR;

union segment_descriptor_addr_t
{
    void* addr;
    struct
    {
        UINT64 low : 16;
        UINT64 middle : 8;
        UINT64 high : 8;
        UINT64 upper : 32;
    };
};

namespace vmm {
    typedef struct _READ_DATA {
        PVOID pOutBuf;
        PVOID pTarget;
        DWORD64 length;
    } READ_DATA, * PREAD_DATA;

    typedef struct _WRITE_DATA {
        PVOID pInBuf;
        PVOID pTarget;
        DWORD64 length;
    } WRITE_DATA, * PWRITE_DATA;

    typedef struct _TRANSLATION_DATA {
        PVOID va;
        DWORD64 pa;
    } TRANSLATION_DATA, *PTRANSLATION_DATA;

    typedef union _READ_WRITE_DATA {
        READ_DATA read;
        WRITE_DATA write;
    } READ_WRITE_DATA, * PREAD_WRITE_DATA;
}

typedef struct _HOOK_SECONDARY_INFO {
    union {
        PVOID* pOrigFn;
        PVOID pSubstitutePage;
    };
} HOOK_SECONDARY_INFO, * PHOOK_SECONDARY_INFO;

#ifdef _KERNEL_MODE

typedef enum _EXCEPTION_VECTOR
{
    EXCEPTION_VECTOR_DIVIDE_ERROR,
    EXCEPTION_VECTOR_DEBUG_BREAKPOINT,
    EXCEPTION_VECTOR_NMI,
    EXCEPTION_VECTOR_BREAKPOINT,
    EXCEPTION_VECTOR_OVERFLOW,
    EXCEPTION_VECTOR_BOUND_RANGE_EXCEEDED,
    EXCEPTION_VECTOR_UNDEFINED_OPCODE,
    EXCEPTION_VECTOR_NO_MATH_COPROCESSOR,
    EXCEPTION_VECTOR_DOUBLE_FAULT,
    EXCEPTION_VECTOR_RESERVED0,
    EXCEPTION_VECTOR_INVALID_TASK_SEGMENT_SELECTOR,
    EXCEPTION_VECTOR_SEGMENT_NOT_PRESENT,
    EXCEPTION_VECTOR_STACK_SEGMENT_FAULT,
    EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT,
    EXCEPTION_VECTOR_PAGE_FAULT,
    EXCEPTION_VECTOR_RESERVED1,
    EXCEPTION_VECTOR_MATH_FAULT,
    EXCEPTION_VECTOR_ALIGNMENT_CHECK,
    EXCEPTION_VECTOR_MACHINE_CHECK,
    EXCEPTION_VECTOR_SIMD_FLOATING_POINT_NUMERIC_ERROR,
    EXCEPTION_VECTOR_VIRTUAL_EXCEPTION,
    EXCEPTION_VECTOR_RESERVED2,
    EXCEPTION_VECTOR_RESERVED3,
    EXCEPTION_VECTOR_RESERVED4,
    EXCEPTION_VECTOR_RESERVED5,
    EXCEPTION_VECTOR_RESERVED6,
    EXCEPTION_VECTOR_RESERVED7,
    EXCEPTION_VECTOR_RESERVED8,
    EXCEPTION_VECTOR_RESERVED9,
    EXCEPTION_VECTOR_RESERVED10,
    EXCEPTION_VECTOR_RESERVED11,
    EXCEPTION_VECTOR_RESERVED12
} EXCEPTION_VECTOR, * PEXCEPTION_VECTOR;

typedef union _INTERRUPT_INFO {
    struct {
        UINT32 Vector : 8;
        /* 0=Ext Int, 1=Rsvd, 2=NMI, 3=Exception, 4=Soft INT,
         * 5=Priv Soft Trap, 6=Unpriv Soft Trap, 7=Other */
        UINT32 InterruptType : 3;
        UINT32 DeliverCode : 1;  /* 0=Do not deliver, 1=Deliver */
        UINT32 Reserved : 19;
        UINT32 Valid : 1;         /* 0=Not valid, 1=Valid. Must be checked first */
    };
    UINT32 Flags;
} INTERRUPT_INFO, * PINTERRUPT_INFO;

union __reset_control_register
{
    unsigned __int8 flags;
    struct
    {
        unsigned __int8 reserved0 : 1;
        unsigned __int8 system_reset : 1;
        unsigned __int8 reset_cpu : 1;
        unsigned __int8 full_reset : 1;
        unsigned __int8 reserved1 : 4;
    };
};

typedef struct _INVPCID
{
    ULONG64 scale : 2;
    ULONG64 und : 5;
    ULONG64 addrssSize : 3;
    ULONG64 rev1 : 1;
    ULONG64 und2 : 4;
    ULONG64 segement : 3;
    ULONG64 index : 4;
    ULONG64 indexInvaild : 1;
    ULONG64 base : 4;
    ULONG64 baseInvaild : 1;
    ULONG64 regOpt : 4;
    ULONG64 un3 : 32;
}INVPCID, * PINVPCID;

typedef enum _SKLIB_BUGCHECK_CODE {
    BUGCHECK_ECODE,
    BUGCHECK_NOCODE
} SKLIB_BUGCHECK_CODE;

typedef struct _MSR_STATE_ENTRY {
    DWORD32 Index;
    DWORD32 reserved;
    DWORD64 Data;
} MSR_STATE_ENTRY, * PMSR_STATE_ENTRY;

typedef struct _MSR_STATE {
    MSR_STATE_ENTRY entry[0x200];
} MSR_STATE, * PMSR_STATE;

typedef struct _VMX_VMXOFF_STATE
{
    BOOLEAN IsVmxoffExecuted;					// Shows whether the VMXOFF executed or not
    UINT64  GuestRip;							// Rip address of guest to return
    UINT64  GuestRsp;							// Rsp address of guest to return
} VMX_VMXOFF_STATE, * PVMX_VMXOFF_STATE;

typedef struct _VMX_NON_ROOT_MODE_MEMORY_ALLOCATOR
{
    PVOID PreAllocatedBuffer;		// As we can't use cpp::kMalloc in VMX Root mode, this holds a pre-allocated buffer address
    // PreAllocatedBuffer == 0 indicates that it's not previously allocated
} VMX_NON_ROOT_MODE_MEMORY_ALLOCATOR, * PVMX_NON_ROOT_MODE_MEMORY_ALLOCATOR;

// The number of 512GB PML4 entries in the page table/
#define VMM_EPT_PML4E_COUNT 512
// The number of 1GB PDPT entries in the page table per 512GB PML4 entry.
#define VMM_EPT_PML3E_COUNT 512
// Then number of 2MB Page Directory entries in the page table per 1GB PML3 entry.
#define VMM_EPT_PML2E_COUNT 512
// Then number of 4096 byte Page Table entries in the page table per 2MB PML2 entry when dynamically split.
#define VMM_EPT_PML1E_COUNT 512

namespace vmm {
    void Virtualise();
    bool IsTimeoutExpired();
}

typedef union _EPT_PML4E {
    ULONG64 Flags;
    struct {
        UINT64 Read : 1; // bit 0
        UINT64 Write : 1; // bit 1
        UINT64 Execute : 1; // bit 2
        UINT64 Reserved1 : 5; // bit 7:3 (Must be Zero)
        UINT64 Accessed : 1; // bit 8
        UINT64 Ignored1 : 1; // bit 9
        UINT64 ExecuteForUserMode : 1; // bit 10
        UINT64 Ignored2 : 1; // bit 11
        UINT64 PhysicalAddress : 40; // bit (N-1):12 or Page-Frame-Number
        UINT64 Ignored3 : 12; // bit 63:52
    } intel;
    struct
    {
        UINT64 Valid : 1;               // [0]
        UINT64 Write : 1;               // [1]
        UINT64 User : 1;                // [2]
        UINT64 WriteThrough : 1;        // [3]
        UINT64 CacheDisable : 1;        // [4]
        UINT64 Accessed : 1;            // [5]
        UINT64 Ignored0 : 1;               // [6]
        UINT64 PageSize : 1;                 // [7]
        UINT64 Ignored1 : 1;              // [8]
        UINT64 Avl : 3;                 // [9:11]
        UINT64 PageFrameNumber : 40;    // [12:51]
        UINT64 Reserved1 : 11;          // [52:62]
        UINT64 NoExecute : 1;           // [63]
    } amd;    
    __forceinline void SetValid(bool bSet = true) {
        if (!CPU::bIntelCPU) {
            amd.Valid = bSet;
            amd.User = bSet;
        }
    }
    __forceinline void SetExecute(bool bSet = true) {
        if (CPU::bIntelCPU)
            intel.Execute = bSet;
        else
            amd.NoExecute = !bSet;
    }
    __forceinline void SetReadWrite(bool bSet = true) {
        if (CPU::bIntelCPU) {
            intel.Write = bSet;
            intel.Read = bSet;
        }
        else {
            amd.Write = bSet;
        }
    }
    __forceinline void SetPFN(UINT64 pfn) {
        if (CPU::bIntelCPU) {
            intel.PhysicalAddress = pfn;
        }
        else {
            amd.PageFrameNumber = pfn;
        }
    }
    __forceinline UINT64 GetPFN() {
        if (CPU::bIntelCPU) {
            return intel.PhysicalAddress;
        }
        else {
            return amd.PageFrameNumber;
        }
    }
    __forceinline bool GetUser() {
        if (!CPU::bIntelCPU)
            return amd.User;
    }
    __forceinline void SetUser(bool bSet) {
        if (!CPU::bIntelCPU)
            amd.User = bSet;
    }
} EPT_PML4E, * PEPT_PML4E;

typedef union _EPT_PDPTE
{
    UINT64 Flags;
    struct
    {
        UINT64 ReadAccess : 1;
        UINT64 WriteAccess : 1;
        UINT64 ExecuteAccess : 1;
        UINT64 Reserved1 : 5;
        UINT64 Accessed : 1;
        UINT64 Reserved2 : 1;
        UINT64 UserModeExecute : 1;
        UINT64 Reserved3 : 1;
        UINT64 PageFrameNumber : 40;
        UINT64 Reserved4 : 12;
    } intel;
    struct
    {
        UINT64 Valid : 1;               // [0]
        UINT64 Write : 1;               // [1]
        UINT64 User : 1;                // [2]
        UINT64 WriteThrough : 1;        // [3]
        UINT64 CacheDisable : 1;        // [4]
        UINT64 Accessed : 1;            // [5]
        UINT64 Ignored0 : 1;               // [6]
        UINT64 PageSize : 1;                 // [7]
        UINT64 Ignored1 : 1;              // [8]
        UINT64 Avl : 3;                 // [9:11]
        UINT64 PageFrameNumber : 40;    // [12:51]
        UINT64 Reserved1 : 11;          // [52:62]
        UINT64 NoExecute : 1;           // [63]
    } amd;
    __forceinline void SetValid(bool bSet = true) {
        if (!CPU::bIntelCPU) {
            amd.Valid = bSet;
            amd.User = bSet;
        }
    }
    __forceinline void SetExecute(bool bSet = true) {
        if (CPU::bIntelCPU)
            intel.ExecuteAccess = bSet;
        else
            amd.NoExecute = !bSet;
    }
    __forceinline void SetReadWrite(bool bSet = true) {
        if (CPU::bIntelCPU) {
            intel.WriteAccess = bSet;
            intel.ReadAccess = bSet;
        }
        else {
            amd.Write = bSet;
        }
    }
    __forceinline void SetPFN(UINT64 pfn) {
        if (CPU::bIntelCPU) {
            intel.PageFrameNumber = pfn;
        }
        else {
            amd.PageFrameNumber = pfn;
        }
    }
    __forceinline UINT64 GetPFN() {
        if (CPU::bIntelCPU) {
            return intel.PageFrameNumber;
        }
        else {
            return amd.PageFrameNumber;
        }
    }
    __forceinline bool GetUser() {
        if (!CPU::bIntelCPU)
            return amd.User;
    }
    __forceinline void SetUser(bool bSet) {
        if (!CPU::bIntelCPU)
            amd.User = bSet;
    }
} EPT_PDPTE, * PEPT_PDPTE;

typedef union _EPT_PDE {
    ULONG64 Flags;
    struct
    {
        UINT64 ReadAccess : 1;
        UINT64 WriteAccess : 1;
        UINT64 ExecuteAccess : 1;
        UINT64 MemoryType : 3;
        UINT64 IgnorePat : 1;
        UINT64 LargePage : 1;
        UINT64 Accessed : 1;
        UINT64 Dirty : 1;
        UINT64 UserModeExecute : 1;
        UINT64 Reserved3 : 1;
        UINT64 PageFrameNumber : 40;
        UINT64 Reserved4 : 12;
    } intel;
    struct
    {
        UINT64 Valid : 1;               // [0]
        UINT64 Write : 1;               // [1]
        UINT64 User : 1;                // [2]
        UINT64 WriteThrough : 1;        // [3]
        UINT64 CacheDisable : 1;        // [4]
        UINT64 Accessed : 1;            // [5]
        UINT64 Ignored0 : 1;               // [6]
        UINT64 PageSize : 1;                 // [7]
        UINT64 Ignored1 : 1;              // [8]
        UINT64 Avl : 3;                 // [9:11]
        UINT64 PageFrameNumber : 40;    // [12:51]
        UINT64 Reserved1 : 11;          // [52:62]
        UINT64 NoExecute : 1;           // [63]
    } amd;

    __forceinline void SetValid(bool bSet = true) {
        if (!CPU::bIntelCPU) {
            amd.Valid = bSet;
            amd.User = bSet;
        }
    }

    __forceinline void SetExecute(bool bSet = true) {
        if (CPU::bIntelCPU)
            intel.ExecuteAccess = bSet;
        else
            amd.NoExecute = !bSet;
    }
    __forceinline void SetReadWrite(bool bSet = true) {
        if (CPU::bIntelCPU) {
            intel.WriteAccess = bSet;
            intel.ReadAccess = bSet;
        }
        else {
            amd.Write = bSet;
        }
    }
    __forceinline void SetPFN(UINT64 pfn) {
        if (CPU::bIntelCPU) {
            intel.PageFrameNumber = pfn;
        }
        else {
            amd.PageFrameNumber = pfn;
        }
    }
    __forceinline UINT64 GetPFN() {
        if (CPU::bIntelCPU) {
            return intel.PageFrameNumber;
        }
        else {
            return amd.PageFrameNumber;
        }
    }
    __forceinline bool GetExecute() {
        if (CPU::bIntelCPU)
            return intel.ExecuteAccess;
        else
            return !amd.NoExecute;
    }
    __forceinline bool GetUser() {
        if (!CPU::bIntelCPU)
            return amd.User;
    }
    __forceinline void SetUser(bool bSet) {
        if (!CPU::bIntelCPU)
            amd.User = bSet;
    }
    __forceinline void SetLarge(bool bSet = true) {
        if (CPU::bIntelCPU) {
            intel.LargePage = bSet;
        }
        else {
            amd.PageSize = bSet;
        }
    }
} EPT_PDE, * PEPT_PDE;

typedef union _EPT_PTE {
    ULONG64 Flags;
    struct {
        UINT64 Read : 1; // bit 0
        UINT64 Write : 1; // bit 1
        UINT64 Execute : 1; // bit 2
        UINT64 EPTMemoryType : 3; // bit 5:3 (EPT Memory type)
        UINT64 IgnorePAT : 1; // bit 6
        UINT64 Ignored1 : 1; // bit 7
        UINT64 AccessedFlag : 1; // bit 8   
        UINT64 DirtyFlag : 1; // bit 9
        UINT64 ExecuteForUserMode : 1; // bit 10
        UINT64 Ignored2 : 1; // bit 11
        UINT64 PhysicalAddress : 40; // bit (N-1):12 or Page-Frame-Number
        UINT64 Ignored3 : 11; // bit 62:52
        UINT64 SuppressVE : 1; // bit 63
    } intel;
    struct
    {
        UINT64 Valid : 1;               // [0]
        UINT64 Write : 1;               // [1]
        UINT64 User : 1;                // [2]
        UINT64 WriteThrough : 1;        // [3]
        UINT64 CacheDisable : 1;        // [4]
        UINT64 Accessed : 1;            // [5]
        UINT64 Dirty : 1;               // [6]
        UINT64 Pat : 1;                 // [7]
        UINT64 Global : 1;              // [8]
        UINT64 Avl : 3;                 // [9:11]
        UINT64 PageFrameNumber : 40;    // [12:51]
        UINT64 Reserved1 : 11;          // [52:62]
        UINT64 NoExecute : 1;           // [63]
    } amd;


    __forceinline void SetValid(bool bSet = true) {
        if (!CPU::bIntelCPU) {
            amd.Valid = bSet;
            amd.User = bSet;
        }
    }
    __forceinline void SetExecute(bool bSet = true) {
        if (CPU::bIntelCPU)
            intel.Execute = bSet;
        else
            amd.NoExecute = !bSet;
    }
    __forceinline void SetReadWrite(bool bSet = true) {
        if (CPU::bIntelCPU) {
            intel.Write = bSet;
            intel.Read = bSet;
        }
        else {
            amd.Write = bSet;
        }
    }
    __forceinline void SetPFN(UINT64 pfn) {
        if (CPU::bIntelCPU) {
            intel.PhysicalAddress = pfn;
        }
        else {
            amd.PageFrameNumber = pfn;
        }
    }
    __forceinline void SetPATWriteback(bool bSet = true) {
        if (CPU::bIntelCPU) {
            intel.EPTMemoryType = bSet ? MEMORY_TYPE_WRITE_BACK : MEMORY_TYPE_UNCACHEABLE;
        }
        else {
            amd.WriteThrough = false;
        }
    }
    __forceinline UINT64 GetPFN() {
        if (CPU::bIntelCPU) {
            return intel.PhysicalAddress;
        }
        else {
            return amd.PageFrameNumber;
        }
    }
    __forceinline bool GetExecute() {
        if (CPU::bIntelCPU)
            return intel.Execute;
        else
            return !amd.NoExecute;
    }
    __forceinline bool GetUser() {
        if (!CPU::bIntelCPU)
            return amd.User;
    }
    __forceinline void SetUser(bool bSet) {
        if (!CPU::bIntelCPU)
            amd.User = bSet;
    }
} EPT_PTE, * PEPT_PTE;

typedef union _EPT_PDE_2MB {
    UINT64 Flags;
    struct
    {
        UINT64 ReadAccess : 1;
        UINT64 WriteAccess : 1;
        UINT64 ExecuteAccess : 1;
        UINT64 MemoryType : 3;
        UINT64 IgnorePat : 1;
        UINT64 LargePage : 1;
        UINT64 Accessed : 1;
        UINT64 Dirty : 1;
        UINT64 UserModeExecute : 1;
        UINT64 Reserved1 : 10;
        UINT64 PageFrameNumber : 31;
        UINT64 Reserved2 : 11;
        UINT64 SuppressVe : 1;
    } intel;
    struct
    {
        UINT64 Valid : 1;               // [0]
        UINT64 Write : 1;               // [1]
        UINT64 User : 1;                // [2]
        UINT64 WriteThrough : 1;        // [3]
        UINT64 CacheDisable : 1;        // [4]
        UINT64 Accessed : 1;            // [5]
        UINT64 Dirty : 1;               // [6]
        UINT64 PageSize : 1;                 // [7]
        UINT64 Global : 1;              // [8]
        UINT64 Avl : 3;                 // [9:11]
        UINT64 PAT : 1; // Page-Attribute Table
        UINT64 : 8;
        UINT64 PageFrameNumber : 31;    // [12:51]
        UINT64 Reserved1 : 11;          // [52:62]
        UINT64 NoExecute : 1;           // [63]
    } amd;

    /*
                    unsigned long long P : 1; // Present
                    unsigned long long RW : 1; // Read/Write
                    unsigned long long US : 1; // User/Supervisor
                    unsigned long long PWT : 1; // Page-Level Writethrough
                    unsigned long long PCD : 1; // Page-Level Cache Disable
                    unsigned long long A : 1; // Accessed
                    unsigned long long D : 1; // Dirty
                    unsigned long long PS : 1; // PageSize == 1
                    unsigned long long G : 1; // Global Page
                    unsigned long long AVL : 3; // Available to software
                    unsigned long long PAT : 1; // Page-Attribute Table
                    unsigned long long : 8;
                    unsigned long long PhysicalPageFrameNumber : 31;
                    unsigned long long Available : 11;
                    unsigned long long NX : 1; // No Execute
*/
    __forceinline void SetValid(bool bSet = true) {
        if (!CPU::bIntelCPU) {
            amd.Valid = bSet;
            amd.User = bSet;
        }
    }
    __forceinline void SetExecute(bool bSet = true) {
        if (CPU::bIntelCPU)
            intel.ExecuteAccess = bSet;
        else
            amd.NoExecute = !bSet;
    }
    __forceinline void SetReadWrite(bool bSet = true) {
        if (CPU::bIntelCPU) {
            intel.WriteAccess = bSet;
            intel.ReadAccess = bSet;
        }
        else {
            amd.Write = bSet;
        }
    }
    __forceinline void SetPFN(UINT64 pfn) {
        if (CPU::bIntelCPU) {
            intel.PageFrameNumber = pfn;
        }
        else {
            amd.PageFrameNumber = pfn;
        }
    }
    __forceinline void SetPATWriteback(bool bSet = true) {
        if (CPU::bIntelCPU) {
            intel.MemoryType = bSet ? MEMORY_TYPE_WRITE_BACK : MEMORY_TYPE_UNCACHEABLE;
        }
        else {
            amd.WriteThrough = false;
        }
    }
    __forceinline void SetLarge(bool bSet = true) {
        if (CPU::bIntelCPU) {
            intel.LargePage = bSet;
        }
        else {
            amd.PageSize = bSet;
        }
    }
    __forceinline bool GetLarge() {
        if (CPU::bIntelCPU) {
            return intel.LargePage;
        }
        else {
            return amd.PageSize;
        }
    }
    __forceinline UINT64 GetPFN() {
        if (CPU::bIntelCPU) {
            return intel.PageFrameNumber;
        }
        else {
            return amd.PageFrameNumber;
        }
    }
    __forceinline bool GetExecute() {
        if (CPU::bIntelCPU)
            return intel.ExecuteAccess;
        else
            return !amd.NoExecute;
    }
    __forceinline bool GetUser() {
        if (!CPU::bIntelCPU)
            return amd.User;
    }
    __forceinline void SetUser(bool bSet) {
        if (!CPU::bIntelCPU)
            amd.User = bSet;
    }
} EPT_PDE_2MB, * PEPT_PDE_2MB;

typedef EPT_PML4E PML4E, * PPML4E;
typedef EPT_PDPTE PML3E, * PPML3E;
typedef EPT_PDE_2MB PML2E_2MB, * PPML2E_2MB;
typedef EPT_PDE PML2E, * PPML2E;
typedef EPT_PTE PML1E, * PPML1E;

typedef union _EPTP
{
    struct
    {
        /**
         * [Bits 2:0] EPT paging-structure memory type:
         * - 0 = Uncacheable (UC)
         * - 6 = Write-back (WB)
         * Other values are reserved.
         *
         * @see Vol3C[28.2.6(EPT and memory Typing)]
         */
        UINT64 MemoryType : 3;

        /**
         * [Bits 5:3] This value is 1 less than the EPT page-walk length.
         *
         * @see Vol3C[28.2.6(EPT and memory Typing)]
         */
        UINT64 PageWalkLength : 3;

        /**
         * [Bit 6] Setting this control to 1 enables accessed and dirty flags for EPT.
         *
         * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
         */
        UINT64 EnableAccessAndDirtyFlags : 1;
        UINT64 Reserved1 : 5;

        /**
         * [Bits 47:12] Bits N-1:12 of the physical address of the 4-KByte aligned EPT PML4 table.
         */
        UINT64 PageFrameNumber : 36;
        UINT64 Reserved2 : 16;
    };

    UINT64 Flags;
} EPTP, * PEPTP;

typedef struct _VMM_EPT_PAGE_TABLE
{
    /**
     * 28.2.2 Describes 512 contiguous 512GB memory regions each with 512 1GB regions.
     */
    DECLSPEC_ALIGN(PAGE_SIZE) PML4E PML4[VMM_EPT_PML4E_COUNT];

    /**
     * Describes exactly 512 contiguous 1GB memory regions within a our singular 512GB PML4 region.
     */
    DECLSPEC_ALIGN(PAGE_SIZE) PML3E PML3[VMM_EPT_PML3E_COUNT];

    /**
     * For each 1GB PML3 entry, create 512 2MB entries to map identity.
     * NOTE: We are using 2MB pages as the smallest paging size in our map, so we do not manage individiual 4096 byte pages.
     * Therefore, we do not allocate any PML1 (4096 byte) paging structures.
     */
    DECLSPEC_ALIGN(PAGE_SIZE) PML2E PML2[VMM_EPT_PML3E_COUNT][VMM_EPT_PML2E_COUNT];

} VMM_EPT_PAGE_TABLE, * PVMM_EPT_PAGE_TABLE;

typedef struct _EPT_STATE
{
    MTRR_RANGE_DESCRIPTOR MemoryRanges[9];							// Physical memory ranges described by the BIOS in the MTRRs. Used to build the EPT identity mapping.
    ULONG NumberOfEnabledMemoryRanges;								// Number of memory ranges specified in MemoryRanges
    EPTP   EptPointer;												// Extended-Page-Table Pointer
    CR3    nCR3;												    
    PVMM_EPT_PAGE_TABLE EptPageTable[512];							    // Page table entries for EPT operation
} EPT_STATE, * PEPT_STATE;

#define GDT_DESCRIPTOR_COUNT 8192


enum CPU_BASED_CTRLS : ULONG {
    CPU_BASED_VIRTUAL_INTR_PENDING = 0x00000004,
    CPU_BASED_USE_TSC_OFFSETING = 0x00000008,
    CPU_BASED_HLT_EXITING = 0x00000080,
    CPU_BASED_INVLPG_EXITING = 0x00000200,
    CPU_BASED_MWAIT_EXITING = 0x00000400,
    CPU_BASED_RDPMC_EXITING = 0x00000800,
    CPU_BASED_RDTSC_EXITING = 0x00001000,
    CPU_BASED_CR3_LOAD_EXITING = 0x00008000,
    CPU_BASED_CR3_STORE_EXITING = 0x00010000,
    CPU_BASED_ACTIVATE_TERTIARY_CONTROLS = 0x00020000,
    CPU_BASED_CR8_LOAD_EXITING = 0x00080000,
    CPU_BASED_CR8_STORE_EXITING = 0x00100000,
    CPU_BASED_TPR_SHADOW = 0x00200000,
    CPU_BASED_VIRTUAL_NMI_PENDING = 0x00400000,
    CPU_BASED_MOV_DR_EXITING = 0x00800000,
    CPU_BASED_UNCOND_IO_EXITING = 0x01000000,
    CPU_BASED_ACTIVATE_IO_BITMAP = 0x02000000,
    CPU_BASED_MONITOR_TRAP_FLAG = 0x08000000,
    CPU_BASED_ACTIVATE_MSR_BITMAP = 0x10000000,
    CPU_BASED_MONITOR_EXITING = 0x20000000,
    CPU_BASED_PAUSE_EXITING = 0x40000000,
    CPU_BASED_ACTIVATE_SECONDARY_CONTROLS = 0x80000000
};

enum CPU_BASED_CTLS2 : ULONG {
    CPU_BASED_CTL2_VIRT_APIC_ACCESS = 0x1,
    CPU_BASED_CTL2_ENABLE_EPT = 0x2,
    CPU_BASED_CTL2_IDT_GDT_ACCESS_EXITING = 0x4,
    CPU_BASED_CTL2_RDTSCP = 0x8,
    CPU_BASED_CTL2_VIRT_x2APIC_ACCESS = 0x10,
    CPU_BASED_CTL2_ENABLE_VPID = 0x20,
    CPU_BASED_CTL2_UNRESTRICTED_GUEST = 0x80,
    CPU_BASED_CTL2_VIRTUAL_INTERRUPT_DELIVERY = 0x200,
    CPU_BASED_CTL2_ENABLE_INVPCID = 0x1000,
    CPU_BASED_CTL2_ENABLE_VMFUNC = 0x2000,
    CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS = 0x100000,
    CPU_BASED_CTL2_ENABLE_TSC_SCALING = 0x2000000
};

typedef enum _EPT_VIOLATION_TYPE {
    READ_ACCESS,
    WRITE_ACCESS,
    EXEC_ACCESS,
    NOT_FOUND
} EPT_VIOLATION_TYPE;

typedef struct _VMM_EPT_DYNAMIC_SPLIT
{
    /*
     * The 4096 byte page table entries that correspond to the split 2MB table entry.
     */
    DECLSPEC_ALIGN(PAGE_SIZE) PML1E PML1[PT_ENTRIES];
} VMM_EPT_DYNAMIC_SPLIT, * PVMM_EPT_DYNAMIC_SPLIT;

typedef union _PAGE_PERMISSIONS {
    UCHAR Flags;
    struct {
        UCHAR Read : 1;
        UCHAR Write : 1;
        UCHAR Exec : 1;
    };
} PAGE_PERMISSIONS, * PPAGE_PERMISSIONS;

//Page state info
typedef struct _EPT_TARGET_DATA {
    union {
        struct {
            PPML1E pShadowPage;
            PPML1E pTargetPage;
            PPML1E pOrigEPTPage;
            PML1E NewEPTPage;
            PML1E OrigEPTFlags;
        };
        struct {
            PPML2E_2MB pShadowPage2MB;
            PPML2E_2MB pTargetPage2MB;
            PPML2E_2MB pOrigEPTPage2MB;
            PML2E_2MB NewEPTPage2MB;
            PML2E_2MB OrigEPTFlags2MB;
        };
    };


    bool operator==(_EPT_TARGET_DATA& rhs) {
        return RtlCompareMemory(this, &rhs, sizeof(rhs));
    }
    bool operator!=(_EPT_TARGET_DATA& rhs) {
        return !(*this == rhs);
    }
} EPT_TARGET_DATA, * PEPT_TARGET_DATA;

typedef struct _INVEPT_DESC
{
    EPTP EptPointer;
    UINT64  Reserved;
} INVEPT_DESC, * PINVEPT_DESC;

struct HOOK_DATA {

    //PFN of the hook page (not hooked one!)
    UINT64 PFN;

    //Pointer to the hook page (virtual address)
    PVOID pPage;
    PVOID pTarget;
    PVOID pHook;
    PVOID pTrampoline;
    size_t szTrampoline;
    PAGE_PERMISSIONS pgPermissions;

    //Page state info
    vector<EPT_TARGET_DATA> vTargetData;

    LIST_ENTRY listEntry;
    bool operator==(HOOK_DATA& rhs) {
        return RtlCompareMemory(this, &rhs, sizeof(rhs));
    }
    bool operator!=(HOOK_DATA& rhs) {
        return !(*this == rhs);
    }
};

typedef struct _MAPPING {
    PPML4T pPml4t;
    PPDPT pPdpt;
    PPDT pPdt;
    PPT pPt;
} MAPPING, * PMAPPING;

/*
 * Storage for guest registers not preserved in VMCS and various exit
 * information.
 *
 * Note that vmx/svm_enter_guest depend on the layout of this struct for
 * field access.
 */

#pragma pack(push, 1)
struct vcpu_gueststate
{
    /* %rsi should be first */
    ULONG64	vg_rsi;			/* 0x00 */
    ULONG64	vg_rax;			/* 0x08 */
    ULONG64	vg_rbx;			/* 0x10 */
    ULONG64	vg_rcx;			/* 0x18 */
    ULONG64	vg_rdx;			/* 0x20 */
    ULONG64	vg_rdi;			/* 0x28 */
    ULONG64	vg_rbp;			/* 0x30 */
    ULONG64	vg_r8;			/* 0x38 */
    ULONG64	vg_r9;			/* 0x40 */
    ULONG64	vg_r10;			/* 0x48 */
    ULONG64	vg_r11;			/* 0x50 */
    ULONG64	vg_r12;			/* 0x58 */
    ULONG64	vg_r13;			/* 0x60 */
    ULONG64	vg_r14;			/* 0x68 */
    ULONG64	vg_r15;			/* 0x70 */
    ULONG64	vg_cr2;			/* 0x78 */
    ULONG64	vg_rip;			/* 0x80 */
    ULONG32	vg_exit_reason;		/* 0x88 */
    ULONG32 vg_pad;
    ULONG64	vg_rflags;		/* 0x90 */
    ULONG64	vg_xcr0;		/* 0x98 */
    /*
     * Debug registers
     * - %dr4/%dr5 are aliased to %dr6/%dr7 (or cause #DE)
     * - %dr7 is saved automatically in the VMCS
     */
    ULONG64	vg_dr0; /* 0xa0 */
    ULONG64	vg_dr1; /* 0xa8 */
    ULONG64	vg_dr2; /* 0xb0 */
    ULONG64	vg_dr3; /* 0xb8 */
    ULONG64	vg_dr6;	/* 0xc0 */

    M128A vg_xmm0; /* 0xc8 */
    M128A vg_xmm1; /* 0xd8 */
    M128A vg_xmm2; /* 0xe8 */
    M128A vg_xmm3; /* 0xf8 */
    M128A vg_xmm4; /* 0x108 */
    M128A vg_xmm5; /* 0x118 */
};
#pragma pack(pop)
/*
* AMD-v
*/

extern "C" void new_stack(void*);
extern "C" void cr4test(void);

extern "C" int svm_enter_guest(ULONG64, struct vcpu_gueststate*, Seg::DescriptorTableRegister<Seg::Mode::longMode>*);
namespace SVM {
    struct SVMShadowRegisters {
        UINT64 ShadowCr4;
        UINT64 ShadowCr3;
    };
    struct SVMCoreFlags {
        bool CETSupported;
    };
    /*Per core state*/
    struct SVMState {
        //__declspec(align(4096))
        Svm::Vmcb* GuestVmcb; //Align 4096

        UINT8* HostState;  // MUST BE ARRAY SIZE OF 4096!!! ALIGNED 4096 //[4096];

        Svm::Msrpm* MsrPermissionsMap; // Align 4096
        void* HostStack;
        vcpu_gueststate GuestState;
        SVMShadowRegisters GuestShadowRegisters;
        SEGMENT_DESCRIPTOR_64 HostGdt[GDT_DESCRIPTOR_COUNT];
        TASK_STATE_SEGMENT_64 HostTss;
        IDT HostIdt;
        Seg::DescriptorTableRegister<Seg::Mode::longMode> GdtReg, IdtReg, TssReg;
        int CPUCore = 0;
        uintptr_t GuestVmcbPhysicalAddress = 0;
        uintptr_t MsrPermissionsMapPhysicalAddress = 0;
        SVMCoreFlags SVMFlags;
        ULONG64 EventInjectionShadow;
    };
    enum EventType {
        e_External = 0,
        e_NMI = 2,
        e_Exception,
        e_Software
    };
    enum EventFlags : char {
        e_None = 0x0,
        e_ErrorCode = 0x1,
    };

    void InjectEvent(SVMState* state, EventType type, InterruptVector vector, int errorCode, bool bErrorCodeValid);

    UINT64* GetRegisterForCrExit(SVMState* state);
    void InjectNMI(SVMState* state);

    bool IsAmdCpu(void);
    bool CanEnterSvm(void);
    bool VirtualiseCore(SVMState*);
    bool VirtualiseAllCores(void);

    void ClearEntireTLB(SVMState* state);
    void ClearGuestTLB(SVMState* state);
}


typedef struct _VM_STATE
{
    VMX_VMXOFF_STATE VmxoffState;									// Shows the vmxoff state of the guest
    VMX_NON_ROOT_MODE_MEMORY_ALLOCATOR PreAllocatedMemoryDetails;	// The details of pre-allocated memory
    UINT64 pVmxonRegion;		// VMXON region
    UINT64 pVmcsRegion;			// VMCS region
    UINT64 pVmmStack;			// Stack for VMM in VM-Exit State
    UINT64 vaMsrBitmap;			// MSR Bitmap Virtual Address
    UINT64 paMsrBitmap;	        // MSR Bitmap Physical Address
    PVOID vaIOBitmapA;
    UINT64 paIOBitmapA;
    PVOID vaIOBitmapB;
    UINT64 paIOBitmapB;
    PMSR_STATE pMsrGuestExitState;  //Store MSRS at VMEXIT
    PMSR_STATE pMsrGuestEntryState; //Load MSRS at VMENTRY
    PMSR_STATE pMsrHostState;       //Load MSRS at VMEXIT

    EPT_STATE eptState;
    SVM::SVMState* SvmState;

#ifdef PROPRIETARY_IDT
    IDT idt;
#endif
#ifdef FAKE_COUNTERS
    DWORD64 apparentTSC;
    DWORD64 lastTSC;
#endif
#ifdef PROPRIETARY_GDT
    SEGMENT_DESCRIPTOR_64 hostGdt[GDT_DESCRIPTOR_COUNT];
    TASK_STATE_SEGMENT_64 hostTss;
#endif
    PREGS pContext;			    // Saved context for breaking VMEXITs
    PREGS pRetContext;			// Saved context for breaking VMEXITs
    UINT64 restoreHookIndex;
    UINT64 lastExitedCr3;
    UINT64 nmiQueue;
    UINT64 lastCr3Tsc;
    bool bRestoreHook;
    bool bVmxRoot;
    bool bIncRip;
    bool bQueuedNMI;
    bool bCETNeedsEnabling;
    bool bTimeoutExpired;
    char lastErrorCode;
} VM_STATE, * PVM_STATE;

/*
* Intel VT-x
*/

namespace VTx
{
    bool Init();
    NTSTATUS Dispose();
    extern "C" NTSTATUS AsmVmxSaveState();
    extern "C" NTSTATUS AsmVmxRestoreState();
    extern "C" void VmxSaveAndLaunch(PREGS pContext);
    extern "C" void VmxRestore(PREGS pContext);
    extern "C" void VmExitWrapper();
    extern "C" void VmRestore(PREGS pContext);

    bool VmxOn(PVOID pRegion);
    void VmxOff(ULONG dwCore);
    void Vmptrst();
    bool VmClear(PVM_STATE pState);
    bool VmPtrld(PVM_STATE pState);
    extern "C" void VmxLaunch(PVOID GuestStack);
    bool VmcsSetup(PVM_STATE pState, PVOID GuestStack);
    extern "C" void VmExitHandler(PREGS pGuestRegs);
    extern "C" void VmResumeExec();
    ULONG64 MoveRip(size_t szInst = 0);

    bool AllocVmxonRegion(PVM_STATE pState);
    bool AllocVmcsRegion(PVM_STATE pState);
    bool AllocVmmStack(PVM_STATE pState);
    bool AllocMsrBitmap(PVM_STATE pState);
    bool AllocIOBitmap(PVM_STATE pState);
    bool AllocMsrState(PVM_STATE pState);

    bool GetSegmentDescriptor(PSEG_SELECTOR SegmentSelector, USHORT Selector, PUCHAR GdtBase);
    void FillGuestSelectorData(PVOID GdtBase, ULONG SegmentRegister, USHORT Selector);

    NTSTATUS VirtualizeSystem();
    NTSTATUS DevirtualizeSystem();

    void DumpCPUState(PREGS pContext);

    PPML4T GetHostPml4t();
};
/*
* EPT
*/

typedef BOOLEAN(*fnHookCallback)(PTE_64* ppte64);

namespace vmm {
    extern DWORD64 dwCores;
    extern ULONG ulProcessorMask;

    extern Spinlock lock;
    extern vector<HOOK_DATA>* vHooks;

    extern PVM_STATE vGuestStates;
    extern EPT_STATE* eptShadow;

    inline constexpr SEGMENT_SELECTOR host_cs_selector = { 0, 0, 1 };
    inline constexpr SEGMENT_SELECTOR host_tr_selector = { 0, 0, 2 };

    extern CR3 hostCR3;
    extern CR3 guestCR3;

    extern PVOID pIdentityMap;
    extern DWORD64 tscDeltaTimeout;
    extern DWORD64 oldestValidTsc;

    void Init();

    inline CR3 GetGuestCR3() {
        CR3 _guestCR3 = { 0 };
        if (CPU::bIntelCPU) {
            __vmx_vmread(GUEST_CR3, &_guestCR3.Flags);
        }
        else {
            DWORD64 dwCore = CPU::GetCPUIndex(true);
            PVM_STATE pState = &vmm::vGuestStates[dwCore];
            _guestCR3.Flags = pState->SvmState->GuestVmcb->StateSaveArea.Cr3;
        }
        return _guestCR3;
    }
    inline void SetGuestCR3(CR3 cr3) {
        CR3 _guestCR3 = { 0 };
        if (CPU::bIntelCPU) {
            __vmx_vmwrite(GUEST_CR3, cr3.Flags);
        }
        else {
            DWORD64 dwCore = CPU::GetCPUIndex(true);
            PVM_STATE pState = &vmm::vGuestStates[dwCore];
            pState->SvmState->GuestVmcb->StateSaveArea.Cr3 = cr3.Flags;
        }
    }
    inline void UpdateLastValidTsc() {
        //DWORD dwCore = CPU::GetCPUIndex(true);
        //vmm::vGuestStates[dwCore].lastCr3Tsc = __rdtsc();
        //
        //bool bOldest = true;
        //for (DWORD i = 0; i < CPU::GetCPUCount(); i++) {
        //    if (vmm::vGuestStates[dwCore].lastCr3Tsc > vmm::vGuestStates[i].lastCr3Tsc) {
        //        bOldest = false;
        //        break;
        //    }
        //}
        //if(bOldest)
        //    oldestValidTsc = vmm::vGuestStates[dwCore].lastCr3Tsc;
    }
}

namespace EPT {
    extern bool bInit;

    bool Init();
    bool IsMTRRSupported();
    bool IsExecOnlySupported();

    BOOLEAN BuildMtrrMap(EPT_STATE* pEptState);
    PVMM_EPT_PAGE_TABLE CreatePageTable(EPT_STATE* pEptState, PML2E_2MB PML2EntryTemplate, ULONG pml4Index = 0);
    BOOLEAN HideDriver();
    PPML1E GetPml1Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress);
    PPML1E MapPml1Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress);
    PPML2E GetPml2Entry(PVMM_EPT_PAGE_TABLE pEpt, SIZE_T pa);
    BOOLEAN SplitLargePage(PVMM_EPT_PAGE_TABLE pEpt, PVOID PBuf, SIZE_T pa, BOOLEAN bVmxRoot = false);

    BOOLEAN HandlePageHookExit(UINT64 GuestPhysicalAddr);
    BOOLEAN HandleEptViolation(ULONG ExitQualification, UINT64 GuestPhysicalAddr);
    VOID HandleMisconfiguration(UINT64 GuestAddress);

    BOOLEAN PageHook(HOOK_DATA& hkData, HOOK_SECONDARY_INFO hkSecondaryInfo, ULONG dwCore);
    BOOLEAN PageHook2MB(HOOK_DATA& hkData, HOOK_SECONDARY_INFO hkSecondaryInfo, ULONG dwCore);
    BOOLEAN PageHookRange(int startIndex, int endIndex, HOOK_SECONDARY_INFO hkSecondaryInfo, BOOLEAN bVmxLaunched, ULONG dwCore);
    BOOLEAN AddToShadow(PVOID pFn);
    BOOLEAN AddToShadowRange(PVOID pFn, SIZE_T sz);
    BOOLEAN Hook(PVOID pFn, PVOID pHook, HOOK_SECONDARY_INFO hkSecondaryInfo, PAGE_PERMISSIONS& pgPermissions, bool bSetPages = true, int* pIndex = nullptr);
    BOOLEAN Hook2MB(PVOID pFn, PVOID pHook, HOOK_SECONDARY_INFO hkSecondaryInfo, PAGE_PERMISSIONS& pgPermissions, bool bSetPages = true, int* pIndex = nullptr);
    BOOLEAN HookExec(PVOID pTarget, PVOID pHook, HOOK_SECONDARY_INFO hkSecondaryInfo);
    BOOLEAN HookIf(PVOID pFn, PVOID pHook, HOOK_SECONDARY_INFO hkSecondaryInfo, PAGE_PERMISSIONS& pgPermissions, fnHookCallback callback, bool bSetPages = true);
    BOOLEAN HookRange(PVOID pBase, size_t size, PVOID pHook, HOOK_SECONDARY_INFO hkSecondaryInfo, PAGE_PERMISSIONS& pgPermissions, bool bSetPages = true, int* pIndex = nullptr);
    BOOLEAN HookRangeIf(PVOID pBase, size_t size, PVOID pHook, HOOK_SECONDARY_INFO hkSecondaryInfo, PAGE_PERMISSIONS& pgPermissions, fnHookCallback callback, bool bSetPages = true);
    BOOLEAN HookSubstitute(PVOID pFn, HOOK_SECONDARY_INFO hkSecondaryInfo, PAGE_PERMISSIONS& pgPermissions, bool bSetPages = true, int* pIndex = nullptr);
    BOOLEAN HookSubstituteRange(PVOID pBase, size_t size, HOOK_SECONDARY_INFO hkSecondaryInfo, PAGE_PERMISSIONS& pgPermissions, bool bSetPages = true, int* pIndex = nullptr);
    BOOLEAN InsertTrampoline(HOOK_DATA& hkData, PVOID* pOrigFn);

    BOOLEAN IsShadowEPTActive(ULONG dwCore);
    NTSTATUS ExitShadow(ULONG dwCore);
    NTSTATUS EnterShadow(ULONG dwCore);
    NTSTATUS Unhook(PVOID pFn);
    NTSTATUS UnhookRange(PVOID pFn, SIZE_T sz);
    VMX_ERROR SetPMLAndInvalidateTLB(PVOID pEntry, DWORD64 Flags, INVEPT_TYPE type, ULONG dwCore);

    VMX_ERROR InvalidateEPT(ULONG dwCore);
    VMX_ERROR InvalidateEPTShadow(ULONG dwCore);

    template<typename F>
    VOID ForEachHook(F fCallback) {
        for (auto& hook : *vmm::vHooks) {
            fCallback(hook);
        }
    }
}

namespace paging {
    namespace vmmhost {
        PVOID GuestVirtToPhy(PVOID va, PVOID pGuestPml4tPa, MAP_TYPE mapType = MAP_TYPE::src, bool* pIsLargePage = nullptr);

        PVOID MapToHost(PVOID pa, MAP_TYPE mapType = MAP_TYPE::src);
        PVOID MapGuestToHost(DWORD64 cr3, PVOID va, MAP_TYPE mapType = MAP_TYPE::src);

        EXIT_ERRORS ReadVirtMemoryEx(PVOID pOut, PVOID pTarget, SIZE_T size, CR3 cr3, CR3 targetCr3);
        EXIT_ERRORS WriteVirtMemoryEx(PVOID pTarget, PVOID pIn, SIZE_T size, CR3 cr3, CR3 inCr3);

        EXIT_ERRORS ReadVirtMemory(PVOID pOut, PVOID pTarget, SIZE_T size, CR3 cr3);
        EXIT_ERRORS WriteVirtMemory(PVOID pTarget, PVOID pIn, SIZE_T size, CR3 cr3);

        EXIT_ERRORS ReadPhyMemory(PVOID pOut, PVOID pTargetPa, SIZE_T size);
        EXIT_ERRORS WritePhyMemory(PVOID pTargetPa, PVOID pIn, SIZE_T size);
    }
    PPML4T CopyPML4Mapping(CR3 cr3 = { 0 });
}

#endif