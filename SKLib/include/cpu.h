#pragma once

#ifdef _KERNEL_MODE
#include <intrin.h>
#include <ntddk.h>
#endif

#include "macros.h"
#include "bitmap.h"
#include "Arch/Cpuid.h"

#pragma warning (disable:4201)

#define OWORD_ALIGN(x) (x & ~0x10)
#define MAX_ADDRESS  0xFFFFFFFFFFFFFFFFULL
#define BIT(x)  (1ull << x)

#define RPL_MASK   3

//Ring definition
#define DPL_USER   3
#define DPL_SYSTEM 0

#define IA32_MPERF_MSR			0xE7
#define IA32_APERF_MSR			0xE8

enum XCRS {
    XCR0 = 0
};

enum XCR0_MASK {
    XCR0_X87 = (1ULL << 0),     /* x87, FPU/MMX (always set) */
    XCR0_SSE = (1ULL << 1),     /* SSE supported by XSAVE/XRESTORE */
    XCR0_YMM = (1ULL << 2),     /* YMM state available */
    XCR0_BNDREGS = (1ULL << 3),     /* MPX Bounds register state */
    XCR0_BNDCSR = (1ULL << 4),     /* MPX Bounds configuration/state  */
    XCR0_OPMASK = (1ULL << 5),     /* Opmask register state */
    XCR0_ZMM_HI256 = (1ULL << 6),     /* ZMM upper 256-bit state */
    XCR0_HI16_ZMM = (1ULL << 7),     /* ZMM16..ZMM31 512-bit state */
    XCR0_ZMM = (XCR0_ZMM_HI256 | XCR0_HI16_ZMM | XCR0_OPMASK)
};

enum COUNTER_TYPE {
    TIME_STAMP = 0,
    MPERF_COUNTER,
    APERF_COUNTER
};

//#define PROCESSOR_MANUFACTURER "UniHideSpoof"

//Windows Reserved MSRs
enum RESERVED_MSR {
    MSR_POWER_STATE = 0x40000004,
    MSR_IDLE_MAX_TIME = 0x400000B0,
    MSR_IDLE_MAX_TIME2 = 0x400000B1,
    MSR_IDLE_PROCESSOR_CYCLES = 0x400000F0,
    MSR_UNK_0 = 0x40000105
};

//CPUID
enum CPUID : ULONG {
    PROC_MANU_CPUID = 0x0,
    PROC_FEATURES_CPUID = 0x1,
    HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS = 0x40000000,
    HYPERV_CPUID_INTERFACE = 0x40000001,
    HYPERV_CPUID_VERSION = 0x40000002,
    HYPERV_CPUID_FEATURES = 0x40000003,
    HYPERV_CPUID_ENLIGHTMENT_INFO = 0x40000004,
    HYPERV_CPUID_IMPLEMENT_LIMITS = 0x40000005,
    HYPERV_HYPERVISOR_PRESENT_BIT = 0x80000000,
    HYPERV_CPUID_MIN = 0x40000005,
    HYPERV_CPUID_MAX = 0x4000ffff
};

// Exit Qualifications for MOV for Control Register Access
enum CR_ACTION {
    TYPE_MOV_TO_CR = 0,
    TYPE_MOV_FROM_CR = 1,
    TYPE_CLTS = 2,
    TYPE_LMSW = 3
};

enum VMCS_FIELDS : ULONG {
    VIRTUAL_PROCESSOR_ID = 0x00000000,
    GUEST_ES_SELECTOR = 0x00000800,
    GUEST_CS_SELECTOR = 0x00000802,
    GUEST_SS_SELECTOR = 0x00000804,
    GUEST_DS_SELECTOR = 0x00000806,
    GUEST_FS_SELECTOR = 0x00000808,
    GUEST_GS_SELECTOR = 0x0000080a,
    GUEST_LDTR_SELECTOR = 0x0000080c,
    GUEST_TR_SELECTOR = 0x0000080e,
    HOST_ES_SELECTOR = 0x00000c00,
    HOST_CS_SELECTOR = 0x00000c02,
    HOST_SS_SELECTOR = 0x00000c04,
    HOST_DS_SELECTOR = 0x00000c06,
    HOST_FS_SELECTOR = 0x00000c08,
    HOST_GS_SELECTOR = 0x00000c0a,
    HOST_TR_SELECTOR = 0x00000c0c,
    IO_BITMAP_A = 0x00002000,
    IO_BITMAP_A_HIGH = 0x00002001,
    IO_BITMAP_B = 0x00002002,
    IO_BITMAP_B_HIGH = 0x00002003,
    MSR_BITMAP = 0x00002004,
    MSR_BITMAP_HIGH = 0x00002005,
    VM_EXIT_MSR_STORE_ADDR = 0x00002006,
    VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,
    VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
    VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,
    VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
    VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,
    TSC_OFFSET = 0x00002010,
    TSC_OFFSET_HIGH = 0x00002011,
    VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
    VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,
    VMFUNC_CONTROLS = 0x00002018,
    VMFUNC_CONTROLS_HIGH = 0x00002019,
    EPT_POINTER_LOW = 0x0000201A,
    EPT_POINTER_HIGH = 0x0000201B,
    EPTP_LIST = 0x00002024,
    EPTP_LIST_HIGH = 0x00002025,
    TSC_MULTIPLIER = 0x00002032,
    TSC_MULTIPLIER_HIGH = 0x00002033,
    GUEST_PHYSICAL_ADDRESS = 0x2400,
    GUEST_PHYSICAL_ADDRESS_HIGH = 0x2401,
    VMCS_LINK_POINTER = 0x00002800,
    VMCS_LINK_POINTER_HIGH = 0x00002801,
    GUEST_IA32_DEBUGCTL = 0x00002802,
    GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,
    PIN_BASED_VM_EXEC_CONTROL = 0x00004000,
    CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
    EXCEPTION_BITMAP = 0x00004004,
    PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
    PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
    CR3_TARGET_COUNT = 0x0000400a,
    VM_EXIT_CONTROLS = 0x0000400c,
    VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
    VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
    VM_ENTRY_CONTROLS = 0x00004012,
    VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
    VM_ENTRY_INTR_INFO_FIELD = 0x00004016,
    VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
    VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
    TPR_THRESHOLD = 0x0000401c,
    SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
    VM_INSTRUCTION_ERROR = 0x00004400,
    VM_EXIT_REASON = 0x00004402,
    VM_EXIT_INTR_INFO = 0x00004404,
    VM_EXIT_INTR_ERROR_CODE = 0x00004406,
    IDT_LISTING_INFO_FIELD = 0x00004408,
    IDT_LISTING_ERROR_CODE = 0x0000440a,
    VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
    VMX_INSTRUCTION_INFO = 0x0000440e,
    GUEST_ES_LIMIT = 0x00004800,
    GUEST_CS_LIMIT = 0x00004802,
    GUEST_SS_LIMIT = 0x00004804,
    GUEST_DS_LIMIT = 0x00004806,
    GUEST_FS_LIMIT = 0x00004808,
    GUEST_GS_LIMIT = 0x0000480a,
    GUEST_LDTR_LIMIT = 0x0000480c,
    GUEST_TR_LIMIT = 0x0000480e,
    GUEST_GDTR_LIMIT = 0x00004810,
    GUEST_IDTR_LIMIT = 0x00004812,
    GUEST_ES_AR_BYTES = 0x00004814,
    GUEST_CS_AR_BYTES = 0x00004816,
    GUEST_SS_AR_BYTES = 0x00004818,
    GUEST_DS_AR_BYTES = 0x0000481a,
    GUEST_FS_AR_BYTES = 0x0000481c,
    GUEST_GS_AR_BYTES = 0x0000481e,
    GUEST_LDTR_AR_BYTES = 0x00004820,
    GUEST_TR_AR_BYTES = 0x00004822,
    GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
    GUEST_ACTIVITY_STATE = 0x00004826,
    GUEST_SM_BASE = 0x00004828,
    GUEST_SYSENTER_CS = 0x0000482A,
    GUEST_PREEMPTION_TIMER_VALUE = 0x0000482E, //It's a 32 bit value!
    HOST_IA32_SYSENTER_CS = 0x00004c00,
    CR0_GUEST_HOST_MASK = 0x00006000,
    CR4_GUEST_HOST_MASK = 0x00006002,
    CR0_READ_SHADOW = 0x00006004,
    CR4_READ_SHADOW = 0x00006006,
    CR3_TARGET_VALUE0 = 0x00006008,
    CR3_TARGET_VALUE1 = 0x0000600a,
    CR3_TARGET_VALUE2 = 0x0000600c,
    CR3_TARGET_VALUE3 = 0x0000600e,
    EXIT_QUALIFICATION = 0x00006400,
    GUEST_LINEAR_ADDRESS = 0x0000640a,
    GUEST_CR0 = 0x00006800,
    GUEST_CR3 = 0x00006802,
    GUEST_CR4 = 0x00006804,
    GUEST_ES_BASE = 0x00006806,
    GUEST_CS_BASE = 0x00006808,
    GUEST_SS_BASE = 0x0000680a,
    GUEST_DS_BASE = 0x0000680c,
    GUEST_FS_BASE = 0x0000680e,
    GUEST_GS_BASE = 0x00006810,
    GUEST_LDTR_BASE = 0x00006812,
    GUEST_TR_BASE = 0x00006814,
    GUEST_GDTR_BASE = 0x00006816,
    GUEST_IDTR_BASE = 0x00006818,
    GUEST_DR7 = 0x0000681a,
    GUEST_RSP = 0x0000681c,
    GUEST_RIP = 0x0000681e,
    GUEST_RFLAGS = 0x00006820,
    GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
    GUEST_SYSENTER_ESP = 0x00006824,
    GUEST_SYSENTER_EIP = 0x00006826,
    HOST_CR0 = 0x00006c00,
    HOST_CR3 = 0x00006c02,
    HOST_CR4 = 0x00006c04,
    HOST_FS_BASE = 0x00006c06,
    HOST_GS_BASE = 0x00006c08,
    HOST_TR_BASE = 0x00006c0a,
    HOST_GDTR_BASE = 0x00006c0c,
    HOST_IDTR_BASE = 0x00006c0e,
    HOST_IA32_SYSENTER_ESP = 0x00006c10,
    HOST_IA32_SYSENTER_EIP = 0x00006c12,
    HOST_RSP = 0x00006c14,
    HOST_RIP = 0x00006c16,
};

enum MSR_IA32 : ULONG {
    MSR_APIC_BASE = 0x01B,
    MSR_IA32_FEATURE_CONTROL = 0x03A,
    MSR_IA32_VMX_BASIC = 0x480,
    MSR_IA32_VMX_PINBASED_CTLS = 0x481,
    MSR_IA32_VMX_PROCBASED_CTLS = 0x482,
    MSR_IA32_VMX_EXIT_CTLS = 0x483,
    MSR_IA32_VMX_ENTRY_CTLS = 0x484,
    MSR_IA32_VMX_MISC = 0x485,
    MSR_IA32_VMX_CR0_FIXED0 = 0x486,
    MSR_IA32_VMX_CR0_FIXED1 = 0x487,
    MSR_IA32_VMX_CR4_FIXED0 = 0x488,
    MSR_IA32_VMX_CR4_FIXED1 = 0x489,
    MSR_IA32_VMX_VMCS_ENUM = 0x48A,
    MSR_IA32_VMX_PROCBASED_CTLS2 = 0x48B,
    MSR_IA32_VMX_TRUE_PINBASED_CTLS = 0x48D,
    MSR_IA32_VMX_TRUE_PROCBASED_CTLS = 0x48E,
    MSR_IA32_VMX_TRUE_EXIT_CTLS = 0x48F,
    MSR_IA32_VMX_TRUE_ENTRY_CTLS = 0x490,
    MSR_IA32_VMX_VMFUNC = 0x491,
    MSR_IA32_SYSENTER_CS = 0x174,
    MSR_IA32_SYSENTER_ESP = 0x175,
    MSR_IA32_SYSENTER_EIP = 0x176,
    MSR_IA32_DEBUGCTL = 0x1D9,
    MSR_FS_BASE = 0xC0000100,
    MSR_GS_BASE = 0xC0000101,
    MSR_SHADOW_GS_BASE = 0xC0000102
};

typedef union _IA32_FEATURE_CONTROL_MSR
{
    ULONG64 All;
    struct
    {
        ULONG64 Lock : 1;               // [0]
        ULONG64 EnableSMX : 1;          // [1]
        ULONG64 EnableVmxon : 1;        // [2]
        ULONG64 Reserved2 : 5;          // [3-7]
        ULONG64 EnableLocalSENTER : 7;  // [8-14]
        ULONG64 EnableGlobalSENTER : 1; // [15]
        ULONG64 Reserved3a : 16;        //
        ULONG64 Reserved3b : 32;        // [16-63]
    } Fields;
} IA32_FEATURE_CONTROL_MSR, * PIA32_FEATURE_CONTROL_MSR;

typedef union _PF_CODE {
    struct {
        DWORD64 present : 1;
        DWORD64 write : 1;
        DWORD64 user : 1;
        DWORD64 reserved : 1;
        DWORD64 exec : 1;
        DWORD64 pk : 1;
        DWORD64 ss : 1;
    };
    DWORD64 Flags;
} PF_CODE, * PPF_CODE;

typedef union _MSR
{
    struct
    {
        ULONG Low;
        ULONG High;
    };
    ULONG64 Content;
} MSR, * PMSR;

typedef struct _XMM_REG {
    DWORD64 low;
    DWORD64 high;
} XMM_REG;

typedef struct _REGS
{
    ULONG64 rax;                  // 0x00         
    ULONG64 rcx;
    ULONG64 rdx;                  // 0x10
    ULONG64 rbx;
    ULONG64 rsp;                  // 0x20         // rsp is not stored here
    ULONG64 rbp;
    ULONG64 rsi;                  // 0x30
    ULONG64 rdi;
    ULONG64 r8;                   // 0x40
    ULONG64 r9;
    ULONG64 r10;                  // 0x50
    ULONG64 r11;
    ULONG64 r12;                  // 0x60
    ULONG64 r13;
    ULONG64 r14;                  // 0x70
    ULONG64 r15;
    ULONG64 rip;
    ULONG64 erflags;
    XMM_REG xmm[6];

    ULONG64 xCtlRegister;
} REGS, * PREGS;

typedef union _MOV_CR_QUALIFICATION
{
    ULONG_PTR All;
    struct
    {
        ULONG ControlRegister : 4;
        ULONG AccessType : 2;
        ULONG LMSWOperandType : 1;
        ULONG Reserved1 : 1;
        ULONG Register : 4;
        ULONG Reserved2 : 4;
        ULONG LMSWSourceData : 16;
        ULONG Reserved3;
    } Fields;
} MOV_CR_QUALIFICATION, * PMOV_CR_QUALIFICATION;

typedef enum _VMX_ERROR
{
    VMX_ERROR_CODE_SUCCESS = 0,
    VMX_ERROR_CODE_FAILED_WITH_STATUS = 1,
    VMX_ERROR_CODE_FAILED = 2
} VMX_ERROR;

typedef union _PROCESSOR_RUN_INFO {
    DWORD64 Flags;

    struct {
        DWORD64 dwProcessorMask : 63;
        DWORD64 bHighIrql : 1;
    };
} PROCESSOR_RUN_INFO, * PPROCESSOR_RUN_INFO;

typedef struct _DESCRIPTOR
{
    USHORT Pad;
    USHORT Limit;
    ULONG Base;
} KDESCRIPTOR, * PKDESCRIPTOR;

//Keep in mind that inline functions need to be defined in header files
namespace CPU {
    extern bool bCETSupported;
    extern bool bIntelCPU;
    constexpr size_t szEndFlag = 0x53746f7056697274; //StopVirt in ASCII
    constexpr DWORD32 chInterfaceID = 'SKLb';

    extern "C" NTSTATUS CPUIDVmCall(ULONG64 ulCallNum, ULONG64 ulOpt1, ULONG64 ulOpt2, ULONG64 key);
    __forceinline bool IsHypervOn(ULONG64 key = 0)
    {
        INT32 CpuInfo[4] = { 0 };
        __cpuidex(CpuInfo, 'Hypr', 'Chck');

        if (CpuInfo[0] != 'Yass')
        {
            return CPUIDVmCall(0x1 /*VMCALL_TEST*/, 0, 0, key) == 'ImON';
        }
        return true;
    }

#pragma warning (disable:4309)
    __forceinline void WriteAbsJmp(PCHAR pHook, size_t pTarget)
    {
        ///* mov r11, Target */
        //pHook[0] = 0x49;
        //pHook[1] = 0xBA;
        //
        ///* Target */
        //*((PSIZE_T)&pHook[2]) = pTarget;
        //
        ///* push r11 */
        //pHook[10] = 0x41;
        //pHook[11] = 0x52;
        //
        ///* ret */
        //pHook[12] = 0xC3;

        /*
            0:  68 ad de ad de          push   0xffffffffdeaddead
            5:  c7 44 24 fc da da da    mov    DWORD PTR [rsp+0x4],0xdadadada
            c:  da
            d:  c3                      ret
        */
        memcpy(pHook, "\x68\xAD\xDE\xAD\xDE\xC7\x44\x24\x04\xDA\xDA\xDA\xDA\xC3", sizeof("\x68\xAD\xDE\xAD\xDE\xC7\x44\x24\x04\xDA\xDA\xDA\xDA\xC3") - 1);
        *((PDWORD32)&pHook[1]) = (DWORD32)pTarget;
        pTarget = pTarget >> 32;
        *((PDWORD32)&pHook[9]) = (DWORD32)pTarget;
    }

#ifdef _KERNEL_MODE
    VOID Init();

    bool IsIntelCPU();

    VOID swapEndianess(PCHAR dest, PCHAR src, SIZE_T strlen);
    VOID invertEndianess(PCHAR src);

    extern "C" DWORD64 MSRRead(ULONG32 rcx);
    extern "C" void MSRWrite(ULONG32 rcx, ULONG64 ulVal);

    DWORD64 GetTSCRate();
    bool GetTSCRateAbnormal();

    bool DetectMPERFBasic();

    bool DetectAPERFBasic();

    bool DetectTimeStampBasic();

    bool DetectMPERFAdvanced();

    bool DetectAPERFAdvanced();

    bool DetectTimeStampAdvanced();

    bool IsVmwareReservedMSR(ULONG64 msr);
    bool IsCPUZReservedMSR(ULONG64 msr);

    UCHAR GetCPUIndex(bool bVmxRoot = false);
    DWORD32 GetCPUCount();
    ULONG AdjustControls(ULONG Ctl, ULONG Msr, bool bSet = true);


    template<typename F, typename ... C>
    NTSTATUS RunOnAllCPUs(F callback, PROCESSOR_RUN_INFO& procInfo, C&& ... params) {
        KIRQL oldIrql = KeGetCurrentIrql();
        NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
        DWORD32 dwCores = GetCPUCount();

        for (DWORD32 i = 0; i < dwCores; i++) {
            KAFFINITY affinity = 1ull << i;
            KeSetSystemAffinityThread(affinity);

            if (procInfo.bHighIrql)
                KeRaiseIrql(HIGH_LEVEL, &oldIrql);

            ntStatus = callback(params ...);


            if (procInfo.bHighIrql)
                KeLowerIrql(oldIrql);

            if (!NT_SUCCESS(ntStatus)) {
                goto _end;
            }
        }

    _end:
        KeRevertToUserAffinityThread();
        return ntStatus;
    };

    extern "C" ULONG64 GetGdtBase();
    extern "C" USHORT  GetGdtLimit();
    extern "C" ULONG64 GetIdtBase();
    extern "C" USHORT  GetIdtLimit();

    extern "C" USHORT  GetCs();
    extern "C" USHORT  GetDs();
    extern "C" USHORT  GetEs();
    extern "C" USHORT  GetFs();
    extern "C" USHORT  GetSs();
    extern "C" USHORT  GetGs();
    extern "C" USHORT  GetTr();
    extern "C" USHORT  GetLdtr();
    extern "C" ULONG64 GetRflags();

    extern "C" void SetCs(USHORT);
    extern "C" void SetDs(USHORT);
    extern "C" void SetEs(USHORT);
    extern "C" void SetFs(USHORT);
    extern "C" void SetSs(USHORT);
    extern "C" void SetGs(USHORT);
    extern "C" void SetTr(USHORT);
    extern "C" void SetLdtr(USHORT);
    extern "C" void SetRflags(ULONG64);

    extern "C" void GetGdt(PVOID pGdt);
    extern "C" void SetGdt(PVOID pGdt);
    extern "C" void GetIdt(PVOID pIdt);
    extern "C" void SetIdt(PVOID pIdt);
    extern "C" void SetIF(bool bSet);

    extern "C" VMX_ERROR InveptContext(ULONG Type, PVOID Descriptors);
    extern "C" VMX_ERROR InvalidateVPID(ULONG Type, PVOID Descriptors);
    extern "C" void ClearTLB();
    extern "C" void Jump(PVOID rip);
    extern "C" void ChangeRSP(size_t rsp);

    extern "C" NTSTATUS VmxVMCALL(ULONG64 ulCallNum, ULONG64 ulOpt1, ULONG64 ulOpt2, ULONG64 key);

    extern "C" void SaveContext(PREGS pContext);
    extern "C" void RestoreContext(PREGS pContext);

    bool IsMsrLocked();
    extern "C" bool IsVmxSupported();
    extern "C" bool IsVmxEnabled();
    extern "C" bool EnableVmx();
    extern "C" bool DisableVmx();

    bool CheckForSvmFeatures();
    bool IsVirtSupported();

    bool DisableWriteProtection();
    void EnableWriteProtection(bool bEnableCET);
    bool DisableCET();
    void EnableCET();
    void DisableInterrupts();
    void EnableInterrupts();

    VOID* WriteBackDataCacheRange(VOID* Address, SIZE_T  Length);

    template<typename T>
    T MmIoRead(DWORD64 pMmio) {
        PHYSICAL_ADDRESS pa = { 0 };
        pa.QuadPart = pMmio;
        PVOID pRegister = MmMapIoSpace(pa, sizeof(T), MEMORY_CACHING_TYPE::MmNonCached);

        T ret = *(T*)pRegister;

        MmUnmapIoSpace(pRegister, sizeof(T));

        return ret;
    }

    template<typename T>
    void MmIoWrite(DWORD64 pMmio, T value) {
        PHYSICAL_ADDRESS pa = { 0 };
        pa.QuadPart = pMmio;
        PVOID pRegister = MmMapIoSpace(pa, sizeof(T), MEMORY_CACHING_TYPE::MmNonCached);

        *(T*)pRegister = value;

        MmUnmapIoSpace(pRegister, sizeof(T));
    }
#endif
}
