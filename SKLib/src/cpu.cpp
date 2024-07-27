#include "cpu.h"
#include <ia32.h>
#include <Arch/Msr.h>
#include <threading.h>

#define TIMING_CHECKS_ITERATIONS 0x100

bool CPU::bCETSupported = false;
bool CPU::bIntelCPU = false;

VOID CPU::Init()
{
    CR4 cr4 = { 0 };
    cr4.Flags = __readcr4();
    bCETSupported = cr4.CETEnabled;

    bIntelCPU = IsIntelCPU();
}

bool CPU::IsIntelCPU()
{
    bool isIntel = Cpuid::Cpuid::query<Cpuid::Generic::MaximumFunctionNumberAndVendorId>()->isIntel();
    if (isIntel)
        DbgMsg("[CPU] Is Intel");
    else
        DbgMsg("[CPU] Is not Intel");
    return isIntel;
}

VOID CPU::swapEndianess(PCHAR dest, PCHAR src, SIZE_T strlen)
{
    for (size_t i = 0; i < strlen; i += 2) {
        dest[i] = src[i + 1];
        dest[i + 1] = src[i];
    }
}

VOID CPU::invertEndianess(PCHAR src) {
    size_t strLen = strlen(src);
    char* pBuf = (char*)cpp::kMalloc(strLen, PAGE_READWRITE);

    for (LONG64 i = strLen - 1; i >= 0; --i) {
        pBuf[i] = src[strLen - 1 - i];
    }
    RtlCopyMemory(src, pBuf, strLen);
    cpp::kFree(pBuf);
}

DWORD64 CPU::GetTSCRate() {
    bool bRes = false;
    ULONG64 avg{ 0 };
    int data[4]{ -1 };

    _disable();

    for (size_t i = 0; i < TIMING_CHECKS_ITERATIONS; i++)
    {
        ULONG64 tick1 = __rdtsc();
        __cpuid(data, 0); //call vm-exit
        ULONG64 tick2 = __rdtsc();
        if (!tick1 && !tick2)
        {
            bRes = true;
            break;
        }
        else if (tick1 > tick2) {
            bRes = true;
            break;
        }
        avg += tick2 - tick1;
    }

    _enable();

    avg /= TIMING_CHECKS_ITERATIONS;
    DbgMsg("[DETECTOR] Time Stamp average: 0x%llx", avg);
    bRes = (350 < avg) || (0x33 > avg);

    DbgMsg("[DETECTOR] Time Stamp basic detection result: %s", bRes ? "detected" : "undetected");

    return avg;
}

bool CPU::GetTSCRateAbnormal()
{
    bool bRes = DetectMPERFBasic();
    bRes |= DetectAPERFBasic();
    bRes |= DetectTimeStampBasic();
    bRes |= DetectMPERFAdvanced();
    bRes |= DetectAPERFAdvanced();
    bRes |= DetectTimeStampAdvanced();

    return bRes;
}

bool CPU::DetectMPERFBasic()
{
    bool bRes = false;
    ULONG64 avg{ 0 };
    int data[4]{ -1 };

    for (size_t i = 0; i < TIMING_CHECKS_ITERATIONS; i++)
    {
        ULONG64 tick1 = __readmsr(IA32_MPERF_MSR);
        __cpuid(data, 0); //call vm-exit
        ULONG64 tick2 = __readmsr(IA32_MPERF_MSR);
        if (!tick1 && !tick2)
        {
            bRes = true;
            goto _end;
        }
        else if (tick1 > tick2) {
            avg = 0;
            DbgMsg("[DETECTOR] Detected backwards TSC at iteration 0x%llx: 0x%llx, 0x%llx -> 0x%llx", i, tick1, tick2, tick2 - tick1);
            break;
        }
        avg += (tick2 - tick1);
    }
    avg /= TIMING_CHECKS_ITERATIONS;
    DbgMsg("[DETECTOR] MPERF average: 0x%llx", avg);
    bRes = (1000 < avg) || (0x33 > avg);
_end:
    DbgMsg("[DETECTOR] MPERF Basic detection result: %s", bRes ? "detected" : "undetected");
    return bRes;
}

bool CPU::DetectAPERFBasic()
{
    bool bRes = false;
    ULONG64 avg{ 0 };
    int data[4]{ -1 };

    for (size_t i = 0; i < TIMING_CHECKS_ITERATIONS; i++)
    {
        ULONG64 tick1 = __readmsr(IA32_APERF_MSR);
        __cpuid(data, 0); //call vm-exit
        ULONG64 tick2 = __readmsr(IA32_APERF_MSR);
        if (!tick1 && !tick2)
        {
            bRes = true;
            goto _end;
        }
        else if (tick1 > tick2) {
            avg = 0;
            DbgMsg("[DETECTOR] Detected backwards TSC at iteration 0x%llx: 0x%llx, 0x%llx -> 0x%llx", i, tick1, tick2, tick2 - tick1);
            break;
        }
        avg += (tick2 - tick1);
    }
    avg /= TIMING_CHECKS_ITERATIONS;
    DbgMsg("[DETECTOR] APERF average: 0x%llx", avg);
    bRes = (1000 < avg) || (0x33 > avg);
_end:
    DbgMsg("[DETECTOR] APERF Basic detection result: %s", bRes ? "detected" : "undetected");
    return bRes;
}

bool CPU::DetectTimeStampBasic()
{
    bool bRes = false;
    ULONG64 avg{ 0 };
    int data[4]{ -1 };

    for (size_t i = 0; i < TIMING_CHECKS_ITERATIONS; i++)
    {
        ULONG64 tick1 = __rdtsc();
        __cpuid(data, 0); //call vm-exit
        ULONG64 tick2 = __rdtsc();
        if (!tick1 && !tick2)
        {
            bRes = true;
            break;
        }
        else if (tick1 > tick2) {
            avg = 0;
            DbgMsg("[DETECTOR] Detected backwards TSC at iteration 0x%llx: 0x%llx, 0x%llx -> 0x%llx", i, tick1, tick2, tick2 - tick1);
            break;
        }
        avg += tick2 - tick1;
    }

    avg /= TIMING_CHECKS_ITERATIONS;
    DbgMsg("[DETECTOR] Time Stamp average: 0x%llx", avg);
    bRes = (1000 < avg) || (0x33 > avg);

    DbgMsg("[DETECTOR] Time Stamp basic detection result: %s", bRes ? "detected" : "undetected");
    return bRes;
}

bool CPU::DetectMPERFAdvanced()
{
    bool bRes = false;
    ULONG64 avg{ 0 };
    int data[4]{ -1 };

    KIRQL irql;
    KeRaiseIrql(HIGH_LEVEL, &irql);

    for (size_t i = 0; i < TIMING_CHECKS_ITERATIONS; i++)
    {
        ULONG64 tick1 = __readmsr(IA32_MPERF_MSR);
        __cpuid(data, 0); //call vm-exit
        ULONG64 tick2 = __readmsr(IA32_MPERF_MSR);
        if (!tick1 && !tick2)
        {
            bRes = true;
            goto _end;
        }
        else if (tick1 > tick2) {
            avg = 0;
            KeLowerIrql(irql);
            DbgMsg("[DETECTOR] Detected backwards TSC at iteration 0x%llx: 0x%llx, 0x%llx -> 0x%llx", i, tick1, tick2, tick2 - tick1);
            KeRaiseIrql(HIGH_LEVEL, &irql);
            break;
        }
        avg += (tick2 - tick1);
    }
    avg /= TIMING_CHECKS_ITERATIONS;
    DbgMsg("[DETECTOR] MPERF average: 0x%llx", avg);
    bRes = (1000 < avg) || (0x33 > avg);
_end:
    KeLowerIrql(irql);
    DbgMsg("[DETECTOR] MPERF Advanced detection result: %s", bRes ? "detected" : "undetected");
    return bRes;
}

bool CPU::DetectAPERFAdvanced()
{
    bool bRes = false;
    ULONG64 avg{ 0 };
    int data[4]{ -1 };

    KIRQL irql;
    KeRaiseIrql(HIGH_LEVEL, &irql);

    for (size_t i = 0; i < TIMING_CHECKS_ITERATIONS; i++)
    {
        ULONG64 tick1 = __readmsr(IA32_APERF_MSR);
        __cpuid(data, 0); //call vm-exit
        ULONG64 tick2 = __readmsr(IA32_APERF_MSR);
        if (!tick1 && !tick2)
        {
            bRes = true;
            goto _end;
        }
        else if (tick1 > tick2) {
            avg = 0;
            KeLowerIrql(irql);
            DbgMsg("[DETECTOR] Detected backwards TSC at iteration 0x%llx: 0x%llx, 0x%llx -> 0x%llx", i, tick1, tick2, tick2 - tick1);
            KeRaiseIrql(HIGH_LEVEL, &irql);
            break;
        }
        avg += (tick2 - tick1);
    }
    avg /= TIMING_CHECKS_ITERATIONS;
    DbgMsg("[DETECTOR] APERF average: 0x%llx", avg);
    bRes = (1000 < avg) || (0x33 > avg);
_end:
    KeLowerIrql(irql);
    DbgMsg("[DETECTOR] APERF Advanced detection result: %s", bRes ? "detected" : "undetected");
    return bRes;
}

bool CPU::DetectTimeStampAdvanced()
{
    bool bRes = false;
    ULONG64 avg{ 0 };
    int data[4]{ -1 };

    KIRQL irql;
    KeRaiseIrql(HIGH_LEVEL, &irql);

    for (size_t i = 0; i < TIMING_CHECKS_ITERATIONS; i++)
    {
        ULONG64 tick1 = __rdtsc();
        __cpuid(data, 0); //call vm-exit
        ULONG64 tick2 = __rdtsc();
        if (!tick1 && !tick2)
        {
            bRes = true;
            break;
        }
        else if (tick1 > tick2) {
            avg = 0;
            KeLowerIrql(irql);
            DbgMsg("[DETECTOR] Detected backwards TSC at iteration 0x%llx: 0x%llx, 0x%llx -> 0x%llx", i, tick1, tick2, tick2 - tick1);
            KeRaiseIrql(HIGH_LEVEL, &irql);
            break;
        }
        avg += tick2 - tick1;
    }

    KeLowerIrql(irql);

    avg /= TIMING_CHECKS_ITERATIONS;
    DbgMsg("[DETECTOR] Time Stamp average: 0x%llx", avg);
    bRes = (1000 < avg) || (0x33 > avg);

    DbgMsg("[DETECTOR] Time Stamp Advanced detection result: %s", bRes ? "detected" : "undetected");
    return bRes;
}

bool CPU::IsVmwareReservedMSR(ULONG64 msr)
{
    return msr == MSR_IDLE_PROCESSOR_CYCLES ||
        msr == MSR_IDLE_MAX_TIME ||
        msr == MSR_IDLE_MAX_TIME2 ||
        msr == MSR_POWER_STATE;
}

bool CPU::IsCPUZReservedMSR(ULONG64 msr) {
    return msr == 0x31
        || msr == 0x39
        || msr == 0x1ae
        || msr == 0x1af
        || msr == 0x602;
}

UCHAR procMap[256] = { 0 };

UCHAR CPU::GetCPUIndex(bool bVmxRoot) {
    DWORD32 result = Cpuid::Cpuid::query<Cpuid::Generic::FeatureInformation>()->InitialApicId;

    if(!bVmxRoot)
        procMap[result] = (UCHAR)KeGetCurrentProcessorIndex();

    return procMap[result];
}

DWORD32 CPU::GetCPUCount()
{
    static auto cpuCount = min(KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS), 64);
    return cpuCount;
}

ULONG CPU::AdjustControls(ULONG Ctl, ULONG Msr, bool bSet)
{
    MSR MsrValue = { 0 };

    MsrValue.Content = __readmsr(Msr);
    if (!bSet)
        Ctl = ~Ctl;

    Ctl &= MsrValue.High;     /* bit == 0 in high word ==> must be zero */
    Ctl |= MsrValue.Low;      /* bit == 1 in low word  ==> must be one  */
    return Ctl;
}

bool CPU::CheckForSvmFeatures()
{
    bool svmSupported = Cpuid::Cpuid::query<Cpuid::Amd::ExtendedFeatureInformation>()->SVM;
    bool nptSupported = Cpuid::Cpuid::query<Cpuid::Amd::SvmFeatures>()->NestedPaging;
    bool tlbSupported = Cpuid::Cpuid::query<Cpuid::Amd::SvmFeatures>()->FlushByAcid;
    bool canSvmEnable = !(Msr::Msr::read<Msr::Amd::VmCr>()->SVMDIS);
    bool supported = svmSupported && nptSupported && canSvmEnable && tlbSupported;
    return supported;
}

bool CPU::IsVirtSupported()
{
    if (bIntelCPU) {
        auto msr = __readmsr(IA32_FEATURE_CONTROL);
        CPU::EnableVmx();
        if (!CPU::IsVmxEnabled()) {
            return false;
        }
        if (!bitmap::GetBit(&msr, 2)) {
            if (!bitmap::GetBit(&msr, 0)) {
                bitmap::SetBit(&msr, 0, true);
                bitmap::SetBit(&msr, 1, true);
                bitmap::SetBit(&msr, 2, true);
                __writemsr(IA32_FEATURE_CONTROL, msr);
            }
            else {
                return false;
            }
        }

        return true;
    }
    else {
        return CheckForSvmFeatures();
    }
}

bool CPU::DisableWriteProtection() {
    bool bRes = DisableCET();
    CR0 cr0;
    cr0.Flags = __readcr0();
    cr0.WriteProtect = false;
    __writecr0(cr0.Flags);
    return bRes;
}

void CPU::EnableWriteProtection(bool bEnableCET) {
    CR0 cr0;
    cr0.Flags = __readcr0();
    cr0.WriteProtect = true;
    __writecr0(cr0.Flags);
    if(bEnableCET)
        EnableCET();
}

bool CPU::DisableCET()
{
    if (!bCETSupported)
        return false;
    CR4 cr4 = { 0 };
    cr4.Flags = __readcr4();
    bool bRes = cr4.CETEnabled;
    if (bRes) {
        cr4.CETEnabled = false;
        __writecr4(cr4.Flags);
    }
    return bRes;
}

void CPU::EnableCET()
{
    if (!bCETSupported)
        return;
    CR4 cr4 = { 0 };
    cr4.Flags = __readcr4();
    cr4.CETEnabled = true;
    __writecr4(cr4.Flags);
}

void CPU::DisableInterrupts()
{
    _disable();
}

void CPU::EnableInterrupts()
{
    _enable();
}

VOID* CPU::WriteBackDataCacheRange(VOID* Address, SIZE_T Length)
{
    int  CpuIdData[4];
    SIZE_T   CacheLineSize;
    SIZE_T   Start;
    SIZE_T   End;

    if (Length == 0) {
        return Address;
    }

    ASSERT((Length - 1) <= (MAX_ADDRESS - (SIZE_T)Address));

    //
    // If the CPU does not support CLFLUSH instruction,
    // then promote flush range to flush entire cache.
    //
    __cpuid(CpuIdData, 0x1);
    if ((CpuIdData[4] & (1ull << 19)) == 0) {
        __wbinvd();
        return Address;
    }

    //
    // Cache line size is 8 * Bits 15-08 of EBX returned from CPUID 01H
    //
    CacheLineSize = (CpuIdData[2] & 0xff00) >> 5;

    Start = (SIZE_T)Address;
    //
    // Calculate the cache line alignment
    //
    End = (Start + Length + (CacheLineSize - 1)) & ~(CacheLineSize - 1);
    Start &= ~((SIZE_T)CacheLineSize - 1);

    while (Start < End) {
        _mm_clflush((VOID*)Start);
        Start = Start + CacheLineSize;
    }

    return Address;
}

bool CPU::IsMsrLocked()
{
    IA32_FEATURE_CONTROL_MSR Control = { 0 };
    Control.All = __readmsr(MSR_IA32_FEATURE_CONTROL);

    if (Control.Fields.Lock == 0)
    {
        return FALSE;
    }

    DbgMsg("[VMX] MSR is currently locked...");
    return TRUE;
}

#pragma warning (default:4309)
