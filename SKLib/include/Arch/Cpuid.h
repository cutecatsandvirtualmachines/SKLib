#pragma once

extern "C" void __cpuidex(int regs[4], int leaf, int subleaf);

#pragma pack(push, 1)

namespace Cpuid
{



template <auto leaf, auto subleaf = 0>
struct CpuidRequest
{
    static constexpr auto k_leaf = static_cast<unsigned int>(leaf);
    static constexpr auto k_subleaf = static_cast<unsigned int>(subleaf);
};



union RawCpuid
{
    int raw[4]{};
    struct
    {
        unsigned int eax;
        unsigned int ebx;
        unsigned int ecx;
        unsigned int edx;
    } regs;
};



template <typename Layout>
union CpuidLayout
{
    RawCpuid raw;
    Layout layout;

    const Layout* operator -> () const noexcept
    {
        return &layout;
    }

    Layout* operator -> () noexcept
    {
        return &layout;
    }

    const Layout& operator * () const noexcept
    {
        return layout;
    }

    Layout& operator * () noexcept
    {
        return layout;
    }
};



struct Cpuid
{
    static RawCpuid query(const unsigned int leaf, const unsigned int subleaf) noexcept
    {
        RawCpuid layout{};
        __cpuidex(&layout.raw[0], static_cast<int>(leaf), static_cast<int>(subleaf));
        return layout;
    }

    template <typename Layout>
    static CpuidLayout<Layout> query() noexcept
    {
        CpuidLayout<Layout> layout{};
        __cpuidex(&layout.raw.raw[0], static_cast<int>(Layout::k_leaf), static_cast<int>(Layout::k_subleaf));
        return layout;
    }
};



class OpaqueCpuid
{
private:
    RawCpuid m_raw;

public:
    template <typename Layout>
    const Layout& update() noexcept
    {
        m_raw = Cpuid::query(Layout::k_leaf, Layout::k_subleaf);
        return *reinterpret_cast<const Layout*>(&m_raw);
    }

    const RawCpuid& update(const unsigned int leaf, const unsigned int subleaf) noexcept
    {
        m_raw = Cpuid::query(leaf, subleaf);
        return m_raw;
    }
};



template <auto leaf>
struct SubleafMatcher
{
    enum class Subleaf
    {
        None
    };
};

template <auto leaf>
using Subleaf = typename SubleafMatcher<leaf>::Subleaf;



namespace Generic
{



// EAX values:
enum class GenericLeaf : unsigned int
{
    // Standard CPUID functions:
    MaximumFunctionNumberAndVendorId = 0x00000000,
    FeatureInformation = 0x00000001,
    MonitorMwaitParameters = 0x00000005,
    ThermalPowerManagement = 0x00000006,
    StructuredExtendedFeatureEnumeration = 0x00000007,

    // Extended CPUID functions:
    MaximumExtendedFunctionNumberAndVendorId = 0x80000000,
    ExtendedFeatureInformation = 0x80000001,
    ProcessorBrandString0 = 0x80000002,
    ProcessorBrandString1 = 0x80000003,
    ProcessorBrandString2 = 0x80000004,
};



namespace Layout
{



struct MaximumFunctionNumberAndVendorId
{
    unsigned int LargestStandardFunctionNumber;
    unsigned int VendorPart1; // 'uneG' || 'htuA'
    unsigned int VendorPart3; // 'letn' || 'DMAc' --> 'GenuineIntel' or 'AuthenticAMD' (EAX + EDX + ECX)
    unsigned int VendorPart2; // 'Ieni' || 'itne'

    bool isIntel() const
    {
        // GenuineIntel:
        return (VendorPart1 == 'uneG')
            && (VendorPart2 == 'Ieni')
            && (VendorPart3 == 'letn');
    }

    bool isAmd() const
    {
        // AuthenticAMD:
        return (VendorPart1 == 'htuA')
            && (VendorPart2 == 'itne')
            && (VendorPart3 == 'DMAc');
    }
};

struct MaximumExtendedFunctionNumberAndVendorId
{
    unsigned int LargestExtendedFunctionNumber;
    unsigned int VendorPart1; // 'uneG' || 'htuA'
    unsigned int VendorPart3; // 'letn' || 'DMAc' --> 'GenuineIntel' or 'AuthenticAMD' (EAX + EDX + ECX)
    unsigned int VendorPart2; // 'Ieni' || 'itne'

    bool isIntel() const
    {
        // GenuineIntel:
        return (VendorPart1 == 'uneG')
            && (VendorPart2 == 'Ieni')
            && (VendorPart3 == 'letn');
    }

    bool isAmd() const
    {
        // AuthenticAMD:
        return (VendorPart1 == 'htuA')
            && (VendorPart2 == 'itne')
            && (VendorPart3 == 'DMAc');
    }
};

struct FeatureInformation
{
    // EAX:
    unsigned int Stepping : 4;
    unsigned int Model : 4;
    unsigned int FamilyId : 4;
    unsigned int : 4;
    unsigned int ExtendedModelId : 4;
    unsigned int ExtendedFamilyId : 8;
    unsigned int : 4;

    // EBX:
    unsigned int BrandIndex : 8;
    unsigned int ClflushLineSize : 8; // Value * 8 = cache line size in bytes
    unsigned int LogicalProcessorCount : 8; // Valid only if CPUID.1.EDX.HTT == 1
    unsigned int InitialApicId : 8;

    // ECX:
    unsigned int SSE3 : 1; // 0
    unsigned int PCLMULQDQ : 1; // 1 
    unsigned int : 1; // 2 
    unsigned int MONITOR : 1; // 3
    unsigned int : 1; // 4
    unsigned int : 1; // 5
    unsigned int : 1; // 6
    unsigned int : 1; // 7
    unsigned int : 1; // 8
    unsigned int SSSE3 : 1;
    unsigned int : 2;
    unsigned int FMA : 1;
    unsigned int CMPXCHG16B : 1;
    unsigned int : 5;
    unsigned int SSE41 : 1;
    unsigned int SSE42 : 1;
    unsigned int : 1;
    unsigned int MOVBE : 1;
    unsigned int POPCNT : 1;
    unsigned int : 1;
    unsigned int AES : 1;
    unsigned int XSAVE : 1;
    unsigned int OSXSAVE : 1;
    unsigned int AVX : 1;
    unsigned int F16C : 1;
    unsigned int RDRAND : 1;
    unsigned int ReservedForHvGuestStatus : 1; // Reserved for use by hypervisor to indicate guest status

    // EDX:
    unsigned int FPU : 1;
    unsigned int VME : 1; // Virtual 8086-mode enhancements (including CR4.VME, CR4.PVI, EFLAGS.VIF and EFLAGS.VIP, etc.)
    unsigned int DE : 1; // Debugging extensions
    unsigned int PSE : 1; // Page size extension
    unsigned int TSC : 1; // Time stamp counter
    unsigned int MSR : 1; // RDMSR/WRMSR support
    unsigned int PAE : 1; // Physical address extensions support
    unsigned int MCE : 1; // Machine check exception
    unsigned int CMPXCHG8B : 1;
    unsigned int APIC : 1;
    unsigned int : 1;
    unsigned int SysEnterSysExit : 1; // SYSENTER/SYSEXIT instructions support
    unsigned int MTRR : 1; // Memory-Type Range Registers support
    unsigned int PGE : 1; // Page global bit (CR4.PGE bit controls this feature)
    unsigned int MCA : 1; // Machine check architecture
    unsigned int CMOV : 1; // Conditional move instruction support
    unsigned int PAT : 1; // Page attribute table
    unsigned int PSE36 : 1; // 36-bit page size extension
    unsigned int : 1;
    unsigned int CLFSH : 1; // CLFLUSH instruction support
    unsigned int : 3;
    unsigned int MMX : 1;
    unsigned int FXSR : 1; // FXSAVE and FXRSTOR support
    unsigned int SSE : 1;
    unsigned int SSE2 : 1;
    unsigned int : 1;
    unsigned int HTT : 1; // Max APIC IDs reserved field is Valid (CPUID.1.EBX.LogicalProcessorCount is valid)
    unsigned int : 3;
};

struct ExtendedFeatureInformation
{
    // EAX:
    unsigned int Stepping : 4;
    unsigned int Model : 4;
    unsigned int FamilyId : 4;
    unsigned int : 4;
    unsigned int ExtendedModelId : 4;
    unsigned int ExtendedFamilyId : 8;
    unsigned int : 4;

    // EBX:
    unsigned int : 32;

    // ECX:
    unsigned int LahfSahf : 1;
    unsigned int : 4;
    unsigned int LZCNT : 1;
    unsigned int : 2;
    unsigned int PREFETCHW : 1;
    unsigned int : 23;

    // EDX:
    unsigned int : 11;
    unsigned int SysCallSysRet : 1;
    unsigned int : 8;
    unsigned int NX : 1;
    unsigned int : 5;
    unsigned int Page1Gb : 1; // 1-Gb large page support
    unsigned int RDTSCP : 1;
    unsigned int : 1;
    unsigned int LongMode : 1; // 64-bit mode
    unsigned int : 2;
};

struct ProcessorBrandString0
{
    unsigned int Part0;
    unsigned int Part1;
    unsigned int Part2;
    unsigned int Part3;
};

struct ProcessorBrandString1
{
    unsigned int Part4;
    unsigned int Part5;
    unsigned int Part6;
    unsigned int Part7;
};

struct ProcessorBrandString2
{
    unsigned int Part8;
    unsigned int Part9;
    unsigned int Part10;
    unsigned int Part11;
};



} // namespace Layout



struct MaximumFunctionNumberAndVendorId
    : public Layout::MaximumFunctionNumberAndVendorId
    , public CpuidRequest<GenericLeaf::MaximumFunctionNumberAndVendorId>
{
};

struct MaximumExtendedFunctionNumberAndVendorId
    : public Layout::MaximumExtendedFunctionNumberAndVendorId
    , public CpuidRequest<GenericLeaf::MaximumExtendedFunctionNumberAndVendorId>
{
};

struct FeatureInformation
    : public Layout::FeatureInformation
    , public CpuidRequest<GenericLeaf::FeatureInformation>
{
};

struct ExtendedFeatureInformation
    : public Layout::ExtendedFeatureInformation
    , public CpuidRequest<GenericLeaf::ExtendedFeatureInformation>
{
};

struct ProcessorBrandString0
    : public Layout::ProcessorBrandString0
    , public CpuidRequest<GenericLeaf::ProcessorBrandString0>
{
};

struct ProcessorBrandString1
    : public Layout::ProcessorBrandString1
    , public CpuidRequest<GenericLeaf::ProcessorBrandString1>
{
};

struct ProcessorBrandString2
    : public Layout::ProcessorBrandString2
    , public CpuidRequest<GenericLeaf::ProcessorBrandString2>
{
};



} // namespace Generic



namespace Intel
{



// EAX values:
enum class IntelLeaf : unsigned int
{
    // Standard CPUID functions:
    MaximumFunctionNumberAndVendorId = 0x00000000,
    FeatureInformation = 0x00000001,
    CacheDescriptors = 0x00000002,
    ProcessorSerialNumber = 0x00000003,
    DeterministicCacheParameters = 0x00000004,
    MonitorMwaitParameters = 0x00000005,
    ThermalPowerManagement = 0x00000006,
    StructuredExtendedFeatureEnumeration = 0x00000007,
    // 0x00000008 is reserved
    DirectCacheAccessParameters = 0x00000009,
    ArchitecturalPerformanceMonitorFeatures = 0x0000000A,
    X2ApicFeatures = 0x0000000B,
    // 0x0000000C is reserved
    XsaveFeatures = 0x0000000D,

    // Extended CPUID functions:
    LargestExtendedFunction = 0x80000000,
    ExtendedFeatureInformation = 0x80000001,
    ProcessorBrandString0 = 0x80000002,
    ProcessorBrandString1 = 0x80000003,
    ProcessorBrandString2 = 0x80000004,
    // 0x80000005 is reserved
    ExtendedL2CacheFeatures = 0x80000006,
    AdvancedPowerManagement = 0x80000007,
    VirtualAndPhysicalAddressSizes = 0x80000008
};



namespace Layout
{



struct FeatureInformation
{
    // EAX:
    unsigned int Stepping : 4;
    unsigned int Model : 4;
    unsigned int FamilyId : 4;
    unsigned int ProcessorType : 2;
    unsigned int : 2;
    unsigned int ExtendedModelId : 4;
    unsigned int ExtendedFamilyId : 8;
    unsigned int : 4;

    // EBX:
    unsigned int BrandIndex : 8;
    unsigned int ClflushLineSize : 8; // Value * 8 = cache line size in bytes
    unsigned int LogicalProcessorCount : 8; // Valid only if CPUID.1.EDX.HTT == 1
    unsigned int InitialApicId : 8;

    // ECX:
    unsigned int SSE3 : 1;
    unsigned int PCLMULQDQ : 1;
    unsigned int DTES64 : 1; // 64-bit DS area
    unsigned int MONITOR : 1;
    unsigned int DS_CPL : 1; // CPL qualified debug store
    unsigned int VMX : 1;
    unsigned int SMX : 1;
    unsigned int EIST : 1; // Enhanced Intel Speed-Step
    unsigned int TM2 : 1; // Thermal monitor 2
    unsigned int SSSE3 : 1;
    unsigned int CNXT_ID : 1; // L1 context ID
    unsigned int SDBG : 1; // Support of IA32_DEBUG_INTERFACE MSR
    unsigned int FMA : 1;
    unsigned int CMPXCHG16B : 1;
    unsigned int xTPRUpdateControl : 1; // Support of IA32_MISC_ENABLE changing
    unsigned int PDCM : 1; // Perfmon and debug capability: support of MSR IA32_PERF_CAPABILITIES
    unsigned int : 1;
    unsigned int PCID : 1; // Process-context identifiers: support of setting the CR4.PCIDE to 1
    unsigned int DSA : 1; // Ability to prefetch data from a memory mapped device
    unsigned int SSE41 : 1;
    unsigned int SSE42 : 1;
    unsigned int x2APIC : 1; // Support of x2APIC feature
    unsigned int MOVBE : 1;
    unsigned int POPCNT : 1;
    unsigned int TSCDeadline : 1; // Indicates that the processor's local APIC timer supports one-shot operation using a TSC deadline value
    unsigned int AESNI : 1;
    unsigned int XSAVE : 1;
    unsigned int OSXSAVE : 1;
    unsigned int AVX : 1;
    unsigned int F16C : 1;
    unsigned int RDRAND : 1;
    unsigned int NotUsed : 1; // Always returns 0

    // EDX:
    unsigned int FPU : 1;
    unsigned int VME : 1; // Virtual 8086-mode enhancements (including CR4.VME, CR4.PVI, EFLAGS.VIF and EFLAGS.VIP, etc.)
    unsigned int DE : 1; // Debugging extensions
    unsigned int PSE : 1; // Page size extension
    unsigned int TSC : 1; // Time stamp counter
    unsigned int MSR : 1; // RDMSR/WRMSR support
    unsigned int PAE : 1; // Physical address extensions support
    unsigned int MCE : 1; // Machine check exception
    unsigned int CX8 : 1; // CMPXCHG8B
    unsigned int APIC : 1;
    unsigned int : 1;
    unsigned int SEP : 1; // SYSENTER/SYSEXIT instructions support
    unsigned int MTRR : 1; // Memory-Type Range Registers support
    unsigned int PGE : 1; // Page global bit (CR4.PGE bit controls this feature)
    unsigned int MCA : 1; // Machine check architecture
    unsigned int CMOV : 1; // Conditional move instruction support
    unsigned int PAT : 1; // Page attribute table
    unsigned int PSE36 : 1; // 36-bit page size extension
    unsigned int PSN : 1; // Support of 96-bit processor serial number
    unsigned int CLFSH : 1; // CLFLUSH instruction support
    unsigned int : 1;
    unsigned int DS : 1; // Debug store
    unsigned int ACPI : 1; // Thermal Monitor and Software Controlled Clock Facilities
    unsigned int MMX : 1;
    unsigned int FXSR : 1; // FXSAVE and FXRSTOR support
    unsigned int SSE : 1;
    unsigned int SSE2 : 1;
    unsigned int SS : 1; // Self-snoop
    unsigned int HTT : 1; // Max APIC IDs reserved field is Valid (CPUID.1.EBX.LogicalProcessorCount is valid)
    unsigned int TM : 1; // Thermal monitor
    unsigned int : 1;
    unsigned int PBE : 1; // Pending break enable
};

struct ExtendedFeatureInformation
{
    // EAX:
    unsigned int Stepping : 4;
    unsigned int Model : 4;
    unsigned int FamilyId : 4;
    unsigned int : 4;
    unsigned int ExtendedModelId : 4;
    unsigned int ExtendedFamilyId : 8;
    unsigned int : 4;

    // EBX:
    unsigned int : 32;

    // ECX:
    unsigned int LahfSahf : 1;
    unsigned int : 4;
    unsigned int LZCNT : 1;
    unsigned int : 2;
    unsigned int PREFETCHW : 1;
    unsigned int : 23;

    // EDX:
    unsigned int : 11;
    unsigned int SysCallSysRet : 1;
    unsigned int : 8;
    unsigned int NX : 1;
    unsigned int : 5;
    unsigned int Page1Gb : 1; // 1-Gb large page support
    unsigned int RdtscpIa32TscAux : 1;
    unsigned int : 1;
    unsigned int IA64 : 1; // Intel64 Architecture support
    unsigned int : 2;
};



} // namespace Layout



struct MaximumFunctionNumberAndVendorId
    : public Generic::Layout::MaximumFunctionNumberAndVendorId
    , public CpuidRequest<IntelLeaf::MaximumFunctionNumberAndVendorId>
{
};

struct FeatureInformation
    : public Layout::FeatureInformation
    , public CpuidRequest<IntelLeaf::FeatureInformation>
{
};

struct ExtendedFeatureInformation
    : public Layout::ExtendedFeatureInformation
    , public CpuidRequest<IntelLeaf::ExtendedFeatureInformation>
{
};

struct ProcessorBrandString0
    : public Generic::Layout::ProcessorBrandString0
    , public CpuidRequest<IntelLeaf::ProcessorBrandString0>
{
};

struct ProcessorBrandString1
    : public Generic::Layout::ProcessorBrandString1
    , public CpuidRequest<IntelLeaf::ProcessorBrandString1>
{
};

struct ProcessorBrandString2
    : public Generic::Layout::ProcessorBrandString2
    , public CpuidRequest<IntelLeaf::ProcessorBrandString2>
{
};



} // namespace Intel



namespace Amd
{



// EAX values:
enum class AmdLeaf : unsigned long
{
    // Standard CPUID functions:
    MaximumFunctionNumberAndVendorId = 0x00000000,
    FeatureInformation = 0x00000001,
    // 0x00000002..0x00000004 are reserved
    MonitorMwaitParameters = 0x00000005,
    ThermalPowerManagement = 0x00000006,
    StructuredExtendedFeatureEnumeration = 0x00000007,
    // 0x00000008..0x0000000C are reserved
    ProcessorExtendedStateEnumeration = 0x0000000C,
    // 0x40000000..0x400000FF are reserved for hypervisor use

    // Extended CPUID functions:
    MaximumExtendedFunctionNumberAndVendorId = 0x80000000,
    ExtendedFeatureInformation = 0x80000001,
    ProcessorBrandString0 = 0x80000002,
    ProcessorBrandString1 = 0x80000003,
    ProcessorBrandString2 = 0x80000004,
    L1AndTlb = 0x80000005,
    L2L3Tlb = 0x80000006,
    PowerManagementAndRasCapabilities = 0x80000007,
    CapacityAndExtendedFeatures = 0x80000008,
    // 0x80000009 is reserved
    SvmFeatures = 0x8000000A,
    // 0x8000000B..0x80000018 are reserved
    TlbCharacteristicsFor1GbPages = 0x80000019,
    InstructionOptimizations = 0x8000001A,
    InstructionBasedSamplingCapabilities = 0x8000001B,
    LightweightProfilingCapabilities = 0x8000001C,
    CacheTopologyInformation = 0x8000001D,
    ProcessorTopologyInformation = 0x8000001E,
    EncryptedMemoryCapabilities = 0x8000001F
};



namespace Layout
{



struct ExtendedFeatureInformation
{
    // EAX:
    unsigned int Stepping : 4;
    unsigned int Model : 4;
    unsigned int FamilyId : 4;
    unsigned int : 4;
    unsigned int ExtendedModelId : 4;
    unsigned int ExtendedFamilyId : 8;
    unsigned int : 4;

    // EBX:
    unsigned int BrandId : 16;
    unsigned int : 12;
    unsigned int PkgType : 4;

    // ECX:
    unsigned int LahfSahf : 1;
    unsigned int CmpLegacy : 1; // Core multiprocessing legacy mode
    unsigned int SVM : 1; // Secure virtual machine
    unsigned int ExtApicSpace : 1;
    unsigned int AltMovCr8 : 1; // "lock mov cr0" means "mov cr8"
    unsigned int ABM : 1; // Advanced bit manipulation
    unsigned int SSE4A : 1; // EXTRQ, INSERTQ, MOVNTSS, and MOVNTSD instruction support
    unsigned int MisAlignSse : 1; // Misaligned SSE mode
    unsigned int _3DNowPrefetch : 1; // PREFETCH and PREFETCHW instruction support
    unsigned int OSVW : 1; // OS visible workaround
    unsigned int IBS : 1; // Instruction based sampling
    unsigned int XOP : 1; // Extended operation support
    unsigned int SKINIT : 1; // SKINIT and STGI are supported, independent of the value of MSRC000_0080[SVME]
    unsigned int WDT : 1; // Watchdog time support
    unsigned int : 1;
    unsigned int LWP : 1; // Lightweight profiling support
    unsigned int FMA4 : 1;
    unsigned int : 1;
    unsigned int : 1;
    unsigned int NodeId : 1;
    unsigned int : 1;
    unsigned int TBM : 1; // Trailing bit manipulation instruction support
    unsigned int TopologyExtension : 1;
    unsigned int : 9;

    // EDX:
    unsigned int FPU : 1;
    unsigned int VME : 1; // Virtual 8086-mode enhancements (including CR4.VME, CR4.PVI, EFLAGS.VIF and EFLAGS.VIP, etc.)
    unsigned int DE : 1; // Debugging extensions
    unsigned int PSE : 1; // Page size extension
    unsigned int TSC : 1; // Time stamp counter
    unsigned int MSR : 1; // RDMSR/WRMSR support
    unsigned int PAE : 1; // Physical address extensions support
    unsigned int MCE : 1; // Machine check exception
    unsigned int CMPXCHG8B : 1;
    unsigned int APIC : 1;
    unsigned int : 1;
    unsigned int SysCallSysRet : 1; // SYSCALL/SYSRET instructions support
    unsigned int MTRR : 1; // Memory-Type Range Registers support
    unsigned int PGE : 1; // Page global bit (CR4.PGE bit controls this feature)
    unsigned int MCA : 1; // Machine check architecture
    unsigned int CMOV : 1; // Conditional move instruction support
    unsigned int PAT : 1; // Page attribute table
    unsigned int PSE36 : 1; // 36-bit page size extension
    unsigned int : 2;
    unsigned int NX : 1; // No-execute page protection
    unsigned int : 1;
    unsigned int MmxExt : 1;
    unsigned int MMX : 1;
    unsigned int FXSR : 1; // FXSAVE and FXRSTOR support
    unsigned int FFXSR : 1;  // FXSAVE and FXRSTOR instruction optimizations
    unsigned int Page1Gb : 1; // 1-Gb large page support
    unsigned int RDTSCP : 1;
    unsigned int : 1;
    unsigned int LM : 1; // Long-mode
    unsigned int _3DNowExt : 1;
    unsigned int _3DNow : 1;
};

struct SvmFeatures
{
    unsigned int : 32; // EAX
    unsigned int : 32; // EBX
    unsigned int : 32; // ECX

    // EDX:
    unsigned int NestedPaging : 1;
    unsigned int LbrVirt : 1;
    unsigned int SVML : 1; // SVM Lock
    unsigned int NRIPS : 1; // NRIP Save
    unsigned int TscRateMsr : 1;
    unsigned int VmcbClean : 1;
    unsigned int FlushByAcid : 1;
    unsigned int DecodeAssists : 1;
    unsigned int : 1;
    unsigned int : 1;
    unsigned int PauseFilter : 1; // Pause intercept filter
    unsigned int : 1;
    unsigned int PauseFilterThreshold : 1;
    unsigned int : 19;
};



} // namespace Layout



struct MaximumFunctionNumberAndVendorId
    : public Generic::Layout::MaximumFunctionNumberAndVendorId
    , public CpuidRequest<AmdLeaf::MaximumFunctionNumberAndVendorId>
{
};

struct FeatureInformation
    : public Generic::Layout::FeatureInformation
    , public CpuidRequest<AmdLeaf::FeatureInformation>
{
};

struct ExtendedFeatureInformation
    : public Layout::ExtendedFeatureInformation
    , public CpuidRequest<AmdLeaf::ExtendedFeatureInformation>
{
};

struct ProcessorBrandString0
    : public Generic::Layout::ProcessorBrandString0
    , public CpuidRequest<AmdLeaf::ProcessorBrandString0>
{
};

struct ProcessorBrandString1
    : public Generic::Layout::ProcessorBrandString1
    , public CpuidRequest<AmdLeaf::ProcessorBrandString1>
{
};

struct ProcessorBrandString2
    : public Generic::Layout::ProcessorBrandString2
    , public CpuidRequest<AmdLeaf::ProcessorBrandString2>
{
};

struct SvmFeatures
    : public Layout::SvmFeatures
    , public CpuidRequest<AmdLeaf::SvmFeatures>
{
};



} // namespace Amd



} // namespace Cpuid

#pragma pack(pop)