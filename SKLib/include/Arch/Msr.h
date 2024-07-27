#pragma once

extern "C" unsigned long long __readmsr(unsigned long index);
extern "C" void __writemsr(unsigned long index, unsigned long long value);

#pragma pack(push, 1)

namespace Msr
{



template <auto msr>
struct MsrAddress
{
    static constexpr auto k_msr = static_cast<unsigned int>(msr);
};



template <typename Layout>
union MsrLayout
{
    unsigned long long raw{};
    Layout layout;

    MsrLayout<Layout>& read() noexcept
    {
        raw = __readmsr(Layout::k_msr);
        return *this;
    }

    MsrLayout<Layout>& write() noexcept
    {
        __writemsr(Layout::k_msr, raw);
        return *this;
    }

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



struct Msr
{
    static unsigned long long read(unsigned int msr) noexcept
    {
        return __readmsr(msr);
    }

    void write(unsigned int msr, unsigned long long value) noexcept
    {
        __writemsr(msr, value);
    }

    template <typename Layout>
    static MsrLayout<Layout> read() noexcept
    {
        MsrLayout<Layout> msr;
        msr.read();
        return msr;
    }
};



namespace Intel
{



enum class IntelMsr : unsigned int
{
    _IA32_FEATURE_CONTROL = 0x0000003A,
    _IA32_SYSENTER_CS = 0x00000174,
    _IA32_SYSENTER_ESP = 0x00000175,
    _IA32_SYSENTER_EIP = 0x00000176,
    _IA32_EFER = 0xC0000080,
    _IA32_STAR = 0xC0000081,
    _IA32_LSTAR = 0xC0000082,
    _IA32_CSTAR = 0xC0000083,
    _IA32_FS_BASE = 0xC0000100,
    _IA32_GS_BASE = 0xC0000101,
    _IA32_KERNEL_GS_BASE = 0xC0000102,
    _IA32_DEBUGCTL = 0x000001D9,

    // MTRR:
    _IA32_MTRRCAP = 0xFE,
    _IA32_MTRR_DEF_TYPE = 0x2FF,
    _IA32_MTRR_PHYSBASE0 = 0x200,
    _IA32_MTRR_PHYSMASK0 = 0x201,
    _IA32_MTRR_PHYSBASE1 = 0x202,
    _IA32_MTRR_PHYSMASK1 = 0x203,
    _IA32_MTRR_PHYSBASE2 = 0x204,
    _IA32_MTRR_PHYSMASK2 = 0x205,
    _IA32_MTRR_PHYSBASE3 = 0x206,
    _IA32_MTRR_PHYSMASK3 = 0x207,
    _IA32_MTRR_PHYSBASE4 = 0x208,
    _IA32_MTRR_PHYSMASK4 = 0x209,
    _IA32_MTRR_PHYSBASE5 = 0x20A,
    _IA32_MTRR_PHYSMASK5 = 0x20B,
    _IA32_MTRR_PHYSBASE6 = 0x20C,
    _IA32_MTRR_PHYSMASK6 = 0x20D,
    _IA32_MTRR_PHYSBASE7 = 0x20E,
    _IA32_MTRR_PHYSMASK7 = 0x20F,
    _IA32_MTRR_PHYSBASE8 = 0x210,
    _IA32_MTRR_PHYSMASK8 = 0x211,
    _IA32_MTRR_PHYSBASE9 = 0x212,
    _IA32_MTRR_PHYSMASK9 = 0x213,
    _IA32_MTRR_FIX64K_00000 = 0x250,
    _IA32_MTRR_FIX16K_80000 = 0x258,
    _IA32_MTRR_FIX16K_A0000 = 0x259,
    _IA32_MTRR_FIX4K_C0000 = 0x268,
    _IA32_MTRR_FIX4K_C8000 = 0x269,
    _IA32_MTRR_FIX4K_D0000 = 0x26A,
    _IA32_MTRR_FIX4K_D8000 = 0x26B,
    _IA32_MTRR_FIX4K_E0000 = 0x26C,
    _IA32_MTRR_FIX4K_E8000 = 0x26D,
    _IA32_MTRR_FIX4K_F0000 = 0x26E,
    _IA32_MTRR_FIX4K_F8000 = 0x26F,

    // VMX-related MSRs:
    _IA32_VMX_BASIC = 0x00000480,
    _IA32_VMX_PINBASED_CTLS = 0x481,
    _IA32_VMX_PROCBASED_CTLS = 0x482,
    _IA32_VMX_EXIT_CTLS = 0x483,
    _IA32_VMX_ENTRY_CTLS = 0x484,
    _IA32_VMX_MISC = 0x485,
    _IA32_VMX_CR0_FIXED0 = 0x486,
    _IA32_VMX_CR0_FIXED1 = 0x487,
    _IA32_VMX_CR4_FIXED0 = 0x488,
    _IA32_VMX_CR4_FIXED1 = 0x489,
    _IA32_VMX_VMCS_ENUM = 0x48A,
    _IA32_VMX_PROCBASED_CTLS2 = 0x48B,
    _IA32_VMX_EPT_VPID_CAP = 0x48C,
    _IA32_VMX_TRUE_PINBASED_CTLS = 0x48D,
    _IA32_VMX_TRUE_PROCBASED_CTLS = 0x48E,
    _IA32_VMX_TRUE_EXIT_CTLS = 0x48F,
    _IA32_VMX_TRUE_ENTRY_CTLS = 0x490,
    _IA32_VMX_VMFUNC = 0x491
};



enum class MtrrMemoryType : unsigned char
{
    Uncacheable = 0x00,
    WriteCombining = 0x01,
    // 0x02 and 0x03 are reserved
    WriteThrough = 0x04,
    WriteProtected = 0x05,
    WriteBack = 0x06,
    // 0x07..0xFF are reserved
};



namespace Layout
{



struct _IA32FeatureControl
{
    unsigned long long LockBit : 1;
    unsigned long long EnableVmxInsideSmx : 1;
    unsigned long long EnableVmxOutsideSmx : 1;
    unsigned long long : 5;
    unsigned long long SenterLocalFunctionEnables : 7;
    unsigned long long SenterGlobalEnable : 1;
    unsigned long long : 1;
    unsigned long long SgxLaunchControlEnable : 1;
    unsigned long long SgxGlobalEnable : 1;
    unsigned long long : 1;
    unsigned long long LmceOn : 1;
    unsigned long long : 43;
};

struct _IA32Efer
{
    unsigned long long SCE : 1; // Syscall enable (R/W) - enables syscall/sysret instructions in 64-bit mode 
    unsigned long long : 7;
    unsigned long long LME : 1; // Enables IA-32e mode operation (R/W)
    unsigned long long : 1;
    unsigned long long LMA : 1; // _IA32-e mode active (R)
    unsigned long long NXE : 1; // Execute Disable bit Enable (R/W)
    unsigned long long : 52;
};

struct _IA32VmxBasic
{
    unsigned long long VmcsRevision : 31;
    unsigned long long : 1;
    unsigned long long VmxonVmcsRegionsSize : 13;
    unsigned long long : 3;
    unsigned long long PhysicalAddressesWidth : 1; // 0 = Processor's physical-address width (always 0 on Intel64), 1 = 32-bit
    unsigned long long DualMonitorTreatmentOfSmiAndSmm : 1;
    unsigned long long MemoryType : 4; // 0 = Uncacheable, 6 = Write-back, 1..5 and 7..15 aren't used
    unsigned long long InsOutsReporting : 1;
    unsigned long long AnyVmxControlsThatDefaultToOneMayBeZeroed : 1;
    unsigned long long CanUseVMEntryToDeliverHardwareException : 1;
    unsigned long long : 7;
};

struct _IA32VmxEptVpidCap
{
    unsigned long long ExecuteOnlyTranslationsSupportByEpt : 1;
    unsigned long long : 5;
    unsigned long long PageWalkLength4Support : 1;
    unsigned long long : 1;
    unsigned long long UncacheableEptSupport : 1;
    unsigned long long : 5;
    unsigned long long WriteBackEptSupport : 1;
    unsigned long long : 1;
    unsigned long long EptPde2MbSupport : 1;
    unsigned long long EptPdpte1GbSupport : 1;
    unsigned long long : 2;
    unsigned long long InveptSupport : 1;
    unsigned long long AccessedDirtyFlagsSupported : 1;
    unsigned long long EptViolationsSupport : 1;
    unsigned long long SupervisorShadowStackControlSupported : 1;
    unsigned long long : 1;
    unsigned long long SingleContextInveptTypeSupported : 1;
    unsigned long long AllContextInveptTypeSupported : 1;
    unsigned long long : 5;
    unsigned long long InvvpidSupported : 1;
    unsigned long long : 7;
    unsigned long long IndividualAddressInvvpidTypeSupported : 1;
    unsigned long long SingleContextInvvpidTypeSupported : 1;
    unsigned long long AllContextInvvpidTypeSupported : 1;
    unsigned long long SingleContextRetainingGlobalsInvvpidTypeSupported : 1;
    unsigned long long : 20;
};

struct _IA32MtrrCap
{
    unsigned long long VCNT : 8; // Variable range registers count
    unsigned long long FIX : 1; // Fixed range registers supported
    unsigned long long : 1;
    unsigned long long WC : 1; // Write combining
    unsigned long long SMRR : 1; // System-management range registers
    unsigned long long PRMRR : 1; // Processor-reserved memory range registers (starting with 7th Gen and 8th Gen Intel Core processors)
    unsigned long long : 51;
};

struct _IA32MtrrDefType
{
    unsigned long long Type : 3; // Default memory type (the only valid values are 0, 1, 4, 5, and 6), look at the MtrrMemoryType
    unsigned long long : 7;
    unsigned long long FE : 1; // Fixed MTRRs are enabled
    unsigned long long E : 1; // MTRRs enabled
    unsigned long long : 52;
};



namespace MtrrGeneric
{



struct FixedGeneric
{
    static constexpr unsigned char k_subrangesCount = 8;

    union
    {
        unsigned long long raw;
        struct
        {
            unsigned long long TypeOfRange0 : 8;
            unsigned long long TypeOfRange1 : 8;
            unsigned long long TypeOfRange2 : 8;
            unsigned long long TypeOfRange3 : 8;
            unsigned long long TypeOfRange4 : 8;
            unsigned long long TypeOfRange5 : 8;
            unsigned long long TypeOfRange6 : 8;
            unsigned long long TypeOfRange7 : 8;
        } types;
    } generic;
};

struct Fixed64k
{
    static constexpr unsigned int k_subrangesCount = 8;
    static constexpr unsigned int k_rangeSize = 512 * 1024;
    static constexpr unsigned int k_subrangeSize = k_rangeSize / k_subrangesCount;

    // Maps the 512-Kbyte address range (0..7FFFF) divided into eight 64-Kbyte sub-ranges:
    union
    {
        unsigned long long raw;
        struct
        {
            unsigned long long TypeOf64KbRange0 : 8; // 00000..0FFFF
            unsigned long long TypeOf64KbRange1 : 8; // 10000..1FFFF
            unsigned long long TypeOf64KbRange2 : 8; // 20000..2FFFF
            unsigned long long TypeOf64KbRange3 : 8; // 30000..3FFFF
            unsigned long long TypeOf64KbRange4 : 8; // 40000..4FFFF
            unsigned long long TypeOf64KbRange5 : 8; // 50000..5FFFF
            unsigned long long TypeOf64KbRange6 : 8; // 60000..6FFFF
            unsigned long long TypeOf64KbRange7 : 8; // 70000..7FFFF
        } layout;
        FixedGeneric generic;
    } types;
};

struct Fixed16k
{
    static constexpr unsigned int k_subrangesCount = 8;
    static constexpr unsigned int k_rangeSize = 128 * 1024;
    static constexpr unsigned int k_subrangeSize = k_rangeSize / k_subrangesCount;

    union
    {
        unsigned long long raw;
        struct
        {
            unsigned long long TypeOf16KbRange0 : 8; // 80000..83FFF  |  A0000..A3FFF
            unsigned long long TypeOf16KbRange1 : 8; // 84000..87FFF  |  A4000..A7FFF
            unsigned long long TypeOf16KbRange2 : 8; // 88000..8BFFF  |  A8000..ABFFF
            unsigned long long TypeOf16KbRange3 : 8; // 8C000..8FFFF  |  AC000..AFFFF
            unsigned long long TypeOf16KbRange4 : 8; // 90000..93FFF  |  B0000..B3FFF
            unsigned long long TypeOf16KbRange5 : 8; // 94000..97FFF  |  B4000..B7FFF
            unsigned long long TypeOf16KbRange6 : 8; // 98000..9BFFF  |  B8000..BBFFF
            unsigned long long TypeOf16KbRange7 : 8; // 9C000..9FFFF  |  BC000..BFFFF
        } layout;
        FixedGeneric generic;
    } types;
};

struct Fixed4k
{
    static constexpr unsigned int k_subrangesCount = 8;
    static constexpr unsigned int k_rangeSize = 32 * 1024;
    static constexpr unsigned int k_subrangeSize = k_rangeSize / k_subrangesCount;

    union
    {
        unsigned long long raw;
        struct
        {
            unsigned long long TypeOf4KbRange0 : 8; // [C..F]0000..[C..F]0FFF  |  [C..F]8000..[C..F]8FFF
            unsigned long long TypeOf4KbRange1 : 8; // [C..F]1000..[C..F]1FFF  |  [C..F]9000..[C..F]9FFF
            unsigned long long TypeOf4KbRange2 : 8; // [C..F]2000..[C..F]2FFF  |  [C..F]A000..[C..F]AFFF
            unsigned long long TypeOf4KbRange3 : 8; // [C..F]3000..[C..F]3FFF  |  [C..F]B000..[C..F]BFFF
            unsigned long long TypeOf4KbRange4 : 8; // [C..F]4000..[C..F]4FFF  |  [C..F]C000..[C..F]CFFF
            unsigned long long TypeOf4KbRange5 : 8; // [C..F]5000..[C..F]5FFF  |  [C..F]D000..[C..F]DFFF
            unsigned long long TypeOf4KbRange6 : 8; // [C..F]6000..[C..F]6FFF  |  [C..F]E000..[C..F]EFFF
            unsigned long long TypeOf4KbRange7 : 8; // [C..F]7000..[C..F]7FFF  |  [C..F]F000..[C..F]FFFF
        } layout;
        FixedGeneric generic;
    } types;
};

struct PhysBase
{
    union
    {
        unsigned long long raw;
        struct
        {
            unsigned long long Type : 8; // Memory type for range
            unsigned long long : 4;
            unsigned long long PhysBasePfn : 52; // 36-bit or MAXPHYSADDR length (depending on CPUID(0x80000008)), all other bits are reserved
        } layout;
    } base;
};

struct PhysMask
{
    union
    {
        unsigned long long raw;
        struct
        {
            unsigned long long : 11;
            unsigned long long V : 1; // Valid
            unsigned long long PhysMaskPfn : 52; // 36-bit or MAXPHYSADDR length (depending on CPUID(0x80000008)), all other bits are reserved
        } layout;
    } mask;
};



} // namespace MtrrGeneric


template <typename Type, unsigned int from, unsigned int to>
struct Mtrr : public Type
{
    using MtrrType = Type;
    static constexpr auto k_from = from;
    static constexpr auto k_to = to;
};



} // namespace Layout



struct _IA32FeatureControl
    : public Layout::_IA32FeatureControl
    , public MsrAddress<IntelMsr::_IA32_FEATURE_CONTROL>
{
};

struct _IA32Efer
    : public Layout::_IA32Efer
    , public MsrAddress<IntelMsr::_IA32_EFER>
{
};

struct _IA32VmxBasic
    : public Layout::_IA32VmxBasic
    , public MsrAddress<IntelMsr::_IA32_VMX_BASIC>
{
};

struct _IA32VmxEptVpidCap
    : public Layout::_IA32VmxEptVpidCap
    , public MsrAddress<IntelMsr::_IA32_VMX_EPT_VPID_CAP>
{
};

struct _IA32MtrrCap
    : public Layout::_IA32MtrrCap
    , public MsrAddress<IntelMsr::_IA32_MTRRCAP>
{
};

struct _IA32MtrrDefType
    : public Layout::_IA32MtrrDefType
    , public MsrAddress<IntelMsr::_IA32_MTRR_DEF_TYPE>
{
};



template <unsigned char index>
struct Mtrr;

template <>
struct Mtrr<0>
    : public Layout::Mtrr<Layout::MtrrGeneric::Fixed64k, 0x00000, 0x7FFFF>
    , public MsrAddress<IntelMsr::_IA32_MTRR_FIX64K_00000>
{
};

template <>
struct Mtrr<1>
    : public Layout::Mtrr<Layout::MtrrGeneric::Fixed16k, 0x80000, 0x9FFFF>
    , public MsrAddress<IntelMsr::_IA32_MTRR_FIX16K_80000>
{
};

template <>
struct Mtrr<2>
    : public Layout::Mtrr<Layout::MtrrGeneric::Fixed16k, 0xA0000, 0xBFFFF>
    , public MsrAddress<IntelMsr::_IA32_MTRR_FIX16K_A0000>
{
};

template <>
struct Mtrr<3>
    : public Layout::Mtrr<Layout::MtrrGeneric::Fixed4k, 0xC0000, 0xC7FFF>
    , public MsrAddress<IntelMsr::_IA32_MTRR_FIX4K_C0000>
{
};

template <>
struct Mtrr<4>
    : public Layout::Mtrr<Layout::MtrrGeneric::Fixed4k, 0xC8000, 0xCFFFF>
    , public MsrAddress<IntelMsr::_IA32_MTRR_FIX4K_C8000>
{
};

template <>
struct Mtrr<5>
    : public Layout::Mtrr<Layout::MtrrGeneric::Fixed4k, 0xD0000, 0xD7FFF>
    , public MsrAddress<IntelMsr::_IA32_MTRR_FIX4K_D0000>
{
};

template <>
struct Mtrr<6>
    : public Layout::Mtrr<Layout::MtrrGeneric::Fixed4k, 0xD8000, 0xDFFFF>
    , public MsrAddress<IntelMsr::_IA32_MTRR_FIX4K_D8000>
{
};

template <>
struct Mtrr<7>
    : public Layout::Mtrr<Layout::MtrrGeneric::Fixed4k, 0xE0000, 0xE7FFF>
    , public MsrAddress<IntelMsr::_IA32_MTRR_FIX4K_E0000>
{
};

template <>
struct Mtrr<8>
    : public Layout::Mtrr<Layout::MtrrGeneric::Fixed4k, 0xE8000, 0xEFFFF>
    , public MsrAddress<IntelMsr::_IA32_MTRR_FIX4K_E8000>
{
};

template <>
struct Mtrr<9>
    : public Layout::Mtrr<Layout::MtrrGeneric::Fixed4k, 0xF0000, 0xF7FFF>
    , public MsrAddress<IntelMsr::_IA32_MTRR_FIX4K_F0000>
{
};

template <>
struct Mtrr<10>
    : public Layout::Mtrr<Layout::MtrrGeneric::Fixed4k, 0xF8000, 0xFFFFF>
    , public MsrAddress<IntelMsr::_IA32_MTRR_FIX4K_F8000>
{
};



template <unsigned char index>
struct PhysBase;

template <unsigned char index>
struct PhysMask;



template <>
struct PhysBase<0>
    : public Layout::MtrrGeneric::PhysBase
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSBASE0>
{
};

template <>
struct PhysMask<0>
    : public Layout::MtrrGeneric::PhysMask
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSMASK0>
{
};



template <>
struct PhysBase<1>
    : public Layout::MtrrGeneric::PhysBase
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSBASE1>
{
};

template <>
struct PhysMask<1>
    : public Layout::MtrrGeneric::PhysMask
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSMASK1>
{
};



template <>
struct PhysBase<2>
    : public Layout::MtrrGeneric::PhysBase
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSBASE2>
{
};

template <>
struct PhysMask<2>
    : public Layout::MtrrGeneric::PhysMask
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSMASK2>
{
};



template <>
struct PhysBase<3>
    : public Layout::MtrrGeneric::PhysBase
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSBASE3>
{
};

template <>
struct PhysMask<3>
    : public Layout::MtrrGeneric::PhysMask
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSMASK3>
{
};



template <>
struct PhysBase<4>
    : public Layout::MtrrGeneric::PhysBase
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSBASE4>
{
};

template <>
struct PhysMask<4>
    : public Layout::MtrrGeneric::PhysMask
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSMASK4>
{
};



template <>
struct PhysBase<5>
    : public Layout::MtrrGeneric::PhysBase
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSBASE5>
{
};

template <>
struct PhysMask<5>
    : public Layout::MtrrGeneric::PhysMask
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSMASK5>
{
};



template <>
struct PhysBase<6>
    : public Layout::MtrrGeneric::PhysBase
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSBASE6>
{
};

template <>
struct PhysMask<6>
    : public Layout::MtrrGeneric::PhysMask
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSMASK6>
{
};



template <>
struct PhysBase<7>
    : public Layout::MtrrGeneric::PhysBase
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSBASE7>
{
};

template <>
struct PhysMask<7>
    : public Layout::MtrrGeneric::PhysMask
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSMASK7>
{
};



template <>
struct PhysBase<8>
    : public Layout::MtrrGeneric::PhysBase
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSBASE8>
{
};

template <>
struct PhysMask<8>
    : public Layout::MtrrGeneric::PhysMask
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSMASK8>
{
};



template <>
struct PhysBase<9>
    : public Layout::MtrrGeneric::PhysBase
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSBASE9>
{
};

template <>
struct PhysMask<9>
    : public Layout::MtrrGeneric::PhysMask
    , public MsrAddress<IntelMsr::_IA32_MTRR_PHYSMASK9>
{
};



} // namespace Intel



namespace Amd
{



enum class AmdMsr : unsigned int
{
    PAT = 0x00000277, // Extension of the page tables in SVM (nested paging)
    EFER = 0xC0000080, // Etended Feature Enable Register
    STAR = 0xC0000081, // Legacy mode: address of a SYSCALL instruction
    LSTAR = 0xC0000081, // Long mode: address of a SYSCALL instruction
    CSTAR = 0xC0000081, // Compatibility mode: address of a SYSCALL instruction
    VM_CR = 0xC0010114, // Controls global aspects of SVM
    VM_HSAVE_PA = 0xC0010117, // Physical address of a 4KB block of memory where VMRUN saves host state, and from which #VMEXIT reloads host state
};



namespace Layout
{



struct Efer
{
    unsigned long long SystemCallExtensions : 1; // 1 = enable SYSCALL/SYSRET support
    unsigned long long : 7;
    unsigned long long LongModeEnable : 1;
    unsigned long long : 1;
    unsigned long long LongModeActive : 1;
    unsigned long long NoExecuteEnable : 1;
    unsigned long long SecureVirtualMachineEnable : 1;
    unsigned long long LongModeSegmentLimitEnable : 1;
    unsigned long long FastFxsaveFxrstor : 1;
    unsigned long long TranslationCacheExtension : 1;
    unsigned long long : 48;
};

struct VmCr
{
    unsigned long long DPD : 1;
    unsigned long long R_INIT : 1;
    unsigned long long DIS_A20M : 1;
    unsigned long long LOCK : 1;
    unsigned long long SVMDIS : 1; // When set, EFER.SVME must be zero
    unsigned long long : 59;
};



} // namespace Layout



struct Efer
    : public Layout::Efer
    , public MsrAddress<AmdMsr::EFER>
{
};

struct VmCr
    : public Layout::VmCr
    , public MsrAddress<AmdMsr::VM_CR>
{
};



} // namespace Amd



} // namespace Msr

#pragma pack(pop)