#pragma once

/*
    Registers CR1, CR5..CR7, CR9..CR15, DR8..DR15 aren't implemented.
    Any attempt to access unimplemented registers results in an invalid-opcode exception (#UD).
*/

#include "Intrinsics.h"

#pragma pack(push, 1)


namespace Regs
{



enum class Mode
{
    unknown,
    legacy,
    longMode,
    native = (sizeof(void*) == sizeof(unsigned int))
        ? legacy
        : ((sizeof(void*) == sizeof(unsigned long long))
            ? longMode
            : unknown
            )
};



union Eflags
{
    unsigned int raw{};
    struct
    {
        unsigned int CF : 1; // Carry flag
        unsigned int MustBe1Bit1 : 1;
        unsigned int PF : 1; // Parity flag
        unsigned int MustBe0Bit3 : 1;
        unsigned int AF : 1; // Auxiliary carry flag
        unsigned int MustBe0Bit5 : 1;
        unsigned int ZF : 1; // Zero flag
        unsigned int SF : 1; // Sign flag
        unsigned int TF : 1; // Trap flag
        unsigned int IF : 1; // Interrupt enable flag
        unsigned int DF : 1; // Direction flag
        unsigned int OF : 1; // Overflow flag
        unsigned int IOPL : 2; // Input-output privilege level
        unsigned int NT : 1; // Nested task
        unsigned int MustBe0Bit15 : 1;
        unsigned int RF : 1; // Resume flag
        unsigned int VM : 1; // Virtual-8086 mode
        unsigned int AC : 1; // Alignment-check / access control
        unsigned int VIF : 1; // Virtual interrupt flag
        unsigned int VIP : 1; // Virtual interrupt pending
        unsigned int ID : 1; // ID flag
        unsigned int MustBe0Bit22 : 1;
        unsigned int MustBe0Bit23 : 1;
        unsigned int MustBe0Bit24 : 1;
        unsigned int MustBe0Bit25 : 1;
        unsigned int MustBe0Bit26 : 1;
        unsigned int MustBe0Bit27 : 1;
        unsigned int MustBe0Bit28 : 1;
        unsigned int MustBe0Bit29 : 1;
        unsigned int MustBe0Bit30 : 1;
        unsigned int MustBe0Bit31 : 1;
    } layout;
};

union Rflags
{
    unsigned long long raw{};
    decltype(Eflags::layout) layout;
};
static_assert(sizeof(Rflags) == sizeof(unsigned long long));



template <Mode mode>
union Cr0;

template <>
union Cr0<Mode::legacy>
{
    unsigned int raw;
    struct
    {
        unsigned int PE : 1; // Protection enabled
        unsigned int MP : 1; // Monitor coprocessor
        unsigned int EM : 1; // Emulation of 8087
        unsigned int TS : 1; // Task switched
        unsigned int ET : 1; // Extension type (readonly)
        unsigned int NE : 1; // Numeric error
        unsigned int Reserved0 : 10;
        unsigned int WP : 1; // Write protect
        unsigned int Reserved1 : 1;
        unsigned int AM : 1; // Alignment mask
        unsigned int Reserved3 : 10;
        unsigned int NW : 1; // Not writethrough
        unsigned int CD : 1; // Cache disable
        unsigned int PG : 1; // Paging
    } layout;
};
static_assert(sizeof(Cr0<Mode::legacy>) == sizeof(unsigned int));

template <>
union Cr0<Mode::longMode>
{
    unsigned long long raw;
    decltype(Cr0<Mode::legacy>::layout) layout;
};
static_assert(sizeof(Cr0<Mode::longMode>) == sizeof(unsigned long long));



template <Mode mode>
union Cr2;

template <>
union Cr2<Mode::legacy>
{
    unsigned int raw;
    unsigned int pf; // Page fault linear address
};
static_assert(sizeof(Cr2<Mode::legacy>) == sizeof(unsigned int));

template <>
union Cr2<Mode::longMode>
{
    unsigned long long raw;
    unsigned long long pf; // Page fault linear address
};
static_assert(sizeof(Cr2<Mode::longMode>) == sizeof(unsigned long long));



template <Mode mode>
union Cr3;

template <>
union Cr3<Mode::legacy>
{
    unsigned int raw;
    struct
    {
        unsigned int : 3;
        unsigned int PWT : 1; // Write through
        unsigned int PCD : 1; // Cache disable
        unsigned int : 7;
        unsigned int PD : 20; // Physical PFN of a Page Directory table
    } nonPae;
    struct
    {
        unsigned int : 3;
        unsigned int PWT : 1; // Write through
        unsigned int PCD : 1; // Cache disable
        unsigned int PDP : 27; // Physical PFN of a Page Directory Pointer table
    } pae;
};
static_assert(sizeof(Cr3<Mode::legacy>) == sizeof(unsigned int));

template <>
union Cr3<Mode::longMode>
{
    unsigned long long raw;
    struct
    {
        unsigned long long : 3;
        unsigned long long PWT : 1; // Write through
        unsigned long long PCD : 1; // Cache disable
        unsigned long long : 7;
        unsigned long long PML4 : 40; // Physical PFN of a PML4 table
        unsigned long long : 12;
    } paging4Level; // CR4.LA57 == 0
    struct
    {
        unsigned long long : 3;
        unsigned long long PWT : 1; // Write through
        unsigned long long PCD : 1; // Cache disable
        unsigned long long : 7;
        unsigned long long PML5 : 40; // Physical PFN of a PML5 table
        unsigned long long : 12;
    } paging5Level; // CR4.LA57 == 1
};
static_assert(sizeof(Cr3<Mode::longMode>) == sizeof(unsigned long long));



template <Mode mode>
union Cr4;

template <>
union Cr4<Mode::legacy>
{
    unsigned int raw;
    struct
    {
        unsigned int VME : 1; // Virtual 8086-mode extensions
        unsigned int PVI : 1; // Protected-mode virtual interrupts
        unsigned int TSD : 1; // Timestamp disable
        unsigned int DE : 1; // Debugging extensions
        unsigned int PSE : 1; // Page size extensions
        unsigned int PAE : 1; // Physical address extension
        unsigned int MCE : 1; // Machine check enable
        unsigned int PGE : 1; // Page global enable
        unsigned int PCE : 1; // Performance-monitoring counter enable
        unsigned int OSFXSR : 1; // Operating system FXSAVE/FXSTOR support
        unsigned int OSXMMEXCPT : 1; // Operating system unmasked exception support
        unsigned int UMIP : 1; // Usermode instruction prevention
        unsigned int LA57 : 1; // 57-bit linear address (5-level paging enable)
        unsigned int VMXE : 1; // VMX-enable bit (Intel only)
        unsigned int SMXE : 1; // SMX-enable bit (Safer Mode Extensions, Intel only)
        unsigned int : 1;
        unsigned int FSGSBASE : 1; // Enable RDFSBASE, RDGSBASE, WRFSBASE and WRGSBASE instructions
        unsigned int PCIDE : 1; // PCID-enable bit (Process-Context Identifiers)
        unsigned int OSXSAVE : 1; // XSAVE and Processor Extended States Enable bit
        unsigned int KL : 1; // Key-Locker enable (Intel only)
        unsigned int SMEP : 1; // Supervisor mode execution prevention
        unsigned int SMAP : 1; // Supervisor mode access prevention
        unsigned int PKE : 1; // Protection key enable
        unsigned int CET : 1; // Control-flow Enforcement Technology
        unsigned int PKS : 1; // Enable protection keys for supervisor-mode pages (Intel only)
        unsigned int UINTR : 1; // User Interrupts Enable (Intel only)
        unsigned int : 6;
    } layout;
};
static_assert(sizeof(Cr4<Mode::legacy>) == sizeof(unsigned int));

template <>
union Cr4<Mode::longMode>
{
    unsigned long long raw;
    decltype(Cr4<Mode::legacy>::layout) layout;
};
static_assert(sizeof(Cr4<Mode::longMode>) == sizeof(unsigned long long));



// Task priority register (64-Bit only):
template <Mode mode>
union Cr8;

template <>
union Cr8<Mode::longMode>
{
    unsigned long long val;
    struct
    {
        unsigned long long TPR : 4; // Priority
        unsigned long long : 60; // Reserved
    } layout;
};
static_assert(sizeof(Cr8<Mode::longMode>) == sizeof(unsigned long long));



template <Mode mode>
union Dr0;

template <>
union Dr0<Mode::legacy>
{
    unsigned int raw;
    unsigned int bp0; // Breakpoint 0 linear address
};
static_assert(sizeof(Dr0<Mode::legacy>) == sizeof(unsigned int));

template <>
union Dr0<Mode::longMode>
{
    unsigned long long raw;
    unsigned long long bp0; // Breakpoint 0 linear address
};
static_assert(sizeof(Dr0<Mode::longMode>) == sizeof(unsigned long long));



template <Mode mode>
union Dr1;

template <>
union Dr1<Mode::legacy>
{
    unsigned int raw;
    unsigned int bp1; // Breakpoint 1 linear address
};
static_assert(sizeof(Dr1<Mode::legacy>) == sizeof(unsigned int));

template <>
union Dr1<Mode::longMode>
{
    unsigned long long raw;
    unsigned long long bp1; // Breakpoint 1 linear address
};
static_assert(sizeof(Dr1<Mode::longMode>) == sizeof(unsigned long long));



template <Mode mode>
union Dr2;

template <>
union Dr2<Mode::legacy>
{
    unsigned int raw;
    unsigned int bp2; // Breakpoint 2 linear address
};
static_assert(sizeof(Dr2<Mode::legacy>) == sizeof(unsigned int));

template <>
union Dr2<Mode::longMode>
{
    unsigned long long raw;
    unsigned long long bp2; // Breakpoint 2 linear address
};
static_assert(sizeof(Dr2<Mode::longMode>) == sizeof(unsigned long long));



template <Mode mode>
union Dr3;

template <>
union Dr3<Mode::legacy>
{
    unsigned int raw;
    unsigned int bp3; // Breakpoint 3 linear address
};
static_assert(sizeof(Dr3<Mode::legacy>) == sizeof(unsigned int));

template <>
union Dr3<Mode::longMode>
{
    unsigned long long raw;
    unsigned long long bp3; // Breakpoint 3 linear address
};
static_assert(sizeof(Dr3<Mode::longMode>) == sizeof(unsigned long long));



// Aliased to DR6:
template <Mode mode>
union Dr4;

template <>
union Dr4<Mode::legacy>
{
    unsigned int raw;
    unsigned int reserved;
};
static_assert(sizeof(Dr4<Mode::legacy>) == sizeof(unsigned int));

template <>
union Dr4<Mode::longMode>
{
    unsigned long long raw;
    unsigned long long reserved;
};
static_assert(sizeof(Dr4<Mode::longMode>) == sizeof(unsigned long long));



// Aliased to DR7:
template <Mode mode>
union Dr5;

template <>
union Dr5<Mode::legacy>
{
    unsigned int raw;
    unsigned int reserved;
};
static_assert(sizeof(Dr5<Mode::legacy>) == sizeof(unsigned int));

template <>
union Dr5<Mode::longMode>
{
    unsigned long long raw;
    unsigned long long reserved;
};
static_assert(sizeof(Dr5<Mode::longMode>) == sizeof(unsigned long long));



template <Mode mode>
union Dr6;

template <>
union Dr6<Mode::legacy>
{
    unsigned int raw;
    struct
    {
        unsigned int B0 : 1; // Breakpoint #0 condition detected
        unsigned int B1 : 1; // Breakpoint #1 condition detected
        unsigned int B2 : 1; // Breakpoint #2 condition detected
        unsigned int B3 : 1; // Breakpoint #3 condition detected
        unsigned int FilledByOnes0 : 8; // Must be 0xFF (8 bits of ones: 0b1111_1111)
        unsigned int ReservedByZero : 1;
        unsigned int BD : 1; // Debug register access detected
        unsigned int BS : 1; // Single step
        unsigned int BT : 1; // Task switch
        unsigned int RTM : 1; // Intel only, must be 1 on AMD platforms
        unsigned int FilledByOnes1 : 15; // Must be 0x7FFF (15 bits of ones: 0b111_1111_1111_1111)
    } layout;
};
static_assert(sizeof(Dr6<Mode::legacy>) == sizeof(unsigned int));

template <>
union Dr6<Mode::longMode>
{
    unsigned long long raw;
    decltype(Dr6<Mode::legacy>::layout) layout;
};
static_assert(sizeof(Dr6<Mode::longMode>) == sizeof(unsigned long long));



template <Mode mode>
union Dr7;

template <>
union Dr7<Mode::legacy>
{
    unsigned int raw;
    struct
    {
        unsigned int L0 : 1; // Local  exact breakpoint #0 enabled
        unsigned int G0 : 1; // Global exact breakpoint #0 enabled
        unsigned int L1 : 1; // Local  exact breakpoint #1 enabled
        unsigned int G1 : 1; // Global exact breakpoint #1 enabled
        unsigned int L2 : 1; // Local  exact breakpoint #2 enabled
        unsigned int G2 : 1; // Global exact breakpoint #2 enabled
        unsigned int L3 : 1; // Local  exact breakpoint #3 enabled
        unsigned int G3 : 1; // Global exact breakpoint #3 enabled
        unsigned int LE : 1; // Local  exact breakpoint enabled
        unsigned int GE : 1; // Global exact breakpoint enabled
        unsigned int ReservedAsOne : 1;
        unsigned int RTM : 1; // Intel only, must be zero on AMD platforms
        unsigned int ReservedAsZero0 : 1;
        unsigned int GD : 1; // General detect enabled
        unsigned int ReservedAsZero1 : 2;
        unsigned int RW0 : 2; // 0b00 - Execute, 0b01 - Write, 0b10 - CR4.DE(0 - Undefined, 1 - I/O Reads & Writes), 0b11 - Read/Write only
        unsigned int LEN0 : 2; // 0b00 = 1 byte, 0b01 = 2 bytes, 0b10 = 8 bytes (long mode only, otherwise undefined), 0b11 = 4 bytes
        unsigned int RW1 : 2; // 0b00 - Execute, 0b01 - Write, 0b10 - CR4.DE(0 - Undefined, 1 - I/O Reads & Writes), 0b11 - Read/Write only
        unsigned int LEN1 : 2; // 0b00 = 1 byte, 0b01 = 2 bytes, 0b10 = 8 bytes (long mode only, otherwise undefined), 0b11 = 4 bytes
        unsigned int RW2 : 2; // 0b00 - Execute, 0b01 - Write, 0b10 - CR4.DE(0 - Undefined, 1 - I/O Reads & Writes), 0b11 - Read/Write only
        unsigned int LEN2 : 2; // 0b00 = 1 byte, 0b01 = 2 bytes, 0b10 = 8 bytes (long mode only, otherwise undefined), 0b11 = 4 bytes
        unsigned int RW3 : 2; // 0b00 - Execute, 0b01 - Write, 0b10 - CR4.DE(0 - Undefined, 1 - I/O Reads & Writes), 0b11 - Read/Write only
        unsigned int LEN3 : 2; // 0b00 = 1 byte, 0b01 = 2 bytes, 0b10 = 8 bytes (long mode only, otherwise undefined), 0b11 = 4 bytes
    } layout;
};
static_assert(sizeof(Dr7<Mode::legacy>) == sizeof(unsigned int));

template <>
union Dr7<Mode::longMode>
{
    unsigned long long raw;
    decltype(Dr7<Mode::legacy>::layout) layout;
};
static_assert(sizeof(Dr7<Mode::longMode>) == sizeof(unsigned long long));



namespace Native
{



template <typename RegLayout, auto getter, auto setter>
class Reg
{
public:
    using Layout = RegLayout;

private:
    Layout m_value;

public:
    static Reg query() noexcept
    {
        Reg reg;
        reg.read();
        return reg;
    }

    constexpr Reg() noexcept : m_value{}
    {
    }

    constexpr explicit Reg(decltype(m_value.raw) raw) noexcept : m_value{ .raw = raw }
    {
    }

    Reg(const Reg&) = default;
    Reg(Reg&&) noexcept = default;

    Reg& operator = (const Reg&) = default;
    Reg& operator = (Reg&&) noexcept = default;

    Reg& read() noexcept
    {
        m_value.raw = static_cast<decltype(m_value.raw)>(getter());
        return *this;
    }

    Reg& write() noexcept
    {
        setter(static_cast<decltype(m_value.raw)>(m_value.raw));
        return *this;
    }

    constexpr const Layout& operator * () const noexcept
    {
        return m_value;
    }

    constexpr Layout& operator * () noexcept
    {
        return m_value;
    }

    constexpr const Layout* operator -> () const noexcept
    {
        return &m_value;
    }

    constexpr Layout* operator -> () noexcept
    {
        return &m_value;
    }
};

template <Mode mode>
struct NativeEflags;

template <>
struct NativeEflags<Mode::legacy>
{
    using Layout = Regs::Eflags;
};

template <>
struct NativeEflags<Mode::longMode>
{
    using Layout = Regs::Rflags;
};

using Eflags = Reg<NativeEflags<Mode::native>, []() -> size_t { return __readeflags(); }, [](size_t value) { __writeeflags(value); }>;

using Cr0 = Reg<Regs::Cr0<Mode::native>, []() -> size_t { return __readcr0(); }, [](size_t value) { __writecr0(value); }>;
using Cr2 = Reg<Regs::Cr2<Mode::native>, []() -> size_t { return __readcr2(); }, [](size_t value) { __writecr2(value); }>;
using Cr3 = Reg<Regs::Cr3<Mode::native>, []() -> size_t { return __readcr3(); }, [](size_t value) { __writecr3(value); }>;
using Cr4 = Reg<Regs::Cr4<Mode::native>, []() -> size_t { return __readcr4(); }, [](size_t value) { __writecr4(value); }>;
using Cr8 = Reg<Regs::Cr8<Mode::native>, []() -> size_t { return __readcr8(); }, [](size_t value) { __writecr8(value); }>;

using Dr0 = Reg<Regs::Dr0<Mode::native>, []() -> size_t { return __readdr(0); }, [](size_t value) { __writedr(0, value); }>;
using Dr1 = Reg<Regs::Dr1<Mode::native>, []() -> size_t { return __readdr(1); }, [](size_t value) { __writedr(1, value); }>;
using Dr2 = Reg<Regs::Dr2<Mode::native>, []() -> size_t { return __readdr(2); }, [](size_t value) { __writedr(2, value); }>;
using Dr3 = Reg<Regs::Dr3<Mode::native>, []() -> size_t { return __readdr(3); }, [](size_t value) { __writedr(3, value); }>;
using Dr4 = Reg<Regs::Dr4<Mode::native>, []() -> size_t { return __readdr(4); }, [](size_t value) { __writedr(4, value); }>;
using Dr5 = Reg<Regs::Dr5<Mode::native>, []() -> size_t { return __readdr(5); }, [](size_t value) { __writedr(5, value); }>;
using Dr6 = Reg<Regs::Dr6<Mode::native>, []() -> size_t { return __readdr(6); }, [](size_t value) { __writedr(6, value); }>;
using Dr7 = Reg<Regs::Dr7<Mode::native>, []() -> size_t { return __readdr(7); }, [](size_t value) { __writedr(7, value); }>;



} // namespace Native



} // namespace Regs
#pragma pack(pop)