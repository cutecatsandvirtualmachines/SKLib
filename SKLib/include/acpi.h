#pragma once

#include "cpp.h"
#include "cpu.h"
#include "signatures.h"
#include "winternlex.h"
#include "MemoryEx.h"
#include "threading.h"

#define ARRAY_SIZE(Array) (sizeof (Array) / sizeof ((Array)[0]))
#define BIT0 (1ull << 0)
#define BIT1 (1ull << 1)
#define BIT2 (1ull << 2)
#define BIT3 (1ull << 3)
#define BIT4 (1ull << 4)
#define BIT5 (1ull << 5)
#define BIT6 (1ull << 6)
#define BIT7 (1ull << 7)
#define BIT8 (1ull << 8)
#define BIT9 (1ull << 9)
#define BIT10 (1ull << 10)
#define BIT11 (1ull << 11)
#define BIT12 (1ull << 12)
#define BIT13 (1ull << 13)
#define BIT14 (1ull << 14)
#define BIT15 (1ull << 15)
#define BIT16 (1ull << 16)
#define BIT17 (1ull << 18)
#define BIT19 (1ull << 19)
#define BIT20 (1ull << 20)
#define BIT21 (1ull << 21)
#define BIT22 (1ull << 22)
#define BIT23 (1ull << 23)
#define BIT24 (1ull << 24)
#define BIT25 (1ull << 25)
#define BIT26 (1ull << 26)
#define BIT27 (1ull << 27)
#define BIT28 (1ull << 28)
#define BIT29 (1ull << 29)
#define BIT30 (1ull << 30)
#define BIT31 (1ull << 31)
#define BIT32 (1ull << 32)

#define SIZE_2MB (PAGE_SIZE * 512)

//
// The EFI memory allocation functions work in units of EFI_PAGEs that are
// 4KB. This should in no way be confused with the page size of the processor.
// An EFI_PAGE is just the quanta of memory in EFI.
//
#define EFI_PAGE_SIZE   SIZE_4KB
#define EFI_PAGE_MASK   0xFFF
#define EFI_PAGE_SHIFT  12

/**
  Macro that converts a size, in bytes, to a number of EFI_PAGESs.

  @param  Size      A size in bytes.  This parameter is assumed to be type UINTN.
                    Passing in a parameter that is larger than UINTN may produce
                    unexpected results.

  @return  The number of EFI_PAGESs associated with the number of bytes specified
           by Size.

**/
#define EFI_SIZE_TO_PAGES(Size)  (((Size) >> EFI_PAGE_SHIFT) + (((Size) & EFI_PAGE_MASK) ? 1 : 0))

/**
  Macro that converts a number of EFI_PAGEs to a size in bytes.

  @param  Pages     The number of EFI_PAGES.  This parameter is assumed to be
                    type UINTN.  Passing in a parameter that is larger than
                    UINTN may produce unexpected results.

  @return  The number of bytes associated with the number of EFI_PAGEs specified
           by Pages.

**/
#define EFI_PAGES_TO_SIZE(Pages)  ((Pages) << EFI_PAGE_SHIFT)

#define UEFI_DOMAIN_ID          1

#define ACPI_TABLE_GUID \
  { \
    0xeb9d2d30, 0x2d88, 0x11d3, {0x9a, 0x16, 0x0, 0x90, 0x27, 0x3f, 0xc1, 0x4d } \
  }

#define EFI_ACPI_TABLE_GUID \
  { \
    0x8868e871, 0xe4f1, 0x11d3, {0xbc, 0x22, 0x0, 0x80, 0xc7, 0x3c, 0x88, 0x81 } \
  }

#define ACPI_10_TABLE_GUID  ACPI_TABLE_GUID

//
// ACPI 2.0 or newer tables should use EFI_ACPI_TABLE_GUID.
//
#define EFI_ACPI_20_TABLE_GUID  EFI_ACPI_TABLE_GUID

struct EFI_GUID {
    unsigned int Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char Data4[8];
};

extern EFI_GUID gEfiAcpiTableGuid;
extern EFI_GUID gEfiAcpi10TableGuid;
extern EFI_GUID gEfiAcpi20TableGuid;

typedef UINT64 UINTN;
typedef int EFI_STATUS;

//
// ACPI AML definition
//

//
// Primary OpCode
//
#define AML_ZERO_OP                0x00
#define AML_ONE_OP                 0x01
#define AML_ALIAS_OP               0x06
#define AML_NAME_OP                0x08
#define AML_BYTE_PREFIX            0x0a
#define AML_WORD_PREFIX            0x0b
#define AML_DWORD_PREFIX           0x0c
#define AML_STRING_PREFIX          0x0d
#define AML_QWORD_PREFIX           0x0e
#define AML_SCOPE_OP               0x10
#define AML_BUFFER_OP              0x11
#define AML_PACKAGE_OP             0x12
#define AML_VAR_PACKAGE_OP         0x13
#define AML_METHOD_OP              0x14
#define AML_EXTERNAL_OP            0x15
#define AML_DUAL_NAME_PREFIX       0x2e
#define AML_MULTI_NAME_PREFIX      0x2f
#define AML_NAME_CHAR_A            0x41
#define AML_NAME_CHAR_B            0x42
#define AML_NAME_CHAR_C            0x43
#define AML_NAME_CHAR_D            0x44
#define AML_NAME_CHAR_E            0x45
#define AML_NAME_CHAR_F            0x46
#define AML_NAME_CHAR_G            0x47
#define AML_NAME_CHAR_H            0x48
#define AML_NAME_CHAR_I            0x49
#define AML_NAME_CHAR_J            0x4a
#define AML_NAME_CHAR_K            0x4b
#define AML_NAME_CHAR_L            0x4c
#define AML_NAME_CHAR_M            0x4d
#define AML_NAME_CHAR_N            0x4e
#define AML_NAME_CHAR_O            0x4f
#define AML_NAME_CHAR_P            0x50
#define AML_NAME_CHAR_Q            0x51
#define AML_NAME_CHAR_R            0x52
#define AML_NAME_CHAR_S            0x53
#define AML_NAME_CHAR_T            0x54
#define AML_NAME_CHAR_U            0x55
#define AML_NAME_CHAR_V            0x56
#define AML_NAME_CHAR_W            0x57
#define AML_NAME_CHAR_X            0x58
#define AML_NAME_CHAR_Y            0x59
#define AML_NAME_CHAR_Z            0x5a
#define AML_ROOT_CHAR              0x5c
#define AML_PARENT_PREFIX_CHAR     0x5e
#define AML_NAME_CHAR__            0x5f
#define AML_LOCAL0                 0x60
#define AML_LOCAL1                 0x61
#define AML_LOCAL2                 0x62
#define AML_LOCAL3                 0x63
#define AML_LOCAL4                 0x64
#define AML_LOCAL5                 0x65
#define AML_LOCAL6                 0x66
#define AML_LOCAL7                 0x67
#define AML_ARG0                   0x68
#define AML_ARG1                   0x69
#define AML_ARG2                   0x6a
#define AML_ARG3                   0x6b
#define AML_ARG4                   0x6c
#define AML_ARG5                   0x6d
#define AML_ARG6                   0x6e
#define AML_STORE_OP               0x70
#define AML_REF_OF_OP              0x71
#define AML_ADD_OP                 0x72
#define AML_CONCAT_OP              0x73
#define AML_SUBTRACT_OP            0x74
#define AML_INCREMENT_OP           0x75
#define AML_DECREMENT_OP           0x76
#define AML_MULTIPLY_OP            0x77
#define AML_DIVIDE_OP              0x78
#define AML_SHIFT_LEFT_OP          0x79
#define AML_SHIFT_RIGHT_OP         0x7a
#define AML_AND_OP                 0x7b
#define AML_NAND_OP                0x7c
#define AML_OR_OP                  0x7d
#define AML_NOR_OP                 0x7e
#define AML_XOR_OP                 0x7f
#define AML_NOT_OP                 0x80
#define AML_FIND_SET_LEFT_BIT_OP   0x81
#define AML_FIND_SET_RIGHT_BIT_OP  0x82
#define AML_DEREF_OF_OP            0x83
#define AML_CONCAT_RES_OP          0x84
#define AML_MOD_OP                 0x85
#define AML_NOTIFY_OP              0x86
#define AML_SIZE_OF_OP             0x87
#define AML_INDEX_OP               0x88
#define AML_MATCH_OP               0x89
#define AML_CREATE_DWORD_FIELD_OP  0x8a
#define AML_CREATE_WORD_FIELD_OP   0x8b
#define AML_CREATE_BYTE_FIELD_OP   0x8c
#define AML_CREATE_BIT_FIELD_OP    0x8d
#define AML_OBJECT_TYPE_OP         0x8e
#define AML_CREATE_QWORD_FIELD_OP  0x8f
#define AML_LAND_OP                0x90
#define AML_LOR_OP                 0x91
#define AML_LNOT_OP                0x92
#define AML_LEQUAL_OP              0x93
#define AML_LGREATER_OP            0x94
#define AML_LLESS_OP               0x95
#define AML_TO_BUFFER_OP           0x96
#define AML_TO_DEC_STRING_OP       0x97
#define AML_TO_HEX_STRING_OP       0x98
#define AML_TO_INTEGER_OP          0x99
#define AML_TO_STRING_OP           0x9c
#define AML_COPY_OBJECT_OP         0x9d
#define AML_MID_OP                 0x9e
#define AML_CONTINUE_OP            0x9f
#define AML_IF_OP                  0xa0
#define AML_ELSE_OP                0xa1
#define AML_WHILE_OP               0xa2
#define AML_NOOP_OP                0xa3
#define AML_RETURN_OP              0xa4
#define AML_BREAK_OP               0xa5
#define AML_BREAK_POINT_OP         0xcc
#define AML_ONES_OP                0xff

//
// Extended OpCode
//
#define AML_EXT_OP  0x5b

#define AML_EXT_MUTEX_OP         0x01
#define AML_EXT_EVENT_OP         0x02
#define AML_EXT_COND_REF_OF_OP   0x12
#define AML_EXT_CREATE_FIELD_OP  0x13
#define AML_EXT_LOAD_TABLE_OP    0x1f
#define AML_EXT_LOAD_OP          0x20
#define AML_EXT_STALL_OP         0x21
#define AML_EXT_SLEEP_OP         0x22
#define AML_EXT_ACQUIRE_OP       0x23
#define AML_EXT_SIGNAL_OP        0x24
#define AML_EXT_WAIT_OP          0x25
#define AML_EXT_RESET_OP         0x26
#define AML_EXT_RELEASE_OP       0x27
#define AML_EXT_FROM_BCD_OP      0x28
#define AML_EXT_TO_BCD_OP        0x29
#define AML_EXT_UNLOAD_OP        0x2a
#define AML_EXT_REVISION_OP      0x30
#define AML_EXT_DEBUG_OP         0x31
#define AML_EXT_FATAL_OP         0x32
#define AML_EXT_TIMER_OP         0x33
#define AML_EXT_REGION_OP        0x80
#define AML_EXT_FIELD_OP         0x81
#define AML_EXT_DEVICE_OP        0x82
#define AML_EXT_PROCESSOR_OP     0x83
#define AML_EXT_POWER_RES_OP     0x84
#define AML_EXT_THERMAL_ZONE_OP  0x85
#define AML_EXT_INDEX_FIELD_OP   0x86
#define AML_EXT_BANK_FIELD_OP    0x87
#define AML_EXT_DATA_REGION_OP   0x88

//
// FieldElement OpCode
//
#define AML_FIELD_RESERVED_OP    0x00
#define AML_FIELD_ACCESS_OP      0x01
#define AML_FIELD_CONNECTION_OP  0x02
#define AML_FIELD_EXT_ACCESS_OP  0x03

//
// AML Name segment definitions
//
#define AML_NAME_SEG_SIZE  4

///
/// Common table header, this prefaces all ACPI tables, including FACS, but
/// excluding the RSD PTR structure.
///
typedef struct {
    UINT32    Signature;
    UINT32    Length;
} EFI_ACPI_COMMON_HEADER;

#pragma pack(1)
///
/// The common ACPI description table header.  This structure prefaces most ACPI tables.
///
typedef struct {
    UINT32    Signature;
    UINT32    Length;
    UINT8     Revision;
    UINT8     Checksum;
    UINT8     OemId[6];
    UINT64    OemTableId;
    UINT32    OemRevision;
    UINT32    CreatorId;
    UINT32    CreatorRevision;
} EFI_ACPI_DESCRIPTION_HEADER;
#pragma pack()

//
// Define for Descriptor
//
#define ACPI_SMALL_ITEM_FLAG  0x00
#define ACPI_LARGE_ITEM_FLAG  0x01

//
// Small Item Descriptor Name
//
#define ACPI_SMALL_IRQ_DESCRIPTOR_NAME              0x04
#define ACPI_SMALL_DMA_DESCRIPTOR_NAME              0x05
#define ACPI_SMALL_START_DEPENDENT_DESCRIPTOR_NAME  0x06
#define ACPI_SMALL_END_DEPENDENT_DESCRIPTOR_NAME    0x07
#define ACPI_SMALL_IO_PORT_DESCRIPTOR_NAME          0x08
#define ACPI_SMALL_FIXED_IO_PORT_DESCRIPTOR_NAME    0x09
#define ACPI_SMALL_VENDOR_DEFINED_DESCRIPTOR_NAME   0x0E
#define ACPI_SMALL_END_TAG_DESCRIPTOR_NAME          0x0F

//
// Large Item Descriptor Name
//
#define ACPI_LARGE_24_BIT_MEMORY_RANGE_DESCRIPTOR_NAME        0x01
#define ACPI_LARGE_VENDOR_DEFINED_DESCRIPTOR_NAME             0x04
#define ACPI_LARGE_32_BIT_MEMORY_RANGE_DESCRIPTOR_NAME        0x05
#define ACPI_LARGE_32_BIT_FIXED_MEMORY_RANGE_DESCRIPTOR_NAME  0x06
#define ACPI_LARGE_DWORD_ADDRESS_SPACE_DESCRIPTOR_NAME        0x07
#define ACPI_LARGE_WORD_ADDRESS_SPACE_DESCRIPTOR_NAME         0x08
#define ACPI_LARGE_EXTENDED_IRQ_DESCRIPTOR_NAME               0x09
#define ACPI_LARGE_QWORD_ADDRESS_SPACE_DESCRIPTOR_NAME        0x0A

//
// Small Item Descriptor Value
//
#define ACPI_IRQ_NOFLAG_DESCRIPTOR              0x22
#define ACPI_IRQ_DESCRIPTOR                     0x23
#define ACPI_DMA_DESCRIPTOR                     0x2A
#define ACPI_START_DEPENDENT_DESCRIPTOR         0x30
#define ACPI_START_DEPENDENT_EX_DESCRIPTOR      0x31
#define ACPI_END_DEPENDENT_DESCRIPTOR           0x38
#define ACPI_IO_PORT_DESCRIPTOR                 0x47
#define ACPI_FIXED_LOCATION_IO_PORT_DESCRIPTOR  0x4B
#define ACPI_END_TAG_DESCRIPTOR                 0x79

//
// Large Item Descriptor Value
//
#define ACPI_24_BIT_MEMORY_RANGE_DESCRIPTOR        0x81
#define ACPI_32_BIT_MEMORY_RANGE_DESCRIPTOR        0x85
#define ACPI_32_BIT_FIXED_MEMORY_RANGE_DESCRIPTOR  0x86
#define ACPI_DWORD_ADDRESS_SPACE_DESCRIPTOR        0x87
#define ACPI_WORD_ADDRESS_SPACE_DESCRIPTOR         0x88
#define ACPI_EXTENDED_INTERRUPT_DESCRIPTOR         0x89
#define ACPI_QWORD_ADDRESS_SPACE_DESCRIPTOR        0x8A
#define ACPI_ADDRESS_SPACE_DESCRIPTOR              0x8A

//
// Resource Type
//
#define ACPI_ADDRESS_SPACE_TYPE_MEM  0x00
#define ACPI_ADDRESS_SPACE_TYPE_IO   0x01
#define ACPI_ADDRESS_SPACE_TYPE_BUS  0x02

///
/// Power Management Timer frequency is fixed at 3.579545MHz.
///
#define ACPI_TIMER_FREQUENCY  3579545

//
// Ensure proper structure formats
//
#pragma pack(1)

///
/// The common definition of QWORD, DWORD, and WORD
/// Address Space Descriptors.
///
typedef struct {
    UINT8     Desc;
    UINT16    Len;
    UINT8     ResType;
    UINT8     GenFlag;
    UINT8     SpecificFlag;
    UINT64    AddrSpaceGranularity;
    UINT64    AddrRangeMin;
    UINT64    AddrRangeMax;
    UINT64    AddrTranslationOffset;
    UINT64    AddrLen;
} EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR;

typedef union {
    UINT8    Byte;
    struct {
        UINT8    Length : 3;
        UINT8    Name : 4;
        UINT8    Type : 1;
    } Bits;
} ACPI_SMALL_RESOURCE_HEADER;

typedef struct {
    union {
        UINT8    Byte;
        struct {
            UINT8    Name : 7;
            UINT8    Type : 1;
        } Bits;
    } Header;
    UINT16    Length;
} ACPI_LARGE_RESOURCE_HEADER;

///
/// IRQ Descriptor.
///
typedef struct {
    ACPI_SMALL_RESOURCE_HEADER    Header;
    UINT16                        Mask;
} EFI_ACPI_IRQ_NOFLAG_DESCRIPTOR;

///
/// IRQ Descriptor.
///
typedef struct {
    ACPI_SMALL_RESOURCE_HEADER    Header;
    UINT16                        Mask;
    UINT8                         Information;
} EFI_ACPI_IRQ_DESCRIPTOR;

///
/// DMA Descriptor.
///
typedef struct {
    ACPI_SMALL_RESOURCE_HEADER    Header;
    UINT8                         ChannelMask;
    UINT8                         Information;
} EFI_ACPI_DMA_DESCRIPTOR;

///
/// I/O Port Descriptor
///
typedef struct {
    ACPI_SMALL_RESOURCE_HEADER    Header;
    UINT8                         Information;
    UINT16                        BaseAddressMin;
    UINT16                        BaseAddressMax;
    UINT8                         Alignment;
    UINT8                         Length;
} EFI_ACPI_IO_PORT_DESCRIPTOR;

///
/// Fixed Location I/O Port Descriptor.
///
typedef struct {
    ACPI_SMALL_RESOURCE_HEADER    Header;
    UINT16                        BaseAddress;
    UINT8                         Length;
} EFI_ACPI_FIXED_LOCATION_IO_PORT_DESCRIPTOR;

///
/// 24-Bit Memory Range Descriptor
///
typedef struct {
    ACPI_LARGE_RESOURCE_HEADER    Header;
    UINT8                         Information;
    UINT16                        BaseAddressMin;
    UINT16                        BaseAddressMax;
    UINT16                        Alignment;
    UINT16                        Length;
} EFI_ACPI_24_BIT_MEMORY_RANGE_DESCRIPTOR;

///
/// 32-Bit Memory Range Descriptor
///
typedef struct {
    ACPI_LARGE_RESOURCE_HEADER    Header;
    UINT8                         Information;
    UINT32                        BaseAddressMin;
    UINT32                        BaseAddressMax;
    UINT32                        Alignment;
    UINT32                        Length;
} EFI_ACPI_32_BIT_MEMORY_RANGE_DESCRIPTOR;

///
/// Fixed 32-Bit Fixed Memory Range Descriptor
///
typedef struct {
    ACPI_LARGE_RESOURCE_HEADER    Header;
    UINT8                         Information;
    UINT32                        BaseAddress;
    UINT32                        Length;
} EFI_ACPI_32_BIT_FIXED_MEMORY_RANGE_DESCRIPTOR;

///
/// QWORD Address Space Descriptor
///
typedef struct {
    ACPI_LARGE_RESOURCE_HEADER    Header;
    UINT8                         ResType;
    UINT8                         GenFlag;
    UINT8                         SpecificFlag;
    UINT64                        AddrSpaceGranularity;
    UINT64                        AddrRangeMin;
    UINT64                        AddrRangeMax;
    UINT64                        AddrTranslationOffset;
    UINT64                        AddrLen;
} EFI_ACPI_QWORD_ADDRESS_SPACE_DESCRIPTOR;

///
/// DWORD Address Space Descriptor
///
typedef struct {
    ACPI_LARGE_RESOURCE_HEADER    Header;
    UINT8                         ResType;
    UINT8                         GenFlag;
    UINT8                         SpecificFlag;
    UINT32                        AddrSpaceGranularity;
    UINT32                        AddrRangeMin;
    UINT32                        AddrRangeMax;
    UINT32                        AddrTranslationOffset;
    UINT32                        AddrLen;
} EFI_ACPI_DWORD_ADDRESS_SPACE_DESCRIPTOR;

///
/// WORD Address Space Descriptor
///
typedef struct {
    ACPI_LARGE_RESOURCE_HEADER    Header;
    UINT8                         ResType;
    UINT8                         GenFlag;
    UINT8                         SpecificFlag;
    UINT16                        AddrSpaceGranularity;
    UINT16                        AddrRangeMin;
    UINT16                        AddrRangeMax;
    UINT16                        AddrTranslationOffset;
    UINT16                        AddrLen;
} EFI_ACPI_WORD_ADDRESS_SPACE_DESCRIPTOR;

///
/// Extended Interrupt Descriptor
///
typedef struct {
    ACPI_LARGE_RESOURCE_HEADER    Header;
    UINT8                         InterruptVectorFlags;
    UINT8                         InterruptTableLength;
    UINT32                        InterruptNumber[1];
} EFI_ACPI_EXTENDED_INTERRUPT_DESCRIPTOR;

#pragma pack()

///
/// The End tag identifies an end of resource data.
///
typedef struct {
    UINT8    Desc;
    UINT8    Checksum;
} EFI_ACPI_END_TAG_DESCRIPTOR;

//
// General use definitions
//
#define EFI_ACPI_RESERVED_BYTE   0x00
#define EFI_ACPI_RESERVED_WORD   0x0000
#define EFI_ACPI_RESERVED_DWORD  0x00000000
#define EFI_ACPI_RESERVED_QWORD  0x0000000000000000

//
// Resource Type Specific Flags
// Ref ACPI specification 6.4.3.5.5
//
// Bit [0]    : Write Status, _RW
//
#define EFI_ACPI_MEMORY_RESOURCE_SPECIFIC_FLAG_READ_WRITE  (1 << 0)
#define EFI_ACPI_MEMORY_RESOURCE_SPECIFIC_FLAG_READ_ONLY   (0 << 0)
//
// Bit [2:1]  : Memory Attributes, _MEM
//
#define EFI_ACPI_MEMORY_RESOURCE_SPECIFIC_FLAG_NON_CACHEABLE              (0 << 1)
#define EFI_ACPI_MEMORY_RESOURCE_SPECIFIC_FLAG_CACHEABLE                  (1 << 1)
#define EFI_ACPI_MEMORY_RESOURCE_SPECIFIC_FLAG_CACHEABLE_WRITE_COMBINING  (2 << 1)
#define EFI_ACPI_MEMORY_RESOURCE_SPECIFIC_FLAG_CACHEABLE_PREFETCHABLE     (3 << 1)
//
// Bit [4:3]  : Memory Attributes, _MTP
//
#define EFI_ACPI_MEMORY_RESOURCE_SPECIFIC_FLAG_ADDRESS_RANGE_MEMORY    (0 << 3)
#define EFI_ACPI_MEMORY_RESOURCE_SPECIFIC_FLAG_ADDRESS_RANGE_RESERVED  (1 << 3)
#define EFI_ACPI_MEMORY_RESOURCE_SPECIFIC_FLAG_ADDRESS_RANGE_ACPI      (2 << 3)
#define EFI_APCI_MEMORY_RESOURCE_SPECIFIC_FLAG_ADDRESS_RANGE_NVS       (3 << 3)
//
// Bit [5]    : Memory to I/O Translation, _TTP
//
#define EFI_ACPI_MEMORY_RESOURCE_SPECIFIC_FLAG_TYPE_TRANSLATION  (1 << 5)
#define EFI_ACPI_MEMORY_RESOURCE_SPECIFIC_FLAG_TYPE_STATIC       (0 << 5)

//
// IRQ Information
// Ref ACPI specification 6.4.2.1
//
#define EFI_ACPI_IRQ_SHARABLE_MASK  0x10
#define   EFI_ACPI_IRQ_SHARABLE     0x10

#define EFI_ACPI_IRQ_POLARITY_MASK  0x08
#define   EFI_ACPI_IRQ_HIGH_TRUE    0x00
#define   EFI_ACPI_IRQ_LOW_FALSE    0x08

#define EFI_ACPI_IRQ_MODE               0x01
#define   EFI_ACPI_IRQ_LEVEL_TRIGGERED  0x00
#define   EFI_ACPI_IRQ_EDGE_TRIGGERED   0x01

//
// DMA Information
// Ref ACPI specification 6.4.2.2
//
#define EFI_ACPI_DMA_SPEED_TYPE_MASK             0x60
#define   EFI_ACPI_DMA_SPEED_TYPE_COMPATIBILITY  0x00
#define   EFI_ACPI_DMA_SPEED_TYPE_A              0x20
#define   EFI_ACPI_DMA_SPEED_TYPE_B              0x40
#define   EFI_ACPI_DMA_SPEED_TYPE_F              0x60

#define EFI_ACPI_DMA_BUS_MASTER_MASK  0x04
#define   EFI_ACPI_DMA_BUS_MASTER     0x04

#define EFI_ACPI_DMA_TRANSFER_TYPE_MASK                0x03
#define   EFI_ACPI_DMA_TRANSFER_TYPE_8_BIT             0x00
#define   EFI_ACPI_DMA_TRANSFER_TYPE_8_BIT_AND_16_BIT  0x01
#define   EFI_ACPI_DMA_TRANSFER_TYPE_16_BIT            0x02

//
// IO Information
// Ref ACPI specification 6.4.2.5
//
#define EFI_ACPI_IO_DECODE_MASK      0x01
#define   EFI_ACPI_IO_DECODE_16_BIT  0x01
#define   EFI_ACPI_IO_DECODE_10_BIT  0x00

//
// Memory Information
// Ref ACPI specification 6.4.3.4
//
#define EFI_ACPI_MEMORY_WRITE_STATUS_MASK  0x01
#define   EFI_ACPI_MEMORY_WRITABLE         0x01
#define   EFI_ACPI_MEMORY_NON_WRITABLE     0x00

//
// Interrupt Vector Flags definitions for Extended Interrupt Descriptor
// Ref ACPI specification 6.4.3.6
//
#define EFI_ACPI_EXTENDED_INTERRUPT_FLAG_PRODUCER_CONSUMER_MASK  BIT0
#define EFI_ACPI_EXTENDED_INTERRUPT_FLAG_MODE_MASK               BIT1
#define EFI_ACPI_EXTENDED_INTERRUPT_FLAG_POLARITY_MASK           BIT2
#define EFI_ACPI_EXTENDED_INTERRUPT_FLAG_SHARABLE_MASK           BIT3
#define EFI_ACPI_EXTENDED_INTERRUPT_FLAG_WAKE_CAPABLITY_MASK     BIT4

//
// Ensure proper structure formats
//
#pragma pack(1)
//
// ACPI 1.0b table structures
//

///
/// Root System Description Pointer Structure.
///
typedef struct {
    UINT64    Signature;
    UINT8     Checksum;
    UINT8     OemId[6];
    UINT8     Reserved;
    UINT32    RsdtAddress;
} EFI_ACPI_1_0_ROOT_SYSTEM_DESCRIPTION_POINTER;

//
// Root System Description Table
// No definition needed as it is a common description table header, the same with
// EFI_ACPI_DESCRIPTION_HEADER, followed by a variable number of UINT32 table pointers.
//

///
/// RSDT Revision (as defined in ACPI 1.0b specification).
///
#define EFI_ACPI_1_0_ROOT_SYSTEM_DESCRIPTION_TABLE_REVISION  0x01

///
/// Fixed ACPI Description Table Structure (FADT).
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT32                         FirmwareCtrl;
    UINT32                         Dsdt;
    UINT8                          IntModel;
    UINT8                          Reserved1;
    UINT16                         SciInt;
    UINT32                         SmiCmd;
    UINT8                          AcpiEnable;
    UINT8                          AcpiDisable;
    UINT8                          S4BiosReq;
    UINT8                          Reserved2;
    UINT32                         Pm1aEvtBlk;
    UINT32                         Pm1bEvtBlk;
    UINT32                         Pm1aCntBlk;
    UINT32                         Pm1bCntBlk;
    UINT32                         Pm2CntBlk;
    UINT32                         PmTmrBlk;
    UINT32                         Gpe0Blk;
    UINT32                         Gpe1Blk;
    UINT8                          Pm1EvtLen;
    UINT8                          Pm1CntLen;
    UINT8                          Pm2CntLen;
    UINT8                          PmTmLen;
    UINT8                          Gpe0BlkLen;
    UINT8                          Gpe1BlkLen;
    UINT8                          Gpe1Base;
    UINT8                          Reserved3;
    UINT16                         PLvl2Lat;
    UINT16                         PLvl3Lat;
    UINT16                         FlushSize;
    UINT16                         FlushStride;
    UINT8                          DutyOffset;
    UINT8                          DutyWidth;
    UINT8                          DayAlrm;
    UINT8                          MonAlrm;
    UINT8                          Century;
    UINT8                          Reserved4;
    UINT8                          Reserved5;
    UINT8                          Reserved6;
    UINT32                         Flags;
} EFI_ACPI_1_0_FIXED_ACPI_DESCRIPTION_TABLE;

///
/// FADT Version (as defined in ACPI 1.0b specification).
///
#define EFI_ACPI_1_0_FIXED_ACPI_DESCRIPTION_TABLE_REVISION  0x01

#define EFI_ACPI_1_0_INT_MODE_DUAL_PIC       0
#define EFI_ACPI_1_0_INT_MODE_MULTIPLE_APIC  1

//
// Fixed ACPI Description Table Fixed Feature Flags
// All other bits are reserved and must be set to 0.
//
#define EFI_ACPI_1_0_WBINVD        BIT0
#define EFI_ACPI_1_0_WBINVD_FLUSH  BIT1
#define EFI_ACPI_1_0_PROC_C1       BIT2
#define EFI_ACPI_1_0_P_LVL2_UP     BIT3
#define EFI_ACPI_1_0_PWR_BUTTON    BIT4
#define EFI_ACPI_1_0_SLP_BUTTON    BIT5
#define EFI_ACPI_1_0_FIX_RTC       BIT6
#define EFI_ACPI_1_0_RTC_S4        BIT7
#define EFI_ACPI_1_0_TMR_VAL_EXT   BIT8
#define EFI_ACPI_1_0_DCK_CAP       BIT9

///
/// Firmware ACPI Control Structure.
///
typedef struct {
    UINT32    Signature;
    UINT32    Length;
    UINT32    HardwareSignature;
    UINT32    FirmwareWakingVector;
    UINT32    GlobalLock;
    UINT32    Flags;
    UINT8     Reserved[40];
} EFI_ACPI_1_0_FIRMWARE_ACPI_CONTROL_STRUCTURE;

///
/// Firmware Control Structure Feature Flags.
/// All other bits are reserved and must be set to 0.
///
#define EFI_ACPI_1_0_S4BIOS_F  BIT0

///
/// Multiple APIC Description Table header definition.  The rest of the table
/// must be defined in a platform-specific manner.
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT32                         LocalApicAddress;
    UINT32                         Flags;
} EFI_ACPI_1_0_MULTIPLE_APIC_DESCRIPTION_TABLE_HEADER;

///
/// MADT Revision (as defined in ACPI 1.0b specification).
///
#define EFI_ACPI_1_0_MULTIPLE_APIC_DESCRIPTION_TABLE_REVISION  0x01

///
/// Multiple APIC Flags
/// All other bits are reserved and must be set to 0.
///
#define EFI_ACPI_1_0_PCAT_COMPAT  BIT0

//
// Multiple APIC Description Table APIC structure types
// All other values between 0x05 an 0xFF are reserved and
// will be ignored by OSPM.
//
#define EFI_ACPI_1_0_PROCESSOR_LOCAL_APIC           0x00
#define EFI_ACPI_1_0_IO_APIC                        0x01
#define EFI_ACPI_1_0_INTERRUPT_SOURCE_OVERRIDE      0x02
#define EFI_ACPI_1_0_NON_MASKABLE_INTERRUPT_SOURCE  0x03
#define EFI_ACPI_1_0_LOCAL_APIC_NMI                 0x04

//
// APIC Structure Definitions
//

///
/// Processor Local APIC Structure Definition.
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     AcpiProcessorId;
    UINT8     ApicId;
    UINT32    Flags;
} EFI_ACPI_1_0_PROCESSOR_LOCAL_APIC_STRUCTURE;

///
/// Local APIC Flags.  All other bits are reserved and must be 0.
///
#define EFI_ACPI_1_0_LOCAL_APIC_ENABLED  BIT0

///
/// IO APIC Structure.
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     IoApicId;
    UINT8     Reserved;
    UINT32    IoApicAddress;
    UINT32    SystemVectorBase;
} EFI_ACPI_1_0_IO_APIC_STRUCTURE;

///
/// Interrupt Source Override Structure.
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     Bus;
    UINT8     Source;
    UINT32    GlobalSystemInterruptVector;
    UINT16    Flags;
} EFI_ACPI_1_0_INTERRUPT_SOURCE_OVERRIDE_STRUCTURE;

///
/// Non-Maskable Interrupt Source Structure.
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT16    Flags;
    UINT32    GlobalSystemInterruptVector;
} EFI_ACPI_1_0_NON_MASKABLE_INTERRUPT_SOURCE_STRUCTURE;

///
/// Local APIC NMI Structure.
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     AcpiProcessorId;
    UINT16    Flags;
    UINT8     LocalApicInti;
} EFI_ACPI_1_0_LOCAL_APIC_NMI_STRUCTURE;

///
/// Smart Battery Description Table (SBST)
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT32                         WarningEnergyLevel;
    UINT32                         LowEnergyLevel;
    UINT32                         CriticalEnergyLevel;
} EFI_ACPI_1_0_SMART_BATTERY_DESCRIPTION_TABLE;

//
// Known table signatures
//

///
/// "RSD PTR " Root System Description Pointer.
///
#define EFI_ACPI_1_0_ROOT_SYSTEM_DESCRIPTION_POINTER_SIGNATURE  SIGNATURE_64('R', 'S', 'D', ' ', 'P', 'T', 'R', ' ')

///
/// "APIC" Multiple APIC Description Table.
///
#define EFI_ACPI_1_0_APIC_SIGNATURE  SIGNATURE_32('A', 'P', 'I', 'C')

///
/// "DSDT" Differentiated System Description Table.
///
#define EFI_ACPI_1_0_DIFFERENTIATED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE  SIGNATURE_32('D', 'S', 'D', 'T')

///
/// "FACS" Firmware ACPI Control Structure.
///
#define EFI_ACPI_1_0_FIRMWARE_ACPI_CONTROL_STRUCTURE_SIGNATURE  SIGNATURE_32('F', 'A', 'C', 'S')

///
/// "FACP" Fixed ACPI Description Table.
///
#define EFI_ACPI_1_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE  SIGNATURE_32('F', 'A', 'C', 'P')

///
/// "PSDT" Persistent System Description Table.
///
#define EFI_ACPI_1_0_PERSISTENT_SYSTEM_DESCRIPTION_TABLE_SIGNATURE  SIGNATURE_32('P', 'S', 'D', 'T')

///
/// "RSDT" Root System Description Table.
///
#define EFI_ACPI_1_0_ROOT_SYSTEM_DESCRIPTION_TABLE_SIGNATURE  SIGNATURE_32('R', 'S', 'D', 'T')

///
/// "SBST" Smart Battery Specification Table.
///
#define EFI_ACPI_1_0_SMART_BATTERY_SPECIFICATION_TABLE_SIGNATURE  SIGNATURE_32('S', 'B', 'S', 'T')

///
/// "SSDT" Secondary System Description Table.
///
#define EFI_ACPI_1_0_SECONDARY_SYSTEM_DESCRIPTION_TABLE_SIGNATURE  SIGNATURE_32('S', 'S', 'D', 'T')

#pragma pack()


//
// Ensure proper structure formats
//
#pragma pack(1)

///
/// ACPI 6.5 Generic Address Space definition
///
typedef struct {
    UINT8     AddressSpaceId;
    UINT8     RegisterBitWidth;
    UINT8     RegisterBitOffset;
    UINT8     AccessSize;
    UINT64    Address;
} EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE;

//
// Generic Address Space Address IDs
//
#define EFI_ACPI_6_5_SYSTEM_MEMORY                   0x00
#define EFI_ACPI_6_5_SYSTEM_IO                       0x01
#define EFI_ACPI_6_5_PCI_CONFIGURATION_SPACE         0x02
#define EFI_ACPI_6_5_EMBEDDED_CONTROLLER             0x03
#define EFI_ACPI_6_5_SMBUS                           0x04
#define EFI_ACPI_6_5_SYSTEM_CMOS                     0x05
#define EFI_ACPI_6_5_PCI_BAR_TARGET                  0x06
#define EFI_ACPI_6_5_IPMI                            0x07
#define EFI_ACPI_6_5_GENERAL_PURPOSE_IO              0x08
#define EFI_ACPI_6_5_GENERIC_SERIAL_BUS              0x09
#define EFI_ACPI_6_5_PLATFORM_COMMUNICATION_CHANNEL  0x0A
#define EFI_ACPI_6_5_FUNCTIONAL_FIXED_HARDWARE       0x7F

//
// Generic Address Space Access Sizes
//
#define EFI_ACPI_6_5_UNDEFINED  0
#define EFI_ACPI_6_5_BYTE       1
#define EFI_ACPI_6_5_WORD       2
#define EFI_ACPI_6_5_DWORD      3
#define EFI_ACPI_6_5_QWORD      4

//
// ACPI 6.5 table structures
//

///
/// Root System Description Pointer Structure
///
typedef struct {
    UINT64    Signature;
    UINT8     Checksum;
    UINT8     OemId[6];
    UINT8     Revision;
    UINT32    RsdtAddress;
    UINT32    Length;
    UINT64    XsdtAddress;
    UINT8     ExtendedChecksum;
    UINT8     Reserved[3];
} EFI_ACPI_6_5_ROOT_SYSTEM_DESCRIPTION_POINTER;

///
/// RSD_PTR Revision (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_ROOT_SYSTEM_DESCRIPTION_POINTER_REVISION  0x02 ///< ACPISpec (Revision 6.5) says current value is 2

///
/// Common table header, this prefaces all ACPI tables, including FACS, but
/// excluding the RSD PTR structure
///
typedef struct {
    UINT32    Signature;
    UINT32    Length;
} EFI_ACPI_6_5_COMMON_HEADER;

//
// Root System Description Table
// No definition needed as it is a common description table header, the same with
// EFI_ACPI_DESCRIPTION_HEADER, followed by a variable number of UINT32 table pointers.
//

///
/// RSDT Revision (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_ROOT_SYSTEM_DESCRIPTION_TABLE_REVISION  0x01

//
// Extended System Description Table
// No definition needed as it is a common description table header, the same with
// EFI_ACPI_DESCRIPTION_HEADER, followed by a variable number of UINT64 table pointers.
//

///
/// XSDT Revision (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_EXTENDED_SYSTEM_DESCRIPTION_TABLE_REVISION  0x01

///
/// Fixed ACPI Description Table Structure (FADT)
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER               Header;
    UINT32                                    FirmwareCtrl;
    UINT32                                    Dsdt;
    UINT8                                     Reserved0;
    UINT8                                     PreferredPmProfile;
    UINT16                                    SciInt;
    UINT32                                    SmiCmd;
    UINT8                                     AcpiEnable;
    UINT8                                     AcpiDisable;
    UINT8                                     S4BiosReq;
    UINT8                                     PstateCnt;
    UINT32                                    Pm1aEvtBlk;
    UINT32                                    Pm1bEvtBlk;
    UINT32                                    Pm1aCntBlk;
    UINT32                                    Pm1bCntBlk;
    UINT32                                    Pm2CntBlk;
    UINT32                                    PmTmrBlk;
    UINT32                                    Gpe0Blk;
    UINT32                                    Gpe1Blk;
    UINT8                                     Pm1EvtLen;
    UINT8                                     Pm1CntLen;
    UINT8                                     Pm2CntLen;
    UINT8                                     PmTmrLen;
    UINT8                                     Gpe0BlkLen;
    UINT8                                     Gpe1BlkLen;
    UINT8                                     Gpe1Base;
    UINT8                                     CstCnt;
    UINT16                                    PLvl2Lat;
    UINT16                                    PLvl3Lat;
    UINT16                                    FlushSize;
    UINT16                                    FlushStride;
    UINT8                                     DutyOffset;
    UINT8                                     DutyWidth;
    UINT8                                     DayAlrm;
    UINT8                                     MonAlrm;
    UINT8                                     Century;
    UINT16                                    IaPcBootArch;
    UINT8                                     Reserved1;
    UINT32                                    Flags;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    ResetReg;
    UINT8                                     ResetValue;
    UINT16                                    ArmBootArch;
    UINT8                                     MinorVersion;
    UINT64                                    XFirmwareCtrl;
    UINT64                                    XDsdt;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    XPm1aEvtBlk;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    XPm1bEvtBlk;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    XPm1aCntBlk;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    XPm1bCntBlk;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    XPm2CntBlk;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    XPmTmrBlk;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    XGpe0Blk;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    XGpe1Blk;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    SleepControlReg;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    SleepStatusReg;
    UINT64                                    HypervisorVendorIdentity;
} EFI_ACPI_6_5_FIXED_ACPI_DESCRIPTION_TABLE;

///
/// FADT Version (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_FIXED_ACPI_DESCRIPTION_TABLE_REVISION        0x06
#define EFI_ACPI_6_5_FIXED_ACPI_DESCRIPTION_TABLE_MINOR_REVISION  0x05

//
// Fixed ACPI Description Table Preferred Power Management Profile
//
#define EFI_ACPI_6_5_PM_PROFILE_UNSPECIFIED         0
#define EFI_ACPI_6_5_PM_PROFILE_DESKTOP             1
#define EFI_ACPI_6_5_PM_PROFILE_MOBILE              2
#define EFI_ACPI_6_5_PM_PROFILE_WORKSTATION         3
#define EFI_ACPI_6_5_PM_PROFILE_ENTERPRISE_SERVER   4
#define EFI_ACPI_6_5_PM_PROFILE_SOHO_SERVER         5
#define EFI_ACPI_6_5_PM_PROFILE_APPLIANCE_PC        6
#define EFI_ACPI_6_5_PM_PROFILE_PERFORMANCE_SERVER  7
#define EFI_ACPI_6_5_PM_PROFILE_TABLET              8

//
// Fixed ACPI Description Table Boot Architecture Flags
// All other bits are reserved and must be set to 0.
//
#define EFI_ACPI_6_5_LEGACY_DEVICES        BIT0
#define EFI_ACPI_6_5_8042                  BIT1
#define EFI_ACPI_6_5_VGA_NOT_PRESENT       BIT2
#define EFI_ACPI_6_5_MSI_NOT_SUPPORTED     BIT3
#define EFI_ACPI_6_5_PCIE_ASPM_CONTROLS    BIT4
#define EFI_ACPI_6_5_CMOS_RTC_NOT_PRESENT  BIT5

//
// Fixed ACPI Description Table Arm Boot Architecture Flags
// All other bits are reserved and must be set to 0.
//
#define EFI_ACPI_6_5_ARM_PSCI_COMPLIANT  BIT0
#define EFI_ACPI_6_5_ARM_PSCI_USE_HVC    BIT1

//
// Fixed ACPI Description Table Fixed Feature Flags
// All other bits are reserved and must be set to 0.
//
#define EFI_ACPI_6_5_WBINVD                                BIT0
#define EFI_ACPI_6_5_WBINVD_FLUSH                          BIT1
#define EFI_ACPI_6_5_PROC_C1                               BIT2
#define EFI_ACPI_6_5_P_LVL2_UP                             BIT3
#define EFI_ACPI_6_5_PWR_BUTTON                            BIT4
#define EFI_ACPI_6_5_SLP_BUTTON                            BIT5
#define EFI_ACPI_6_5_FIX_RTC                               BIT6
#define EFI_ACPI_6_5_RTC_S4                                BIT7
#define EFI_ACPI_6_5_TMR_VAL_EXT                           BIT8
#define EFI_ACPI_6_5_DCK_CAP                               BIT9
#define EFI_ACPI_6_5_RESET_REG_SUP                         BIT10
#define EFI_ACPI_6_5_SEALED_CASE                           BIT11
#define EFI_ACPI_6_5_HEADLESS                              BIT12
#define EFI_ACPI_6_5_CPU_SW_SLP                            BIT13
#define EFI_ACPI_6_5_PCI_EXP_WAK                           BIT14
#define EFI_ACPI_6_5_USE_PLATFORM_CLOCK                    BIT15
#define EFI_ACPI_6_5_S4_RTC_STS_VALID                      BIT16
#define EFI_ACPI_6_5_REMOTE_POWER_ON_CAPABLE               BIT17
#define EFI_ACPI_6_5_FORCE_APIC_CLUSTER_MODEL              BIT18
#define EFI_ACPI_6_5_FORCE_APIC_PHYSICAL_DESTINATION_MODE  BIT19
#define EFI_ACPI_6_5_HW_REDUCED_ACPI                       BIT20
#define EFI_ACPI_6_5_LOW_POWER_S0_IDLE_CAPABLE             BIT21

///
/// Firmware ACPI Control Structure
///
typedef struct {
    UINT32    Signature;
    UINT32    Length;
    UINT32    HardwareSignature;
    UINT32    FirmwareWakingVector;
    UINT32    GlobalLock;
    UINT32    Flags;
    UINT64    XFirmwareWakingVector;
    UINT8     Version;
    UINT8     Reserved0[3];
    UINT32    OspmFlags;
    UINT8     Reserved1[24];
} EFI_ACPI_6_5_FIRMWARE_ACPI_CONTROL_STRUCTURE;

///
/// FACS Version (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_FIRMWARE_ACPI_CONTROL_STRUCTURE_VERSION  0x02

///
/// Firmware Control Structure Feature Flags
/// All other bits are reserved and must be set to 0.
///
#define EFI_ACPI_6_5_S4BIOS_F                BIT0
#define EFI_ACPI_6_5_64BIT_WAKE_SUPPORTED_F  BIT1

///
/// OSPM Enabled Firmware Control Structure Flags
/// All other bits are reserved and must be set to 0.
///
#define EFI_ACPI_6_5_OSPM_64BIT_WAKE_F  BIT0

//
// Differentiated System Description Table,
// Secondary System Description Table
// and Persistent System Description Table,
// no definition needed as they are common description table header, the same with
// EFI_ACPI_DESCRIPTION_HEADER, followed by a definition block.
//
#define EFI_ACPI_6_5_DIFFERENTIATED_SYSTEM_DESCRIPTION_TABLE_REVISION  0x02
#define EFI_ACPI_6_5_SECONDARY_SYSTEM_DESCRIPTION_TABLE_REVISION       0x02

///
/// Multiple APIC Description Table header definition.  The rest of the table
/// must be defined in a platform specific manner.
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT32                         LocalApicAddress;
    UINT32                         Flags;
} EFI_ACPI_6_5_MULTIPLE_APIC_DESCRIPTION_TABLE_HEADER;

///
/// MADT Revision (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_MULTIPLE_APIC_DESCRIPTION_TABLE_REVISION  0x06

///
/// Multiple APIC Flags
/// All other bits are reserved and must be set to 0.
///
#define EFI_ACPI_6_5_PCAT_COMPAT  BIT0

//
// Multiple APIC Description Table APIC structure types
// All other values between 0x18 and 0x7F are reserved and
// will be ignored by OSPM. 0x80 ~ 0xFF are reserved for OEM.
//
#define EFI_ACPI_6_5_PROCESSOR_LOCAL_APIC           0x00
#define EFI_ACPI_6_5_IO_APIC                        0x01
#define EFI_ACPI_6_5_INTERRUPT_SOURCE_OVERRIDE      0x02
#define EFI_ACPI_6_5_NON_MASKABLE_INTERRUPT_SOURCE  0x03
#define EFI_ACPI_6_5_LOCAL_APIC_NMI                 0x04
#define EFI_ACPI_6_5_LOCAL_APIC_ADDRESS_OVERRIDE    0x05
#define EFI_ACPI_6_5_IO_SAPIC                       0x06
#define EFI_ACPI_6_5_LOCAL_SAPIC                    0x07
#define EFI_ACPI_6_5_PLATFORM_INTERRUPT_SOURCES     0x08
#define EFI_ACPI_6_5_PROCESSOR_LOCAL_X2APIC         0x09
#define EFI_ACPI_6_5_LOCAL_X2APIC_NMI               0x0A
#define EFI_ACPI_6_5_GIC                            0x0B
#define EFI_ACPI_6_5_GICD                           0x0C
#define EFI_ACPI_6_5_GIC_MSI_FRAME                  0x0D
#define EFI_ACPI_6_5_GICR                           0x0E
#define EFI_ACPI_6_5_GIC_ITS                        0x0F
#define EFI_ACPI_6_5_MULTIPROCESSOR_WAKEUP          0x10
#define EFI_ACPI_6_5_CORE_PIC                       0x11
#define EFI_ACPI_6_5_LIO_PIC                        0x12
#define EFI_ACPI_6_5_HT_PIC                         0x13
#define EFI_ACPI_6_5_EIO_PIC                        0x14
#define EFI_ACPI_6_5_MSI_PIC                        0x15
#define EFI_ACPI_6_5_BIO_PIC                        0x16
#define EFI_ACPI_6_5_LPC_PIC                        0x17

//
// APIC Structure Definitions
//

///
/// Processor Local APIC Structure Definition
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     AcpiProcessorUid;
    UINT8     ApicId;
    UINT32    Flags;
} EFI_ACPI_6_5_PROCESSOR_LOCAL_APIC_STRUCTURE;

///
/// Local APIC Flags.  All other bits are reserved and must be 0.
///
#define EFI_ACPI_6_5_LOCAL_APIC_ENABLED         BIT0
#define EFI_ACPI_6_5_LOCAL_APIC_ONLINE_CAPABLE  BIT1

///
/// IO APIC Structure
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     IoApicId;
    UINT8     Reserved;
    UINT32    IoApicAddress;
    UINT32    GlobalSystemInterruptBase;
} EFI_ACPI_6_5_IO_APIC_STRUCTURE;

///
/// Interrupt Source Override Structure
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     Bus;
    UINT8     Source;
    UINT32    GlobalSystemInterrupt;
    UINT16    Flags;
} EFI_ACPI_6_5_INTERRUPT_SOURCE_OVERRIDE_STRUCTURE;

///
/// Platform Interrupt Sources Structure Definition
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT16    Flags;
    UINT8     InterruptType;
    UINT8     ProcessorId;
    UINT8     ProcessorEid;
    UINT8     IoSapicVector;
    UINT32    GlobalSystemInterrupt;
    UINT32    PlatformInterruptSourceFlags;
    UINT8     CpeiProcessorOverride;
    UINT8     Reserved[31];
} EFI_ACPI_6_5_PLATFORM_INTERRUPT_APIC_STRUCTURE;

//
// MPS INTI flags.
// All other bits are reserved and must be set to 0.
//
#define EFI_ACPI_6_5_POLARITY      (3 << 0)
#define EFI_ACPI_6_5_TRIGGER_MODE  (3 << 2)

///
/// Non-Maskable Interrupt Source Structure
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT16    Flags;
    UINT32    GlobalSystemInterrupt;
} EFI_ACPI_6_5_NON_MASKABLE_INTERRUPT_SOURCE_STRUCTURE;

///
/// Local APIC NMI Structure
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     AcpiProcessorUid;
    UINT16    Flags;
    UINT8     LocalApicLint;
} EFI_ACPI_6_5_LOCAL_APIC_NMI_STRUCTURE;

///
/// Local APIC Address Override Structure
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT16    Reserved;
    UINT64    LocalApicAddress;
} EFI_ACPI_6_5_LOCAL_APIC_ADDRESS_OVERRIDE_STRUCTURE;

///
/// IO SAPIC Structure
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     IoApicId;
    UINT8     Reserved;
    UINT32    GlobalSystemInterruptBase;
    UINT64    IoSapicAddress;
} EFI_ACPI_6_5_IO_SAPIC_STRUCTURE;

///
/// Local SAPIC Structure
/// This struct followed by a null-terminated ASCII string - ACPI Processor UID String
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     AcpiProcessorId;
    UINT8     LocalSapicId;
    UINT8     LocalSapicEid;
    UINT8     Reserved[3];
    UINT32    Flags;
    UINT32    ACPIProcessorUIDValue;
} EFI_ACPI_6_5_PROCESSOR_LOCAL_SAPIC_STRUCTURE;

///
/// Platform Interrupt Sources Structure
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT16    Flags;
    UINT8     InterruptType;
    UINT8     ProcessorId;
    UINT8     ProcessorEid;
    UINT8     IoSapicVector;
    UINT32    GlobalSystemInterrupt;
    UINT32    PlatformInterruptSourceFlags;
} EFI_ACPI_6_5_PLATFORM_INTERRUPT_SOURCES_STRUCTURE;

///
/// Platform Interrupt Source Flags.
/// All other bits are reserved and must be set to 0.
///
#define EFI_ACPI_6_5_CPEI_PROCESSOR_OVERRIDE  BIT0

///
/// Processor Local x2APIC Structure Definition
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     Reserved[2];
    UINT32    X2ApicId;
    UINT32    Flags;
    UINT32    AcpiProcessorUid;
} EFI_ACPI_6_5_PROCESSOR_LOCAL_X2APIC_STRUCTURE;

///
/// Local x2APIC NMI Structure
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT16    Flags;
    UINT32    AcpiProcessorUid;
    UINT8     LocalX2ApicLint;
    UINT8     Reserved[3];
} EFI_ACPI_6_5_LOCAL_X2APIC_NMI_STRUCTURE;

///
/// GIC Structure
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT16    Reserved;
    UINT32    CPUInterfaceNumber;
    UINT32    AcpiProcessorUid;
    UINT32    Flags;
    UINT32    ParkingProtocolVersion;
    UINT32    PerformanceInterruptGsiv;
    UINT64    ParkedAddress;
    UINT64    PhysicalBaseAddress;
    UINT64    GICV;
    UINT64    GICH;
    UINT32    VGICMaintenanceInterrupt;
    UINT64    GICRBaseAddress;
    UINT64    MPIDR;
    UINT8     ProcessorPowerEfficiencyClass;
    UINT8     Reserved2;
    UINT16    SpeOverflowInterrupt;
} EFI_ACPI_6_5_GIC_STRUCTURE;

///
/// GIC Flags.  All other bits are reserved and must be 0.
///
#define EFI_ACPI_6_5_GIC_ENABLED                            BIT0
#define EFI_ACPI_6_5_PERFORMANCE_INTERRUPT_MODEL            BIT1
#define EFI_ACPI_6_5_VGIC_MAINTENANCE_INTERRUPT_MODE_FLAGS  BIT2

///
/// GIC Distributor Structure
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT16    Reserved1;
    UINT32    GicId;
    UINT64    PhysicalBaseAddress;
    UINT32    SystemVectorBase;
    UINT8     GicVersion;
    UINT8     Reserved2[3];
} EFI_ACPI_6_5_GIC_DISTRIBUTOR_STRUCTURE;

///
/// GIC Version
///
#define EFI_ACPI_6_5_GIC_V1  0x01
#define EFI_ACPI_6_5_GIC_V2  0x02
#define EFI_ACPI_6_5_GIC_V3  0x03
#define EFI_ACPI_6_5_GIC_V4  0x04

///
/// GIC MSI Frame Structure
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT16    Reserved1;
    UINT32    GicMsiFrameId;
    UINT64    PhysicalBaseAddress;
    UINT32    Flags;
    UINT16    SPICount;
    UINT16    SPIBase;
} EFI_ACPI_6_5_GIC_MSI_FRAME_STRUCTURE;

///
/// GIC MSI Frame Flags.  All other bits are reserved and must be 0.
///
#define EFI_ACPI_6_5_SPI_COUNT_BASE_SELECT  BIT0

///
/// GICR Structure
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT16    Reserved;
    UINT64    DiscoveryRangeBaseAddress;
    UINT32    DiscoveryRangeLength;
} EFI_ACPI_6_5_GICR_STRUCTURE;

///
/// GIC Interrupt Translation Service Structure
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT16    Reserved;
    UINT32    GicItsId;
    UINT64    PhysicalBaseAddress;
    UINT32    Reserved2;
} EFI_ACPI_6_5_GIC_ITS_STRUCTURE;

///
/// Multiprocessor Wakeup Structure
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT16    MailBoxVersion;
    UINT32    Reserved;
    UINT64    MailBoxAddress;
} EFI_ACPI_6_5_MULTIPROCESSOR_WAKEUP_STRUCTURE;

///
/// Multiprocessor Wakeup Mailbox Structure
///
typedef struct {
    UINT16    Command;
    UINT16    Reserved;
    UINT32    AcpiId;
    UINT64    WakeupVector;
    UINT8     ReservedForOs[2032];
    UINT8     ReservedForFirmware[2048];
} EFI_ACPI_6_5_MULTIPROCESSOR_WAKEUP_MAILBOX_STRUCTURE;

#define EFI_ACPI_6_5_MULTIPROCESSOR_WAKEUP_MAILBOX_COMMAND_NOOP    0x0000
#define EFI_ACPI_6_5_MULTIPROCESSOR_WAKEUP_MAILBOX_COMMAND_WAKEUP  0x0001

///
/// Core Programmable Interrupt Controller
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     Version;
    UINT32    ProcessorId;
    UINT32    CoreId;
    UINT32    Flags;
} EFI_ACPI_6_5_CORE_PIC_STRUCTURE;

///
/// Legacy I/O Programmable Interrupt Controller
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     Version;
    UINT64    Address;
    UINT16    Size;
    UINT8     Cascade[2];
    UINT32    CascadeMap[2];
} EFI_ACPI_6_5_LIO_PIC_STRUCTURE;

///
/// HyperTransport Programmable Interrupt Controller
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     Version;
    UINT64    Address;
    UINT16    Size;
    UINT8     Cascade[8];
} EFI_ACPI_6_5_HT_PIC_STRUCTURE;

///
/// Extend I/O Programmable Interrupt Controller
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     Version;
    UINT8     Cascade;
    UINT8     Node;
    UINT64    NodeMap;
} EFI_ACPI_6_5_EIO_PIC_STRUCTURE;

///
/// MSI Programmable Interrupt Controller
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     Version;
    UINT64    MsgAddress;
    UINT32    Start;
    UINT32    Count;
} EFI_ACPI_6_5_MSI_PIC_STRUCTURE;

///
/// Bridge I/O Programmable Interrupt Controller
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     Version;
    UINT64    Address;
    UINT16    Size;
    UINT16    Id;
    UINT16    GsiBase;
} EFI_ACPI_6_5_BIO_PIC_STRUCTURE;

///
/// Low Pin Count Programmable Interrupt Controller
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     Version;
    UINT64    Address;
    UINT16    Size;
    UINT8     Cascade;
} EFI_ACPI_6_5_LPC_PIC_STRUCTURE;

///
/// Smart Battery Description Table (SBST)
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT32                         WarningEnergyLevel;
    UINT32                         LowEnergyLevel;
    UINT32                         CriticalEnergyLevel;
} EFI_ACPI_6_5_SMART_BATTERY_DESCRIPTION_TABLE;

///
/// SBST Version (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_SMART_BATTERY_DESCRIPTION_TABLE_REVISION  0x01

///
/// Embedded Controller Boot Resources Table (ECDT)
/// The table is followed by a null terminated ASCII string that contains
/// a fully qualified reference to the name space object.
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER               Header;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    EcControl;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    EcData;
    UINT32                                    Uid;
    UINT8                                     GpeBit;
} EFI_ACPI_6_5_EMBEDDED_CONTROLLER_BOOT_RESOURCES_TABLE;

///
/// ECDT Version (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_EMBEDDED_CONTROLLER_BOOT_RESOURCES_TABLE_REVISION  0x01

///
/// System Resource Affinity Table (SRAT).  The rest of the table
/// must be defined in a platform specific manner.
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT32                         Reserved1; ///< Must be set to 1
    UINT64                         Reserved2;
} EFI_ACPI_6_5_SYSTEM_RESOURCE_AFFINITY_TABLE_HEADER;

///
/// SRAT Version (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_SYSTEM_RESOURCE_AFFINITY_TABLE_REVISION  0x03

//
// SRAT structure types.
// All other values between 0x06 an 0xFF are reserved and
// will be ignored by OSPM.
//
#define EFI_ACPI_6_5_PROCESSOR_LOCAL_APIC_SAPIC_AFFINITY  0x00
#define EFI_ACPI_6_5_MEMORY_AFFINITY                      0x01
#define EFI_ACPI_6_5_PROCESSOR_LOCAL_X2APIC_AFFINITY      0x02
#define EFI_ACPI_6_5_GICC_AFFINITY                        0x03
#define EFI_ACPI_6_5_GIC_ITS_AFFINITY                     0x04
#define EFI_ACPI_6_5_GENERIC_INITIATOR_AFFINITY           0x05

///
/// Processor Local APIC/SAPIC Affinity Structure Definition
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     ProximityDomain7To0;
    UINT8     ApicId;
    UINT32    Flags;
    UINT8     LocalSapicEid;
    UINT8     ProximityDomain31To8[3];
    UINT32    ClockDomain;
} EFI_ACPI_6_5_PROCESSOR_LOCAL_APIC_SAPIC_AFFINITY_STRUCTURE;

///
/// Local APIC/SAPIC Flags.  All other bits are reserved and must be 0.
///
#define EFI_ACPI_6_5_PROCESSOR_LOCAL_APIC_SAPIC_ENABLED  (1 << 0)

///
/// Memory Affinity Structure Definition
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT32    ProximityDomain;
    UINT16    Reserved1;
    UINT32    AddressBaseLow;
    UINT32    AddressBaseHigh;
    UINT32    LengthLow;
    UINT32    LengthHigh;
    UINT32    Reserved2;
    UINT32    Flags;
    UINT64    Reserved3;
} EFI_ACPI_6_5_MEMORY_AFFINITY_STRUCTURE;

//
// Memory Flags.  All other bits are reserved and must be 0.
//
#define EFI_ACPI_6_5_MEMORY_ENABLED        (1 << 0)
#define EFI_ACPI_6_5_MEMORY_HOT_PLUGGABLE  (1 << 1)
#define EFI_ACPI_6_5_MEMORY_NONVOLATILE    (1 << 2)

///
/// Processor Local x2APIC Affinity Structure Definition
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     Reserved1[2];
    UINT32    ProximityDomain;
    UINT32    X2ApicId;
    UINT32    Flags;
    UINT32    ClockDomain;
    UINT8     Reserved2[4];
} EFI_ACPI_6_5_PROCESSOR_LOCAL_X2APIC_AFFINITY_STRUCTURE;

///
/// GICC Affinity Structure Definition
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT32    ProximityDomain;
    UINT32    AcpiProcessorUid;
    UINT32    Flags;
    UINT32    ClockDomain;
} EFI_ACPI_6_5_GICC_AFFINITY_STRUCTURE;

///
/// GICC Flags.  All other bits are reserved and must be 0.
///
#define EFI_ACPI_6_5_GICC_ENABLED  (1 << 0)

///
/// GIC Interrupt Translation Service (ITS) Affinity Structure Definition
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT32    ProximityDomain;
    UINT8     Reserved[2];
    UINT32    ItsId;
} EFI_ACPI_6_5_GIC_ITS_AFFINITY_STRUCTURE;

//
// Generic Initiator Affinity Structure Device Handle Types
// All other values between 0x02 an 0xFF are reserved and
// will be ignored by OSPM.
//
#define EFI_ACPI_6_5_ACPI_DEVICE_HANDLE  0x00
#define EFI_ACPI_6_5_PCI_DEVICE_HANDLE   0x01

///
/// Device Handle - ACPI
///
typedef struct {
    UINT64    AcpiHid;
    UINT32    AcpiUid;
    UINT8     Reserved[4];
} EFI_ACPI_6_5_DEVICE_HANDLE_ACPI;

///
/// Device Handle - PCI
///
typedef struct {
    UINT16    PciSegment;
    UINT16    PciBdfNumber;
    UINT8     Reserved[12];
} EFI_ACPI_6_5_DEVICE_HANDLE_PCI;

///
/// Device Handle
///
typedef union {
    EFI_ACPI_6_5_DEVICE_HANDLE_ACPI    Acpi;
    EFI_ACPI_6_5_DEVICE_HANDLE_PCI     Pci;
} EFI_ACPI_6_5_DEVICE_HANDLE;

///
/// Generic Initiator Affinity Structure
///
typedef struct {
    UINT8                         Type;
    UINT8                         Length;
    UINT8                         Reserved1;
    UINT8                         DeviceHandleType;
    UINT32                        ProximityDomain;
    EFI_ACPI_6_5_DEVICE_HANDLE    DeviceHandle;
    UINT32                        Flags;
    UINT8                         Reserved2[4];
} EFI_ACPI_6_5_GENERIC_INITIATOR_AFFINITY_STRUCTURE;

///
/// Generic Initiator Affinity Structure Flags. All other bits are reserved
/// and must be 0.
///
#define EFI_ACPI_6_5_GENERIC_INITIATOR_AFFINITY_STRUCTURE_ENABLED                     BIT0
#define EFI_ACPI_6_5_GENERIC_INITIATOR_AFFINITY_STRUCTURE_ARCHITECTURAL_TRANSACTIONS  BIT1

///
/// System Locality Distance Information Table (SLIT).
/// The rest of the table is a matrix.
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT64                         NumberOfSystemLocalities;
} EFI_ACPI_6_5_SYSTEM_LOCALITY_DISTANCE_INFORMATION_TABLE_HEADER;

///
/// SLIT Version (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_SYSTEM_LOCALITY_DISTANCE_INFORMATION_TABLE_REVISION  0x01

///
/// Corrected Platform Error Polling Table (CPEP)
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT8                          Reserved[8];
} EFI_ACPI_6_5_CORRECTED_PLATFORM_ERROR_POLLING_TABLE_HEADER;

///
/// CPEP Version (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_CORRECTED_PLATFORM_ERROR_POLLING_TABLE_REVISION  0x01

//
// CPEP processor structure types.
//
#define EFI_ACPI_6_5_CPEP_PROCESSOR_APIC_SAPIC  0x00

///
/// Corrected Platform Error Polling Processor Structure Definition
///
typedef struct {
    UINT8     Type;
    UINT8     Length;
    UINT8     ProcessorId;
    UINT8     ProcessorEid;
    UINT32    PollingInterval;
} EFI_ACPI_6_5_CPEP_PROCESSOR_APIC_SAPIC_STRUCTURE;

///
/// Maximum System Characteristics Table (MSCT)
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT32                         OffsetProxDomInfo;
    UINT32                         MaximumNumberOfProximityDomains;
    UINT32                         MaximumNumberOfClockDomains;
    UINT64                         MaximumPhysicalAddress;
} EFI_ACPI_6_5_MAXIMUM_SYSTEM_CHARACTERISTICS_TABLE_HEADER;

///
/// MSCT Version (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_MAXIMUM_SYSTEM_CHARACTERISTICS_TABLE_REVISION  0x01

///
/// Maximum Proximity Domain Information Structure Definition
///
typedef struct {
    UINT8     Revision;
    UINT8     Length;
    UINT32    ProximityDomainRangeLow;
    UINT32    ProximityDomainRangeHigh;
    UINT32    MaximumProcessorCapacity;
    UINT64    MaximumMemoryCapacity;
} EFI_ACPI_6_5_MAXIMUM_PROXIMITY_DOMAIN_INFORMATION_STRUCTURE;

///
/// ACPI RAS Feature Table definition.
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT8                          PlatformCommunicationChannelIdentifier[12];
} EFI_ACPI_6_5_RAS_FEATURE_TABLE;

///
/// RASF Version (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_RAS_FEATURE_TABLE_REVISION  0x01

///
/// ACPI RASF Platform Communication Channel Shared Memory Region definition.
///
typedef struct {
    UINT32    Signature;
    UINT16    Command;
    UINT16    Status;
    UINT16    Version;
    UINT8     RASCapabilities[16];
    UINT8     SetRASCapabilities[16];
    UINT16    NumberOfRASFParameterBlocks;
    UINT32    SetRASCapabilitiesStatus;
} EFI_ACPI_6_5_RASF_PLATFORM_COMMUNICATION_CHANNEL_SHARED_MEMORY_REGION;

///
/// ACPI RASF PCC command code
///
#define EFI_ACPI_6_5_RASF_PCC_COMMAND_CODE_EXECUTE_RASF_COMMAND  0x01

///
/// ACPI RASF Platform RAS Capabilities
///
#define EFI_ACPI_6_5_RASF_PLATFORM_RAS_CAPABILITY_HARDWARE_BASED_PATROL_SCRUB_SUPPORTED                          BIT0
#define EFI_ACPI_6_5_RASF_PLATFORM_RAS_CAPABILITY_HARDWARE_BASED_PATROL_SCRUB_SUPPORTED_AND_EXPOSED_TO_SOFTWARE  BIT1
#define EFI_ACPI_6_5_RASF_PLATFORM_RAS_CAPABILITY_CPU_CACHE_FLUSH_TO_NVDIMM_DURABILITY_ON_POWER_LOSS             BIT2
#define EFI_ACPI_6_5_RASF_PLATFORM_RAS_CAPABILITY_MEMORY_CONTROLLER_FLUSH_TO_NVDIMM_DURABILITY_ON_POWER_LOSS     BIT3
#define EFI_ACPI_6_5_RASF_PLATFORM_RAS_CAPABILITY_BYTE_ADDRESSABLE_PERSISTENT_MEMORY_HARDWARE_MIRRORING          BIT4

///
/// ACPI RASF Parameter Block structure for PATROL_SCRUB
///
typedef struct {
    UINT16    Type;
    UINT16    Version;
    UINT16    Length;
    UINT16    PatrolScrubCommand;
    UINT64    RequestedAddressRange[2];
    UINT64    ActualAddressRange[2];
    UINT16    Flags;
    UINT8     RequestedSpeed;
} EFI_ACPI_6_5_RASF_PATROL_SCRUB_PLATFORM_BLOCK_STRUCTURE;

///
/// ACPI RASF Patrol Scrub command
///
#define EFI_ACPI_6_5_RASF_PATROL_SCRUB_COMMAND_GET_PATROL_PARAMETERS  0x01
#define EFI_ACPI_6_5_RASF_PATROL_SCRUB_COMMAND_START_PATROL_SCRUBBER  0x02
#define EFI_ACPI_6_5_RASF_PATROL_SCRUB_COMMAND_STOP_PATROL_SCRUBBER   0x03

///
/// Memory Power State Table definition.
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT8                          PlatformCommunicationChannelIdentifier;
    UINT8                          Reserved[3];
    // Memory Power Node Structure
    // Memory Power State Characteristics
} EFI_ACPI_6_5_MEMORY_POWER_STATUS_TABLE;

///
/// MPST Version (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_MEMORY_POWER_STATE_TABLE_REVISION  0x01

///
/// MPST Platform Communication Channel Shared Memory Region definition.
///
typedef struct {
    UINT32    Signature;
    UINT16    Command;
    UINT16    Status;
    UINT32    MemoryPowerCommandRegister;
    UINT32    MemoryPowerStatusRegister;
    UINT32    PowerStateId;
    UINT32    MemoryPowerNodeId;
    UINT64    MemoryEnergyConsumed;
    UINT64    ExpectedAveragePowerComsuned;
} EFI_ACPI_6_5_MPST_PLATFORM_COMMUNICATION_CHANNEL_SHARED_MEMORY_REGION;

///
/// ACPI MPST PCC command code
///
#define EFI_ACPI_6_5_MPST_PCC_COMMAND_CODE_EXECUTE_MPST_COMMAND  0x03

///
/// ACPI MPST Memory Power command
///
#define EFI_ACPI_6_5_MPST_MEMORY_POWER_COMMAND_GET_MEMORY_POWER_STATE      0x01
#define EFI_ACPI_6_5_MPST_MEMORY_POWER_COMMAND_SET_MEMORY_POWER_STATE      0x02
#define EFI_ACPI_6_5_MPST_MEMORY_POWER_COMMAND_GET_AVERAGE_POWER_CONSUMED  0x03
#define EFI_ACPI_6_5_MPST_MEMORY_POWER_COMMAND_GET_MEMORY_ENERGY_CONSUMED  0x04

///
/// MPST Memory Power Node Table
///
typedef struct {
    UINT8    PowerStateValue;
    UINT8    PowerStateInformationIndex;
} EFI_ACPI_6_5_MPST_MEMORY_POWER_STATE;

typedef struct {
    UINT8     Flag;
    UINT8     Reserved;
    UINT16    MemoryPowerNodeId;
    UINT32    Length;
    UINT64    AddressBase;
    UINT64    AddressLength;
    UINT32    NumberOfPowerStates;
    UINT32    NumberOfPhysicalComponents;
    // EFI_ACPI_6_5_MPST_MEMORY_POWER_STATE              MemoryPowerState[NumberOfPowerStates];
    // UINT16                                            PhysicalComponentIdentifier[NumberOfPhysicalComponents];
} EFI_ACPI_6_5_MPST_MEMORY_POWER_STRUCTURE;

#define EFI_ACPI_6_5_MPST_MEMORY_POWER_STRUCTURE_FLAG_ENABLE         0x01
#define EFI_ACPI_6_5_MPST_MEMORY_POWER_STRUCTURE_FLAG_POWER_MANAGED  0x02
#define EFI_ACPI_6_5_MPST_MEMORY_POWER_STRUCTURE_FLAG_HOT_PLUGGABLE  0x04

typedef struct {
    UINT16    MemoryPowerNodeCount;
    UINT8     Reserved[2];
} EFI_ACPI_6_5_MPST_MEMORY_POWER_NODE_TABLE;

///
/// MPST Memory Power State Characteristics Table
///
typedef struct {
    UINT8     PowerStateStructureID;
    UINT8     Flag;
    UINT16    Reserved;
    UINT32    AveragePowerConsumedInMPS0;
    UINT32    RelativePowerSavingToMPS0;
    UINT64    ExitLatencyToMPS0;
} EFI_ACPI_6_5_MPST_MEMORY_POWER_STATE_CHARACTERISTICS_STRUCTURE;

#define EFI_ACPI_6_5_MPST_MEMORY_POWER_STATE_CHARACTERISTICS_STRUCTURE_FLAG_MEMORY_CONTENT_PRESERVED             0x01
#define EFI_ACPI_6_5_MPST_MEMORY_POWER_STATE_CHARACTERISTICS_STRUCTURE_FLAG_AUTONOMOUS_MEMORY_POWER_STATE_ENTRY  0x02
#define EFI_ACPI_6_5_MPST_MEMORY_POWER_STATE_CHARACTERISTICS_STRUCTURE_FLAG_AUTONOMOUS_MEMORY_POWER_STATE_EXIT   0x04

typedef struct {
    UINT16    MemoryPowerStateCharacteristicsCount;
    UINT8     Reserved[2];
} EFI_ACPI_6_5_MPST_MEMORY_POWER_STATE_CHARACTERISTICS_TABLE;

///
/// Platform Memory Topology Table definition.
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT32                         NumberOfMemoryDevices;
    // EFI_ACPI_6_5_PMTT_COMMON_MEMORY_DEVICE  MemoryDeviceStructure[NumberOfMemoryDevices];
} EFI_ACPI_6_5_PLATFORM_MEMORY_TOPOLOGY_TABLE;

///
/// PMTT Version (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_MEMORY_TOPOLOGY_TABLE_REVISION  0x02

///
/// Common Memory Device.
///
typedef struct {
    UINT8     Type;
    UINT8     Reserved;
    UINT16    Length;
    UINT16    Flags;
    UINT16    Reserved1;
    UINT32    NumberOfMemoryDevices;
    // UINT8                                   TypeSpecificData[];
    // EFI_ACPI_6_5_PMTT_COMMON_MEMORY_DEVICE  MemoryDeviceStructure[NumberOfMemoryDevices];
} EFI_ACPI_6_5_PMTT_COMMON_MEMORY_DEVICE;

///
/// Memory Device Type.
///
#define EFI_ACPI_6_5_PMTT_MEMORY_DEVICE_TYPE_SOCKET                0x0
#define EFI_ACPI_6_5_PMTT_MEMORY_DEVICE_TYPE_MEMORY_CONTROLLER     0x1
#define EFI_ACPI_6_5_PMTT_MEMORY_DEVICE_TYPE_DIMM                  0x2
#define EFI_ACPI_6_5_PMTT_MEMORY_DEVICE_TYPE_VENDOR_SPECIFIC_TYPE  0xFF

///
/// Socket Type Data.
///
typedef struct {
    EFI_ACPI_6_5_PMTT_COMMON_MEMORY_DEVICE    CommonMemoryDeviceHeader;
    UINT16                                    SocketIdentifier;
    UINT16                                    Reserved;
    // EFI_ACPI_6_5_PMTT_COMMON_MEMORY_DEVICE  MemoryDeviceStructure[];
} EFI_ACPI_6_5_PMTT_SOCKET_TYPE_DATA;

///
/// Memory Controller Type Data.
///
typedef struct {
    EFI_ACPI_6_5_PMTT_COMMON_MEMORY_DEVICE    CommonMemoryDeviceHeader;
    UINT16                                    MemoryControllerIdentifier;
    UINT16                                    Reserved;
    // EFI_ACPI_6_5_PMTT_COMMON_MEMORY_DEVICE  MemoryDeviceStructure[];
} EFI_ACPI_6_5_PMTT_MEMORY_CONTROLLER_TYPE_DATA;

///
/// DIMM Type Specific Data.
///
typedef struct {
    EFI_ACPI_6_5_PMTT_COMMON_MEMORY_DEVICE    CommonMemoryDeviceHeader;
    UINT32                                    SmbiosHandle;
} EFI_ACPI_6_5_PMTT_DIMM_TYPE_SPECIFIC_DATA;

///
/// Vendor Specific Type Data.
///
typedef struct {
    EFI_ACPI_6_5_PMTT_COMMON_MEMORY_DEVICE    CommonMemoryDeviceHeader;
    UINT8                                     TypeUuid[16];
    // EFI_ACPI_6_5_PMTT_VENDOR_SPECIFIC_TYPE_DATA   VendorSpecificData[];
    // EFI_ACPI_6_5_PMTT_COMMON_MEMORY_DEVICE        MemoryDeviceStructure[];
} EFI_ACPI_6_5_PMTT_VENDOR_SPECIFIC_TYPE_DATA;

///
/// Boot Graphics Resource Table definition.
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    ///
    /// 2-bytes (16 bit) version ID. This value must be 1.
    ///
    UINT16                         Version;
    ///
    /// 1-byte status field indicating current status about the table.
    ///     Bits[7:3] = Reserved (must be zero)
    ///     Bits[2:1] = Orientation Offset. These bits describe the clockwise
    ///                 degree offset from the image's default orientation.
    ///                 [00] = 0, no offset
    ///                 [01] = 90
    ///                 [10] = 180
    ///                 [11] = 270
    ///     Bit [0] = Displayed. A one indicates the boot image graphic is
    ///               displayed.
    ///
    UINT8     Status;
    ///
    /// 1-byte enumerated type field indicating format of the image.
    ///     0 = Bitmap
    ///     1 - 255  Reserved (for future use)
    ///
    UINT8     ImageType;
    ///
    /// 8-byte (64 bit) physical address pointing to the firmware's in-memory copy
    /// of the image bitmap.
    ///
    UINT64    ImageAddress;
    ///
    /// A 4-byte (32-bit) unsigned long describing the display X-offset of the boot image.
    /// (X, Y) display offset of the top left corner of the boot image.
    /// The top left corner of the display is at offset (0, 0).
    ///
    UINT32    ImageOffsetX;
    ///
    /// A 4-byte (32-bit) unsigned long describing the display Y-offset of the boot image.
    /// (X, Y) display offset of the top left corner of the boot image.
    /// The top left corner of the display is at offset (0, 0).
    ///
    UINT32    ImageOffsetY;
} EFI_ACPI_6_5_BOOT_GRAPHICS_RESOURCE_TABLE;

///
/// BGRT Revision
///
#define EFI_ACPI_6_5_BOOT_GRAPHICS_RESOURCE_TABLE_REVISION  1

///
/// BGRT Version
///
#define EFI_ACPI_6_5_BGRT_VERSION  0x01

///
/// BGRT Status
///
#define EFI_ACPI_6_5_BGRT_STATUS_NOT_DISPLAYED  0x00
#define EFI_ACPI_6_5_BGRT_STATUS_DISPLAYED      0x01

///
/// BGRT Image Type
///
#define EFI_ACPI_6_5_BGRT_IMAGE_TYPE_BMP  0x00

///
/// FPDT Version (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_FIRMWARE_PERFORMANCE_DATA_TABLE_REVISION  0x01

///
/// FPDT Performance Record Types
///
#define EFI_ACPI_6_5_FPDT_RECORD_TYPE_FIRMWARE_BASIC_BOOT_POINTER   0x0000
#define EFI_ACPI_6_5_FPDT_RECORD_TYPE_S3_PERFORMANCE_TABLE_POINTER  0x0001

///
/// FPDT Performance Record Revision
///
#define EFI_ACPI_6_5_FPDT_RECORD_REVISION_FIRMWARE_BASIC_BOOT_POINTER   0x01
#define EFI_ACPI_6_5_FPDT_RECORD_REVISION_S3_PERFORMANCE_TABLE_POINTER  0x01

///
/// FPDT Runtime Performance Record Types
///
#define EFI_ACPI_6_5_FPDT_RUNTIME_RECORD_TYPE_S3_RESUME            0x0000
#define EFI_ACPI_6_5_FPDT_RUNTIME_RECORD_TYPE_S3_SUSPEND           0x0001
#define EFI_ACPI_6_5_FPDT_RUNTIME_RECORD_TYPE_FIRMWARE_BASIC_BOOT  0x0002

///
/// FPDT Runtime Performance Record Revision
///
#define EFI_ACPI_6_5_FPDT_RUNTIME_RECORD_REVISION_S3_RESUME            0x01
#define EFI_ACPI_6_5_FPDT_RUNTIME_RECORD_REVISION_S3_SUSPEND           0x01
#define EFI_ACPI_6_5_FPDT_RUNTIME_RECORD_REVISION_FIRMWARE_BASIC_BOOT  0x02

///
/// FPDT Performance Record header
///
typedef struct {
    UINT16    Type;
    UINT8     Length;
    UINT8     Revision;
} EFI_ACPI_6_5_FPDT_PERFORMANCE_RECORD_HEADER;

///
/// FPDT Performance Table header
///
typedef struct {
    UINT32    Signature;
    UINT32    Length;
} EFI_ACPI_6_5_FPDT_PERFORMANCE_TABLE_HEADER;

///
/// FPDT Firmware Basic Boot Performance Pointer Record Structure
///
typedef struct {
    EFI_ACPI_6_5_FPDT_PERFORMANCE_RECORD_HEADER    Header;
    UINT32                                         Reserved;
    ///
    /// 64-bit processor-relative physical address of the Basic Boot Performance Table.
    ///
    UINT64                                         BootPerformanceTablePointer;
} EFI_ACPI_6_5_FPDT_BOOT_PERFORMANCE_TABLE_POINTER_RECORD;

///
/// FPDT S3 Performance Table Pointer Record Structure
///
typedef struct {
    EFI_ACPI_6_5_FPDT_PERFORMANCE_RECORD_HEADER    Header;
    UINT32                                         Reserved;
    ///
    /// 64-bit processor-relative physical address of the S3 Performance Table.
    ///
    UINT64                                         S3PerformanceTablePointer;
} EFI_ACPI_6_5_FPDT_S3_PERFORMANCE_TABLE_POINTER_RECORD;

///
/// FPDT Firmware Basic Boot Performance Record Structure
///
typedef struct {
    EFI_ACPI_6_5_FPDT_PERFORMANCE_RECORD_HEADER    Header;
    UINT32                                         Reserved;
    ///
    /// Timer value logged at the beginning of firmware image execution.
    /// This may not always be zero or near zero.
    ///
    UINT64                                         ResetEnd;
    ///
    /// Timer value logged just prior to loading the OS boot loader into memory.
    /// For non-UEFI compatible boots, this field must be zero.
    ///
    UINT64                                         OsLoaderLoadImageStart;
    ///
    /// Timer value logged just prior to launching the previously loaded OS boot loader image.
    /// For non-UEFI compatible boots, the timer value logged will be just prior
    /// to the INT 19h handler invocation.
    ///
    UINT64                                         OsLoaderStartImageStart;
    ///
    /// Timer value logged at the point when the OS loader calls the
    /// ExitBootServices function for UEFI compatible firmware.
    /// For non-UEFI compatible boots, this field must be zero.
    ///
    UINT64                                         ExitBootServicesEntry;
    ///
    /// Timer value logged at the point just prior towhen the OS loader gaining
    /// control back from calls the ExitBootServices function for UEFI compatible firmware.
    /// For non-UEFI compatible boots, this field must be zero.
    ///
    UINT64                                         ExitBootServicesExit;
} EFI_ACPI_6_5_FPDT_FIRMWARE_BASIC_BOOT_RECORD;

///
/// FPDT Firmware Basic Boot Performance Table signature
///
#define EFI_ACPI_6_5_FPDT_BOOT_PERFORMANCE_TABLE_SIGNATURE  SIGNATURE_32('F', 'B', 'P', 'T')

//
// FPDT Firmware Basic Boot Performance Table
//
typedef struct {
    EFI_ACPI_6_5_FPDT_PERFORMANCE_TABLE_HEADER    Header;
    //
    // one or more Performance Records.
    //
} EFI_ACPI_6_5_FPDT_FIRMWARE_BASIC_BOOT_TABLE;

///
/// FPDT "S3PT" S3 Performance Table
///
#define EFI_ACPI_6_5_FPDT_S3_PERFORMANCE_TABLE_SIGNATURE  SIGNATURE_32('S', '3', 'P', 'T')

//
// FPDT Firmware S3 Boot Performance Table
//
typedef struct {
    EFI_ACPI_6_5_FPDT_PERFORMANCE_TABLE_HEADER    Header;
    //
    // one or more Performance Records.
    //
} EFI_ACPI_6_5_FPDT_FIRMWARE_S3_BOOT_TABLE;

///
/// FPDT Basic S3 Resume Performance Record
///
typedef struct {
    EFI_ACPI_6_5_FPDT_PERFORMANCE_RECORD_HEADER    Header;
    ///
    /// A count of the number of S3 resume cycles since the last full boot sequence.
    ///
    UINT32                                         ResumeCount;
    ///
    /// Timer recorded at the end of BIOS S3 resume, just prior to handoff to the
    /// OS waking vector. Only the most recent resume cycle's time is retained.
    ///
    UINT64                                         FullResume;
    ///
    /// Average timer value of all resume cycles logged since the last full boot
    /// sequence, including the most recent resume.  Note that the entire log of
    /// timer values does not need to be retained in order to calculate this average.
    ///
    UINT64                                         AverageResume;
} EFI_ACPI_6_5_FPDT_S3_RESUME_RECORD;

///
/// FPDT Basic S3 Suspend Performance Record
///
typedef struct {
    EFI_ACPI_6_5_FPDT_PERFORMANCE_RECORD_HEADER    Header;
    ///
    /// Timer value recorded at the OS write to SLP_TYP upon entry to S3.
    /// Only the most recent suspend cycle's timer value is retained.
    ///
    UINT64                                         SuspendStart;
    ///
    /// Timer value recorded at the final firmware write to SLP_TYP (or other
    /// mechanism) used to trigger hardware entry to S3.
    /// Only the most recent suspend cycle's timer value is retained.
    ///
    UINT64                                         SuspendEnd;
} EFI_ACPI_6_5_FPDT_S3_SUSPEND_RECORD;

///
/// Firmware Performance Record Table definition.
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
} EFI_ACPI_6_5_FIRMWARE_PERFORMANCE_RECORD_TABLE;

///
/// Generic Timer Description Table definition.
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT64                         CntControlBasePhysicalAddress;
    UINT32                         Reserved;
    UINT32                         SecurePL1TimerGSIV;
    UINT32                         SecurePL1TimerFlags;
    UINT32                         NonSecurePL1TimerGSIV;
    UINT32                         NonSecurePL1TimerFlags;
    UINT32                         VirtualTimerGSIV;
    UINT32                         VirtualTimerFlags;
    UINT32                         NonSecurePL2TimerGSIV;
    UINT32                         NonSecurePL2TimerFlags;
    UINT64                         CntReadBasePhysicalAddress;
    UINT32                         PlatformTimerCount;
    UINT32                         PlatformTimerOffset;
    UINT32                         VirtualPL2TimerGSIV;
    UINT32                         VirtualPL2TimerFlags;
} EFI_ACPI_6_5_GENERIC_TIMER_DESCRIPTION_TABLE;

///
/// GTDT Version (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_GENERIC_TIMER_DESCRIPTION_TABLE_REVISION  0x03

///
/// Timer Flags.  All other bits are reserved and must be 0.
///
#define EFI_ACPI_6_5_GTDT_TIMER_FLAG_TIMER_INTERRUPT_MODE      BIT0
#define EFI_ACPI_6_5_GTDT_TIMER_FLAG_TIMER_INTERRUPT_POLARITY  BIT1
#define EFI_ACPI_6_5_GTDT_TIMER_FLAG_ALWAYS_ON_CAPABILITY      BIT2

///
/// Platform Timer Type
///
#define EFI_ACPI_6_5_GTDT_GT_BLOCK              0
#define EFI_ACPI_6_5_GTDT_ARM_GENERIC_WATCHDOG  1

///
/// GT Block Structure
///
typedef struct {
    UINT8     Type;
    UINT16    Length;
    UINT8     Reserved;
    UINT64    CntCtlBase;
    UINT32    GTBlockTimerCount;
    UINT32    GTBlockTimerOffset;
} EFI_ACPI_6_5_GTDT_GT_BLOCK_STRUCTURE;

///
/// GT Block Timer Structure
///
typedef struct {
    UINT8     GTFrameNumber;
    UINT8     Reserved[3];
    UINT64    CntBaseX;
    UINT64    CntEL0BaseX;
    UINT32    GTxPhysicalTimerGSIV;
    UINT32    GTxPhysicalTimerFlags;
    UINT32    GTxVirtualTimerGSIV;
    UINT32    GTxVirtualTimerFlags;
    UINT32    GTxCommonFlags;
} EFI_ACPI_6_5_GTDT_GT_BLOCK_TIMER_STRUCTURE;

///
/// GT Block Physical Timers and Virtual Timers Flags.  All other bits are reserved and must be 0.
///
#define EFI_ACPI_6_5_GTDT_GT_BLOCK_TIMER_FLAG_TIMER_INTERRUPT_MODE      BIT0
#define EFI_ACPI_6_5_GTDT_GT_BLOCK_TIMER_FLAG_TIMER_INTERRUPT_POLARITY  BIT1

///
/// Common Flags Flags.  All other bits are reserved and must be 0.
///
#define EFI_ACPI_6_5_GTDT_GT_BLOCK_COMMON_FLAG_SECURE_TIMER          BIT0
#define EFI_ACPI_6_5_GTDT_GT_BLOCK_COMMON_FLAG_ALWAYS_ON_CAPABILITY  BIT1

///
/// Arm Generic Watchdog Structure
///
typedef struct {
    UINT8     Type;
    UINT16    Length;
    UINT8     Reserved;
    UINT64    RefreshFramePhysicalAddress;
    UINT64    WatchdogControlFramePhysicalAddress;
    UINT32    WatchdogTimerGSIV;
    UINT32    WatchdogTimerFlags;
} EFI_ACPI_6_5_GTDT_ARM_GENERIC_WATCHDOG_STRUCTURE;

///
/// Arm Generic Watchdog Timer Flags.  All other bits are reserved and must be 0.
///
#define EFI_ACPI_6_5_GTDT_ARM_GENERIC_WATCHDOG_FLAG_TIMER_INTERRUPT_MODE      BIT0
#define EFI_ACPI_6_5_GTDT_ARM_GENERIC_WATCHDOG_FLAG_TIMER_INTERRUPT_POLARITY  BIT1
#define EFI_ACPI_6_5_GTDT_ARM_GENERIC_WATCHDOG_FLAG_SECURE_TIMER              BIT2

//
// NVDIMM Firmware Interface Table definition.
//
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT32                         Reserved;
} EFI_ACPI_6_5_NVDIMM_FIRMWARE_INTERFACE_TABLE;

//
// NFIT Version (as defined in ACPI 6.5 spec.)
//
#define EFI_ACPI_6_5_NVDIMM_FIRMWARE_INTERFACE_TABLE_REVISION  0x1

//
// Definition for NFIT Table Structure Types
//
#define EFI_ACPI_6_5_NFIT_SYSTEM_PHYSICAL_ADDRESS_RANGE_STRUCTURE_TYPE    0
#define EFI_ACPI_6_5_NFIT_NVDIMM_REGION_MAPPING_STRUCTURE_TYPE            1
#define EFI_ACPI_6_5_NFIT_INTERLEAVE_STRUCTURE_TYPE                       2
#define EFI_ACPI_6_5_NFIT_SMBIOS_MANAGEMENT_INFORMATION_STRUCTURE_TYPE    3
#define EFI_ACPI_6_5_NFIT_NVDIMM_CONTROL_REGION_STRUCTURE_TYPE            4
#define EFI_ACPI_6_5_NFIT_NVDIMM_BLOCK_DATA_WINDOW_REGION_STRUCTURE_TYPE  5
#define EFI_ACPI_6_5_NFIT_FLUSH_HINT_ADDRESS_STRUCTURE_TYPE               6
#define EFI_ACPI_6_5_NFIT_PLATFORM_CAPABILITIES_STRUCTURE_TYPE            7

//
// Definition for NFIT Structure Header
//
typedef struct {
    UINT16    Type;
    UINT16    Length;
} EFI_ACPI_6_5_NFIT_STRUCTURE_HEADER;

//
// Definition for System Physical Address Range Structure
//
#define EFI_ACPI_6_5_NFIT_SYSTEM_PHYSICAL_ADDRESS_RANGE_FLAGS_CONTROL_REGION_FOR_MANAGEMENT  BIT0
#define EFI_ACPI_6_5_NFIT_SYSTEM_PHYSICAL_ADDRESS_RANGE_FLAGS_PROXIMITY_DOMAIN_VALID         BIT1
#define EFI_ACPI_6_5_NFIT_SYSTEM_PHYSICAL_ADDRESS_RANGE_FLAGS_SPA_LOCATION_COOKIE_VALID      BIT2

#define EFI_ACPI_6_5_NFIT_GUID_VOLATILE_MEMORY_REGION                              { 0x7305944F, 0xFDDA, 0x44E3, { 0xB1, 0x6C, 0x3F, 0x22, 0xD2, 0x52, 0xE5, 0xD0 }}
#define EFI_ACPI_6_5_NFIT_GUID_BYTE_ADDRESSABLE_PERSISTENT_MEMORY_REGION           { 0x66F0D379, 0xB4F3, 0x4074, { 0xAC, 0x43, 0x0D, 0x33, 0x18, 0xB7, 0x8C, 0xDB }}
#define EFI_ACPI_6_5_NFIT_GUID_NVDIMM_CONTROL_REGION                               { 0x92F701F6, 0x13B4, 0x405D, { 0x91, 0x0B, 0x29, 0x93, 0x67, 0xE8, 0x23, 0x4C }}
#define EFI_ACPI_6_5_NFIT_GUID_NVDIMM_BLOCK_DATA_WINDOW_REGION                     { 0x91AF0530, 0x5D86, 0x470E, { 0xA6, 0xB0, 0x0A, 0x2D, 0xB9, 0x40, 0x82, 0x49 }}
#define EFI_ACPI_6_5_NFIT_GUID_RAM_DISK_SUPPORTING_VIRTUAL_DISK_REGION_VOLATILE    { 0x77AB535A, 0x45FC, 0x6.5B, { 0x55, 0x60, 0xF7, 0xB2, 0x81, 0xD1, 0xF9, 0x6E }}
#define EFI_ACPI_6_5_NFIT_GUID_RAM_DISK_SUPPORTING_VIRTUAL_CD_REGION_VOLATILE      { 0x3D5ABD30, 0x4175, 0x87CE, { 0x6D, 0x64, 0xD2, 0xAD, 0xE5, 0x23, 0xC4, 0xBB }}
#define EFI_ACPI_6_5_NFIT_GUID_RAM_DISK_SUPPORTING_VIRTUAL_DISK_REGION_PERSISTENT  { 0x5CEA02C9, 0x4D07, 0x69D3, { 0x26, 0x9F ,0x44, 0x96, 0xFB, 0xE0, 0x96, 0xF9 }}
#define EFI_ACPI_6_5_NFIT_GUID_RAM_DISK_SUPPORTING_VIRTUAL_CD_REGION_PERSISTENT    { 0x08018188, 0x42CD, 0xBB48, { 0x10, 0x0F, 0x53, 0x87, 0xD5, 0x3D, 0xED, 0x3D }}

typedef struct {
    UINT16    Type;
    UINT16    Length;
    UINT16    SPARangeStructureIndex;
    UINT16    Flags;
    UINT32    Reserved_8;
    UINT32    ProximityDomain;
    GUID      AddressRangeTypeGUID;
    UINT64    SystemPhysicalAddressRangeBase;
    UINT64    SystemPhysicalAddressRangeLength;
    UINT64    AddressRangeMemoryMappingAttribute;
    UINT64    SPALocationCookie;
} EFI_ACPI_6_5_NFIT_SYSTEM_PHYSICAL_ADDRESS_RANGE_STRUCTURE;

//
// Definition for Memory Device to System Physical Address Range Mapping Structure
//
typedef struct {
    UINT32    DIMMNumber : 4;
    UINT32    MemoryChannelNumber : 4;
    UINT32    MemoryControllerID : 4;
    UINT32    SocketID : 4;
    UINT32    NodeControllerID : 12;
    UINT32    Reserved_28 : 4;
} EFI_ACPI_6_5_NFIT_DEVICE_HANDLE;

#define EFI_ACPI_6_5_NFIT_MEMORY_DEVICE_STATE_FLAGS_PREVIOUS_SAVE_FAIL                                      BIT0
#define EFI_ACPI_6_5_NFIT_MEMORY_DEVICE_STATE_FLAGS_LAST_RESTORE_FAIL                                       BIT1
#define EFI_ACPI_6_5_NFIT_MEMORY_DEVICE_STATE_FLAGS_PLATFORM_FLUSH_FAIL                                     BIT2
#define EFI_ACPI_6_5_NFIT_MEMORY_DEVICE_STATE_FLAGS_NOT_ARMED_PRIOR_TO_OSPM_HAND_OFF                        BIT3
#define EFI_ACPI_6_5_NFIT_MEMORY_DEVICE_STATE_FLAGS_SMART_HEALTH_EVENTS_PRIOR_OSPM_HAND_OFF                 BIT4
#define EFI_ACPI_6_5_NFIT_MEMORY_DEVICE_STATE_FLAGS_FIRMWARE_ENABLED_TO_NOTIFY_OSPM_ON_SMART_HEALTH_EVENTS  BIT5
#define EFI_ACPI_6_5_NFIT_MEMORY_DEVICE_STATE_FLAGS_FIRMWARE_NOT_MAP_NVDIMM_TO_SPA                          BIT6

typedef struct {
    UINT16                             Type;
    UINT16                             Length;
    EFI_ACPI_6_5_NFIT_DEVICE_HANDLE    NFITDeviceHandle;
    UINT16                             NVDIMMPhysicalID;
    UINT16                             NVDIMMRegionID;
    UINT16                             SPARangeStructureIndex;
    UINT16                             NVDIMMControlRegionStructureIndex;
    UINT64                             NVDIMMRegionSize;
    UINT64                             RegionOffset;
    UINT64                             NVDIMMPhysicalAddressRegionBase;
    UINT16                             InterleaveStructureIndex;
    UINT16                             InterleaveWays;
    UINT16                             NVDIMMStateFlags;
    UINT16                             Reserved_46;
} EFI_ACPI_6_5_NFIT_NVDIMM_REGION_MAPPING_STRUCTURE;

//
// Definition for Interleave Structure
//
typedef struct {
    UINT16    Type;
    UINT16    Length;
    UINT16    InterleaveStructureIndex;
    UINT16    Reserved_6;
    UINT32    NumberOfLines;
    UINT32    LineSize;
    // UINT32                                      LineOffset[NumberOfLines];
} EFI_ACPI_6_5_NFIT_INTERLEAVE_STRUCTURE;

//
// Definition for SMBIOS Management Information Structure
//
typedef struct {
    UINT16    Type;
    UINT16    Length;
    UINT32    Reserved_4;
    // UINT8                                       Data[];
} EFI_ACPI_6_5_NFIT_SMBIOS_MANAGEMENT_INFORMATION_STRUCTURE;

//
// Definition for NVDIMM Control Region Structure
//
#define EFI_ACPI_6_5_NFIT_NVDIMM_CONTROL_REGION_VALID_FIELDS_MANUFACTURING  BIT0

#define EFI_ACPI_6_5_NFIT_NVDIMM_CONTROL_REGION_FLAGS_BLOCK_DATA_WINDOWS_BUFFERED  BIT0

typedef struct {
    UINT16    Type;
    UINT16    Length;
    UINT16    NVDIMMControlRegionStructureIndex;
    UINT16    VendorID;
    UINT16    DeviceID;
    UINT16    RevisionID;
    UINT16    SubsystemVendorID;
    UINT16    SubsystemDeviceID;
    UINT16    SubsystemRevisionID;
    UINT8     ValidFields;
    UINT8     ManufacturingLocation;
    UINT16    ManufacturingDate;
    UINT8     Reserved_22[2];
    UINT32    SerialNumber;
    UINT16    RegionFormatInterfaceCode;
    UINT16    NumberOfBlockControlWindows;
    UINT64    SizeOfBlockControlWindow;
    UINT64    CommandRegisterOffsetInBlockControlWindow;
    UINT64    SizeOfCommandRegisterInBlockControlWindows;
    UINT64    StatusRegisterOffsetInBlockControlWindow;
    UINT64    SizeOfStatusRegisterInBlockControlWindows;
    UINT16    NVDIMMControlRegionFlag;
    UINT8     Reserved_74[6];
} EFI_ACPI_6_5_NFIT_NVDIMM_CONTROL_REGION_STRUCTURE;

//
// Definition for NVDIMM Block Data Window Region Structure
//
typedef struct {
    UINT16    Type;
    UINT16    Length;
    UINT16    NVDIMMControlRegionStructureIndex;
    UINT16    NumberOfBlockDataWindows;
    UINT64    BlockDataWindowStartOffset;
    UINT64    SizeOfBlockDataWindow;
    UINT64    BlockAccessibleMemoryCapacity;
    UINT64    BeginningAddressOfFirstBlockInBlockAccessibleMemory;
} EFI_ACPI_6_5_NFIT_NVDIMM_BLOCK_DATA_WINDOW_REGION_STRUCTURE;

//
// Definition for Flush Hint Address Structure
//
typedef struct {
    UINT16                             Type;
    UINT16                             Length;
    EFI_ACPI_6_5_NFIT_DEVICE_HANDLE    NFITDeviceHandle;
    UINT16                             NumberOfFlushHintAddresses;
    UINT8                              Reserved_10[6];
    // UINT64                                      FlushHintAddress[NumberOfFlushHintAddresses];
} EFI_ACPI_6_5_NFIT_FLUSH_HINT_ADDRESS_STRUCTURE;

//
// Definition for Platform Capabilities Structure
//
typedef struct {
    UINT16    Type;
    UINT16    Length;
    UINT8     HighestValidCapability;
    UINT8     Reserved_5[3];
    UINT32    Capabilities;
    UINT8     Reserved_12[4];
} EFI_ACPI_6_5_NFIT_PLATFORM_CAPABILITIES_STRUCTURE;

#define EFI_ACPI_6_5_NFIT_PLATFORM_CAPABILITY_CPU_CACHE_FLUSH_TO_NVDIMM_DURABILITY_ON_POWER_LOSS          BIT0
#define EFI_ACPI_6_5_NFIT_PLATFORM_CAPABILITY_MEMORY_CONTROLLER_FLUSH_TO_NVDIMM_DURABILITY_ON_POWER_LOSS  BIT1
#define EFI_ACPI_6_5_NFIT_PLATFORM_CAPABILITY_BYTE_ADDRESSABLE_PERSISTENT_MEMORY_HARDWARE_MIRRORING       BIT2

///
/// Secure DEVices Table (SDEV)
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
} EFI_ACPI_6_5_SECURE_DEVICES_TABLE_HEADER;

///
/// SDEV Revision (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_SECURE_DEVICES_TABLE_REVISION  0x01

///
/// Secure Device types
///
#define EFI_ACPI_6_5_SDEV_TYPE_ACPI_NAMESPACE_DEVICE  0x00
#define EFI_ACPI_6_5_SDEV_TYPE_PCIE_ENDPOINT_DEVICE   0x01

///
/// Secure Device flags
///
#define EFI_ACPI_6_5_SDEV_FLAG_ALLOW_HANDOFF                     BIT0
#define EFI_ACPI_6_5_SDEV_FLAG_SECURE_ACCESS_COMPONENTS_PRESENT  BIT1

///
/// SDEV Structure Header
///
typedef struct {
    UINT8     Type;
    UINT8     Flags;
    UINT16    Length;
} EFI_ACPI_6_5_SDEV_STRUCTURE_HEADER;

///
/// ACPI_NAMESPACE_DEVICE based Secure Device Structure
///
typedef struct {
    EFI_ACPI_6_5_SDEV_STRUCTURE_HEADER    Header;
    UINT16                                DeviceIdentifierOffset;
    UINT16                                DeviceIdentifierLength;
    UINT16                                VendorSpecificDataOffset;
    UINT16                                VendorSpecificDataLength;
    UINT16                                SecureAccessComponentsOffset;
    UINT16                                SecureAccessComponentsLength;
} EFI_ACPI_6_5_SDEV_STRUCTURE_ACPI_NAMESPACE_DEVICE;

///
/// Secure Access Component Types
///
#define EFI_ACPI_6_5_SDEV_SECURE_ACCESS_COMPONENT_TYPE_IDENTIFICATION  0x00
#define EFI_ACPI_6_5_SDEV_SECURE_ACCESS_COMPONENT_TYPE_MEMORY          0x01

///
/// Identification Based Secure Access Component
///
typedef struct {
    EFI_ACPI_6_5_SDEV_STRUCTURE_HEADER    Header;
    UINT16                                HardwareIdentifierOffset;
    UINT16                                HardwareIdentifierLength;
    UINT16                                SubsystemIdentifierOffset;
    UINT16                                SubsystemIdentifierLength;
    UINT16                                HardwareRevision;
    UINT8                                 HardwareRevisionPresent;
    UINT8                                 ClassCodePresent;
    UINT8                                 PciCompatibleBaseClass;
    UINT8                                 PciCompatibleSubClass;
    UINT8                                 PciCompatibleProgrammingInterface;
} EFI_ACPI_6_5_SDEV_SECURE_ACCESS_COMPONENT_IDENTIFICATION_STRUCTURE;

///
/// Memory-based Secure Access Component
///
typedef struct {
    EFI_ACPI_6_5_SDEV_STRUCTURE_HEADER    Header;
    UINT32                                Reserved;
    UINT64                                MemoryAddressBase;
    UINT64                                MemoryLength;
} EFI_ACPI_6_5_SDEV_SECURE_ACCESS_COMPONENT_MEMORY_STRUCTURE;

///
/// PCIe Endpoint Device based Secure Device Structure
///
typedef struct {
    EFI_ACPI_6_5_SDEV_STRUCTURE_HEADER    Header;
    UINT16                                PciSegmentNumber;
    UINT16                                StartBusNumber;
    UINT16                                PciPathOffset;
    UINT16                                PciPathLength;
    UINT16                                VendorSpecificDataOffset;
    UINT16                                VendorSpecificDataLength;
} EFI_ACPI_6_5_SDEV_STRUCTURE_PCIE_ENDPOINT_DEVICE;

///
/// Boot Error Record Table (BERT)
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT32                         BootErrorRegionLength;
    UINT64                         BootErrorRegion;
} EFI_ACPI_6_5_BOOT_ERROR_RECORD_TABLE_HEADER;

///
/// BERT Version (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_BOOT_ERROR_RECORD_TABLE_REVISION  0x01

///
/// Boot Error Region Block Status Definition
///
typedef struct {
    UINT32    UncorrectableErrorValid : 1;
    UINT32    CorrectableErrorValid : 1;
    UINT32    MultipleUncorrectableErrors : 1;
    UINT32    MultipleCorrectableErrors : 1;
    UINT32    ErrorDataEntryCount : 10;
    UINT32    Reserved : 18;
} EFI_ACPI_6_5_ERROR_BLOCK_STATUS;

///
/// Boot Error Region Definition
///
typedef struct {
    EFI_ACPI_6_5_ERROR_BLOCK_STATUS    BlockStatus;
    UINT32                             RawDataOffset;
    UINT32                             RawDataLength;
    UINT32                             DataLength;
    UINT32                             ErrorSeverity;
} EFI_ACPI_6_5_BOOT_ERROR_REGION_STRUCTURE;

//
// Boot Error Severity types
//
#define EFI_ACPI_6_5_ERROR_SEVERITY_RECOVERABLE  0x00
#define EFI_ACPI_6_5_ERROR_SEVERITY_FATAL        0x01
#define EFI_ACPI_6_5_ERROR_SEVERITY_CORRECTED    0x02
#define EFI_ACPI_6_5_ERROR_SEVERITY_NONE         0x03
//
// The term 'Correctable' is no longer being used as an error severity of the
// reported error since ACPI Specification Version 5.1 Errata B.
// The below macro is considered as deprecated and should no longer be used.
//
#define EFI_ACPI_6_5_ERROR_SEVERITY_CORRECTABLE  0x00

///
/// Generic Error Data Entry Definition
///
typedef struct {
    UINT8     SectionType[16];
    UINT32    ErrorSeverity;
    UINT16    Revision;
    UINT8     ValidationBits;
    UINT8     Flags;
    UINT32    ErrorDataLength;
    UINT8     FruId[16];
    UINT8     FruText[20];
    UINT8     Timestamp[8];
} EFI_ACPI_6_5_GENERIC_ERROR_DATA_ENTRY_STRUCTURE;

///
/// Generic Error Data Entry Version (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_GENERIC_ERROR_DATA_ENTRY_REVISION  0x0300

///
/// HEST - Hardware Error Source Table
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT32                         ErrorSourceCount;
} EFI_ACPI_6_5_HARDWARE_ERROR_SOURCE_TABLE_HEADER;

///
/// HEST Version (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_HARDWARE_ERROR_SOURCE_TABLE_REVISION  0x01

//
// Error Source structure types.
//
#define EFI_ACPI_6_5_IA32_ARCHITECTURE_MACHINE_CHECK_EXCEPTION  0x00
#define EFI_ACPI_6_5_IA32_ARCHITECTURE_CORRECTED_MACHINE_CHECK  0x01
#define EFI_ACPI_6_5_IA32_ARCHITECTURE_NMI_ERROR                0x02
#define EFI_ACPI_6_5_PCI_EXPRESS_ROOT_PORT_AER                  0x06
#define EFI_ACPI_6_5_PCI_EXPRESS_DEVICE_AER                     0x07
#define EFI_ACPI_6_5_PCI_EXPRESS_BRIDGE_AER                     0x08
#define EFI_ACPI_6_5_GENERIC_HARDWARE_ERROR                     0x09
#define EFI_ACPI_6_5_GENERIC_HARDWARE_ERROR_VERSION_2           0x0A
#define EFI_ACPI_6_5_IA32_ARCHITECTURE_DEFERRED_MACHINE_CHECK   0x0B

//
// Error Source structure flags.
//
#define EFI_ACPI_6_5_ERROR_SOURCE_FLAG_FIRMWARE_FIRST  (1 << 0)
#define EFI_ACPI_6_5_ERROR_SOURCE_FLAG_GLOBAL          (1 << 1)
#define EFI_ACPI_6_5_ERROR_SOURCE_FLAG_GHES_ASSIST     (1 << 2)

///
/// IA-32 Architecture Machine Check Exception Structure Definition
///
typedef struct {
    UINT16    Type;
    UINT16    SourceId;
    UINT8     Reserved0[2];
    UINT8     Flags;
    UINT8     Enabled;
    UINT32    NumberOfRecordsToPreAllocate;
    UINT32    MaxSectionsPerRecord;
    UINT64    GlobalCapabilityInitData;
    UINT64    GlobalControlInitData;
    UINT8     NumberOfHardwareBanks;
    UINT8     Reserved1[7];
} EFI_ACPI_6_5_IA32_ARCHITECTURE_MACHINE_CHECK_EXCEPTION_STRUCTURE;

///
/// IA-32 Architecture Machine Check Bank Structure Definition
///
typedef struct {
    UINT8     BankNumber;
    UINT8     ClearStatusOnInitialization;
    UINT8     StatusDataFormat;
    UINT8     Reserved0;
    UINT32    ControlRegisterMsrAddress;
    UINT64    ControlInitData;
    UINT32    StatusRegisterMsrAddress;
    UINT32    AddressRegisterMsrAddress;
    UINT32    MiscRegisterMsrAddress;
} EFI_ACPI_6_5_IA32_ARCHITECTURE_MACHINE_CHECK_ERROR_BANK_STRUCTURE;

///
/// IA-32 Architecture Machine Check Bank Structure MCA data format
///
#define EFI_ACPI_6_5_IA32_ARCHITECTURE_MACHINE_CHECK_ERROR_DATA_FORMAT_IA32     0x00
#define EFI_ACPI_6_5_IA32_ARCHITECTURE_MACHINE_CHECK_ERROR_DATA_FORMAT_INTEL64  0x01
#define EFI_ACPI_6_5_IA32_ARCHITECTURE_MACHINE_CHECK_ERROR_DATA_FORMAT_AMD64    0x02

//
// Hardware Error Notification types. All other values are reserved
//
#define EFI_ACPI_6_5_HARDWARE_ERROR_NOTIFICATION_POLLED                        0x00
#define EFI_ACPI_6_5_HARDWARE_ERROR_NOTIFICATION_EXTERNAL_INTERRUPT            0x01
#define EFI_ACPI_6_5_HARDWARE_ERROR_NOTIFICATION_LOCAL_INTERRUPT               0x02
#define EFI_ACPI_6_5_HARDWARE_ERROR_NOTIFICATION_SCI                           0x03
#define EFI_ACPI_6_5_HARDWARE_ERROR_NOTIFICATION_NMI                           0x04
#define EFI_ACPI_6_5_HARDWARE_ERROR_NOTIFICATION_CMCI                          0x05
#define EFI_ACPI_6_5_HARDWARE_ERROR_NOTIFICATION_MCE                           0x06
#define EFI_ACPI_6_5_HARDWARE_ERROR_NOTIFICATION_GPIO_SIGNAL                   0x07
#define EFI_ACPI_6_5_HARDWARE_ERROR_NOTIFICATION_ARMV8_SEA                     0x08
#define EFI_ACPI_6_5_HARDWARE_ERROR_NOTIFICATION_ARMV8_SEI                     0x09
#define EFI_ACPI_6_5_HARDWARE_ERROR_NOTIFICATION_GSIV                          0x0A
#define EFI_ACPI_6_5_HARDWARE_ERROR_NOTIFICATION_SOFTWARE_DELEGATED_EXCEPTION  0x0B

///
/// Hardware Error Notification Configuration Write Enable Structure Definition
///
typedef struct {
    UINT16    Type : 1;
    UINT16    PollInterval : 1;
    UINT16    SwitchToPollingThresholdValue : 1;
    UINT16    SwitchToPollingThresholdWindow : 1;
    UINT16    ErrorThresholdValue : 1;
    UINT16    ErrorThresholdWindow : 1;
    UINT16    Reserved : 10;
} EFI_ACPI_6_5_HARDWARE_ERROR_NOTIFICATION_CONFIGURATION_WRITE_ENABLE_STRUCTURE;

///
/// Hardware Error Notification Structure Definition
///
typedef struct {
    UINT8                                                                            Type;
    UINT8                                                                            Length;
    EFI_ACPI_6_5_HARDWARE_ERROR_NOTIFICATION_CONFIGURATION_WRITE_ENABLE_STRUCTURE    ConfigurationWriteEnable;
    UINT32                                                                           PollInterval;
    UINT32                                                                           Vector;
    UINT32                                                                           SwitchToPollingThresholdValue;
    UINT32                                                                           SwitchToPollingThresholdWindow;
    UINT32                                                                           ErrorThresholdValue;
    UINT32                                                                           ErrorThresholdWindow;
} EFI_ACPI_6_5_HARDWARE_ERROR_NOTIFICATION_STRUCTURE;

///
/// IA-32 Architecture Corrected Machine Check Structure Definition
///
typedef struct {
    UINT16                                                Type;
    UINT16                                                SourceId;
    UINT8                                                 Reserved0[2];
    UINT8                                                 Flags;
    UINT8                                                 Enabled;
    UINT32                                                NumberOfRecordsToPreAllocate;
    UINT32                                                MaxSectionsPerRecord;
    EFI_ACPI_6_5_HARDWARE_ERROR_NOTIFICATION_STRUCTURE    NotificationStructure;
    UINT8                                                 NumberOfHardwareBanks;
    UINT8                                                 Reserved1[3];
} EFI_ACPI_6_5_IA32_ARCHITECTURE_CORRECTED_MACHINE_CHECK_STRUCTURE;

///
/// IA-32 Architecture NMI Error Structure Definition
///
typedef struct {
    UINT16    Type;
    UINT16    SourceId;
    UINT8     Reserved0[2];
    UINT32    NumberOfRecordsToPreAllocate;
    UINT32    MaxSectionsPerRecord;
    UINT32    MaxRawDataLength;
} EFI_ACPI_6_5_IA32_ARCHITECTURE_NMI_ERROR_STRUCTURE;

///
/// PCI Express Root Port AER Structure Definition
///
typedef struct {
    UINT16    Type;
    UINT16    SourceId;
    UINT8     Reserved0[2];
    UINT8     Flags;
    UINT8     Enabled;
    UINT32    NumberOfRecordsToPreAllocate;
    UINT32    MaxSectionsPerRecord;
    UINT32    Bus;
    UINT16    Device;
    UINT16    Function;
    UINT16    DeviceControl;
    UINT8     Reserved1[2];
    UINT32    UncorrectableErrorMask;
    UINT32    UncorrectableErrorSeverity;
    UINT32    CorrectableErrorMask;
    UINT32    AdvancedErrorCapabilitiesAndControl;
    UINT32    RootErrorCommand;
} EFI_ACPI_6_5_PCI_EXPRESS_ROOT_PORT_AER_STRUCTURE;

///
/// PCI Express Device AER Structure Definition
///
typedef struct {
    UINT16    Type;
    UINT16    SourceId;
    UINT8     Reserved0[2];
    UINT8     Flags;
    UINT8     Enabled;
    UINT32    NumberOfRecordsToPreAllocate;
    UINT32    MaxSectionsPerRecord;
    UINT32    Bus;
    UINT16    Device;
    UINT16    Function;
    UINT16    DeviceControl;
    UINT8     Reserved1[2];
    UINT32    UncorrectableErrorMask;
    UINT32    UncorrectableErrorSeverity;
    UINT32    CorrectableErrorMask;
    UINT32    AdvancedErrorCapabilitiesAndControl;
} EFI_ACPI_6_5_PCI_EXPRESS_DEVICE_AER_STRUCTURE;

///
/// PCI Express Bridge AER Structure Definition
///
typedef struct {
    UINT16    Type;
    UINT16    SourceId;
    UINT8     Reserved0[2];
    UINT8     Flags;
    UINT8     Enabled;
    UINT32    NumberOfRecordsToPreAllocate;
    UINT32    MaxSectionsPerRecord;
    UINT32    Bus;
    UINT16    Device;
    UINT16    Function;
    UINT16    DeviceControl;
    UINT8     Reserved1[2];
    UINT32    UncorrectableErrorMask;
    UINT32    UncorrectableErrorSeverity;
    UINT32    CorrectableErrorMask;
    UINT32    AdvancedErrorCapabilitiesAndControl;
    UINT32    SecondaryUncorrectableErrorMask;
    UINT32    SecondaryUncorrectableErrorSeverity;
    UINT32    SecondaryAdvancedErrorCapabilitiesAndControl;
} EFI_ACPI_6_5_PCI_EXPRESS_BRIDGE_AER_STRUCTURE;

///
/// Generic Hardware Error Source Structure Definition
///
typedef struct {
    UINT16                                                Type;
    UINT16                                                SourceId;
    UINT16                                                RelatedSourceId;
    UINT8                                                 Flags;
    UINT8                                                 Enabled;
    UINT32                                                NumberOfRecordsToPreAllocate;
    UINT32                                                MaxSectionsPerRecord;
    UINT32                                                MaxRawDataLength;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE                ErrorStatusAddress;
    EFI_ACPI_6_5_HARDWARE_ERROR_NOTIFICATION_STRUCTURE    NotificationStructure;
    UINT32                                                ErrorStatusBlockLength;
} EFI_ACPI_6_5_GENERIC_HARDWARE_ERROR_SOURCE_STRUCTURE;

///
/// Generic Hardware Error Source Version 2 Structure Definition
///
typedef struct {
    UINT16                                                Type;
    UINT16                                                SourceId;
    UINT16                                                RelatedSourceId;
    UINT8                                                 Flags;
    UINT8                                                 Enabled;
    UINT32                                                NumberOfRecordsToPreAllocate;
    UINT32                                                MaxSectionsPerRecord;
    UINT32                                                MaxRawDataLength;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE                ErrorStatusAddress;
    EFI_ACPI_6_5_HARDWARE_ERROR_NOTIFICATION_STRUCTURE    NotificationStructure;
    UINT32                                                ErrorStatusBlockLength;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE                ReadAckRegister;
    UINT64                                                ReadAckPreserve;
    UINT64                                                ReadAckWrite;
} EFI_ACPI_6_5_GENERIC_HARDWARE_ERROR_SOURCE_VERSION_2_STRUCTURE;

///
/// Generic Error Status Definition
///
typedef struct {
    EFI_ACPI_6_5_ERROR_BLOCK_STATUS    BlockStatus;
    UINT32                             RawDataOffset;
    UINT32                             RawDataLength;
    UINT32                             DataLength;
    UINT32                             ErrorSeverity;
} EFI_ACPI_6_5_GENERIC_ERROR_STATUS_STRUCTURE;

///
/// IA-32 Architecture Deferred Machine Check Structure Definition
///
typedef struct {
    UINT16                                                Type;
    UINT16                                                SourceId;
    UINT8                                                 Reserved0[2];
    UINT8                                                 Flags;
    UINT8                                                 Enabled;
    UINT32                                                NumberOfRecordsToPreAllocate;
    UINT32                                                MaxSectionsPerRecord;
    EFI_ACPI_6_5_HARDWARE_ERROR_NOTIFICATION_STRUCTURE    NotificationStructure;
    UINT8                                                 NumberOfHardwareBanks;
    UINT8                                                 Reserved1[3];
} EFI_ACPI_6_5_IA32_ARCHITECTURE_DEFERRED_MACHINE_CHECK_STRUCTURE;

///
/// HMAT - Heterogeneous Memory Attribute Table
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT8                          Reserved[4];
} EFI_ACPI_6_5_HETEROGENEOUS_MEMORY_ATTRIBUTE_TABLE_HEADER;

///
/// HMAT Revision (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_HETEROGENEOUS_MEMORY_ATTRIBUTE_TABLE_REVISION  0x02

///
/// HMAT types
///
#define EFI_ACPI_6_5_HMAT_TYPE_MEMORY_PROXIMITY_DOMAIN_ATTRIBUTES          0x00
#define EFI_ACPI_6_5_HMAT_TYPE_SYSTEM_LOCALITY_LATENCY_AND_BANDWIDTH_INFO  0x01
#define EFI_ACPI_6_5_HMAT_TYPE_MEMORY_SIDE_CACHE_INFO                      0x02

///
/// HMAT Structure Header
///
typedef struct {
    UINT16    Type;
    UINT8     Reserved[2];
    UINT32    Length;
} EFI_ACPI_6_5_HMAT_STRUCTURE_HEADER;

///
/// Memory Proximity Domain Attributes Structure flags
///
typedef struct {
    UINT16    InitiatorProximityDomainValid : 1;
    UINT16    Reserved : 15;
} EFI_ACPI_6_5_HMAT_STRUCTURE_MEMORY_PROXIMITY_DOMAIN_ATTRIBUTES_FLAGS;

///
/// Memory Proximity Domain Attributes Structure
///
typedef struct {
    UINT16                                                                  Type;
    UINT8                                                                   Reserved[2];
    UINT32                                                                  Length;
    EFI_ACPI_6_5_HMAT_STRUCTURE_MEMORY_PROXIMITY_DOMAIN_ATTRIBUTES_FLAGS    Flags;
    UINT8                                                                   Reserved1[2];
    UINT32                                                                  InitiatorProximityDomain;
    UINT32                                                                  MemoryProximityDomain;
    UINT8                                                                   Reserved2[20];
} EFI_ACPI_6_5_HMAT_STRUCTURE_MEMORY_PROXIMITY_DOMAIN_ATTRIBUTES;

///
/// System Locality Latency and Bandwidth Information Structure flags
///
typedef struct {
    UINT8    MemoryHierarchy : 4;
    UINT8    AccessAttributes : 2;
    UINT8    Reserved : 2;
} EFI_ACPI_6_5_HMAT_STRUCTURE_SYSTEM_LOCALITY_LATENCY_AND_BANDWIDTH_INFO_FLAGS;

///
/// System Locality Latency and Bandwidth Information Structure
///
typedef struct {
    UINT16                                                                          Type;
    UINT8                                                                           Reserved[2];
    UINT32                                                                          Length;
    EFI_ACPI_6_5_HMAT_STRUCTURE_SYSTEM_LOCALITY_LATENCY_AND_BANDWIDTH_INFO_FLAGS    Flags;
    UINT8                                                                           DataType;
    UINT8                                                                           MinTransferSize;
    UINT8                                                                           Reserved1;
    UINT32                                                                          NumberOfInitiatorProximityDomains;
    UINT32                                                                          NumberOfTargetProximityDomains;
    UINT8                                                                           Reserved2[4];
    UINT64                                                                          EntryBaseUnit;
} EFI_ACPI_6_5_HMAT_STRUCTURE_SYSTEM_LOCALITY_LATENCY_AND_BANDWIDTH_INFO;

///
/// Memory Side Cache Information Structure cache attributes
///
typedef struct {
    UINT32    TotalCacheLevels : 4;
    UINT32    CacheLevel : 4;
    UINT32    CacheAssociativity : 4;
    UINT32    WritePolicy : 4;
    UINT32    CacheLineSize : 16;
} EFI_ACPI_6_5_HMAT_STRUCTURE_MEMORY_SIDE_CACHE_INFO_CACHE_ATTRIBUTES;

///
/// Memory Side Cache Information Structure
///
typedef struct {
    UINT16                                                                 Type;
    UINT8                                                                  Reserved[2];
    UINT32                                                                 Length;
    UINT32                                                                 MemoryProximityDomain;
    UINT8                                                                  Reserved1[4];
    UINT64                                                                 MemorySideCacheSize;
    EFI_ACPI_6_5_HMAT_STRUCTURE_MEMORY_SIDE_CACHE_INFO_CACHE_ATTRIBUTES    CacheAttributes;
    UINT8                                                                  Reserved2[2];
    UINT16                                                                 NumberOfSmbiosHandles;
} EFI_ACPI_6_5_HMAT_STRUCTURE_MEMORY_SIDE_CACHE_INFO;

///
/// ERST - Error Record Serialization Table
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT32                         SerializationHeaderSize;
    UINT8                          Reserved0[4];
    UINT32                         InstructionEntryCount;
} EFI_ACPI_6_5_ERROR_RECORD_SERIALIZATION_TABLE_HEADER;

///
/// ERST Version (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_ERROR_RECORD_SERIALIZATION_TABLE_REVISION  0x01

///
/// ERST Serialization Actions
///
#define EFI_ACPI_6_5_ERST_BEGIN_WRITE_OPERATION                   0x00
#define EFI_ACPI_6_5_ERST_BEGIN_READ_OPERATION                    0x01
#define EFI_ACPI_6_5_ERST_BEGIN_CLEAR_OPERATION                   0x02
#define EFI_ACPI_6_5_ERST_END_OPERATION                           0x03
#define EFI_ACPI_6_5_ERST_SET_RECORD_OFFSET                       0x04
#define EFI_ACPI_6_5_ERST_EXECUTE_OPERATION                       0x05
#define EFI_ACPI_6_5_ERST_CHECK_BUSY_STATUS                       0x06
#define EFI_ACPI_6_5_ERST_GET_COMMAND_STATUS                      0x07
#define EFI_ACPI_6_5_ERST_GET_RECORD_IDENTIFIER                   0x08
#define EFI_ACPI_6_5_ERST_SET_RECORD_IDENTIFIER                   0x09
#define EFI_ACPI_6_5_ERST_GET_RECORD_COUNT                        0x0A
#define EFI_ACPI_6_5_ERST_BEGIN_DUMMY_WRITE_OPERATION             0x0B
#define EFI_ACPI_6_5_ERST_GET_ERROR_LOG_ADDRESS_RANGE             0x0D
#define EFI_ACPI_6_5_ERST_GET_ERROR_LOG_ADDRESS_RANGE_LENGTH      0x0E
#define EFI_ACPI_6_5_ERST_GET_ERROR_LOG_ADDRESS_RANGE_ATTRIBUTES  0x0F
#define EFI_ACPI_6_5_ERST_GET_EXECUTE_OPERATION_TIMINGS           0x10

///
/// ERST Action Command Status
///
#define EFI_ACPI_6_5_ERST_STATUS_SUCCESS                 0x00
#define EFI_ACPI_6_5_ERST_STATUS_NOT_ENOUGH_SPACE        0x01
#define EFI_ACPI_6_5_ERST_STATUS_HARDWARE_NOT_AVAILABLE  0x02
#define EFI_ACPI_6_5_ERST_STATUS_FAILED                  0x03
#define EFI_ACPI_6_5_ERST_STATUS_RECORD_STORE_EMPTY      0x04
#define EFI_ACPI_6_5_ERST_STATUS_RECORD_NOT_FOUND        0x05

///
/// ERST Serialization Instructions
///
#define EFI_ACPI_6_5_ERST_READ_REGISTER                  0x00
#define EFI_ACPI_6_5_ERST_READ_REGISTER_VALUE            0x01
#define EFI_ACPI_6_5_ERST_WRITE_REGISTER                 0x02
#define EFI_ACPI_6_5_ERST_WRITE_REGISTER_VALUE           0x03
#define EFI_ACPI_6_5_ERST_NOOP                           0x04
#define EFI_ACPI_6_5_ERST_LOAD_VAR1                      0x05
#define EFI_ACPI_6_5_ERST_LOAD_VAR2                      0x06
#define EFI_ACPI_6_5_ERST_STORE_VAR1                     0x07
#define EFI_ACPI_6_5_ERST_ADD                            0x08
#define EFI_ACPI_6_5_ERST_SUBTRACT                       0x09
#define EFI_ACPI_6_5_ERST_ADD_VALUE                      0x0A
#define EFI_ACPI_6_5_ERST_SUBTRACT_VALUE                 0x0B
#define EFI_ACPI_6_5_ERST_STALL                          0x0C
#define EFI_ACPI_6_5_ERST_STALL_WHILE_TRUE               0x0D
#define EFI_ACPI_6_5_ERST_SKIP_NEXT_INSTRUCTION_IF_TRUE  0x0E
#define EFI_ACPI_6_5_ERST_GOTO                           0x0F
#define EFI_ACPI_6_5_ERST_SET_SRC_ADDRESS_BASE           0x10
#define EFI_ACPI_6_5_ERST_SET_DST_ADDRESS_BASE           0x11
#define EFI_ACPI_6_5_ERST_MOVE_DATA                      0x12

///
/// ERST Instruction Flags
///
#define EFI_ACPI_6_5_ERST_PRESERVE_REGISTER  0x01

///
/// ERST Serialization Instruction Entry
///
typedef struct {
    UINT8                                     SerializationAction;
    UINT8                                     Instruction;
    UINT8                                     Flags;
    UINT8                                     Reserved0;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    RegisterRegion;
    UINT64                                    Value;
    UINT64                                    Mask;
} EFI_ACPI_6_5_ERST_SERIALIZATION_INSTRUCTION_ENTRY;

///
/// EINJ - Error Injection Table
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT32                         InjectionHeaderSize;
    UINT8                          InjectionFlags;
    UINT8                          Reserved0[3];
    UINT32                         InjectionEntryCount;
} EFI_ACPI_6_5_ERROR_INJECTION_TABLE_HEADER;

///
/// EINJ Version (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_ERROR_INJECTION_TABLE_REVISION  0x01

///
/// EINJ Error Injection Actions
///
#define EFI_ACPI_6_5_EINJ_BEGIN_INJECTION_OPERATION       0x00
#define EFI_ACPI_6_5_EINJ_GET_TRIGGER_ERROR_ACTION_TABLE  0x01
#define EFI_ACPI_6_5_EINJ_SET_ERROR_TYPE                  0x02
#define EFI_ACPI_6_5_EINJ_GET_ERROR_TYPE                  0x03
#define EFI_ACPI_6_5_EINJ_END_OPERATION                   0x04
#define EFI_ACPI_6_5_EINJ_EXECUTE_OPERATION               0x05
#define EFI_ACPI_6_5_EINJ_CHECK_BUSY_STATUS               0x06
#define EFI_ACPI_6_5_EINJ_GET_COMMAND_STATUS              0x07
#define EFI_ACPI_6_5_EINJ_TRIGGER_ERROR                   0xFF

///
/// EINJ Action Command Status
///
#define EFI_ACPI_6_5_EINJ_STATUS_SUCCESS          0x00
#define EFI_ACPI_6_5_EINJ_STATUS_UNKNOWN_FAILURE  0x01
#define EFI_ACPI_6_5_EINJ_STATUS_INVALID_ACCESS   0x02

///
/// EINJ Error Type Definition
///
#define EFI_ACPI_6_5_EINJ_ERROR_PROCESSOR_CORRECTABLE               (1 << 0)
#define EFI_ACPI_6_5_EINJ_ERROR_PROCESSOR_UNCORRECTABLE_NONFATAL    (1 << 1)
#define EFI_ACPI_6_5_EINJ_ERROR_PROCESSOR_UNCORRECTABLE_FATAL       (1 << 2)
#define EFI_ACPI_6_5_EINJ_ERROR_MEMORY_CORRECTABLE                  (1 << 3)
#define EFI_ACPI_6_5_EINJ_ERROR_MEMORY_UNCORRECTABLE_NONFATAL       (1 << 4)
#define EFI_ACPI_6_5_EINJ_ERROR_MEMORY_UNCORRECTABLE_FATAL          (1 << 5)
#define EFI_ACPI_6_5_EINJ_ERROR_PCI_EXPRESS_CORRECTABLE             (1 << 6)
#define EFI_ACPI_6_5_EINJ_ERROR_PCI_EXPRESS_UNCORRECTABLE_NONFATAL  (1 << 7)
#define EFI_ACPI_6_5_EINJ_ERROR_PCI_EXPRESS_UNCORRECTABLE_FATAL     (1 << 8)
#define EFI_ACPI_6_5_EINJ_ERROR_PLATFORM_CORRECTABLE                (1 << 9)
#define EFI_ACPI_6_5_EINJ_ERROR_PLATFORM_UNCORRECTABLE_NONFATAL     (1 << 10)
#define EFI_ACPI_6_5_EINJ_ERROR_PLATFORM_UNCORRECTABLE_FATAL        (1 << 11)

///
/// EINJ Injection Instructions
///
#define EFI_ACPI_6_5_EINJ_READ_REGISTER         0x00
#define EFI_ACPI_6_5_EINJ_READ_REGISTER_VALUE   0x01
#define EFI_ACPI_6_5_EINJ_WRITE_REGISTER        0x02
#define EFI_ACPI_6_5_EINJ_WRITE_REGISTER_VALUE  0x03
#define EFI_ACPI_6_5_EINJ_NOOP                  0x04

///
/// EINJ Instruction Flags
///
#define EFI_ACPI_6_5_EINJ_PRESERVE_REGISTER  0x01

///
/// EINJ Injection Instruction Entry
///
typedef struct {
    UINT8                                     InjectionAction;
    UINT8                                     Instruction;
    UINT8                                     Flags;
    UINT8                                     Reserved0;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    RegisterRegion;
    UINT64                                    Value;
    UINT64                                    Mask;
} EFI_ACPI_6_5_EINJ_INJECTION_INSTRUCTION_ENTRY;

///
/// EINJ Trigger Action Table
///
typedef struct {
    UINT32    HeaderSize;
    UINT32    Revision;
    UINT32    TableSize;
    UINT32    EntryCount;
} EFI_ACPI_6_5_EINJ_TRIGGER_ACTION_TABLE;

///
/// Platform Communications Channel Table (PCCT)
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT32                         Flags;
    UINT64                         Reserved;
} EFI_ACPI_6_5_PLATFORM_COMMUNICATION_CHANNEL_TABLE_HEADER;

///
/// PCCT Version (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_PLATFORM_COMMUNICATION_CHANNEL_TABLE_REVISION  0x02

///
/// PCCT Global Flags
///
#define EFI_ACPI_6_5_PCCT_FLAGS_PLATFORM_INTERRUPT  BIT0

//
// PCCT Subspace type
//
#define EFI_ACPI_6_5_PCCT_SUBSPACE_TYPE_GENERIC                        0x00
#define EFI_ACPI_6_5_PCCT_SUBSPACE_TYPE_1_HW_REDUCED_COMMUNICATIONS    0x01
#define EFI_ACPI_6_5_PCCT_SUBSPACE_TYPE_2_HW_REDUCED_COMMUNICATIONS    0x02
#define EFI_ACPI_6_5_PCCT_SUBSPACE_TYPE_3_EXTENDED_PCC                 0x03
#define EFI_ACPI_6_5_PCCT_SUBSPACE_TYPE_4_EXTENDED_PCC                 0x04
#define EFI_ACPI_6_5_PCCT_SUBSPACE_TYPE_5_HW_REGISTERS_COMMUNICATIONS  0x05

///
/// PCC Subspace Structure Header
///
typedef struct {
    UINT8    Type;
    UINT8    Length;
} EFI_ACPI_6_5_PCCT_SUBSPACE_HEADER;

///
/// Generic Communications Subspace Structure
///
typedef struct {
    UINT8                                     Type;
    UINT8                                     Length;
    UINT8                                     Reserved[6];
    UINT64                                    BaseAddress;
    UINT64                                    AddressLength;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    DoorbellRegister;
    UINT64                                    DoorbellPreserve;
    UINT64                                    DoorbellWrite;
    UINT32                                    NominalLatency;
    UINT32                                    MaximumPeriodicAccessRate;
    UINT16                                    MinimumRequestTurnaroundTime;
} EFI_ACPI_6_5_PCCT_SUBSPACE_GENERIC;

///
/// Generic Communications Channel Shared Memory Region
///

typedef struct {
    UINT8    Command;
    UINT8    Reserved : 7;
    UINT8    NotifyOnCompletion : 1;
} EFI_ACPI_6_5_PCCT_GENERIC_SHARED_MEMORY_REGION_COMMAND;

typedef struct {
    UINT8    CommandComplete : 1;
    UINT8    PlatformInterrupt : 1;
    UINT8    Error : 1;
    UINT8    PlatformNotification : 1;
    UINT8    Reserved : 4;
    UINT8    Reserved1;
} EFI_ACPI_6_5_PCCT_GENERIC_SHARED_MEMORY_REGION_STATUS;

typedef struct {
    UINT32                                                    Signature;
    EFI_ACPI_6_5_PCCT_GENERIC_SHARED_MEMORY_REGION_COMMAND    Command;
    EFI_ACPI_6_5_PCCT_GENERIC_SHARED_MEMORY_REGION_STATUS     Status;
} EFI_ACPI_6_5_PCCT_GENERIC_SHARED_MEMORY_REGION_HEADER;

#define EFI_ACPI_6_5_PCCT_SUBSPACE_PLATFORM_INTERRUPT_FLAGS_POLARITY  BIT0
#define EFI_ACPI_6_5_PCCT_SUBSPACE_PLATFORM_INTERRUPT_FLAGS_MODE      BIT1

///
/// Type 1 HW-Reduced Communications Subspace Structure
///
typedef struct {
    UINT8                                     Type;
    UINT8                                     Length;
    UINT32                                    PlatformInterrupt;
    UINT8                                     PlatformInterruptFlags;
    UINT8                                     Reserved;
    UINT64                                    BaseAddress;
    UINT64                                    AddressLength;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    DoorbellRegister;
    UINT64                                    DoorbellPreserve;
    UINT64                                    DoorbellWrite;
    UINT32                                    NominalLatency;
    UINT32                                    MaximumPeriodicAccessRate;
    UINT16                                    MinimumRequestTurnaroundTime;
} EFI_ACPI_6_5_PCCT_SUBSPACE_1_HW_REDUCED_COMMUNICATIONS;

///
/// Type 2 HW-Reduced Communications Subspace Structure
///
typedef struct {
    UINT8                                     Type;
    UINT8                                     Length;
    UINT32                                    PlatformInterrupt;
    UINT8                                     PlatformInterruptFlags;
    UINT8                                     Reserved;
    UINT64                                    BaseAddress;
    UINT64                                    AddressLength;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    DoorbellRegister;
    UINT64                                    DoorbellPreserve;
    UINT64                                    DoorbellWrite;
    UINT32                                    NominalLatency;
    UINT32                                    MaximumPeriodicAccessRate;
    UINT16                                    MinimumRequestTurnaroundTime;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    PlatformInterruptAckRegister;
    UINT64                                    PlatformInterruptAckPreserve;
    UINT64                                    PlatformInterruptAckWrite;
} EFI_ACPI_6_5_PCCT_SUBSPACE_2_HW_REDUCED_COMMUNICATIONS;

///
/// Type 3 Extended PCC Subspace Structure
///
typedef struct {
    UINT8                                     Type;
    UINT8                                     Length;
    UINT32                                    PlatformInterrupt;
    UINT8                                     PlatformInterruptFlags;
    UINT8                                     Reserved;
    UINT64                                    BaseAddress;
    UINT32                                    AddressLength;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    DoorbellRegister;
    UINT64                                    DoorbellPreserve;
    UINT64                                    DoorbellWrite;
    UINT32                                    NominalLatency;
    UINT32                                    MaximumPeriodicAccessRate;
    UINT32                                    MinimumRequestTurnaroundTime;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    PlatformInterruptAckRegister;
    UINT64                                    PlatformInterruptAckPreserve;
    UINT64                                    PlatformInterruptAckSet;
    UINT8                                     Reserved1[8];
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    CommandCompleteCheckRegister;
    UINT64                                    CommandCompleteCheckMask;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    CommandCompleteUpdateRegister;
    UINT64                                    CommandCompleteUpdatePreserve;
    UINT64                                    CommandCompleteUpdateSet;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    ErrorStatusRegister;
    UINT64                                    ErrorStatusMask;
} EFI_ACPI_6_5_PCCT_SUBSPACE_3_EXTENDED_PCC;

///
/// Type 4 Extended PCC Subspace Structure
///
typedef EFI_ACPI_6_5_PCCT_SUBSPACE_3_EXTENDED_PCC EFI_ACPI_6_5_PCCT_SUBSPACE_4_EXTENDED_PCC;

#define EFI_ACPI_6_5_PCCT_MASTER_SLAVE_COMMUNICATIONS_CHANNEL_FLAGS_NOTIFY_ON_COMPLETION  BIT0

typedef struct {
    UINT32    Signature;
    UINT32    Flags;
    UINT32    Length;
    UINT32    Command;
} EFI_ACPI_6_5_PCCT_EXTENDED_PCC_SHARED_MEMORY_REGION_HEADER;

///
/// Type 5 HW Registers based Communications Subspace Structure
///
typedef struct {
    UINT8                                     Type;
    UINT8                                     Length;
    UINT16                                    Version;
    UINT64                                    BaseAddress;
    UINT64                                    SharedMemoryRangeLength;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    DoorbellRegister;
    UINT64                                    DoorbellPreserve;
    UINT64                                    DoorbellWrite;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    CommandCompleteCheckRegister;
    UINT64                                    CommandCompleteCheckMask;
    EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE    ErrorStatusRegister;
    UINT64                                    ErrorStatusMask;
    UINT32                                    NominalLatency;
    UINT32                                    MinimumRequestTurnaroundTime;
} EFI_ACPI_6_5_PCCT_SUBSPACE_5_HW_REGISTERS_COMMUNICATIONS;

///
/// Reduced PCC Subspace Shared Memory Region
///
typedef struct {
    UINT32    Signature;
    // UINT8       CommunicationSubspace[];
} EFI_6_5_PCCT_REDUCED_PCC_SUBSPACE_SHARED_MEMORY_REGION;

///
/// Platform Debug Trigger Table (PDTT)
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT8                          TriggerCount;
    UINT8                          Reserved[3];
    UINT32                         TriggerIdentifierArrayOffset;
} EFI_ACPI_6_5_PLATFORM_DEBUG_TRIGGER_TABLE_HEADER;

///
/// PDTT Revision (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_PLATFORM_DEBUG_TRIGGER_TABLE_REVISION  0x00

///
/// PDTT Platform Communication Channel Identifier Structure
///
typedef struct {
    UINT16    SubChannelIdentifer : 8;
    UINT16    Runtime : 1;
    UINT16    WaitForCompletion : 1;
    UINT16    TriggerOrder : 1;
    UINT16    Reserved : 5;
} EFI_ACPI_6_5_PDTT_PCC_IDENTIFIER;

///
/// PCC Commands Codes used by Platform Debug Trigger Table
///
#define EFI_ACPI_6_5_PDTT_PCC_COMMAND_DOORBELL_ONLY    0x00
#define EFI_ACPI_6_5_PDTT_PCC_COMMAND_VENDOR_SPECIFIC  0x01

///
/// PDTT Platform Communication Channel
///
typedef EFI_ACPI_6_5_PCCT_GENERIC_SHARED_MEMORY_REGION_HEADER EFI_ACPI_6_5_PDTT_PCC;

///
/// Processor Properties Topology Table (PPTT)
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
} EFI_ACPI_6_5_PROCESSOR_PROPERTIES_TOPOLOGY_TABLE_HEADER;

///
/// PPTT Revision (as defined in ACPI 6.5 spec.)
///
#define EFI_ACPI_6_5_PROCESSOR_PROPERTIES_TOPOLOGY_TABLE_REVISION  0x03

///
/// PPTT types
///
#define EFI_ACPI_6_5_PPTT_TYPE_PROCESSOR  0x00
#define EFI_ACPI_6_5_PPTT_TYPE_CACHE      0x01

///
/// PPTT Structure Header
///
typedef struct {
    UINT8    Type;
    UINT8    Length;
    UINT8    Reserved[2];
} EFI_ACPI_6_5_PPTT_STRUCTURE_HEADER;

///
/// For PPTT struct processor flags
///
#define EFI_ACPI_6_5_PPTT_PACKAGE_NOT_PHYSICAL          0x0
#define EFI_ACPI_6_5_PPTT_PACKAGE_PHYSICAL              0x1
#define EFI_ACPI_6_5_PPTT_PROCESSOR_ID_INVALID          0x0
#define EFI_ACPI_6_5_PPTT_PROCESSOR_ID_VALID            0x1
#define EFI_ACPI_6_5_PPTT_PROCESSOR_IS_NOT_THREAD       0x0
#define EFI_ACPI_6_5_PPTT_PROCESSOR_IS_THREAD           0x1
#define EFI_ACPI_6_5_PPTT_NODE_IS_NOT_LEAF              0x0
#define EFI_ACPI_6_5_PPTT_NODE_IS_LEAF                  0x1
#define EFI_ACPI_6_5_PPTT_IMPLEMENTATION_NOT_IDENTICAL  0x0
#define EFI_ACPI_6_5_PPTT_IMPLEMENTATION_IDENTICAL      0x1

///
/// Processor hierarchy node structure flags
///
typedef struct {
    UINT32    PhysicalPackage : 1;
    UINT32    AcpiProcessorIdValid : 1;
    UINT32    ProcessorIsAThread : 1;
    UINT32    NodeIsALeaf : 1;
    UINT32    IdenticalImplementation : 1;
    UINT32    Reserved : 27;
} EFI_ACPI_6_5_PPTT_STRUCTURE_PROCESSOR_FLAGS;

///
/// Processor hierarchy node structure
///
typedef struct {
    UINT8                                          Type;
    UINT8                                          Length;
    UINT8                                          Reserved[2];
    EFI_ACPI_6_5_PPTT_STRUCTURE_PROCESSOR_FLAGS    Flags;
    UINT32                                         Parent;
    UINT32                                         AcpiProcessorId;
    UINT32                                         NumberOfPrivateResources;
} EFI_ACPI_6_5_PPTT_STRUCTURE_PROCESSOR;

///
/// For PPTT struct cache flags
///
#define EFI_ACPI_6_5_PPTT_CACHE_SIZE_INVALID       0x0
#define EFI_ACPI_6_5_PPTT_CACHE_SIZE_VALID         0x1
#define EFI_ACPI_6_5_PPTT_NUMBER_OF_SETS_INVALID   0x0
#define EFI_ACPI_6_5_PPTT_NUMBER_OF_SETS_VALID     0x1
#define EFI_ACPI_6_5_PPTT_ASSOCIATIVITY_INVALID    0x0
#define EFI_ACPI_6_5_PPTT_ASSOCIATIVITY_VALID      0x1
#define EFI_ACPI_6_5_PPTT_ALLOCATION_TYPE_INVALID  0x0
#define EFI_ACPI_6_5_PPTT_ALLOCATION_TYPE_VALID    0x1
#define EFI_ACPI_6_5_PPTT_CACHE_TYPE_INVALID       0x0
#define EFI_ACPI_6_5_PPTT_CACHE_TYPE_VALID         0x1
#define EFI_ACPI_6_5_PPTT_WRITE_POLICY_INVALID     0x0
#define EFI_ACPI_6_5_PPTT_WRITE_POLICY_VALID       0x1
#define EFI_ACPI_6_5_PPTT_LINE_SIZE_INVALID        0x0
#define EFI_ACPI_6_5_PPTT_LINE_SIZE_VALID          0x1
#define EFI_ACPI_6_5_PPTT_CACHE_ID_INVALID         0x0
#define EFI_ACPI_6_5_PPTT_CACHE_ID_VALID           0x1

///
/// Cache Type Structure flags
///
typedef struct {
    UINT32    SizePropertyValid : 1;
    UINT32    NumberOfSetsValid : 1;
    UINT32    AssociativityValid : 1;
    UINT32    AllocationTypeValid : 1;
    UINT32    CacheTypeValid : 1;
    UINT32    WritePolicyValid : 1;
    UINT32    LineSizeValid : 1;
    UINT32    CacheIdValid : 1;
    UINT32    Reserved : 24;
} EFI_ACPI_6_5_PPTT_STRUCTURE_CACHE_FLAGS;

///
/// For cache attributes
///
#define EFI_ACPI_6_5_CACHE_ATTRIBUTES_ALLOCATION_READ             0x0
#define EFI_ACPI_6_5_CACHE_ATTRIBUTES_ALLOCATION_WRITE            0x1
#define EFI_ACPI_6_5_CACHE_ATTRIBUTES_ALLOCATION_READ_WRITE       0x2
#define EFI_ACPI_6_5_CACHE_ATTRIBUTES_CACHE_TYPE_DATA             0x0
#define EFI_ACPI_6_5_CACHE_ATTRIBUTES_CACHE_TYPE_INSTRUCTION      0x1
#define EFI_ACPI_6_5_CACHE_ATTRIBUTES_CACHE_TYPE_UNIFIED          0x2
#define EFI_ACPI_6_5_CACHE_ATTRIBUTES_WRITE_POLICY_WRITE_BACK     0x0
#define EFI_ACPI_6_5_CACHE_ATTRIBUTES_WRITE_POLICY_WRITE_THROUGH  0x1

///
/// Cache Type Structure cache attributes
///
typedef struct {
    UINT8    AllocationType : 2;
    UINT8    CacheType : 2;
    UINT8    WritePolicy : 1;
    UINT8    Reserved : 3;
} EFI_ACPI_6_5_PPTT_STRUCTURE_CACHE_ATTRIBUTES;

///
/// Cache Type Structure
///
typedef struct {
    UINT8                                           Type;
    UINT8                                           Length;
    UINT8                                           Reserved[2];
    EFI_ACPI_6_5_PPTT_STRUCTURE_CACHE_FLAGS         Flags;
    UINT32                                          NextLevelOfCache;
    UINT32                                          Size;
    UINT32                                          NumberOfSets;
    UINT8                                           Associativity;
    EFI_ACPI_6_5_PPTT_STRUCTURE_CACHE_ATTRIBUTES    Attributes;
    UINT16                                          LineSize;
    UINT32                                          CacheId;
} EFI_ACPI_6_5_PPTT_STRUCTURE_CACHE;

///
/// Platform Health Assessment Table (PHAT) Format
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    // UINT8                         PlatformTelemetryRecords[];
} EFI_ACPI_6_5_PLATFORM_HEALTH_ASSESSMENT_TABLE;

#define EFI_ACPI_6_5_PLATFORM_HEALTH_ASSESSMENT_TABLE_REVISION  0x01

///
/// PHAT Record Format
///
typedef struct {
    UINT16    PlatformHealthAssessmentRecordType;
    UINT16    RecordLength;
    UINT8     Revision;
    // UINT8   Data[];
} EFI_ACPI_6_5_PHAT_RECORD;

///
/// PHAT Record Type Format
///
#define EFI_ACPI_6_5_PHAT_RECORD_TYPE_FIRMWARE_VERSION_DATA_RECORD  0x0000
#define EFI_ACPI_6_5_PHAT_RECORD_TYPE_FIRMWARE_HEALTH_DATA_RECORD   0x0001

///
/// PHAT Version Element
///
typedef struct {
    GUID      ComponentId;
    UINT64    VersionValue;
    UINT32    ProducerId;
} EFI_ACPI_6_5_PHAT_VERSION_ELEMENT;

///
/// PHAT Firmware Version Data Record
///
typedef struct {
    UINT16    PlatformRecordType;
    UINT16    RecordLength;
    UINT8     Revision;
    UINT8     Reserved[3];
    UINT32    RecordCount;
    // UINT8   PhatVersionElement[];
} EFI_ACPI_6_5_PHAT_FIRMWARE_VERISON_DATA_RECORD;

#define EFI_ACPI_6_5_PHAT_FIRMWARE_VERSION_DATA_RECORD_REVISION  0x01

///
/// Firmware Health Data Record Structure
///
typedef struct {
    UINT16    PlatformRecordType;
    UINT16    RecordLength;
    UINT8     Revision;
    UINT16    Reserved;
    UINT8     AmHealthy;
    GUID      DeviceSignature;
    UINT32    DeviceSpecificDataOffset;
    // UINT8   DevicePath[];
    // UINT8   DeviceSpecificData[];
} EFI_ACPI_6_5_PHAT_FIRMWARE_HEALTH_DATA_RECORD_STRUCTURE;

#define EFI_ACPI_6_5_PHAT_FIRMWARE_HEALTH_DATA_RECORD_REVISION  0x01

///
/// Firmware Health Data Record device health state
///
#define EFI_ACPI_6_5_PHAT_FIRMWARE_HEALTH_DATA_RECORD_ERRORS_FOUND     0x00
#define EFI_ACPI_6_5_PHAT_FIRMWARE_HEALTH_DATA_RECORD_NO_ERRORS_FOUND  0x01
#define EFI_ACPI_6_5_PHAT_FIRMWARE_HEALTH_DATA_RECORD_UNKNOWN          0x02
#define EFI_ACPI_6_5_PHAT_FIRMWARE_HEALTH_DATA_RECORD_ADVISORY         0x03

//
// Known table signatures
//

///
/// "RSD PTR " Root System Description Pointer
///
#define EFI_ACPI_6_5_ROOT_SYSTEM_DESCRIPTION_POINTER_SIGNATURE  SIGNATURE_64('R', 'S', 'D', ' ', 'P', 'T', 'R', ' ')

///
/// "APIC" Multiple APIC Description Table
///
#define EFI_ACPI_6_5_MULTIPLE_APIC_DESCRIPTION_TABLE_SIGNATURE  SIGNATURE_32('A', 'P', 'I', 'C')

///
/// "APMT" Arm Performance Monitoring Unit Table
///
#define EFI_ACPI_6_5_ARM_PERFORMANCE_MONITORING_UNIT_TABLE_SIGNATURE  SIGNATURE_32('A', 'P', 'M', 'T')

///
/// "BERT" Boot Error Record Table
///
#define EFI_ACPI_6_5_BOOT_ERROR_RECORD_TABLE_SIGNATURE  SIGNATURE_32('B', 'E', 'R', 'T')

///
/// "BGRT" Boot Graphics Resource Table
///
#define EFI_ACPI_6_5_BOOT_GRAPHICS_RESOURCE_TABLE_SIGNATURE  SIGNATURE_32('B', 'G', 'R', 'T')

///
/// "CDIT" Component Distance Information Table
///
#define EFI_ACPI_6_5_COMPONENT_DISTANCE_INFORMATION_TABLE_SIGNATURE  SIGNATURE_32('C', 'D', 'I', 'T')

///
/// "CPEP" Corrected Platform Error Polling Table
///
#define EFI_ACPI_6_5_CORRECTED_PLATFORM_ERROR_POLLING_TABLE_SIGNATURE  SIGNATURE_32('C', 'P', 'E', 'P')

///
/// "CRAT" Component Resource Attribute Table
///
#define EFI_ACPI_6_5_COMPONENT_RESOURCE_ATTRIBUTE_TABLE_SIGNATURE  SIGNATURE_32('C', 'R', 'A', 'T')

///
/// "DSDT" Differentiated System Description Table
///
#define EFI_ACPI_6_5_DIFFERENTIATED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE  SIGNATURE_32('D', 'S', 'D', 'T')

///
/// "ECDT" Embedded Controller Boot Resources Table
///
#define EFI_ACPI_6_5_EMBEDDED_CONTROLLER_BOOT_RESOURCES_TABLE_SIGNATURE  SIGNATURE_32('E', 'C', 'D', 'T')

///
/// "EINJ" Error Injection Table
///
#define EFI_ACPI_6_5_ERROR_INJECTION_TABLE_SIGNATURE  SIGNATURE_32('E', 'I', 'N', 'J')

///
/// "ERST" Error Record Serialization Table
///
#define EFI_ACPI_6_5_ERROR_RECORD_SERIALIZATION_TABLE_SIGNATURE  SIGNATURE_32('E', 'R', 'S', 'T')

///
/// "FACP" Fixed ACPI Description Table
///
#define EFI_ACPI_6_5_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE  SIGNATURE_32('F', 'A', 'C', 'P')

///
/// "FACS" Firmware ACPI Control Structure
///
#define EFI_ACPI_6_5_FIRMWARE_ACPI_CONTROL_STRUCTURE_SIGNATURE  SIGNATURE_32('F', 'A', 'C', 'S')

///
/// "FPDT" Firmware Performance Data Table
///
#define EFI_ACPI_6_5_FIRMWARE_PERFORMANCE_DATA_TABLE_SIGNATURE  SIGNATURE_32('F', 'P', 'D', 'T')

///
/// "GTDT" Generic Timer Description Table
///
#define EFI_ACPI_6_5_GENERIC_TIMER_DESCRIPTION_TABLE_SIGNATURE  SIGNATURE_32('G', 'T', 'D', 'T')

///
/// "HEST" Hardware Error Source Table
///
#define EFI_ACPI_6_5_HARDWARE_ERROR_SOURCE_TABLE_SIGNATURE  SIGNATURE_32('H', 'E', 'S', 'T')

///
/// "HMAT" Heterogeneous Memory Attribute Table
///
#define EFI_ACPI_6_5_HETEROGENEOUS_MEMORY_ATTRIBUTE_TABLE_SIGNATURE  SIGNATURE_32('H', 'M', 'A', 'T')

///
/// "MPST" Memory Power State Table
///
#define EFI_ACPI_6_5_MEMORY_POWER_STATE_TABLE_SIGNATURE  SIGNATURE_32('M', 'P', 'S', 'T')

///
/// "MSCT" Maximum System Characteristics Table
///
#define EFI_ACPI_6_5_MAXIMUM_SYSTEM_CHARACTERISTICS_TABLE_SIGNATURE  SIGNATURE_32('M', 'S', 'C', 'T')

///
/// "NFIT" NVDIMM Firmware Interface Table
///
#define EFI_ACPI_6_5_NVDIMM_FIRMWARE_INTERFACE_TABLE_STRUCTURE_SIGNATURE  SIGNATURE_32('N', 'F', 'I', 'T')

///
/// "PDTT" Platform Debug Trigger Table
///
#define EFI_ACPI_6_5_PLATFORM_DEBUG_TRIGGER_TABLE_STRUCTURE_SIGNATURE  SIGNATURE_32('P', 'D', 'T', 'T')

///
/// "PMTT" Platform Memory Topology Table
///
#define EFI_ACPI_6_5_PLATFORM_MEMORY_TOPOLOGY_TABLE_SIGNATURE  SIGNATURE_32('P', 'M', 'T', 'T')

///
/// "PPTT" Processor Properties Topology Table
///
#define EFI_ACPI_6_5_PROCESSOR_PROPERTIES_TOPOLOGY_TABLE_STRUCTURE_SIGNATURE  SIGNATURE_32('P', 'P', 'T', 'T')

///
/// "PSDT" Persistent System Description Table
///
#define EFI_ACPI_6_5_PERSISTENT_SYSTEM_DESCRIPTION_TABLE_SIGNATURE  SIGNATURE_32('P', 'S', 'D', 'T')

///
/// "RASF" ACPI RAS Feature Table
///
#define EFI_ACPI_6_5_ACPI_RAS_FEATURE_TABLE_SIGNATURE  SIGNATURE_32('R', 'A', 'S', 'F')

///
/// "RSDT" Root System Description Table
///
#define EFI_ACPI_6_5_ROOT_SYSTEM_DESCRIPTION_TABLE_SIGNATURE  SIGNATURE_32('R', 'S', 'D', 'T')

///
/// "SBST" Smart Battery Specification Table
///
#define EFI_ACPI_6_5_SMART_BATTERY_SPECIFICATION_TABLE_SIGNATURE  SIGNATURE_32('S', 'B', 'S', 'T')

///
/// "SDEV" Secure DEVices Table
///
#define EFI_ACPI_6_5_SECURE_DEVICES_TABLE_SIGNATURE  SIGNATURE_32('S', 'D', 'E', 'V')

///
/// "SLIT" System Locality Information Table
///
#define EFI_ACPI_6_5_SYSTEM_LOCALITY_INFORMATION_TABLE_SIGNATURE  SIGNATURE_32('S', 'L', 'I', 'T')

///
/// "SRAT" System Resource Affinity Table
///
#define EFI_ACPI_6_5_SYSTEM_RESOURCE_AFFINITY_TABLE_SIGNATURE  SIGNATURE_32('S', 'R', 'A', 'T')

///
/// "SSDT" Secondary System Description Table
///
#define EFI_ACPI_6_5_SECONDARY_SYSTEM_DESCRIPTION_TABLE_SIGNATURE  SIGNATURE_32('S', 'S', 'D', 'T')

///
/// "XSDT" Extended System Description Table
///
#define EFI_ACPI_6_5_EXTENDED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE  SIGNATURE_32('X', 'S', 'D', 'T')

///
/// "BOOT" MS Simple Boot Spec
///
#define EFI_ACPI_6_5_SIMPLE_BOOT_FLAG_TABLE_SIGNATURE  SIGNATURE_32('B', 'O', 'O', 'T')

///
/// "CSRT" MS Core System Resource Table
///
#define EFI_ACPI_6_5_CORE_SYSTEM_RESOURCE_TABLE_SIGNATURE  SIGNATURE_32('C', 'S', 'R', 'T')

///
/// "DBG2" MS Debug Port 2 Spec
///
#define EFI_ACPI_6_5_DEBUG_PORT_2_TABLE_SIGNATURE  SIGNATURE_32('D', 'B', 'G', '2')

///
/// "DBGP" MS Debug Port Spec
///
#define EFI_ACPI_6_5_DEBUG_PORT_TABLE_SIGNATURE  SIGNATURE_32('D', 'B', 'G', 'P')

///
/// "DMAR" DMA Remapping Table
///
#define EFI_ACPI_6_5_DMA_REMAPPING_TABLE_SIGNATURE  SIGNATURE_32('D', 'M', 'A', 'R')

///
/// "DRTM" Dynamic Root of Trust for Measurement Table
///
#define EFI_ACPI_6_5_DYNAMIC_ROOT_OF_TRUST_FOR_MEASUREMENT_TABLE_SIGNATURE  SIGNATURE_32('D', 'R', 'T', 'M')

///
/// "ETDT" Event Timer Description Table
///
#define EFI_ACPI_6_5_EVENT_TIMER_DESCRIPTION_TABLE_SIGNATURE  SIGNATURE_32('E', 'T', 'D', 'T')

///
/// "HPET" IA-PC High Precision Event Timer Table
///
#define EFI_ACPI_6_5_HIGH_PRECISION_EVENT_TIMER_TABLE_SIGNATURE  SIGNATURE_32('H', 'P', 'E', 'T')

///
/// "iBFT" iSCSI Boot Firmware Table
///
#define EFI_ACPI_6_5_ISCSI_BOOT_FIRMWARE_TABLE_SIGNATURE  SIGNATURE_32('i', 'B', 'F', 'T')

///
/// "IORT" I/O Remapping Table
///
#define EFI_ACPI_6_5_IO_REMAPPING_TABLE_SIGNATURE  SIGNATURE_32('I', 'O', 'R', 'T')

///
/// "IVRS" I/O Virtualization Reporting Structure
///
#define EFI_ACPI_6_5_IO_VIRTUALIZATION_REPORTING_STRUCTURE_SIGNATURE  SIGNATURE_32('I', 'V', 'R', 'S')

///
/// "LPIT" Low Power Idle Table
///
#define EFI_ACPI_6_5_LOW_POWER_IDLE_TABLE_STRUCTURE_SIGNATURE  SIGNATURE_32('L', 'P', 'I', 'T')

///
/// "MCFG" PCI Express Memory Mapped Configuration Space Base Address Description Table
///
#define EFI_ACPI_6_5_PCI_EXPRESS_MEMORY_MAPPED_CONFIGURATION_SPACE_BASE_ADDRESS_DESCRIPTION_TABLE_SIGNATURE  SIGNATURE_32('M', 'C', 'F', 'G')

///
/// "MCHI" Management Controller Host Interface Table
///
#define EFI_ACPI_6_5_MANAGEMENT_CONTROLLER_HOST_INTERFACE_TABLE_SIGNATURE  SIGNATURE_32('M', 'C', 'H', 'I')

///
/// "MSDM" MS Data Management Table
///
#define EFI_ACPI_6_5_DATA_MANAGEMENT_TABLE_SIGNATURE  SIGNATURE_32('M', 'S', 'D', 'M')

///
/// "PCCT" Platform Communications Channel Table
///
#define EFI_ACPI_6_5_PLATFORM_COMMUNICATIONS_CHANNEL_TABLE_SIGNATURE  SIGNATURE_32('P', 'C', 'C', 'T')

///
/// "PHAT" Platform Health Assessment Table
///
#define EFI_ACPI_6_5_PLATFORM_HEALTH_ASSESSMENT_TABLE_SIGNATURE  SIGNATURE_32('P', 'H', 'A', 'T')

///
/// "SDEI" Software Delegated Exceptions Interface Table
///
#define EFI_ACPI_6_5_SOFTWARE_DELEGATED_EXCEPTIONS_INTERFACE_TABLE_SIGNATURE  SIGNATURE_32('S', 'D', 'E', 'I')

///
/// "SLIC" MS Software Licensing Table Specification
///
#define EFI_ACPI_6_5_SOFTWARE_LICENSING_TABLE_SIGNATURE  SIGNATURE_32('S', 'L', 'I', 'C')

///
/// "SPCR" Serial Port Concole Redirection Table
///
#define EFI_ACPI_6_5_SERIAL_PORT_CONSOLE_REDIRECTION_TABLE_SIGNATURE  SIGNATURE_32('S', 'P', 'C', 'R')

///
/// "SPMI" Server Platform Management Interface Table
///
#define EFI_ACPI_6_5_SERVER_PLATFORM_MANAGEMENT_INTERFACE_TABLE_SIGNATURE  SIGNATURE_32('S', 'P', 'M', 'I')

///
/// "STAO" _STA Override Table
///
#define EFI_ACPI_6_5_STA_OVERRIDE_TABLE_SIGNATURE  SIGNATURE_32('S', 'T', 'A', 'O')

///
/// "TCPA" Trusted Computing Platform Alliance Capabilities Table
///
#define EFI_ACPI_6_5_TRUSTED_COMPUTING_PLATFORM_ALLIANCE_CAPABILITIES_TABLE_SIGNATURE  SIGNATURE_32('T', 'C', 'P', 'A')

///
/// "TPM2" Trusted Computing Platform 1 Table
///
#define EFI_ACPI_6_5_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE  SIGNATURE_32('T', 'P', 'M', '2')

///
/// "UEFI" UEFI ACPI Data Table
///
#define EFI_ACPI_6_5_UEFI_ACPI_DATA_TABLE_SIGNATURE  SIGNATURE_32('U', 'E', 'F', 'I')

///
/// "WAET" Windows ACPI Emulated Devices Table
///
#define EFI_ACPI_6_5_WINDOWS_ACPI_EMULATED_DEVICES_TABLE_SIGNATURE  SIGNATURE_32('W', 'A', 'E', 'T')

///
/// "WDAT" Watchdog Action Table
///
#define EFI_ACPI_6_5_WATCHDOG_ACTION_TABLE_SIGNATURE  SIGNATURE_32('W', 'D', 'A', 'T')

///
/// "WDRT" Watchdog Resource Table
///
#define EFI_ACPI_6_5_WATCHDOG_RESOURCE_TABLE_SIGNATURE  SIGNATURE_32('W', 'D', 'R', 'T')

///
/// "WPBT" MS Platform Binary Table
///
#define EFI_ACPI_6_5_PLATFORM_BINARY_TABLE_SIGNATURE  SIGNATURE_32('W', 'P', 'B', 'T')

///
/// "WSMT" Windows SMM Security Mitigation Table
///
#define EFI_ACPI_6_5_WINDOWS_SMM_SECURITY_MITIGATION_TABLE_SIGNATURE  SIGNATURE_32('W', 'S', 'M', 'T')

///
/// "XENV" Xen Project Table
///
#define EFI_ACPI_6_5_XEN_PROJECT_TABLE_SIGNATURE  SIGNATURE_32('X', 'E', 'N', 'V')

#pragma pack()

#pragma pack(1)

///
/// ACPI 2.0 Generic Address Space definition
///
typedef struct {
    UINT8     AddressSpaceId;
    UINT8     RegisterBitWidth;
    UINT8     RegisterBitOffset;
    UINT8     Reserved;
    UINT64    Address;
} EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE;

///
/// Root System Description Pointer Structure
///
typedef struct {
    UINT64    Signature;
    UINT8     Checksum;
    UINT8     OemId[6];
    UINT8     Revision;
    UINT32    RsdtAddress;
    UINT32    Length;
    UINT64    XsdtAddress;
    UINT8     ExtendedChecksum;
    UINT8     Reserved[3];
} EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER;

///
/// Common table header, this prefaces all ACPI tables, including FACS, but
/// excluding the RSD PTR structure
///
typedef struct {
    UINT32    Signature;
    UINT32    Length;
} EFI_ACPI_2_0_COMMON_HEADER;

//
// Root System Description Table
// No definition needed as it is a common description table header, the same with
// EFI_ACPI_DESCRIPTION_HEADER, followed by a variable number of UINT32 table pointers.
//

///
/// RSDT Revision (as defined in ACPI 2.0 spec.)
///
#define EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_TABLE_REVISION  0x01

//
// Extended System Description Table
// No definition needed as it is a common description table header, the same with
// EFI_ACPI_DESCRIPTION_HEADER, followed by a variable number of UINT64 table pointers.
//

///
/// XSDT Revision (as defined in ACPI 2.0 spec.)
///
#define EFI_ACPI_2_0_EXTENDED_SYSTEM_DESCRIPTION_TABLE_REVISION  0x01

///
/// RSD_PTR Revision (as defined in ACPI 2.0 spec.)
///
#define EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER_REVISION  0x02

///
/// FADT Version (as defined in ACPI 2.0 spec.)
///
#define EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE_REVISION  0x03

///
/// "DSDT" Differentiated System Description Table
///
#define EFI_ACPI_2_0_DIFFERENTIATED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE  SIGNATURE_32('D', 'S', 'D', 'T')

///
/// "FACP" Fixed ACPI Description Table
///
#define EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE  SIGNATURE_32('F', 'A', 'C', 'P')

///
/// "FACS" Firmware ACPI Control Structure
///
#define EFI_ACPI_2_0_FIRMWARE_ACPI_CONTROL_STRUCTURE_SIGNATURE  SIGNATURE_32('F', 'A', 'C', 'S')

///
/// Fixed ACPI Description Table Structure (FADT)
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER               Header;
    UINT32                                    FirmwareCtrl;
    UINT32                                    Dsdt;
    UINT8                                     Reserved0;
    UINT8                                     PreferredPmProfile;
    UINT16                                    SciInt;
    UINT32                                    SmiCmd;
    UINT8                                     AcpiEnable;
    UINT8                                     AcpiDisable;
    UINT8                                     S4BiosReq;
    UINT8                                     PstateCnt;
    UINT32                                    Pm1aEvtBlk;
    UINT32                                    Pm1bEvtBlk;
    UINT32                                    Pm1aCntBlk;
    UINT32                                    Pm1bCntBlk;
    UINT32                                    Pm2CntBlk;
    UINT32                                    PmTmrBlk;
    UINT32                                    Gpe0Blk;
    UINT32                                    Gpe1Blk;
    UINT8                                     Pm1EvtLen;
    UINT8                                     Pm1CntLen;
    UINT8                                     Pm2CntLen;
    UINT8                                     PmTmrLen;
    UINT8                                     Gpe0BlkLen;
    UINT8                                     Gpe1BlkLen;
    UINT8                                     Gpe1Base;
    UINT8                                     CstCnt;
    UINT16                                    PLvl2Lat;
    UINT16                                    PLvl3Lat;
    UINT16                                    FlushSize;
    UINT16                                    FlushStride;
    UINT8                                     DutyOffset;
    UINT8                                     DutyWidth;
    UINT8                                     DayAlrm;
    UINT8                                     MonAlrm;
    UINT8                                     Century;
    UINT16                                    IaPcBootArch;
    UINT8                                     Reserved1;
    UINT32                                    Flags;
    EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE    ResetReg;
    UINT8                                     ResetValue;
    UINT8                                     Reserved2[3];
    UINT64                                    XFirmwareCtrl;
    UINT64                                    XDsdt;
    EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE    XPm1aEvtBlk;
    EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE    XPm1bEvtBlk;
    EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE    XPm1aCntBlk;
    EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE    XPm1bCntBlk;
    EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE    XPm2CntBlk;
    EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE    XPmTmrBlk;
    EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE    XGpe0Blk;
    EFI_ACPI_2_0_GENERIC_ADDRESS_STRUCTURE    XGpe1Blk;
} EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE;

typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;

    /**
      This field indicates the maximum DMA physical addressability supported by
      this platform. The system address map reported by the BIOS indicates what
      portions of this addresses are populated. The Host Address Width (HAW) of
      the platform is computed as (N+1), where N is the value reported in this
      field.
      For example, for a platform supporting 40 bits of physical addressability,
      the value of 100111b is reported in this field.
    **/
    UINT8    HostAddressWidth;

    /**
      - Bit[0]:   INTR_REMAP - If Clear, the platform does not support interrupt
                  remapping. If Set, the platform supports interrupt remapping.
      - Bit[1]:   X2APIC_OPT_OUT - For firmware compatibility reasons, platform
                  firmware may Set this field to request system software to opt
                  out of enabling Extended xAPIC (X2APIC) mode. This field is
                  valid only when the INTR_REMAP field (bit 0) is Set.
      - Bit[2]:   DMA_CTRL_PLATFORM_OPT_IN_FLAG - Platform firmware is
                  recommended to Set this field to report any platform initiated
                  DMA is restricted to only reserved memory regions (reported in
                  RMRR structures) when transferring control to system software
                  such as on ExitBootServices().
      - Bits[7:3] Reserved.
    **/
    UINT8    Flags;
    UINT8    Reserved[10];
} EFI_ACPI_DMAR_HEADER;

//
// Translation Structure Formats
//
#define VTD_ROOT_ENTRY_NUMBER       256
#define VTD_CONTEXT_ENTRY_NUMBER    256
#define EFI_ACPI_4_0_DMA_REMAPPING_TABLE_SIGNATURE  SIGNATURE_32('D', 'M', 'A', 'R')

typedef union {
    struct {
        UINT64  Present : 1;
        UINT64  Reserved_1 : 11;
        UINT64  ContextTablePointerLo : 20;
        UINT64  ContextTablePointerHi : 32;

        UINT64  Reserved_64;
    } Bits;
    struct {
        UINT64  Uint64Lo;
        UINT64  Uint64Hi;
    } Uint128;
} VTD_ROOT_ENTRY;

typedef union {
    struct {
        UINT64  LowerPresent : 1;
        UINT64  Reserved_1 : 11;
        UINT64  LowerContextTablePointerLo : 20;
        UINT64  LowerContextTablePointerHi : 32;

        UINT64  UpperPresent : 1;
        UINT64  Reserved_65 : 11;
        UINT64  UpperContextTablePointerLo : 20;
        UINT64  UpperContextTablePointerHi : 32;
    } Bits;
    struct {
        UINT64  Uint64Lo;
        UINT64  Uint64Hi;
    } Uint128;
} VTD_EXT_ROOT_ENTRY;

typedef union {
    struct {
        UINT64  Present : 1;
        UINT64  FaultProcessingDisable : 1;
        UINT64  TranslationType : 2;
        UINT64  Reserved_4 : 8;
        UINT64  SecondLevelPageTranslationPointerLo : 20;
        UINT64  SecondLevelPageTranslationPointerHi : 32;
        
        UINT64  AddressWidth : 3;
        UINT64  Ignored_67 : 4;
        UINT64  Reserved_71 : 1;
        UINT64  DomainIdentifier : 16;
        UINT64  Reserved_88 : 8;
        UINT64  Reserved_96 : 32;
    } Bits;
    struct {
        UINT64  Uint64Lo;
        UINT64  Uint64Hi;
    } Uint128;
} VTD_CONTEXT_ENTRY;

typedef union {
    struct {
        UINT64  Present : 1;
        UINT64  FaultProcessingDisable : 1;
        UINT64  TranslationType : 3;
        UINT64  ExtendedMemoryType : 3;
        UINT64  DeferredInvalidateEnable : 1;
        UINT64  PageRequestEnable : 1;
        UINT64  NestedTranslationEnable : 1;
        UINT64  PASIDEnable : 1;
        UINT64  SecondLevelPageTranslationPointerLo : 20;
        UINT64  SecondLevelPageTranslationPointerHi : 32;
        
        UINT64  AddressWidth : 3;
        UINT64  PageGlobalEnable : 1;
        UINT64  NoExecuteEnable : 1;
        UINT64  WriteProtectEnable : 1;
        UINT64  CacheDisable : 1;
        UINT64  ExtendedMemoryTypeEnable : 1;
        UINT64  DomainIdentifier : 16;
        UINT64  SupervisorModeExecuteProtection : 1;
        UINT64  ExtendedAccessedFlagEnable : 1;
        UINT64  ExecuteRequestsEnable : 1;
        UINT64  SecondLevelExecuteEnable : 1;
        UINT64  Reserved_92 : 4;
        UINT64  PageAttributeTable0 : 3;
        UINT64  Reserved_Pat0 : 1;
        UINT64  PageAttributeTable1 : 3;
        UINT64  Reserved_Pat1 : 1;
        UINT64  PageAttributeTable2 : 3;
        UINT64  Reserved_Pat2 : 1;
        UINT64  PageAttributeTable3 : 3;
        UINT64  Reserved_Pat3 : 1;
        UINT64  PageAttributeTable4 : 3;
        UINT64  Reserved_Pat4 : 1;
        UINT64  PageAttributeTable5 : 3;
        UINT64  Reserved_Pat5 : 1;
        UINT64  PageAttributeTable6 : 3;
        UINT64  Reserved_Pat6 : 1;
        UINT64  PageAttributeTable7 : 3;
        UINT64  Reserved_Pat7 : 1;
        
        UINT64  PASIDTableSize : 4;
        UINT64  Reserved_132 : 8;
        UINT64  PASIDTablePointerLo : 20;
        UINT64  PASIDTablePointerHi : 32;
        
        UINT64  Reserved_192 : 12;
        UINT64  PASIDStateTablePointerLo : 20;
        UINT64  PASIDStateTablePointerHi : 32;
    } Bits;
    struct {
        UINT64  Uint64_1;
        UINT64  Uint64_2;
        UINT64  Uint64_3;
        UINT64  Uint64_4;
    } Uint256;
} VTD_EXT_CONTEXT_ENTRY;

typedef union {
    struct {
        UINT64  Present : 1;
        UINT64  Reserved_1 : 2;
        UINT64  PageLevelCacheDisable : 1;
        UINT64  PageLevelWriteThrough : 1;
        UINT64  Reserved_5 : 6;
        UINT64  SupervisorRequestsEnable : 1;
        UINT64  FirstLevelPageTranslationPointerLo : 20;
        UINT64  FirstLevelPageTranslationPointerHi : 32;
    } Bits;
    UINT64    Uint64;
} VTD_PASID_ENTRY;

typedef union {
    struct {
        UINT64  Reserved_0 : 32;
        UINT64  ActiveReferenceCount : 16;
        UINT64  Reserved_48 : 15;
        UINT64  DeferredInvalidate : 1;
    } Bits;
    UINT64    Uint64;
} VTD_PASID_STATE_ENTRY;

typedef union {
    struct {
        UINT64  Present : 1;
        UINT64  ReadWrite : 1;
        UINT64  UserSupervisor : 1;
        UINT64  PageLevelWriteThrough : 1;
        UINT64  PageLevelCacheDisable : 1;
        UINT64  Accessed : 1;
        UINT64  Dirty : 1;
        UINT64  PageSize : 1; // It is PageAttribute:1 for 4K page entry
        UINT64  Global : 1;
        UINT64  Ignored_9 : 1;
        UINT64  ExtendedAccessed : 1;
        UINT64  Ignored_11 : 1;
        // NOTE: There is PageAttribute:1 as bit12 for 1G page entry and 2M page entry
        UINT64  AddressLo : 20;
        UINT64  AddressHi : 20;
        UINT64  Ignored_52 : 11;
        UINT64  ExecuteDisable : 1;
    } Bits;
    UINT64    Uint64;
} VTD_FIRST_LEVEL_PAGING_ENTRY;

typedef union {
    struct {
        UINT64  Read : 1;
        UINT64  Write : 1;
        UINT64  Execute : 1;
        UINT64  ExtendedMemoryType : 3;
        UINT64  IgnorePAT : 1;
        UINT64  PageSize : 1;
        UINT64  Ignored_8 : 3;
        UINT64  Snoop : 1;
        UINT64  AddressLo : 20;
        UINT64  AddressHi : 20;
        UINT64  Ignored_52 : 10;
        UINT64  TransientMapping : 1;
        UINT64  Ignored_63 : 1;
    } Bits;
    UINT64    Uint64;
} VTD_SECOND_LEVEL_PAGING_ENTRY;

//
// Register Descriptions
//
#define R_VER_REG        0x00
#define R_CAP_REG        0x08
#define   B_CAP_REG_RWBF       BIT4
#define R_ECAP_REG       0x10
#define R_GCMD_REG       0x18
#define   B_GMCD_REG_QIE       BIT26
#define   B_GMCD_REG_WBF       BIT27
#define   B_GMCD_REG_SRTP      BIT30
#define   B_GMCD_REG_TE        BIT31
#define R_GSTS_REG       0x1C
#define   B_GSTS_REG_WBF       BIT27
#define   B_GSTS_REG_RTPS      BIT30
#define   B_GSTS_REG_TE        BIT31
#define R_RTADDR_REG     0x20
#define R_CCMD_REG       0x28
#define   B_CCMD_REG_CIRG_MASK    (BIT(62)|BIT(61))
#define   V_CCMD_REG_CIRG_GLOBAL  BIT(61)
#define   V_CCMD_REG_CIRG_DOMAIN  BIT(62)
#define   V_CCMD_REG_CIRG_DEVICE  (BIT(62)|BIT(61))
#define   B_CCMD_REG_ICC          BIT(63)
#define R_FSTS_REG       0x34
#define R_FECTL_REG      0x38
#define R_FEDATA_REG     0x3C
#define R_FEADDR_REG     0x40
#define R_FEUADDR_REG    0x44
#define R_AFLOG_REG      0x58

#define R_IVA_REG        0x00 // + IRO
#define   B_IVA_REG_AM_MASK       (BIT0|BIT1|BIT2|BIT3|BIT4|BIT5)
#define   B_IVA_REG_AM_4K         0 // 1 page
#define   B_IVA_REG_AM_2M         9 // 2M page
#define   B_IVA_REG_IH            BIT6
#define R_IOTLB_REG      0x08 // + IRO
#define   B_IOTLB_REG_IIRG_MASK   (BIT(61)|BIT(60))
#define   V_IOTLB_REG_IIRG_GLOBAL BIT(60)
#define   V_IOTLB_REG_IIRG_DOMAIN BIT(61)
#define   V_IOTLB_REG_IIRG_PAGE   (BIT(61)|BIT(60))
#define   B_IOTLB_REG_IVT         BIT(63)
#define   V_IOTLB_REG_DR          BIT(48)
#define   V_IOTLB_REG_DW          BIT(49)

#define R_FRCD_REG       0x00 // + FRO

#define R_PMEN_ENABLE_REG           0x64
#define R_PMEN_LOW_BASE_REG         0x68
#define R_PMEN_LOW_LIMITE_REG       0x6C
#define R_PMEN_HIGH_BASE_REG        0x70
#define R_PMEN_HIGH_LIMITE_REG      0x78
#define R_IQ_HEAD_REG               0x80
#define R_IQ_TAIL_REG               0x88
#define R_IQ_ADDR_REG               0x90

typedef union {
    struct {
        UINT8         ND : 3; // Number of domains supported
        UINT8         AFL : 1; // Advanced Fault Logging
        UINT8         RWBF : 1; // Required Write-Buffer Flushing
        UINT8         PLMR : 1; // Protected Low-Memory Region
        UINT8         PHMR : 1; // Protected High-Memory Region
        UINT8         CM : 1; // Caching Mode

        UINT8         SAGAW : 5; // Supported Adjusted Guest Address Widths
        UINT8         Rsvd_13 : 3;

        UINT8         MGAW : 6; // Maximum Guest Address Width
        UINT8         ZLR : 1; // Zero Length Read
        UINT8         Rsvd_23 : 1;

        UINT16        FRO : 10; // Fault-recording Register offset
        UINT16        SLLPS : 4; // Second Level Large Page Support
        UINT16        Rsvd_38 : 1;
        UINT16        PSI : 1; // Page Selective Invalidation

        UINT8         NFR : 8; // Number of Fault-recording Registers

        UINT8         MAMV : 6; // Maximum Address Mask Value
        UINT8         DWD : 1; // Write Draining
        UINT8         DRD : 1; // Read Draining

        UINT8         FL1GP : 1; // First Level 1-GByte Page Support
        UINT8         Rsvd_57 : 2;
        UINT8         PI : 1; // Posted Interrupts Support
        UINT8         Rsvd_60 : 4;
    } Bits;
    UINT64     Uint64;
} VTD_CAP_REG;

typedef union {
    struct {
        UINT8         C : 1; // Page-walk Coherency
        UINT8         QI : 1; // Queued Invalidation support
        UINT8         DT : 1; // Device-TLB support
        UINT8         IR : 1; // Interrupt Remapping support
        UINT8         EIM : 1; // Extended Interrupt Mode
        UINT8         Rsvd_5 : 1;
        UINT8         PT : 1; // Pass Through
        UINT8         SC : 1; // Snoop Control

        UINT16        IRO : 10; // IOTLB Register Offset
        UINT16        Rsvd_18 : 2;
        UINT16        MHMV : 4; // Maximum Handle Mask Value

        UINT8         ECS : 1; // Extended Context Support
        UINT8         MTS : 1; // Memory Type Support
        UINT8         NEST : 1; // Nested Translation Support
        UINT8         DIS : 1; // Deferred Invalidate Support
        UINT8         PASID : 1; // Process Address Space ID Support
        UINT8         PRS : 1; // Page Request Support
        UINT8         ERS : 1; // Execute Request Support
        UINT8         SRS : 1; // Supervisor Request Support

        UINT32        Rsvd_32 : 1;
        UINT32        NWFS : 1; // No Write Flag Support
        UINT32        EAFS : 1; // Extended Accessed Flag Support
        UINT32        PSS : 5; // PASID Size Supported
        UINT32        Rsvd_40 : 24;
    } Bits;
    UINT64     Uint64;
} VTD_ECAP_REG;

typedef union {
    struct {
        UINT32   Rsvd_0 : 12;
        UINT32   FILo : 20;      // FaultInfo
        UINT32   FIHi : 32;      // FaultInfo

        UINT32   SID : 16;       // Source Identifier
        UINT32   Rsvd_80 : 13;
        UINT32   PRIV : 1;       // Privilege Mode Requested
        UINT32   EXE : 1;        // Execute Permission Requested
        UINT32   PP : 1;         // PASID Present

        UINT32   FR : 8;         // Fault Reason
        UINT32   PV : 20;        // PASID Value
        UINT32   AT : 2;         // Address Type
        UINT32   T : 1;          // Type (0: Write, 1: Read)
        UINT32   F : 1;          // Fault
    } Bits;
    UINT64     Uint64[2];
} VTD_FRCD_REG;

typedef union {
    struct {
        UINT8    Function : 3;
        UINT8    Device : 5;
        UINT8    Bus;
    } Bits;
    struct {
        UINT8    ContextIndex;
        UINT8    RootIndex;
    } Index;
    UINT16     Uint16;
} VTD_SOURCE_ID;

typedef struct _DMAR_TRANSLATIONS
{
    //
    // The root table is only for each hardware unit and made up of 256 entries.
    //
    VTD_ROOT_ENTRY RootTable[256];

    //
    // The context table can be multiple but all root entries set up by this
    // project point to the same, single context table, hence this is not
    // ContextTable[256][256]. This table is made up of 256 entries.
    //
    VTD_CONTEXT_ENTRY ContextTable[256];

    //
    // The second-level PML4 can be multiple but all context entries set up by
    // this projects point to the same, single PML4, This table is made up of
    // 512 entries.
    //
    VTD_SECOND_LEVEL_PAGING_ENTRY SlPml4[512];

    //
    // This project only uses PML4[0], hence only one PDPT is used. PDPT is made
    // up of 512 entries.
    //
    VTD_SECOND_LEVEL_PAGING_ENTRY SlPdpt[1][512];

    //
    // Have PD for each PDPT and each PD is made up of 512 entries; hence [512][512].
    //
    VTD_SECOND_LEVEL_PAGING_ENTRY SlPd[1][512][512];
} DMAR_TRANSLATIONS;

typedef struct _DMAR_TRANSLATIONS_POINTERS
{
    //
    // The root table is only for each hardware unit and made up of 256 entries.
    //
    VTD_ROOT_ENTRY* RootTable;

    //
    // The context table can be multiple but all root entries set up by this
    // project point to the same, single context table, hence this is not
    // ContextTable[256][256]. This table is made up of 256 entries.
    //
    VTD_CONTEXT_ENTRY* ContextTable;

    //
    // The second-level PML4 can be multiple but all context entries set up by
    // this projects point to the same, single PML4, This table is made up of
    // 512 entries.
    //
    VTD_SECOND_LEVEL_PAGING_ENTRY* SlPml4;

    //
    // This project only uses PML4[0], hence only one PDPT is used. PDPT is made
    // up of 512 entries.
    //
    VTD_SECOND_LEVEL_PAGING_ENTRY* SlPdpt;

    //
    // Have PD for each PDPT and each PD is made up of 512 entries; hence [512][512].
    //
    VTD_SECOND_LEVEL_PAGING_ENTRY* SlPd;
} DMAR_TRANSLATIONS_POINTERS;

typedef struct _DMAR_UNIT_INFORMATION
{
    UINT64 RegisterBasePa;
    VTD_CAP_REG Capability;
    VTD_ECAP_REG ExtendedCapability;
    DMAR_TRANSLATIONS* Translations;
    BOOLEAN bEnabled;
} DMAR_UNIT_INFORMATION;

///
/// Definition for DMA Remapping Structure Header
///
typedef struct {
    UINT16    Type;
    UINT16    Length;
} EFI_ACPI_DMAR_STRUCTURE_HEADER;


///
/// Remapping Structure Types definitions from section 8.2
///@{
#define EFI_ACPI_DMAR_TYPE_DRHD  0x00
#define EFI_ACPI_DMAR_TYPE_RMRR  0x01
#define EFI_ACPI_DMAR_TYPE_ATSR  0x02
#define EFI_ACPI_DMAR_TYPE_RHSA  0x03
#define EFI_ACPI_DMAR_TYPE_ANDD  0x04
#define EFI_ACPI_DMAR_TYPE_SATC  0x05
#define EFI_ACPI_DMAR_TYPE_SIDP  0x06
///@}

typedef struct {
    EFI_ACPI_DMAR_STRUCTURE_HEADER    Header;

    /**
      - Bit[0]: INCLUDE_PCI_ALL
                - If Set, this remapping hardware unit has under its scope all
                  PCI compatible devices in the specified Segment, except devices
                  reported under the scope of other remapping hardware units for
                  the same Segment.
                - If Clear, this remapping hardware unit has under its scope only
                  devices in the specified Segment that are explicitly identified
                  through the DeviceScope field.
      - Bits[7:1] Reserved.
    **/
    UINT8     Flags;

    /**
      - Bits[3:0]: Indicates the size of the remapping hardware register set for
                   this remapping unit. If the value in this field is N, the size
                   of the register set is 2^N 4 KB pages
      - Bits[7:4]: Reserved.
    **/
    UINT8     Size;
    ///
    /// The PCI Segment associated with this unit.
    ///
    UINT16    SegmentNumber;
    ///
    /// Base address of remapping hardware register-set for this unit.
    ///
    UINT64    RegisterBaseAddress;
} EFI_ACPI_DMAR_DRHD_HEADER;

//
// 10.4.6 Root Table Address Register
//
typedef union _VTD_ROOT_TABLE_ADDRESS_REGISTER
{
    struct
    {
        UINT64 Reserved_1 : 10;             // [9:0]
        UINT64 TranslationTableMode : 2;    // [11:10]
        UINT64 RootTable : 52;              // [63:12]
    } Bits;
    UINT64 AsUInt64;
} VTD_ROOT_TABLE_ADDRESS_REGISTER;

///
/// Memory Mapped Configuration Space Access Table (MCFG)
/// This table is a basic description table header followed by
/// a number of base address allocation structures.
///
typedef struct {
    UINT64    BaseAddress;
    UINT16    PciSegmentGroupNumber;
    UINT8     StartBusNumber;
    UINT8     EndBusNumber;
    UINT32    Reserved;
} EFI_ACPI_MEMORY_MAPPED_ENHANCED_CONFIGURATION_SPACE_BASE_ADDRESS_ALLOCATION_STRUCTURE;

///
/// MCFG Table header definition.  The rest of the table
/// must be defined in a platform specific manner.
///
typedef struct {
    EFI_ACPI_DESCRIPTION_HEADER    Header;
    UINT64                         Reserved;
} EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER;

/** This typedef is used to shorten the name of the Enhanced
    Configuration Space address structure.
*/
typedef
EFI_ACPI_MEMORY_MAPPED_ENHANCED_CONFIGURATION_SPACE_BASE_ADDRESS_ALLOCATION_STRUCTURE
MCFG_CFG_SPACE_ADDR;

/*
* The number of entries in the table is given by (headers.Header.Length - sizeof(headers)) / sizeof(MCFG_CFG_SPACE_ADDR)
*/
typedef struct {
    EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER headers;
    MCFG_CFG_SPACE_ADDR entry[1];
} MCFG_TABLE, *PMCFG_TABLE;

///
/// MCFG Revision (defined in spec)
///
#define EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_SPACE_ACCESS_TABLE_REVISION  0x01

#define EFI_ACPI_4_0_MEMORY_MAPPED_ENHANCED_CONFIGURATION_SPACE_BASE_ADDRESS_ALLOCATION_SIGNATURE  SIGNATURE_32('M', 'C', 'F', 'G')

#pragma pack()

#define Add2Ptr(Ptr, Value)     ((VOID*)((UINT8*)(Ptr) + (Value)))
#define Int2Chars(Value) (Value), (Value >> 8), (Value >> 16), (Value >> 24)

typedef union _ADDRESS_TRANSLATION_HELPER
{
    //
    // Indexes to locate paging-structure entries corresponds to this virtual
    // address.
    //
    struct
    {
        UINT64 Unused : 12;         //< [11:0]
        UINT64 Pt : 9;              //< [20:12]
        UINT64 Pd : 9;              //< [29:21]
        UINT64 Pdpt : 9;            //< [38:30]
        UINT64 Pml4 : 9;            //< [47:39]
    } AsIndex;
    UINT64 AsUInt64;
} ADDRESS_TRANSLATION_HELPER;

typedef union {
    struct {
        USHORT function : 3;
        USHORT device : 5;
        USHORT bus : 8;
    } bits;

    USHORT Flags;
} ACPI_BDF, *PACPI_BDF;

typedef enum {
    PciDevice,
    PciP2pBridge,
    PciCardBusBridge,
    PciUndefined
} PCI_HEADER_TYPE;

#pragma pack(1)

///
/// Common header region in PCI Configuration Space
/// Section 6.1, PCI Local Bus Specification, 2.2
///
typedef struct {
    UINT16    VendorId;
    UINT16    DeviceId;
    UINT16    Command;
    UINT16    Status;
    UINT8     RevisionID;
    UINT8     ProgInterface;
    UINT8     Subclass;
    UINT8     Class;
    UINT8     CacheLineSize;
    UINT8     LatencyTimer;
    UINT8     HeaderType;
    UINT8     BIST;
} PCI_DEVICE_INDEPENDENT_REGION;

///
/// PCI Device header region in PCI Configuration Space
/// Section 6.1, PCI Local Bus Specification, 2.2
///
typedef struct {
    UINT32    Bar[6];
    UINT32    CISPtr;
    UINT16    SubsystemVendorID;
    UINT16    SubsystemID;
    UINT32    ExpansionRomBar;
    UINT8     CapabilityPtr;
    UINT8     Reserved1[3];
    UINT32    Reserved2;
    UINT8     InterruptLine;
    UINT8     InterruptPin;
    UINT8     MinGnt;
    UINT8     MaxLat;
} PCI_DEVICE_HEADER_TYPE_REGION;

///
/// PCI-PCI Bridge header region in PCI Configuration Space
/// Section 3.2, PCI-PCI Bridge Architecture, Version 1.2
///
typedef struct {
    UINT32    Bar[2];
    UINT8     PrimaryBus;
    UINT8     SecondaryBus;
    UINT8     SubordinateBus;
    UINT8     SecondaryLatencyTimer;
    UINT8     IoBase;
    UINT8     IoLimit;
    UINT16    SecondaryStatus;
    UINT16    MemoryBase;
    UINT16    MemoryLimit;
    UINT16    PrefetchableMemoryBase;
    UINT16    PrefetchableMemoryLimit;
    UINT32    PrefetchableBaseUpper32;
    UINT32    PrefetchableLimitUpper32;
    UINT16    IoBaseUpper16;
    UINT16    IoLimitUpper16;
    UINT8     CapabilityPtr;
    UINT8     Reserved[3];
    UINT32    ExpansionRomBAR;
    UINT8     InterruptLine;
    UINT8     InterruptPin;
    UINT16    BridgeControl;
} PCI_BRIDGE_CONTROL_REGISTER;

///
/// CardBus Controller Configuration Space,
/// Section 4.5.1, PC Card Standard. 8.0
///
typedef struct {
    UINT32    CardBusSocketReg;   ///< Cardbus Socket/ExCA Base
    UINT8     Cap_Ptr;
    UINT8     Reserved;
    UINT16    SecondaryStatus;      ///< Secondary Status
    UINT8     PciBusNumber;         ///< PCI Bus Number
    UINT8     CardBusBusNumber;     ///< CardBus Bus Number
    UINT8     SubordinateBusNumber; ///< Subordinate Bus Number
    UINT8     CardBusLatencyTimer;  ///< CardBus Latency Timer
    UINT32    MemoryBase0;          ///< Memory Base Register 0
    UINT32    MemoryLimit0;         ///< Memory Limit Register 0
    UINT32    MemoryBase1;
    UINT32    MemoryLimit1;
    UINT32    IoBase0;
    UINT32    IoLimit0;           ///< I/O Base Register 0
    UINT32    IoBase1;            ///< I/O Limit Register 0
    UINT32    IoLimit1;
    UINT8     InterruptLine;      ///< Interrupt Line
    UINT8     InterruptPin;       ///< Interrupt Pin
    UINT16    BridgeControl;      ///< Bridge Control
} PCI_CARDBUS_CONTROL_REGISTER;

typedef struct {
    UINT16    SubVendorId; // Subsystem Vendor ID
    UINT16    SubSystemId; // Subsystem ID
    UINT32    LegacyBase;  // Optional 16-Bit PC Card Legacy
    // Mode Base Address
    //
    UINT32    Data[46];
} PCI_CARDBUS_DATA;

typedef union {
    PCI_DEVICE_HEADER_TYPE_REGION    Device;
    PCI_BRIDGE_CONTROL_REGISTER      Bridge;
    PCI_CARDBUS_CONTROL_REGISTER     CardBus;
} NON_COMMON_UNION;

typedef struct alignas(PAGE_SIZE) {
    PCI_DEVICE_INDEPENDENT_REGION    Common;
    NON_COMMON_UNION                 NonCommon;
    UINT32                           Data[48];
} PCI_CONFIG_SPACE, *PPCI_CONFIG_SPACE;

typedef struct _QI_CMD {
    DWORD64 low;
    DWORD64 high;
} QI_CMD, *PQI_CMD;

typedef union _QI_REG {
    struct {
        DWORD64 Reserved0 : 4;
        DWORD64 Offset : 15;
        DWORD64 Reserved1 : 45;
    };
    DWORD64 Flags;
} QI_REG, *PQI_REG;

typedef union _IOTLB_QI_DESC {
    struct {
        DWORD64 is2 : 4;
        DWORD64 G : 2;
        DWORD64 DW : 1;
        DWORD64 DR : 1;
        DWORD64 Reserved0 : 8;
        DWORD64 DID : 16;
        DWORD64 Reserved1 : 32;
    } low;
    struct {
        DWORD64 AM : 5;
        DWORD64 IH : 2;
        DWORD64 Reserved0 : 5;
        DWORD64 ADDR : 52;
    } high;
    QI_CMD Flags;
} IOTLB_QI_DESC, *PIOTLB_QI_DESC;

#define MAX_PCIE_IN_CONFIG_SPACE 0x200
#define SYSTEM_BASE_PERIPHERAL_CLASS 0x8
#define IOMMU_SUBCLASS 0x6

#pragma pack()

namespace acpi {
    class DmarRegister {
        DWORD64 _registerPa;
        volatile PVOID _mappedRegister;
        volatile PVOID _mappedQIRegister;

    public:
        DmarRegister(DWORD64 registerPa);
        ~DmarRegister();

        void SendGlobalCmdSerialized(DWORD64 mask, BOOLEAN bSet);
        void SendContextCmdSerialized(DWORD64 mask);
        void SendQueuedInvalidation(QI_CMD cmd);
        void SetRootTable(PVOID pTable);
        PVOID GetRootTable();
        PVOID GetMappedRegister();
        PVOID GetMappedQIRegister();
        void InvalidateIoTlb(DWORD64 mask);
    };

    class McfgRegister {
        MCFG_TABLE* _mcfgTable;
        DWORD64 _entries;
    public:
        McfgRegister(MCFG_TABLE* table);

        PPCI_CONFIG_SPACE GetPCIeConfigSpace(ACPI_BDF bdf);
        PPCI_CONFIG_SPACE AllPCIeConfigSpace(int index);

        int size();
        MCFG_CFG_SPACE_ADDR& operator [](int index);
    };

    extern EFI_ACPI_DMAR_HEADER* dmarTable;
    extern MCFG_TABLE* mcfgTable;

    bool Init();
}