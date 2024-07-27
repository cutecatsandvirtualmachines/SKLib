#pragma once

#ifdef _KERNEL_MODE

#include "VectorEx.h"
#include <winternlex.h>

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
#define IMAGE_NT_SIGNATURE                  0x00004550  // PE00
#define IMAGE_SIZEOF_SHORT_NAME             8
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA    0x00000080  // Section contains uninitialized data.
#define IMAGE_SCN_MEM_WRITE                 0x80000000
#define UNW_FLAG_EHANDLER  1
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
#define IMAGE_REL_BASED_DIR64                   10
#define IMAGE_DEBUG_TYPE_CODEVIEW   2

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#define RELOC_FLAG RELOC_FLAG64

#define IMAGE_ORDINAL_FLAG64 0x8000000000000000ULL

#define IMAGE_ORDINAL_FLAG32 0x80000000

#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)

#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)

#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)

#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)

#define IMAGE_SNAP_BY_ORDINAL IMAGE_SNAP_BY_ORDINAL64

#define IS_MZ(Base) (*(USHORT*)Base == 'MZ')

/* Section header defines */

#define IMAGE_SCN_TYPE_REG 0x00000000    /* Reserved */

#define IMAGE_SCN_TYPE_DSECT 0x00000001  /* Reserved */

#define IMAGE_SCN_TYPE_NOLOAD 0x00000002 /* Reserved */

#define IMAGE_SCN_TYPE_GROUP 0x00000003  /* Reserved */

#define IMAGE_SCN_TYPE_NO_PAD 0x00000008 /* Obsolete */

#define IMAGE_SCN_TYPE_COPY 0x00000010   /* Reserved */

#define IMAGE_SCN_CNT_CODE 0x00000020

#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040

#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080

#define IMAGE_SCN_LNK_OTHER 0x00000100 /* Reserved */

#define IMAGE_SCN_LNK_INFO 0x00000200

#define IMAGE_SCN_TYPE_OVER 0x00000400 /* Reserved */

#define IMAGE_SCN_LNK_REMOVE 0x00000800

#define IMAGE_SCN_LNK_COMDAT 0x00001000

#define IMAGE_SCN_MEM_FARDATA 0x00008000   /* Reserved */

#define IMAGE_SCN_MEM_PURGEABLE 0x00020000 /* Reserved */

#define IMAGE_SCN_MEM_16BIT 0x00020000     /* Reserved */

#define IMAGE_SCN_MEM_LOCKED 0x00040000    /* Reserved */

#define IMAGE_SCN_MEM_PRELOAD 0x00080000   /* Reserved */

#define IMAGE_SCN_ALIGN_1BYTES 0x00100000

#define IMAGE_SCN_ALIGN_2BYTES 0x00200000

#define IMAGE_SCN_ALIGN_4BYTES 0x00300000

#define IMAGE_SCN_ALIGN_8BYTES 0x00400000

#define IMAGE_SCN_ALIGN_16BYTES 0x00500000

#define IMAGE_SCN_ALIGN_32BYTES 0x00600000

#define IMAGE_SCN_ALIGN_64BYTES 0x00700000

#define IMAGE_SCN_ALIGN_128BYTES 0x00800000

#define IMAGE_SCN_ALIGN_256BYTES 0x00900000

#define IMAGE_SCN_ALIGN_512BYTES 0x00A00000

#define IMAGE_SCN_ALIGN_1024BYTES 0x00B00000

#define IMAGE_SCN_ALIGN_2048BYTES 0x00C00000

#define IMAGE_SCN_ALIGN_4096BYTES 0x00D00000

#define IMAGE_SCN_ALIGN_8192BYTES 0x00E00000

#define IMAGE_SCN_ALIGN_MASK 0x00F00000

#define IMAGE_SCN_LNK_NRELOC_OVFL 0x01000000

#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000

#define IMAGE_SCN_MEM_NOT_CACHED 0x04000000

#define IMAGE_SCN_MEM_NOT_PAGED 0x08000000

#define IMAGE_SCN_MEM_SHARED 0x10000000

#define IMAGE_SCN_MEM_EXECUTE 0x20000000

#define IMAGE_SCN_MEM_READ 0x40000000

#define IMAGE_SCN_MEM_WRITE 0x80000000

typedef struct _IMAGE_BASE_RELOCATION {
    ULONG VirtualAddress;
    ULONG SizeOfBlock;
} IMAGE_BASE_RELOCATION, * PIMAGE_BASE_RELOCATION;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        ULONG   Characteristics;
        ULONG   OriginalFirstThunk;
    } DUMMYUNIONNAME;
    ULONG   TimeDateStamp;
    ULONG   ForwarderChain;
    ULONG   Name;
    ULONG   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR, * PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_IMPORT_BY_NAME {
    USHORT  Hint;
    UCHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, * PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    ULONG Characteristics;
    ULONG TimeDateStamp;
    USHORT MajorVersion;
    USHORT MinorVersion;
    ULONG Name;
    ULONG Base;
    ULONG NumberOfFunctions;
    ULONG NumberOfNames;
    ULONG AddressOfFunctions;
    ULONG AddressOfNames;
    ULONG AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

typedef struct _API_SET_VALUE_ENTRY_10
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_10, * PAPI_SET_VALUE_ENTRY_10;

typedef struct _API_SET_VALUE_ARRAY_10
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG Unk;
    ULONG NameLength;
    ULONG DataOffset;
    ULONG Count;

    inline PAPI_SET_VALUE_ENTRY_10 entry(void* pApiSet, DWORD i)
    {
        return (PAPI_SET_VALUE_ENTRY_10)((BYTE*)pApiSet + DataOffset + i * sizeof(API_SET_VALUE_ENTRY_10));
    }
} API_SET_VALUE_ARRAY_10, * PAPI_SET_VALUE_ARRAY_10;

typedef struct _API_SET_NAMESPACE_ENTRY_10
{
    ULONG Limit;
    ULONG Size;
} API_SET_NAMESPACE_ENTRY_10, * PAPI_SET_NAMESPACE_ENTRY_10;

typedef struct _API_SET_NAMESPACE_ARRAY_10
{
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG Start;
    ULONG End;
    ULONG Unk[2];

    inline PAPI_SET_NAMESPACE_ENTRY_10 entry(DWORD i)
    {
        return (PAPI_SET_NAMESPACE_ENTRY_10)((BYTE*)this + End + i * sizeof(API_SET_NAMESPACE_ENTRY_10));
    }

    inline PAPI_SET_VALUE_ARRAY_10 valArray(PAPI_SET_NAMESPACE_ENTRY_10 pEntry)
    {
        return (PAPI_SET_VALUE_ARRAY_10)((BYTE*)this + Start + sizeof(API_SET_VALUE_ARRAY_10) * pEntry->Size);
    }

    inline ULONG apiName(PAPI_SET_NAMESPACE_ENTRY_10 pEntry, wchar_t* output)
    {
        auto pArray = valArray(pEntry);
        memcpy(output, (char*)this + pArray->NameOffset, pArray->NameLength);
        return  pArray->NameLength;
    }
} API_SET_NAMESPACE_ARRAY_10, * PAPI_SET_NAMESPACE_ARRAY_10;

typedef PAPI_SET_VALUE_ENTRY_10     PAPISET_VALUE_ENTRY;
typedef PAPI_SET_VALUE_ARRAY_10     PAPISET_VALUE_ARRAY;
typedef PAPI_SET_NAMESPACE_ENTRY_10 PAPISET_NAMESPACE_ENTRY;
typedef PAPI_SET_NAMESPACE_ARRAY_10 PAPISET_NAMESPACE_ARRAY;

typedef struct _SCOPE_RECORD {
    UINT32 BeginAddress;
    UINT32 EndAddress;
    UINT32 HandlerAddress;
    UINT32 JumpTarget;
} SCOPE_RECORD;

typedef struct _SCOPE_TABLE {
    UINT32 Count;
    SCOPE_RECORD ScopeRecords[1];
} SCOPE_TABLE;

typedef struct _RUNTIME_FUNCTION {
    UINT32 BeginAddress;
    UINT32 EndAddress;
    UINT32 UnwindData;
} RUNTIME_FUNCTION;

typedef union _UNWIND_CODE {
    UINT8 CodeOffset;
    UINT8 UnwindOp : 4;
    UINT8 OpInfo : 4;
    UINT16 FrameOffset;
} UNWIND_CODE;

typedef struct _UNWIND_INFO {
    UINT8 Version : 3;
    UINT8 Flags : 5;
    UINT8 SizeOfProlog;
    UINT8 CountOfCodes;
    UINT8 FrameRegister : 4;
    UINT8 FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];

    union {
        UINT32 ExceptionHandler;
        UINT32 FunctionEntry;
    };

    UINT32 ExceptionData[1];
} UNWIND_INFO;

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    UINT16   e_magic;                     // Magic number
    UINT16   e_cblp;                      // UINT8s on last page of file
    UINT16   e_cp;                        // Pages in file
    UINT16   e_crlc;                      // Relocations
    UINT16   e_cparhdr;                   // Size of header in paragraphs
    UINT16   e_minalloc;                  // Minimum extra paragraphs needed
    UINT16   e_maxalloc;                  // Maximum extra paragraphs needed
    UINT16   e_ss;                        // Initial (relative) SS value
    UINT16   e_sp;                        // Initial SP value
    UINT16   e_csum;                      // Checksum
    UINT16   e_ip;                        // Initial IP value
    UINT16   e_cs;                        // Initial (relative) CS value
    UINT16   e_lfarlc;                    // File address of relocation table
    UINT16   e_ovno;                      // Overlay number
    UINT16   e_res[4];                    // Reserved words
    UINT16   e_oemid;                     // OEM identifier (for e_oeminfo)
    UINT16   e_oeminfo;                   // OEM information; e_oemid specific
    UINT16   e_res2[10];                  // Reserved words
    UINT32   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    UINT16    Machine;
    UINT16    NumberOfSections;
    UINT32   TimeDateStamp;
    UINT32   PointerToSymbolTable;
    UINT32   NumberOfSymbols;
    UINT16    SizeOfOptionalHeader;
    UINT16    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    UINT32   VirtualAddress;
    UINT32   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    UINT16        Magic;
    UINT8        MajorLinkerVersion;
    UINT8        MinorLinkerVersion;
    UINT32       SizeOfCode;
    UINT32       SizeOfInitializedData;
    UINT32       SizeOfUninitializedData;
    UINT32       AddressOfEntryPoint;
    UINT32       BaseOfCode;
    ULONGLONG   ImageBase;
    UINT32       SectionAlignment;
    UINT32       FileAlignment;
    UINT16        MajorOperatingSystemVersion;
    UINT16        MinorOperatingSystemVersion;
    UINT16        MajorImageVersion;
    UINT16        MinorImageVersion;
    UINT16        MajorSubsystemVersion;
    UINT16        MinorSubsystemVersion;
    UINT32       Win32VersionValue;
    UINT32       SizeOfImage;
    UINT32       SizeOfHeaders;
    UINT32       CheckSum;
    UINT16        Subsystem;
    UINT16        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    UINT16       LoaderFlags;
    UINT32       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    UINT32 Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
    UINT8    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        UINT32   PhysicalAddress;
        UINT32   VirtualSize;
    } Misc;
    UINT32   VirtualAddress;
    UINT32   SizeOfRawData;
    UINT32   PointerToRawData;
    UINT32   PointerToRelocations;
    UINT32   PointerToLinenumbers;
    UINT16    NumberOfRelocations;
    UINT16    NumberOfLinenumbers;
    UINT32   Characteristics;

    bool operator==(_IMAGE_SECTION_HEADER& rhs) {
        return !memcmp(this, &rhs, sizeof(rhs));
    }
    bool operator!=(_IMAGE_SECTION_HEADER& rhs) {
        return !(*this == rhs);
    }
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

typedef IMAGE_NT_HEADERS64                  IMAGE_NT_HEADERS;

typedef struct _IMAGE_DEBUG_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD Type;
    DWORD SizeOfData;
    DWORD AddressOfRawData;
    DWORD PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, * PIMAGE_DEBUG_DIRECTORY;

typedef struct _PDB_INFO
{
    DWORD     Signature;
    GUID      Guid;
    DWORD     Age;
    char      PdbFileName[1];
} PDB_INFO, *PPDB_INFO;

typedef struct _PE_SECURITY_INFO {
    DWORD Length;
    USHORT Revision;
    USHORT Type;
    USHORT Content[1];
} PE_SECURITY_INFO, *PPE_SECURITY_INFO;

class PE {
private:
    PIMAGE_NT_HEADERS64 pNtHeaders;
    DWORD64 szHeader;
    DWORD64 pImageBase;
    vector<IMAGE_SECTION_HEADER> vSections;

public:
	PE(PVOID pImageBase);

    PIMAGE_NT_HEADERS64 ntHeaders();

    DWORD64 imageSize();
    DWORD64 sizeOfCode();
    DWORD64 headerSize();
    DWORD64 entryPoint();
    vector<IMAGE_SECTION_HEADER>& sections();

    PVOID DataDir(ULONG entry);
    char* pdbPath();
    PDB_INFO* pdbInfo();
    void relocate(DWORD64 delta = 0);
    void fixImports(DWORD64 pPeb);
};

namespace pe {
    uintptr_t GetModuleHandle(uintptr_t pPeb, char* pModName);
    uintptr_t GetProcAddress(uintptr_t pPeb, uintptr_t pBase, char* pImport);
}
#endif