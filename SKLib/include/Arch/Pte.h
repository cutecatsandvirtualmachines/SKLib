#pragma once



/*



Tables:
PML5 = Page-Map Level-5.
PML4 = Page-Map Level-4.
PDP  = Page Directory Pointer.
PD   = Page Directory.
PT   = Page Table.

PML5E/PML4E/PDPE/PDE/PTE = Entries in the corresponding tables.

PFN = Page Frame Number (number of a physical page).
PageSize = Size of a page depending on CR4.PSE, PDPE.PS and PDE.PS bits (4Kb, 2Mb, 4Mb or 1Gb).

Each entry contains a 4Kb-based physical PFN of a next level table
except the last translation level that contains a PFN of a physical page.

Physical address of the first level translation table = [CR3.PML5/CR3.PML4/CR3.PDP/CR3.PD depending on the current processor mode] * 4Kb
Physical address of the next translation level table = [Current level table entry].PFN * 4Kb
Physical address translated from a given linear address = [The last table entry].PFN * PageSize + LinearAddress.Offset

FirstLevelTable = CR3.PFN * 4Kb
NextLevelTable = CurrentLevelTableEntry.PFN * 4Kb
PhysAddress = LastLevelTableEntry.PFN * PageSize + LinearAddress.Offset

CPU mode is specified by the EFER.LME and the EFER.LMA bits (Long Mode Enabled and Long Mode Active).

+--------+---------+---------+----------+---------+--------+-----------+------------+----------------------------------------------+
|  Mode  | CR4.PAE | CR4.PSE | CR4.LA57 | PDPE.PS | PDE.PS | Page size | MAXPHYADDR |               Translation chain              |
+--------+---------+---------+----------+---------+--------+-----------+------------+----------------------------------------------+
|  i386  |    0    |    0    |   N/A    |   N/A   |   0    |    4Kb    |   32 bit   | PDE -> PTE -> Phys                           |
+--------+---------+---------+----------+---------+--------+-----------+------------+----------------------------------------------+
|  i386  |    0    |    1    |   N/A    |   N/A   |   0    |    4Kb    |   32 bit   | PDE -> PTE -> Phys                           |
+--------+---------+---------+----------+---------+--------+-----------+------------+----------------------------------------------+
|  i386  |    0    |    1    |   N/A    |   N/A   |   1    |    4Mb    |   40 bit   | PDE -> Phys                                  |
+--------+---------+---------+----------+---------+--------+-----------+------------+----------------------------------------------+
|  i386  |    1    | Ignored |   N/A    |   N/A   |   0    |    4Kb    |   52 bit   | PDPE -> PDE -> PTE -> Phys                   |
+--------+---------+---------+----------+---------+--------+-----------+------------+----------------------------------------------+
|  i386  |    1    | Ignored |   N/A    |   N/A   |   1    |    2Mb    |   52 bit   | PDPE -> PDE -> Phys                          |
+--------+---------+---------+----------+---------+--------+-----------+------------+----------------------------------------------+
| amd64  | Always1 | Ignored |    0     |    0    |   0    |    4Kb    |   52 bit   | PML4E -> PDPE -> PDE -> PTE -> Phys          |
+--------+---------+---------+----------+---------+--------+-----------+------------+----------------------------------------------+
| amd64  | Always1 | Ignored |    0     |    0    |   1    |    2Mb    |   52 bit   | PML4E -> PDPE -> PDE -> Phys                 |
+--------+---------+---------+----------+---------+--------+-----------+------------+----------------------------------------------+
| amd64  | Always1 | Ignored |    0     |    1    |  N/A   |    1Gb    |   52 bit   | PML4E -> PDPE -> Phys                        |
+--------+---------+---------+----------+---------+--------+-----------+------------+----------------------------------------------+
| amd64  | Always1 | Ignored |    1     |    0    |   0    |    4Kb    |   52 bit   | PML5E -> PML4E -> PDPE -> PDE -> PTE -> Phys |
+--------+---------+---------+----------+---------+--------+-----------+------------+----------------------------------------------+
| amd64  | Always1 | Ignored |    1     |    0    |   1    |    2Mb    |   52 bit   | PML5E -> PML4E -> PDPE -> PDE -> Phys        |
+--------+---------+---------+----------+---------+--------+-----------+------------+----------------------------------------------+
| amd64  | Always1 | Ignored |    1     |    1    |  N/A   |    1Gb    |   52 bit   | PML5E -> PML4E -> PDPE -> Phys               |
+--------+---------+---------+----------+---------+--------+-----------+------------+----------------------------------------------+

Linear address is interpreted differently depending on a CPU mode specified by EFER.LMA and CR4.[PAE/PSE/LA57]
and depending on a PageSize bit in PDPE/PDE entries belonging to the linear address.

The exact form of a linear address determines size of page tables.


Pseudocode describing translation principles:

if (EFER.LME && EFER.LMA) // Is long mode enabled and active?
{
    // It's a long mode (AMD64):

    PML4 = {}; // Depends on paging type (4-Level or 5-Level)

    if (CR4.LA57) // Is 5-level paging enabled?
    {
        // 5-level paging:
        PML5 = CR3.PML5_PFN * 4Kb;
        PML5E = PML5[LinearAddress.PML5_INDEX];

        PML4 = PML5E.PML4_PFN * 4Kb;
    }
    else
    {
        // 4-level paging:
        PML4 = CR3.PML4_PFN * 4Kb;
    }

    PML4E = PML4[LinearAddress.PML4_INDEX];

    PDP = PML4E.PDP_PFN * 4Kb;
    PDPE = PDP[LinearAddress.PDP_INDEX]

    if (PDPE.PS)
    {
        // PML4E -> PDPE -> PA
        PageSize = 1 Gbyte;
        PhysAddr = PDPE.PFN * PageSize + LinearAddress.OffsetInPage;
    }
    else
    {
        PD = PDPE.PD_PFN * 4Kb;
        PDE = PD[LinearAddress.PD_INDEX];

        if (PDE.PS)
        {
            // PML4E -> PDPE -> PDE -> PA
            PageSize = 2 Mbyte;
            PhysAddr = PDE.PFN * PageSize + LinearAddress.OffsetInPage;
        }
        else
        {
            // PML4E -> PDPE -> PDE -> PTE -> PA
            PT = PDE.PT_PFN * 4Kb;
            PTE = PT[LinearAddress.PT_INDEX];

            PageSize = 4 Kbyte;
            PhysAddr = PTE.PFN * PageSize + LinearAddress.OffsetInPage;
        }
    }
}
else
{
    // It's a legacy mode (i386):

    if (CR4.PAE)
    {
        // CR4.PSE is ignored in PAE mode.

        PDP = CR3.PDP_PFN * 4Kb;
        PDPE = PDP[LinearAddress.PDP_INDEX];

        PD = PDPE.PD_PFN * 4Kb;
        PDE = PD[LinearAddress.PD_INDEX];

        if (PDE.PS)
        {
            // PDPE -> PDE -> PA
            PageSize = 2 Mbyte;
            PhysAddr = PDE.PFN * PageSize + LinearAddress.OffsetInPage;
        }
        else
        {
            // PDPE -> PDE -> PTE -> PA

            PT = PDE.PT_PFN * 4Kb;
            PTE = PT[LinearAddress.PT_INDEX];

            PageSize = 4 Kbyte;
            PhysAddr = PTE.PFN * PageSize + LinearAddress.OffsetInPage;
        }
    }
    else
    {
        // Non-PAE mode:

        if (CR4.PSE) // Whether Page Size Extensions are enabled?
        {
            PD = CR3.PD_PFN * 4Kb;
            PDE = PD[LinearAddress.PD_INDEX];

            if (PDE.PS)
            {
                // PDE -> PA
                PageSize = 4 Mbyte;
                PhysAddr = PDE.PFN * PageSize + LinerAddress.OffsetInPage;
            }
            else
            {
                // PDE -> PTE -> PA
                
                PT = PDE.PT_PFN * 4Kb;
                PTE = PT[LinearAddress.PT_INDEX];
                
                PageSize = 4 Kbyte;
                PhysAddr = PTE.PFN * PageSize + LinearAddress.OffsetInPage;
            }
        }
        else
        {
            // PDE -> PTE -> PA
            // PDE.PS is ignored if Page Size Extentsions are disabled.

            PD = CR3.PD_PFN * 4Kb;
            PDE = PD[LinearAddress.PD_INDEX];

            PT = PTE.PT_PFN * 4Kb;
            PTE = PT[LinearAddress.PT_INDEX];

            PageSize = 4 Kbyte;
            PhysAddr = PTE.PFN * PageSize + LinearAddress.OffsetInPage;
        }
    }
}



Legacy mode, 4Kb pages:
EFER.LMA == 0
CR4.PAE  == 0
CR4.PSE  == 0

   Linear address:
   +----------+----------+----------------+
   | PD Index | PT Index | Offset in page |
   +--+-------+-----+----+---------+------+
      |             |              |
      |   PD Table  |              |
CR3 -----> +-----+  |              |
      |    | PDE |  |              |
      |    +-----+  |              +--------------------+
      |    | PDE |  |                                   |
      |    +-----+  | Page Table                        |
      +--> | PDE | ---> +-----+                         |
           +-----+  |   | PTE |                         |
           |     |  |   +-----+                         V
          ...   ... +-> | PTE | -> (PFN * PageSize) + Offset = PhysicalAddress
                        +-----+             [4Kb]
                        |     |
                       ...   ...



Legacy mode, PSE, 4Kb pages:
EFER.LMA == 0
CR4.PAE  == 0
CR4.PSE  == 1
PDE.PS   == 0

   Linear address:
   +----------+----------+----------------+
   | PD Index | PT Index | Offset in page |
   +--+-------+-----+----+---------+------+
      |             |              |
      |   PD Table  |              |
CR3 -----> +-----+  |              |
      |    | PDE |  |              |
      |    +-----+  |              +--------------------+
      |    | PDE |  |                                   |
      |    +-----+  | Page Table                        |
      +--> | PDE | ---> +-----+                         |
         / +-----+  |   | PTE |                         |
        /  |     |  |   +-----+                         V
       /  ...   ... +-> | PTE | -> (PFN * PageSize) + Offset = PhysicalAddress
      /                 +-----+             [4Kb]
 PDE.PS == 0            |     |
                       ...   ...


Legacy mode, PSE, large (4Mb) pages:
EFER.LMA == 0
CR4.PAE  == 0
CR4.PSE  == 1
PDE.PS   == 1

   Linear address:
   +----------+---------------------------+
   | PD Index |       Offset in page      |
   +--+-------+--------------------+------+
      |                            |
      |   PD Table                 |
CR3 -----> +-----+                 |
      |    | PDE |                 |
      |    +-----+                 +-------+
      |    | PDE |                         |
      |    +-----+                         V
      +--> | PDE | -> (PFN * PageSize) + Offset = PhysicalAddress
         / +-----+             [4Mb]
        /  |     |
       /  ...   ...
      /           
 PDE.PS == 1
                  


Legacy mode, PAE, 4Kb pages:
EFER.LMA == 0
CR4.PAE  == 1
PDE.PS   == 0

   Linear address:
   +------------+----------+----------+----------------+
   | PDPE Index | PD Index | PT Index | Offset in page |
   +-+----------+----+-----+------+---+----------+-----+
     |               |            |              |
     |  PDP Table    |  PD Table  |              |
CR3 ---> +------+  +---> +-----+  |              |
     |   | PDPE |  | |   | PDE |  |              |
     |   +------+  | |   +-----+  |              +--------------------+
     +-> | PDPE | -+ |   | PDE |  |                                   |
         +------+    |   +-----+  | Page Table                        |
         |      |    +-> | PDE | ---> +-----+                         |
        ...    ...     / +-----+  |   | PTE |                         |
                      /  |     |  |   +-----+                         V
                     /  ...   ... +-> | PTE | -> (PFN * PageSize) + Offset = PhysicalAddress
                    /                 +-----+             [4Kb]
               PDE.PS == 0            |     |
                                     ...   ...
        
        

Legacy mode, PAE, large (2Mb) pages:
EFER.LMA == 0
CR4.PAE  == 1
PDE.PS   == 1

   Linear address:
   +------------+----------+---------------------------+
   | PDPE Index | PD Index |       Offset in page      |
   +-+----------+----+-----+---------------------+-----+
     |               |                           |
     |  PDP Table    |  PD Table                 |
CR3 ---> +------+  +---> +-----+                 |
     |   | PDPE |  | |   | PDE |                 +-------+
     |   +------+  | |   +-----+                         |
     +-> | PDPE | -+ |   | PDE |                         |
         +------+    |   +-----+                         V
         |      |    +-> | PDE | -> (PFN * PageSize) + Offset = PhysicalAddress
        ...    ...     / +-----+ 
                      /  |     | 
                     /  ...   ...
                    /            
               PDE.PS == 1       
                                 


Long mode, 4-Level paging, 4Kb pages:
EFER.LMA == 1
CR4.LA57 == 0
PDPE.PS  == 0
PDE.PS   == 0

   Linear address:
   +------------+-----------+----------+----------+----------------+
   | PML4 Index | PDP Index | PD Index | PT Index | Offset in page |
   +-+----------+-----+-----+-------+--+-----+----+---------+------+
     |                |             |        |              |
     |    PML4 Table  |             |        |              +-------+
CR3 -----> +-------+  |             |        |                      |
     |     | PML4E |  |             |        +---+      Page Table  |
     |     +-------+  |  PDP Table  |            |  +--> +-----+    |
     +---> | PML4E | ---> +------+  |            |  |    | PTE |    |
           +-------+  |   | PDPE |  |            |  |    +-----+    +--------------------+
           | PML4E |  |   +------+  |   PD Table |  |    | PTE |                         |
           +-------+  +-> | PDPE | ---> +-----+  |  |    +-----+                         V
           |       |    / +------+  |   | PDE |  +--|--> | PTE | -> (PFN * PageSize) + Offset = Physical Address
          ...     ...  /  |      |  |   +-----+     |    +-----+             [4Kb]
                      /  ...    ... |   | PDE |     |    |     |
                     /              |   +-----+     |   ...   ...
              PDPE.PS == 0          +-> | PDE | ----+
                                      / +-----+
                                     /  |     |
                                    /  ...   ...
                                   /
                             PDE.PS == 0



Long mode, 4-Level paging, large (2Mb) pages:
EFER.LMA == 1
CR4.LA57 == 0
PDPE.PS  == 0
PDE.PS   == 1

   Linear address:
   +------------+-----------+----------+------------------------+
   | PML4 Index | PDP Index | PD Index |     Offset in page     |
   +-+----------+-----+-----+-------+--+---------------------+--+
     |                |             |                        |
     |    PML4 Table  |             |                        |
CR3 -----> +-------+  |             |                        |
     |     | PML4E |  |             |                        |
     |     +-------+  |  PDP Table  |                        |
     +---> | PML4E | ---> +------+  |                        |
           +-------+  |   | PDPE |  |                        +----------+
           | PML4E |  |   +------+  |   PD Table                        |
           +-------+  +-> | PDPE | ---> +-----+                         |
           |       |    / +------+  |   | PDE |                         |
          ...     ...  /  |      |  |   +-----+                         |
                      /  ...    ... |   | PDE |                         |
                     /              |   +-----+                         V
                    /               +-> | PDE | -> (PFN * PageSize) + Offset = Physical Address
              PDPE.PS == 0            / +-----+             [2Mb]
                                     /  |     |
                                    /  ...   ...
                                   /
                             PDE.PS == 1



Long mode, 4-Level paging, huge (1Gb) pages:
EFER.LMA == 1
CR4.LA57 == 0
PDPE.PS  == 1

   Linear address:
   +------------+-----------+-----------------------------------+
   | PML4 Index | PDP Index |           Offset in page          |
   +-+----------+-----+-----+------------------------------+----+
     |                |                                    |
     |    PML4 Table  |                                    |
CR3 -----> +-------+  |                                    |
     |     | PML4E |  |                                    |
     |     +-------+  |  PDP Table                         |
     +---> | PML4E | ---> +------+                         |
           +-------+  |   | PDPE |                         |
           | PML4E |  |   +------+                         V
           +-------+  +-> | PDPE | -> (PFN * PageSize) + Offset = Physical Address
           |       |    / +------+            [1Gb]
          ...     ...  /  |      |
                      /  ...    ...
                     /
               PDPE.PS == 1



Long mode, 5-Level paging:
EFER.LMA == 1
CR4.LA57 == 1
PDPE.PS  == The same variants as in 4-Level paging
PDE.PS   == The same variants as in 4-Level paging

   Linear address:
   +------------+------------+-----------+----------+----------+----------------+
   | PML5 Index | PML4 Index | PDP Index | PD Index | PT Index | Offset in page |
   +------------+-----+------+--------+--+--------+-+--------+-+-----------+----+
     |                |               |           |          |             |
     |    PML5 Table  |              ...         ...        ...           ...
CR3 -----> +-------+  |
     |     | PML5E |  |
     |     +-------+  |  PML4 Table
     +---> | PML5E | ---> +-------+
           +-------+  |   | PML4E |
           | PML5E |  |   +-------+
           +-------+  +-> | PML4E | -> ...The same variants as in 4-Level paging...
           |       |      +-------+
          ...     ...     |       |
                         ...     ...



*/



#pragma pack(push, 1)

namespace Pte
{



//
// 5-Level paging is available starting with Intel Ice Lake (10th Gen) and AMD EPYC 7xxx "Genoa" (Zen 4).
//
enum class Mode
{
    legacyNonPae,   // i386 (EFER.LMA == 0, CR4.PAE == 0, CR4.PSE is meaningful)
    legacyPae,      // i386 with Physical Address Extension (EFER.LMA == 0, CR4.PAE == 1, CR4.PSE is ignored)
    longMode4Level, // amd64 with 4-Level paging (EFER.LMA == 1, CR4.PAE is always 1, CR4.LA57 = 0, CR4.PSE is ignored)
    longMode5Level, // amd64 with 5-Level paging (EFER.LMA == 1, CR4.PAE is always 1, CR4.LA57 = 1, CR4.PSE is ignored)
};

enum class PageSize
{
    generic,
    nonPse,
    pse
};



struct PhysicalAddress
{
    unsigned long long physicalAddress{};
};

template <typename Type>
struct PhysicalLayout : public PhysicalAddress
{
    using Layout = Type;
};



template <Mode mode>
union LinearAddress;

template <>
union LinearAddress<Mode::legacyNonPae> // CR4.PAE == 0
{
    unsigned int raw{};

    struct
    {
        unsigned int : 22; // Depends on page size
        unsigned int PageDirectoryOffset : 10;
    } generic;

    union
    {
        struct
        {
            unsigned int PageOffset : 12; // Offset into the physical page
            unsigned int PageTableOffset : 10; // Index into the 1024-entry page-table
            unsigned int PageDirectoryOffset : 10; // Index into the 1024-entry Page-Directory Table
        } page4Kb;
    } pdeNonPageSize; // PDE.PS == 0

    union
    {
        struct
        {
            unsigned int PageOffset : 22; // Offset into the physical page
            unsigned int PageDirectoryOffset : 10; // Index into the 1024-entry Page-Directory Table
        } page4Mb;
    } pdePageSize; // PDE.PS == 1
};
static_assert(sizeof(LinearAddress<Mode::legacyNonPae>) == sizeof(unsigned int));

template <>
union LinearAddress<Mode::legacyPae> // CR4.PAE == 1
{
    unsigned int raw{};

    struct
    {
        unsigned int : 21; // Depends on page size
        unsigned int PageDirectoryOffset : 9;
        unsigned int PageDirectoryPointerOffset : 2;
    } generic;

    union
    {
        struct
        {
            unsigned int PageOffset : 12; // Byte offset into the physical page
            unsigned int PageTableOffset : 9; // Index into the 512-entry Page Table
            unsigned int PageDirectoryOffset : 9; // Index into the 512-entry Page-Directory Table
            unsigned int PageDirectoryPointerOffset : 2; // Index into a 4-entry Page-Directory Pointer table
        } page4Kb;
    } pdeNonPageSize; // PDE.PS == 0

    union
    {
        struct
        {
            unsigned int PageOffset : 21; // Byte offset into the physical page
            unsigned int PageDirectoryOffset : 9; // Index into the 512-entry Page-Directory Table
            unsigned int PageDirectoryPointerOffset : 2; // Index into a 4-entry Page-Directory Pointer table
        } page2Mb;
    } pdePageSize; // PDE.PS == 1
};
static_assert(sizeof(LinearAddress<Mode::legacyPae>) == sizeof(unsigned int));

template <>
union LinearAddress<Mode::longMode4Level>
{
    unsigned long long raw{};

    struct
    {
        unsigned long long : 30; // Depends on page size
        unsigned long long PageDirectoryPointerOffset : 9;
        unsigned long long PageMapLevel4Offset : 9;
        unsigned long long SignExtend : 16;
    } generic;

    union
    {
        struct
        {
            unsigned long long : 21; // Depends on page size
            unsigned long long PageDirectoryOffset : 9;
            unsigned long long PageDirectoryPointerOffset : 9;
            unsigned long long PageMapLevel4Offset : 9;
            unsigned long long SignExtend : 16;
        } generic; // To determine whether the page size is 4Kb or 2Mb

        union
        {
            struct
            {
                unsigned long long PageOffset : 12; // Byte offset into the physical page
                unsigned long long PageTableOffset : 9; // Index into the 512-entry Page Table
                unsigned long long PageDirectoryOffset : 9; // Index into the 512-entry Page-Directory Table
                unsigned long long PageDirectoryPointerOffset : 9; // Index into the 512-entry Page-Directory Pointer table
                unsigned long long PageMapLevel4Offset : 9; // Index into the 512-entry Page-Map Level-4 table
                unsigned long long SignExtend : 16;
            } page4Kb;
        } pdeNonPageSize; // PDE.PS == 0

        union
        {
            struct
            {
                unsigned long long PageOffset : 21; // Byte offset into the physical page
                unsigned long long PageDirectoryOffset : 9; // Index into the 512-entry Page-Directory Table
                unsigned long long PageDirectoryPointerOffset : 9; // Index into the 512-entry Page-Directory Pointer table
                unsigned long long PageMapLevel4Offset : 9; // Index into the 512-entry Page-Map Level-4 table
                unsigned long long SignExtend : 16;
            } page2Mb;
        } pdePageSize; // PDE.PS == 1
    } pdpeNonPageSize; // PDPE.PS == 0

    union
    {
        struct
        {
            unsigned long long PageOffset : 30; // Byte offset into the physical page
            unsigned long long PageDirectoryPointerOffset : 9; // Index into the 512-entry Page-Directory Pointer table
            unsigned long long PageMapLevel4Offset : 9; // Index into the 512-entry Page-Map Level-4 table
            unsigned long long SignExtend : 16;
        } page1Gb;
    } pdpePageSize; // PDPE.PS == 1
};
static_assert(sizeof(LinearAddress<Mode::longMode4Level>) == sizeof(unsigned long long));

template <>
union LinearAddress<Mode::longMode5Level>
{
    unsigned long long raw{};

    struct
    {
        unsigned long long : 30; // Depends on page size
        unsigned long long PageDirectoryPointerOffset : 9; // Index into the 512-entry Page-Directory Pointer table
        unsigned long long PageMapLevel4Offset : 9; // Index into the 512-entry Page-Map Level-4 table
        unsigned long long PageMapLevel5Offset : 9; // Index into the 512-entry Page-Map Level-5 table
        unsigned long long SignExtend : 7;
    } generic;

    union
    {
        struct
        {
            unsigned long long : 21; // Depends on page size
            unsigned long long PageDirectoryOffset : 9;
            unsigned long long PageDirectoryPointerOffset : 9;
            unsigned long long PageMapLevel4Offset : 9;
            unsigned long long PageMapLevel5Offset : 9;
            unsigned long long SignExtend : 7;
        } generic; // To determine whether the page size is 4Kb or 2Mb

        union
        {
            struct
            {
                unsigned long long PageOffset : 12; // Byte offset into the physical page
                unsigned long long PageTableOffset : 9; // Index into the 512-entry Page Table
                unsigned long long PageDirectoryOffset : 9; // Index into the 512-entry Page-Directory Table
                unsigned long long PageDirectoryPointerOffset : 9; // Index into the 512-entry Page-Directory Pointer table
                unsigned long long PageMapLevel4Offset : 9; // Index into the 512-entry Page-Map Level-4 table
                unsigned long long PageMapLevel5Offset : 9; // Index into the 512-entry Page-Map Level-5 table
                unsigned long long SignExtend : 7;
            } page4Kb;
        } pdeNonPageSize; // PDE.PS == 0

        union
        {
            struct
            {
                unsigned long long PageOffset : 21; // Byte offset into the physical page
                unsigned long long PageDirectoryOffset : 9; // Index into the 512-entry Page-Directory Table
                unsigned long long PageDirectoryPointerOffset : 9; // Index into the 512-entry Page-Directory Pointer table
                unsigned long long PageMapLevel4Offset : 9; // Index into the 512-entry Page-Map Level-4 table
                unsigned long long PageMapLevel5Offset : 9; // Index into the 512-entry Page-Map Level-5 table
                unsigned long long SignExtend : 7;
            } page2Mb;
        } pdePageSize; // PDE.PS == 1
    } pdpeNonPageSize; // PDPE.PS == 0

    union
    {
        struct
        {
            unsigned long long PageOffset : 30; // Byte offset into the physical page
            unsigned long long PageDirectoryPointerOffset : 9; // Index into the 512-entry Page-Directory Pointer table
            unsigned long long PageMapLevel4Offset : 9; // Index into the 512-entry Page-Map Level-4 table
            unsigned long long PageMapLevel5Offset : 9; // Index into the 512-entry Page-Map Level-5 table
            unsigned long long SignExtend : 7;
        } page1Gb;
    } pdpePageSize; // PDPE.PS == 1
};
static_assert(sizeof(LinearAddress<Mode::longMode5Level>) == sizeof(unsigned long long));



// Page frame number:
template <Mode mode>
struct Pfn;

template <>
struct Pfn<Mode::legacyNonPae>
{
    static constexpr unsigned int toPage(const unsigned int pfn) noexcept
    {
        return pfn << 12u; // 1 << 12 == 4096 (0x1000, 4Kb)
    }

    static constexpr unsigned int toLarge(const unsigned int pfn) noexcept
    {
        return pfn << 22u; // 1 << 22 == 4'194'304 (0x400'000, 4Mb)
    }
};

template <>
struct Pfn<Mode::legacyPae>
{
    static constexpr unsigned int toPage(const unsigned int pfn) noexcept
    {
        return pfn << 12u; // 1 << 12 == 4096 (0x1000, 4Kb)
    }

    static constexpr unsigned int toLarge(const unsigned int pfn) noexcept
    {
        return pfn << 21u; // 1 << 21 == 2'097'152 (0x200'000, 2Mb)
    }
};

template <>
struct Pfn<Mode::longMode4Level>
{
    static constexpr unsigned long long toPage(const unsigned long long pfn) noexcept
    {
        return pfn << 12ull; // 1 << 12 == 4096 (0x1000, 4Kb)
    }

    static constexpr unsigned long long toLarge(const unsigned long long pfn) noexcept
    {
        return pfn << 21ull; // 1 << 21 == 2'097'152 (0x20'0000, 2Mb)
    }

    static constexpr unsigned long long toHuge(const unsigned long long pfn) noexcept
    {
        return pfn << 30ull; // 1 << 30 == 1'073'741'824 (0x4000'0000, 1Gb)
    }
};

template <>
struct Pfn<Mode::longMode5Level>
{
    static constexpr unsigned long long toPage(const unsigned long long pfn) noexcept
    {
        return pfn << 12ull; // 1 << 12 == 4096 (0x1000, 4Kb)
    }

    static constexpr unsigned long long toLarge(const unsigned long long pfn) noexcept
    {
        return pfn << 21ull; // 1 << 21 == 2'097'152 (0x20'0000, 2Mb)
    }

    static constexpr unsigned long long toHuge(const unsigned long long pfn) noexcept
    {
        return pfn << 30ull; // 1 << 30 == 1'073'741'824 (0x4000'0000, 1Gb)
    }
};



template <Mode mode>
struct Tables;

template <>
struct Tables<Mode::legacyNonPae>
{
    static constexpr Mode k_mode = Mode::legacyNonPae;
    static constexpr auto k_entrySize = sizeof(unsigned int);
    using LinearAddress = LinearAddress<k_mode>;
    using Pfn = Pfn<k_mode>;

    template <PageSize pageSize>
    union Pde;

    //
    // Describes 4Mb in 1024x4Kb pages: PDE(PS=0) -> PTE -> PA (4Kb)
    //
    template <>
    union Pde<PageSize::nonPse>
    {
        //
        // Describes 4Kb page: PDE -> PTE -> PA (4Kb)
        //
        union Pte
        {
            unsigned int raw;
            struct
            {
                unsigned int P : 1; // Present
                unsigned int RW : 1; // Read/Write
                unsigned int US : 1; // User/Supervisor
                unsigned int PWT : 1; // Page-Level Writethrough
                unsigned int PCD : 1; // Page-Level Cache Disable
                unsigned int A : 1; // Accessed
                unsigned int D : 1; // Dirty
                unsigned int PAT : 1; // Page-Attribute Table
                unsigned int G : 1; // Global Page
                unsigned int AVL : 3; // Available to software
                unsigned int PhysicalPageFrameNumber : 20;
            } page4Kb;

            constexpr PhysicalAddress physicalPageBase() const noexcept
            {
                return PhysicalAddress{ Pfn::toPage(this->page4Kb.PhysicalPageFrameNumber) };
            }

            constexpr PhysicalAddress physicalAddress(const LinearAddress& linear) const noexcept
            {
                return PhysicalAddress{ this->physicalPageBase().physicalAddress + linear.pdeNonPageSize.page4Kb.PageOffset };
            }
        };

        //
        // Describes 4Mb of linear address space.
        //
        using Pt = Pte[1024];

        unsigned int raw{};
        struct
        {
            unsigned int P : 1; // Present
            unsigned int RW : 1; // Read/Write
            unsigned int US : 1; // User/Supervisor
            unsigned int PWT : 1; // Page-Level Writethrough
            unsigned int PCD : 1; // Page-Level Cache Disable
            unsigned int A : 1; // Accessed
            unsigned int Ignored0 : 1;
            unsigned int PS : 1; // PageSize == 0
            unsigned int Ignored1 : 1;
            unsigned int AVL : 3; // Available to software
            unsigned int PT : 20; // Page frame number
        } layout;

        constexpr PhysicalLayout<Pt> pt() const noexcept
        {
            return PhysicalLayout<Pt>{ Pfn::toPage(this->layout.PT) };
        }

        constexpr PhysicalLayout<Pte> pte(const LinearAddress& linear) const noexcept
        {
            return PhysicalLayout<Pte>{ this->pt().physicalAddress + linear.pdeNonPageSize.page4Kb.PageTableOffset * k_entrySize };
        }
    };
    static_assert(sizeof(Pde<PageSize::nonPse>) == sizeof(unsigned int));

    //
    // Describes 4Mb page itself: PDE(PS=1) -> PA (4Mb)
    //
    template <>
    union Pde<PageSize::pse>
    {
        unsigned int raw;
        struct
        {
            unsigned int P : 1; // Present
            unsigned int RW : 1; // Read/Write
            unsigned int US : 1; // User/Supervisor
            unsigned int PWT : 1; // Page-Level Writethrough
            unsigned int PCD : 1; // Page-Level Cache Disable
            unsigned int A : 1; // Accessed
            unsigned int D : 1; // Dirty
            unsigned int PS : 1; // PageSize == 1
            unsigned int G : 1; // Global Page
            unsigned int AVL : 3; // Available to software
            unsigned int PAT : 1; // Page-Attribute Table
            unsigned int PhysicalPageFrameNumberHigh : 8;
            unsigned int : 1;
            unsigned int PhysicalPageFrameNumberLow : 10;
        } page4Mb;

        constexpr PhysicalAddress physicalPageBase() const noexcept
        {
            return PhysicalAddress{ Pfn::toLarge((this->page4Mb.PhysicalPageFrameNumberHigh << 10) | this->page4Mb.PhysicalPageFrameNumberLow) };
        }

        constexpr PhysicalAddress physicalAddress(const LinearAddress& linear) const noexcept
        {
            return PhysicalAddress{ this->physicalPageBase().physicalAddress + linear.pdePageSize.page4Mb.PageOffset };
        }
    };
    static_assert(sizeof(Pde<PageSize::pse>) == sizeof(unsigned int));

    //
    // Describes 4 Mb in the following ways:
    //   4Mb page itself  | PDE(PS=1) -> PA (4Mb)
    //   1024x4Kb pages   | PDE(PS=0) -> PTE -> PA (4Kb)
    //
    template <>
    union Pde<PageSize::generic>
    {
        unsigned int raw;
        struct
        {
            unsigned int P : 1; // Present
            unsigned int RW : 1; // Read/Write
            unsigned int US : 1; // User/Supervisor
            unsigned int PWT : 1; // Page-Level Writethrough
            unsigned int PCD : 1; // Page-Level Cache Disable
            unsigned int A : 1; // Accessed
            unsigned int : 1;
            unsigned int PS : 1; // PageSize bit
            unsigned int : 1;
            unsigned int AVL : 3; // Available to software
            unsigned int : 20;
        } layout;

        Pde<PageSize::nonPse> nonPse;
        Pde<PageSize::pse> pse;

        constexpr PageSize pageSize() const noexcept
        {
            return this->layout.PS
                ? PageSize::pse
                : PageSize::nonPse;
        }
    };
    static_assert(sizeof(Pde<PageSize::generic>) == sizeof(unsigned int));

    using PdeGeneric = Pde<PageSize::generic>;
    using PdeNonPse = Pde<PageSize::nonPse>;
    using PdePse = Pde<PageSize::pse>;

    //
    // Describes 4 Gb of linear address space.
    //
    using Pd = PdeGeneric[1024];

    static constexpr PhysicalLayout<Pd> pd(const unsigned int cr3Pfn) noexcept
    {
        return PhysicalLayout<Pd>{ Pfn::toPage(cr3Pfn) };
    }

    static constexpr PhysicalLayout<PdeGeneric> pde(const unsigned int cr3Pfn, const LinearAddress& linear) noexcept
    {
        return PhysicalLayout<PdeGeneric>{ pd(cr3Pfn).physicalAddress + linear.generic.PageDirectoryOffset * k_entrySize };
    }
};

template <>
struct Tables<Mode::legacyPae> // EFER.LMA == 0, CR4.PAE == 1, CR4.PSE is ignored
{
    static constexpr Mode k_mode = Mode::legacyPae;
    static constexpr auto k_entrySize = sizeof(unsigned long long);
    using LinearAddress = LinearAddress<k_mode>;
    using Pfn = Pfn<k_mode>;

    //
    // Describes 1 Gb in one of the following ways:
    //   512x2Mb pages        | PDPE -> PDE(PS=1) -> PA (2Mb)
    //   512x[512x4Kb] pages  | PDPE -> PDE(PS=0) -> PA (4Kb)
    //
    union Pdpe
    {
        unsigned long long raw;
        struct
        {
            unsigned long long P : 1; // Present
            unsigned long long : 2;
            unsigned long long PWT : 1; // Page-Level Writethrough
            unsigned long long PCD : 1; // Page-Level Cache Disable
            unsigned long long : 4;
            unsigned long long AVL : 3; // Available to software
            unsigned long long PD : 40; // Page frame number
            unsigned long long : 12;
        } layout;

        template <PageSize pageSize>
        union Pde;

        //
        // Describes 2 Mb in 512x4Kb pages: PDPE -> PDE(PS=0) -> PTE -> PA (2Mb)
        //
        template <>
        union Pde<PageSize::nonPse>
        {
            unsigned long long raw;
            struct
            {
                unsigned long long P : 1; // Present
                unsigned long long RW : 1; // Read/Write
                unsigned long long US : 1; // User/Supervisor
                unsigned long long PWT : 1; // Page-Level Writethrough
                unsigned long long PCD : 1; // Page-Level Cache Disable
                unsigned long long A : 1; // Accessed
                unsigned long long Ignored0 : 1;
                unsigned long long PS : 1; // PageSize == 0
                unsigned long long Ignored1 : 1;
                unsigned long long AVL : 3; // Available to software
                unsigned long long PT : 40; // Page frame number
                unsigned long long Available : 11;
                unsigned long long NX : 1; // No Execute
            } layout;

            //
            // Describes 4Kb page: PDPE -> PDE(PS=0) -> PTE -> PA (4Kb)
            //
            union Pte
            {
                unsigned long long raw;
                struct
                {
                    unsigned long long P : 1; // Present
                    unsigned long long RW : 1; // Read/Write
                    unsigned long long US : 1; // User/Supervisor
                    unsigned long long PWT : 1; // Page-Level Writethrough
                    unsigned long long PCD : 1; // Page-Level Cache Disable
                    unsigned long long A : 1; // Accessed
                    unsigned long long D : 1; // Dirty
                    unsigned long long PAT : 1; // Page-Attribute Table
                    unsigned long long G : 1; // Global Page
                    unsigned long long AVL : 3; // Available to software
                    unsigned long long PhysicalPageFrameNumber : 40;
                    unsigned long long : 11;
                    unsigned long long NX : 1; // No Execute
                } page4Kb;

                constexpr PhysicalAddress physicalPageBase() const noexcept
                {
                    return PhysicalAddress{ Pfn::toPage(this->page4Kb.PhysicalPageFrameNumber) };
                }

                constexpr PhysicalAddress physicalAddress(const LinearAddress& linear) const noexcept
                {
                    return PhysicalAddress{ this->physicalPageBase().physicalAddress + linear.pdeNonPageSize.page4Kb.PageOffset };
                }
            };
            static_assert(sizeof(Pte) == sizeof(unsigned long long));

            //
            // Describes 2 Mb of linear address space.
            //
            using Pt = Pte[512];

            constexpr PhysicalLayout<Pt> pt() const noexcept
            {
                return PhysicalLayout<Pt>{ Pfn::toPage(this->layout.PT) };
            }

            constexpr PhysicalLayout<Pte> pte(const LinearAddress& linear) const noexcept
            {
                return PhysicalLayout<Pte>{ this->pt().physicalAddress + linear.pdeNonPageSize.page4Kb.PageTableOffset * k_entrySize };
            }
        };
        static_assert(sizeof(Pde<PageSize::nonPse>) == sizeof(unsigned long long));

        //
        // Describes 2Mb page: PDPE -> PDE(PS=1) -> PA (2Mb)
        //
        template <>
        union Pde<PageSize::pse>
        {
            unsigned long long raw;
            struct
            {
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
            } page2Mb;

            constexpr PhysicalAddress physicalPageBase() const noexcept
            {
                return PhysicalAddress{ Pfn::toLarge(this->page2Mb.PhysicalPageFrameNumber) };
            }

            constexpr PhysicalAddress physicalAddress(const LinearAddress& linear) const noexcept
            {
                return PhysicalAddress{ this->physicalPageBase().physicalAddress + linear.pdePageSize.page2Mb.PageOffset };
            }
        };
        static_assert(sizeof(Pde<PageSize::pse>) == sizeof(unsigned long long));

        //
        // Describes 2Mb in one of the following ways:
        //   2Mb page itself  | PDPE -> PDE(PS=1) -> PA (2Mb)
        //   512x4Kb pages    | PDPE -> PDE(PS=0) -> PA (4Kb)
        //
        template <>
        union Pde<PageSize::generic>
        {
            unsigned long long raw;
            struct
            {
                unsigned long long P : 1; // Present
                unsigned long long RW : 1; // Read/Write
                unsigned long long US : 1; // User/Supervisor
                unsigned long long PWT : 1; // Page-Level Writethrough
                unsigned long long PCD : 1; // Page-Level Cache Disable
                unsigned long long A : 1; // Accessed
                unsigned long long : 1;
                unsigned long long PS : 1; // PageSize
                unsigned long long : 1;
                unsigned long long AVL : 3; // Available to software
                unsigned long long : 51;
                unsigned long long NX : 1; // No Execute
            } layout;

            Pde<PageSize::nonPse> nonPse;
            Pde<PageSize::pse> pse;

            constexpr PageSize pageSize() const noexcept
            {
                return this->layout.PS
                    ? PageSize::pse
                    : PageSize::nonPse;
            }
        };
        static_assert(sizeof(Pde<PageSize::generic>) == sizeof(unsigned long long));

        using PdeGeneric = Pde<PageSize::generic>;
        using PdeNonPse = Pde<PageSize::nonPse>;
        using PdePse = Pde<PageSize::pse>;

        //
        // Describes 1 Gb of linear address space.
        //
        using Pd = PdeGeneric[512];

        constexpr PhysicalLayout<Pd> pd() const noexcept
        {
            return PhysicalLayout<Pd>{ Pfn::toPage(this->layout.PD) };
        }

        constexpr PhysicalLayout<PdeGeneric> pde(const LinearAddress& linear) const noexcept
        {
            return PhysicalLayout<PdeGeneric>{ this->pd().physicalAddress + linear.generic.PageDirectoryOffset * k_entrySize };
        }
    };
    static_assert(sizeof(Pdpe) == sizeof(unsigned long long));

    //
    // Describes 4Gb of linear address space.
    //
    using Pdp = Pdpe[4];

    static constexpr PhysicalLayout<Pdp> pdp(const unsigned int cr3Pfn) noexcept
    {
        return PhysicalLayout<Pdp>{ Pfn::toPage(cr3Pfn) };
    }

    static constexpr PhysicalLayout<Pdpe> pdpe(const unsigned int cr3Pfn, const LinearAddress& linear) noexcept
    {
        return PhysicalLayout<Pdpe>{ pdp(cr3Pfn).physicalAddress + linear.generic.PageDirectoryPointerOffset * k_entrySize };
    }
};

template <>
struct Tables<Mode::longMode4Level> // EFER.LMA == 1, CR4.PAE is always 1, CR4.PSE is ignored, CR4.LA57 == 0
{
    static constexpr Mode k_mode = Mode::longMode4Level;
    static constexpr auto k_entrySize = sizeof(unsigned long long);
    using LinearAddress = LinearAddress<k_mode>;
    using Pfn = Pfn<k_mode>;

    //
    // Describes 512 Gb in one of the following ways:
    //   512x1Gb page               | PML4E -> PDPE(PS=1) -> PA (1Gb)
    //   512x[512x2Mb] pages        | PML4E -> PDPE(PS=0) -> PDE(PS=1) -> PA (2Mb)
    //   512x[512x[512x4Kb]] pages  | PML4E -> PDPE(PS=0) -> PDE(PS=0) -> PTE -> PA (4Kb)
    //
    union Pml4e
    {
        unsigned long long raw;
        struct
        {
            unsigned long long P : 1; // Present
            unsigned long long RW : 1; // Read/Write
            unsigned long long US : 1; // User/Supervisor
            unsigned long long PWT : 1; // Page-Level Writethrough
            unsigned long long PCD : 1; // Page-Level Cache Disable
            unsigned long long A : 1; // Accessed
            unsigned long long Ignored0 : 1;
            unsigned long long : 2;
            unsigned long long AVL : 3; // Available to software
            unsigned long long PDP : 40; // Page frame number of Page Directory Pointer table
            unsigned long long Available : 11;
            unsigned long long NX : 1; // No Execute
        } layout;

        template <PageSize pageSize>
        union Pdpe;

        //
        // Describes 1 Gb in one of the following ways:
        //   512x2Mb pages        | PML4E -> PDPE(PS=0) -> PDE(PS=1) -> PA (2Mb)
        //   512x[512x4Kb] pages  | PML4E -> PDPE(PS=0) -> PDE(PS=0) -> PTE -> PA (4Kb)
        //
        template <>
        union Pdpe<PageSize::nonPse>
        {
            unsigned long long raw;
            struct
            {
                unsigned long long P : 1; // Present
                unsigned long long RW : 1; // Read/Write
                unsigned long long US : 1; // User/Supervisor
                unsigned long long PWT : 1; // Page-Level Writethrough
                unsigned long long PCD : 1; // Page-Level Cache Disable
                unsigned long long A : 1; // Accessed
                unsigned long long Ignored0 : 1;
                unsigned long long PS : 1; // PageSize == 0
                unsigned long long : 1;
                unsigned long long AVL : 3; // Available to software
                unsigned long long PD : 40; // Page frame number of Page Directory table
                unsigned long long Available : 11;
                unsigned long long NX : 1; // No Execute
            } layout;

            template <PageSize pageSize>
            union Pde;

            //
            // Describes 2 Mb in 512x4Kb pages: PML4E -> PDPE(PS=0) -> PDE(PS=0) -> PTE -> PA (2Mb)
            //
            template <>
            union Pde<PageSize::nonPse>
            {
                unsigned long long raw;
                struct
                {
                    unsigned long long P : 1; // Present
                    unsigned long long RW : 1; // Read/Write
                    unsigned long long US : 1; // User/Supervisor
                    unsigned long long PWT : 1; // Page-Level Writethrough
                    unsigned long long PCD : 1; // Page-Level Cache Disable
                    unsigned long long A : 1; // Accessed
                    unsigned long long Ignored0 : 1;
                    unsigned long long PS : 1; // PageSize == 0
                    unsigned long long Ignored1 : 1;
                    unsigned long long AVL : 3; // Available to software
                    unsigned long long PT : 40; // Page frame number of Page Table
                    unsigned long long Available : 11;
                    unsigned long long NX : 1; // No Execute
                } layout;

                //
                // Describes 4Kb page: PML4E -> PDPE(PS=0) -> PDE(PS=0) -> PTE -> PA (4Kb)
                //
                union Pte
                {
                    unsigned long long raw;
                    struct
                    {
                        unsigned long long P : 1; // Present
                        unsigned long long RW : 1; // Read/Write
                        unsigned long long US : 1; // User/Supervisor
                        unsigned long long PWT : 1; // Page-Level Writethrough
                        unsigned long long PCD : 1; // Page-Level Cache Disable
                        unsigned long long A : 1; // Accessed
                        unsigned long long D : 1; // Dirty
                        unsigned long long PAT : 1; // Page-Attribute Table
                        unsigned long long G : 1; // Global Page
                        unsigned long long AVL : 3; // Available to software
                        unsigned long long PhysicalPageFrameNumber : 40;
                        unsigned long long Available : 11;
                        unsigned long long NX : 1; // No Execute
                    } page4Kb;

                    constexpr PhysicalAddress physicalPageBase() const noexcept
                    {
                        return PhysicalAddress{ Pfn::toPage(this->page4Kb.PhysicalPageFrameNumber) };
                    }

                    constexpr PhysicalAddress physicalAddress(const LinearAddress& linear) const noexcept
                    {
                        return PhysicalAddress{ this->physicalPageBase().physicalAddress + linear.pdpeNonPageSize.pdeNonPageSize.page4Kb.PageOffset };
                    }
                };
                static_assert(sizeof(Pte) == sizeof(unsigned long long));

                //
                // Describes 2 Mb of linear address space.
                //
                using Pt = Pte[512];

                constexpr PhysicalLayout<Pt> pt() const noexcept
                {
                    return PhysicalLayout<Pt>{ Pfn::toPage(this->layout.PT) };
                }

                constexpr PhysicalLayout<Pte> pte(const LinearAddress& linear) const noexcept
                {
                    return PhysicalLayout<Pte>{ this->pt().physicalAddress + linear.pdpeNonPageSize.pdeNonPageSize.page4Kb.PageTableOffset * k_entrySize };
                }
            };
            static_assert(sizeof(Pde<PageSize::nonPse>) == sizeof(unsigned long long));

            //
            // Describes 2Mb page: PML4E -> PDPE(PS=0) -> PDE(PS=1) -> PA (2Mb)
            //
            template <>
            union Pde<PageSize::pse>
            {
                unsigned long long raw;
                struct
                {
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
                } page2Mb;

                constexpr PhysicalAddress physicalPageBase() const noexcept
                {
                    return PhysicalAddress{ Pfn::toLarge(this->page2Mb.PhysicalPageFrameNumber) };
                }

                constexpr PhysicalAddress physicalAddress(const LinearAddress& linear) const noexcept
                {
                    return PhysicalAddress{ this->physicalPageBase().physicalAddress + linear.pdpeNonPageSize.pdePageSize.page2Mb.PageOffset };
                }
            };
            static_assert(sizeof(Pde<PageSize::pse>) == sizeof(unsigned long long));

            //
            // Describes 2 Mb in one of the following ways:
            //   2Mb page itself  | PML4E -> PDPE(PS=0) -> PDE(PS=1) -> PA (2Mb)
            //   512x4Kb pages    | PML4E -> PDPE(PS=0) -> PDE(PS=0) -> PTE -> PA (4Kb)
            //
            template <>
            union Pde<PageSize::generic>
            {
                unsigned long long raw;
                struct
                {
                    unsigned long long P : 1; // Present
                    unsigned long long RW : 1; // Read/Write
                    unsigned long long US : 1; // User/Supervisor
                    unsigned long long PWT : 1; // Page-Level Writethrough
                    unsigned long long PCD : 1; // Page-Level Cache Disable
                    unsigned long long A : 1; // Accessed
                    unsigned long long : 1;
                    unsigned long long PS : 1; // PageSize
                    unsigned long long : 1;
                    unsigned long long AVL : 3; // Available to software
                    unsigned long long : 51;
                    unsigned long long NX : 1; // No Execute
                } layout;

                Pde<PageSize::nonPse> nonPse;
                Pde<PageSize::pse> pse;

                constexpr PageSize pageSize() const noexcept
                {
                    return this->layout.PS
                        ? PageSize::pse
                        : PageSize::nonPse;
                }
            };
            static_assert(sizeof(Pde<PageSize::generic>) == sizeof(unsigned long long));

            using PdeGeneric = Pde<PageSize::generic>;
            using PdeNonPse = Pde<PageSize::nonPse>;
            using PdePse = Pde<PageSize::pse>;

            //
            // Describes 1 Gb of linear address space.
            //
            using Pd = PdeGeneric[512];

            constexpr PhysicalLayout<Pd> pd() const noexcept
            {
                return PhysicalLayout<Pd>{ Pfn::toPage(this->layout.PD) };
            }

            constexpr PhysicalLayout<PdeGeneric> pde(const LinearAddress& linear) const noexcept
            {
                return PhysicalLayout<PdeGeneric>{ this->pd().physicalAddress + linear.pdpeNonPageSize.generic.PageDirectoryOffset * k_entrySize };
            }
        };
        static_assert(sizeof(Pdpe<PageSize::nonPse>) == sizeof(unsigned long long));

        //
        // Describes 1Gb page: PML4E -> PDPE(PS=1) -> PA (1Gb)
        //
        template <>
        union Pdpe<PageSize::pse>
        {
            unsigned long long raw;
            struct
            {
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
                unsigned long long : 17;
                unsigned long long PhysicalPageFrameNumber : 22;
                unsigned long long Available : 11;
                unsigned long long NX : 1; // No Execute
            } page1Gb;

            constexpr PhysicalAddress physicalPageBase() const noexcept
            {
                return PhysicalAddress{ Pfn::toHuge(this->page1Gb.PhysicalPageFrameNumber) };
            }

            constexpr PhysicalAddress physicalAddress(const LinearAddress& linear) const noexcept
            {
                return PhysicalAddress{ this->physicalPageBase().physicalAddress + linear.pdpePageSize.page1Gb.PageOffset };
            }
        };
        static_assert(sizeof(Pdpe<PageSize::pse>) == sizeof(unsigned long long));

        //
        // Describes 1 Gb in one of the following ways:
        //   1Gb page itself      | PML4E -> PDPE(PS=1) -> PA (1Gb)
        //   512x2Mb pages        | PML4E -> PDPE(PS=0) -> PDE(PS=1) -> PA (2Mb)
        //   512x[512x4Kb] pages  | PML4E -> PDPE(PS=0) -> PDE(PS=0) -> PTE -> PA (4Kb)
        //
        template <>
        union Pdpe<PageSize::generic>
        {
            unsigned long long raw;
            struct
            {
                unsigned long long P : 1; // Present
                unsigned long long RW : 1; // Read/Write
                unsigned long long US : 1; // User/Supervisor
                unsigned long long PWT : 1; // Page-Level Writethrough
                unsigned long long PCD : 1; // Page-Level Cache Disable
                unsigned long long A : 1; // Accessed
                unsigned long long : 1;
                unsigned long long PS : 1; // PageSize
                unsigned long long : 1;
                unsigned long long AVL : 3; // Available to software
                unsigned long long : 51;
                unsigned long long NX : 1; // No Execute
            } layout;

            Pdpe<PageSize::nonPse> nonPse;
            Pdpe<PageSize::pse> pse;

            constexpr PageSize pageSize() const noexcept
            {
                return this->layout.PS
                    ? PageSize::pse
                    : PageSize::nonPse;
            }
        };
        static_assert(sizeof(Pdpe<PageSize::generic>) == sizeof(unsigned long long));

        using PdpeGeneric = Pdpe<PageSize::generic>;
        using PdpeNonPse = Pdpe<PageSize::nonPse>;
        using PdpePse = Pdpe<PageSize::pse>;

        //
        // Describes 512 Gb of linear address space.
        //
        using Pdp = PdpeGeneric[512];

        constexpr PhysicalLayout<Pdp> pdp() const noexcept
        {
            return PhysicalLayout<Pdp>{ Pfn::toPage(this->layout.PDP) };
        }

        constexpr PhysicalLayout<PdpeGeneric> pdpe(const LinearAddress& linear) const noexcept
        {
            return PhysicalLayout<PdpeGeneric>{ this->pdp().physicalAddress + linear.generic.PageDirectoryPointerOffset * k_entrySize };
        }
    };
    static_assert(sizeof(Pml4e) == sizeof(unsigned long long));

    //
    // Describes 262 Tb of linear address space.
    //
    using Pml4 = Pml4e[512];

    static constexpr PhysicalLayout<Pml4> pml4(const unsigned long long cr3Pfn) noexcept
    {
        return PhysicalLayout<Pml4>{ Pfn::toPage(cr3Pfn) };
    }

    static constexpr PhysicalLayout<Pml4e> pml4e(const unsigned long long cr3Pfn, const LinearAddress& linear) noexcept
    {
        return PhysicalLayout<Pml4e>{ pml4(cr3Pfn).physicalAddress + linear.generic.PageMapLevel4Offset * k_entrySize };
    }
};

template <>
struct Tables<Mode::longMode5Level> // EFER.LMA == 1, CR4.PAE is always 1, CR4.PSE is ignored, CR4.LA57 == 1
{
    static constexpr Mode k_mode = Mode::longMode5Level;
    static constexpr auto k_entrySize = sizeof(unsigned long long);
    using LinearAddress = LinearAddress<k_mode>;
    using Pfn = Pfn<k_mode>;

    union Pml5e
    {
        unsigned long long raw;
        struct
        {
            unsigned long long P : 1; // Present
            unsigned long long RW : 1; // Read/Write
            unsigned long long US : 1; // User/Supervisor
            unsigned long long PWT : 1; // Page-Level Writethrough
            unsigned long long PCD : 1; // Page-Level Cache Disable
            unsigned long long A : 1; // Accessed
            unsigned long long Ignored0 : 1;
            unsigned long long : 2;
            unsigned long long AVL : 3; // Available to software
            unsigned long long PML4 : 40; // Page frame number of Page-Map 4-Level table
            unsigned long long Available : 11;
            unsigned long long NX : 1; // No Execute
        } layout;

        using Tables4Level = Tables<Mode::longMode4Level>;

        using Pml4e = Tables4Level::Pml4e; // The same as in 4-level paging
        using Pml4 = Tables4Level::Pml4; // The same as in 4-level paging
    };
    static_assert(sizeof(Pml5e) == sizeof(unsigned long long));

    //
    // Describes 134 Pb of linear address space.
    //
    using Pml5 = Pml5e[512];

    static constexpr PhysicalLayout<Pml5> pml5(const unsigned long long cr3Pfn) noexcept
    {
        return PhysicalLayout<Pml5>{ Pfn::toPage(cr3Pfn) };
    }

    static constexpr PhysicalLayout<Pml5e> pml5e(const unsigned long long cr3Pfn, const LinearAddress& linear) noexcept
    {
        return PhysicalLayout<Pml5e>{ pml5(cr3Pfn).physicalAddress + linear.generic.PageMapLevel5Offset * k_entrySize };
    }
};



} // namespace Pte

#pragma pack(pop)