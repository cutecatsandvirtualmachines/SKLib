#include "acpi.h"

EFI_GUID gEfiAcpiTableGuid = { 0x8868E871, 0xE4F1, 0x11D3, { 0xBC, 0x22, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81 } };
EFI_GUID gEfiAcpi10TableGuid = { 0xEB9D2D30, 0x2D88, 0x11D3, { 0x9A, 0x16, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D } };
EFI_GUID gEfiAcpi20TableGuid = { 0x8868E871, 0xE4F1, 0x11D3, { 0xBC, 0x22, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81 } };

/**
  This function scans ACPI table in XSDT/RSDT.

  @param Sdt                    ACPI XSDT/RSDT.
  @param TablePointerSize       Size of table pointer: 8(XSDT) or 4(RSDT).
  @param Signature              ACPI table signature.
  @param PreviousTable          Pointer to previous returned table to locate
                                next table, or NULL to locate first table.
  @param PreviousTableLocated   Pointer to the indicator about whether the
                                previous returned table could be located, or
                                NULL if PreviousTable is NULL.

  If PreviousTable is NULL and PreviousTableLocated is not NULL, then ASSERT().
  If PreviousTable is not NULL and PreviousTableLocated is NULL, then ASSERT().

  @return ACPI table or NULL if not found.

**/
EFI_ACPI_COMMON_HEADER*
ScanTableInSDT(
    IN  EFI_ACPI_DESCRIPTION_HEADER* Sdt,
    IN  UINTN                        TablePointerSize,
    IN  UINT32                       Signature,
    IN  EFI_ACPI_COMMON_HEADER* PreviousTable  OPTIONAL,
    OUT BOOLEAN* PreviousTableLocated OPTIONAL
)
{
    UINTN                   Index;
    UINTN                   EntryCount;
    UINT64                  EntryPtr;
    UINTN                   BasePtr;
    EFI_ACPI_COMMON_HEADER* Table;

    if (PreviousTableLocated != NULL) {
        ASSERT(PreviousTable != NULL);
        *PreviousTableLocated = FALSE;
    }
    else {
        ASSERT(PreviousTable == NULL);
    }

    if (Sdt == NULL) {
        DbgMsg("[ACPI] SDT is null!");
        return NULL;
    }

    DbgMsg("[ACPI] SDT %c%c%c%c with length: 0x%x", Int2Chars(Signature), Sdt->Length);
    EntryCount = (Sdt->Length - sizeof(EFI_ACPI_DESCRIPTION_HEADER)) / TablePointerSize;
    DbgMsg("[ACPI] SDT found with %d entries", EntryCount);

    BasePtr = (UINTN)(Sdt + 1);
    DbgMsg("[ACPI] Base ptr at: %p", BasePtr);
    for (Index = 0; Index < EntryCount; Index++) {
        EntryPtr = 0;
        memcpy(&EntryPtr, (VOID*)(BasePtr + Index * TablePointerSize), TablePointerSize);
        DbgMsg("[ACPI] Table %d at: %p", Index, EntryPtr);
        if (!MmIsAddressValid((PVOID)EntryPtr)) {
            PHYSICAL_ADDRESS pa = { 0 };
            pa.QuadPart = EntryPtr;
            EntryPtr = (UINTN)MmMapIoSpace(pa, sizeof(EFI_ACPI_COMMON_HEADER), MEMORY_CACHING_TYPE::MmNonCached);
            if (!EntryPtr) {
                DbgMsg("[ACPI] Could not map address!");
                continue;
            }
        }
        Table = (EFI_ACPI_COMMON_HEADER*)(EntryPtr);
        if ((Table != NULL) && (Table->Signature == Signature)) {
            if (PreviousTable != NULL) {
                if (Table == PreviousTable) {
                    *PreviousTableLocated = TRUE;
                }
                else if (*PreviousTableLocated) {
                    //
                    // Return next table.
                    //
                    return Table;
                }
            }
            else {
                //
                // Return first table.
                //
                return Table;
            }
        }
    }

    DbgMsg("[ACPI] No table found in SDT");
    return NULL;
}

/**
  To locate FACS in FADT.

  @param Fadt   FADT table pointer.

  @return FACS table pointer or NULL if not found.

**/
EFI_ACPI_COMMON_HEADER*
LocateAcpiFacsFromFadt(
    IN EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE* Fadt
)
{
    EFI_ACPI_COMMON_HEADER* Facs;
    UINT64                  Data64;

    if (Fadt == NULL) {
        DbgMsg("[ACPI] FADT is null!");
        return NULL;
    }

    if (Fadt->Header.Revision < EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE_REVISION) {
        Facs = (EFI_ACPI_COMMON_HEADER*)Fadt->FirmwareCtrl;
    }
    else {
        memcpy(&Data64, &Fadt->XFirmwareCtrl, sizeof(UINT64));
        if (Data64 != 0) {
            Facs = (EFI_ACPI_COMMON_HEADER*)Data64;
        }
        else {
            Facs = (EFI_ACPI_COMMON_HEADER*)Fadt->FirmwareCtrl;
        }
    }

    return Facs;
}

/**
  To locate DSDT in FADT.

  @param Fadt   FADT table pointer.

  @return DSDT table pointer or NULL if not found.

**/
EFI_ACPI_COMMON_HEADER*
LocateAcpiDsdtFromFadt(
    IN EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE* Fadt
)
{
    EFI_ACPI_COMMON_HEADER* Dsdt;
    UINT64                  Data64;

    if (Fadt == NULL) {
        DbgMsg("[ACPI] FADT is null!");
        return NULL;
    }

    if (Fadt->Header.Revision < EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE_REVISION) {
        Dsdt = (EFI_ACPI_COMMON_HEADER*)Fadt->Dsdt;
    }
    else {
        memcpy(&Data64, &Fadt->XDsdt, sizeof(UINT64));
        if (Data64 != 0) {
            Dsdt = (EFI_ACPI_COMMON_HEADER*)Data64;
        }
        else {
            Dsdt = (EFI_ACPI_COMMON_HEADER*)Fadt->Dsdt;
        }
    }

    return Dsdt;
}

/**
  To locate ACPI table in ACPI ConfigurationTable.

  @param AcpiGuid               The GUID used to get ACPI ConfigurationTable.
  @param Signature              ACPI table signature.
  @param PreviousTable          Pointer to previous returned table to locate
                                next table, or NULL to locate first table.
  @param PreviousTableLocated   Pointer to the indicator to return whether the
                                previous returned table could be located or not,
                                or NULL if PreviousTable is NULL.

  If PreviousTable is NULL and PreviousTableLocated is not NULL, then ASSERT().
  If PreviousTable is not NULL and PreviousTableLocated is NULL, then ASSERT().
  If AcpiGuid is NULL, then ASSERT().

  @return ACPI table or NULL if not found.

**/
EFI_ACPI_COMMON_HEADER*
LocateAcpiTableInAcpiConfigurationTable(
    IN  EFI_GUID* AcpiGuid,
    IN  UINT32                  Signature,
    IN  EFI_ACPI_COMMON_HEADER* PreviousTable  OPTIONAL,
    OUT BOOLEAN* PreviousTableLocated OPTIONAL
)
{
    EFI_STATUS Status = STATUS_SUCCESS;
    EFI_ACPI_COMMON_HEADER* Table;
    EFI_ACPI_DESCRIPTION_HEADER* Rsdt;
    EFI_ACPI_DESCRIPTION_HEADER* Xsdt;
    EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE* Fadt;

    if (PreviousTableLocated != NULL) {
        ASSERT(PreviousTable != NULL);
        *PreviousTableLocated = FALSE;
    }
    else {
        ASSERT(PreviousTable == NULL);
    }

    Table = NULL;

    //
    // Search XSDT
    //
    Xsdt = (EFI_ACPI_DESCRIPTION_HEADER*)HalGetCachedAcpiTable('TDSX', 0, 0);
    if (Xsdt) {
        DbgMsg("[ACPI] XSDT found at: %p", Xsdt);
        if (Signature == EFI_ACPI_2_0_DIFFERENTIATED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE) {
            ASSERT(PreviousTable == NULL);
            //
            // It is to locate DSDT,
            // need to locate FADT first.
            //
            Fadt = (EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE*)ScanTableInSDT(
                Xsdt,
                sizeof(UINT64),
                EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE,
                NULL,
                NULL
            );
            Table = LocateAcpiDsdtFromFadt(Fadt);
        }
        else if (Signature == EFI_ACPI_2_0_FIRMWARE_ACPI_CONTROL_STRUCTURE_SIGNATURE) {
            ASSERT(PreviousTable == NULL);
            //
            // It is to locate FACS,
            // need to locate FADT first.
            //
            Fadt = (EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE*)ScanTableInSDT(
                Xsdt,
                sizeof(UINT64),
                EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE,
                NULL,
                NULL
            );
            Table = LocateAcpiFacsFromFadt(Fadt);
        }
        else {
            Table = ScanTableInSDT(
                Xsdt,
                sizeof(UINT64),
                Signature,
                PreviousTable,
                PreviousTableLocated
            );
        }
    }
    else {
        DbgMsg("[ACPI] XSDT could not be found");
    }

    if (Table != NULL) {
        return Table;
    }
    else if ((PreviousTableLocated != NULL) &&
        *PreviousTableLocated)
    {
        //
        // PreviousTable could be located in XSDT,
        // but next table could not be located in XSDT.
        //
        return NULL;
    }

    //
    // Search RSDT
    //
    Rsdt = (EFI_ACPI_DESCRIPTION_HEADER*)HalGetCachedAcpiTable('TDSR', 0, 0);
    if (!Rsdt) {
        DbgMsg("[ACPI] Rsdt could not be found too, aborting...");
    }
    else if (Signature == EFI_ACPI_2_0_DIFFERENTIATED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE) {
        ASSERT(PreviousTable == NULL);
        //
        // It is to locate DSDT,
        // need to locate FADT first.
        //
        Fadt = (EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE*)ScanTableInSDT(
            Rsdt,
            sizeof(UINT32),
            EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE,
            NULL,
            NULL
        );
        Table = LocateAcpiDsdtFromFadt(Fadt);
    }
    else if (Signature == EFI_ACPI_2_0_FIRMWARE_ACPI_CONTROL_STRUCTURE_SIGNATURE) {
        ASSERT(PreviousTable == NULL);
        //
        // It is to locate FACS,
        // need to locate FADT first.
        //
        Fadt = (EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE*)ScanTableInSDT(
            Rsdt,
            sizeof(UINT32),
            EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE,
            NULL,
            NULL
        );
        Table = LocateAcpiFacsFromFadt(Fadt);
    }
    else {
        Table = ScanTableInSDT(
            Rsdt,
            sizeof(UINT32),
            Signature,
            PreviousTable,
            PreviousTableLocated
        );
    }

    return Table;
}

/**
  This function locates next ACPI table in XSDT/RSDT based on Signature and
  previous returned Table.

  If PreviousTable is NULL:
  This function will locate the first ACPI table in XSDT/RSDT based on
  Signature in gEfiAcpi20TableGuid system configuration table first, and then
  gEfiAcpi10TableGuid system configuration table.
  This function will locate in XSDT first, and then RSDT.
  For DSDT, this function will locate XDsdt in FADT first, and then Dsdt in
  FADT.
  For FACS, this function will locate XFirmwareCtrl in FADT first, and then
  FirmwareCtrl in FADT.

  If PreviousTable is not NULL:
  1. If it could be located in XSDT in gEfiAcpi20TableGuid system configuration
     table, then this function will just locate next table in XSDT in
     gEfiAcpi20TableGuid system configuration table.
  2. If it could be located in RSDT in gEfiAcpi20TableGuid system configuration
     table, then this function will just locate next table in RSDT in
     gEfiAcpi20TableGuid system configuration table.
  3. If it could be located in RSDT in gEfiAcpi10TableGuid system configuration
     table, then this function will just locate next table in RSDT in
     gEfiAcpi10TableGuid system configuration table.

  It's not supported that PreviousTable is not NULL but PreviousTable->Signature
  is not same with Signature, NULL will be returned.

  @param Signature          ACPI table signature.
  @param PreviousTable      Pointer to previous returned table to locate next
                            table, or NULL to locate first table.

  @return Next ACPI table or NULL if not found.

**/
EFI_ACPI_COMMON_HEADER*
EfiLocateNextAcpiTable(
    IN UINT32                  Signature,
    IN EFI_ACPI_COMMON_HEADER* PreviousTable OPTIONAL
)
{
    EFI_ACPI_COMMON_HEADER* Table;
    BOOLEAN                 TempPreviousTableLocated;
    BOOLEAN* PreviousTableLocated;

    if (PreviousTable != NULL) {
        if (PreviousTable->Signature != Signature) {
            //
            // PreviousTable->Signature is not same with Signature.
            //
            DbgMsg("[ACPI] Signature does not match, aborting...");
            return NULL;
        }
        else if ((Signature == EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE) ||
            (Signature == EFI_ACPI_2_0_DIFFERENTIATED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE) ||
            (Signature == EFI_ACPI_2_0_FIRMWARE_ACPI_CONTROL_STRUCTURE_SIGNATURE))
        {
            //
            // There is only one FADT/DSDT/FACS table,
            // so don't try to locate next one.
            //
            DbgMsg("[ACPI] Only one table available, aborting...");
            return NULL;
        }

        PreviousTableLocated = &TempPreviousTableLocated;
        *PreviousTableLocated = FALSE;
    }
    else {
        PreviousTableLocated = NULL;
    }

    Table = LocateAcpiTableInAcpiConfigurationTable(
        &gEfiAcpi20TableGuid,
        Signature,
        PreviousTable,
        PreviousTableLocated
    );
    if (Table != NULL) {
        return Table;
    }
    else if ((PreviousTableLocated != NULL) &&
        *PreviousTableLocated)
    {
        //
        // PreviousTable could be located in gEfiAcpi20TableGuid system
        // configuration table, but next table could not be located in
        // gEfiAcpi20TableGuid system configuration table.
        //
        DbgMsg("[ACPI] Table could not be located in gEfiAcpi20TableGuid, aborting...");
        return NULL;
    }

    return LocateAcpiTableInAcpiConfigurationTable(
        &gEfiAcpi10TableGuid,
        Signature,
        PreviousTable,
        PreviousTableLocated
    );
}

/**
  This function locates first ACPI table in XSDT/RSDT based on Signature.

  This function will locate the first ACPI table in XSDT/RSDT based on
  Signature in gEfiAcpi20TableGuid system configuration table first, and then
  gEfiAcpi10TableGuid system configuration table.
  This function will locate in XSDT first, and then RSDT.
  For DSDT, this function will locate XDsdt in FADT first, and then Dsdt in
  FADT.
  For FACS, this function will locate XFirmwareCtrl in FADT first, and then
  FirmwareCtrl in FADT.

  @param Signature          ACPI table signature.

  @return First ACPI table or NULL if not found.

**/
EFI_ACPI_COMMON_HEADER*
EfiLocateFirstAcpiTable(
    IN UINT32  Signature
)
{
    return EfiLocateNextAcpiTable(Signature, NULL);
}

EFI_ACPI_DMAR_HEADER* acpi::dmarTable = nullptr;
MCFG_TABLE* acpi::mcfgTable = nullptr;
bool bAcpiInit = false;

bool acpi::Init()
{
    if (bAcpiInit)
        return true;

    dmarTable = (EFI_ACPI_DMAR_HEADER*)EfiLocateFirstAcpiTable(EFI_ACPI_4_0_DMA_REMAPPING_TABLE_SIGNATURE);
    if (!MmIsAddressValid(dmarTable)) {
        DbgMsg("[ACPI] Failed locating ACPI DMAR table!");
        if (CPU::bIntelCPU)
            return false;
    }
    else {
        DbgMsg("[ACPI] DMAR table at: %p", dmarTable);
    }

    mcfgTable = (MCFG_TABLE*)EfiLocateFirstAcpiTable(EFI_ACPI_4_0_MEMORY_MAPPED_ENHANCED_CONFIGURATION_SPACE_BASE_ADDRESS_ALLOCATION_SIGNATURE);
    if (!MmIsAddressValid(mcfgTable)) {
        DbgMsg("[ACPI] Failed locating ACPI MCFG table!");
        if(!CPU::bIntelCPU)
            return false;
    }
    else if (!CPU::bIntelCPU) {
        DbgMsg("[ACPI] MCFG table with 0x%llx entries at: %p", (mcfgTable->headers.Header.Length - sizeof(mcfgTable->headers)) / sizeof(*mcfgTable->entry), mcfgTable);
        acpi::McfgRegister mcfgRegister(acpi::mcfgTable);
        for (int i = 0; i < mcfgRegister.size(); i++) {
            auto pConfigSpace = mcfgRegister.AllPCIeConfigSpace(i);
            if (!MmIsAddressValid(pConfigSpace)) {
                DbgMsg("[ACPI] Could not map config space!");
                return false;
            }

            bool bFound = false;
            for (int j = 0; j < MAX_PCIE_IN_CONFIG_SPACE; j++) {
                PPCI_CONFIG_SPACE pCurrConfigSpace = (PPCI_CONFIG_SPACE)&pConfigSpace[j];

                if (pCurrConfigSpace->Common.Class == SYSTEM_BASE_PERIPHERAL_CLASS
                    && pCurrConfigSpace->Common.Subclass == IOMMU_SUBCLASS
                    && pCurrConfigSpace->Common.ProgInterface == 0) {
                    DbgMsg("[ACPI] Found IOMMU configuration space at: %p", pCurrConfigSpace);

                    bFound = true;
                    break;
                }
            }
            if (!bFound)
                return false;
        }
    }

    DbgMsg("[ACPI] Succesfully setup!");
    bAcpiInit = true;
    return true;
}

acpi::DmarRegister::DmarRegister(DWORD64 registerPa)
{
    _registerPa = registerPa;
    PHYSICAL_ADDRESS pa = { 0 };
    pa.QuadPart = _registerPa;
    _mappedRegister = MmMapIoSpaceEx(pa, PAGE_SIZE, PAGE_READWRITE | PAGE_NOCACHE);
    pa.QuadPart = *(DWORD64*)((DWORD64)_mappedRegister + R_IQ_ADDR_REG);
    _mappedQIRegister = MmMapIoSpaceEx(pa, PAGE_SIZE, PAGE_READWRITE | PAGE_NOCACHE);
}

acpi::DmarRegister::~DmarRegister()
{
    MmUnmapIoSpace(_mappedRegister, PAGE_SIZE);
}

void acpi::DmarRegister::SendGlobalCmdSerialized(DWORD64 mask, BOOLEAN bSet)
{
    if (!mask)
        return;

    DWORD32 flags = *(DWORD32*)((DWORD64)_mappedRegister + R_GSTS_REG);
    if (bSet) {
        flags |= mask;
    }
    else {
        flags &= ~mask;
    }
    *(DWORD32*)((DWORD64)_mappedRegister + R_GCMD_REG) = flags;

    threading::Sleep(100);
}

void acpi::DmarRegister::SendContextCmdSerialized(DWORD64 mask)
{
    *(DWORD64*)((DWORD64)_mappedRegister + R_CCMD_REG) = (mask | B_CCMD_REG_ICC);
    //for (; (*(DWORD64*)((DWORD64)_mappedRegister + R_CCMD_REG) & B_CCMD_REG_ICC) != 0;)
    //{
    //    __noop();
    //}
}

void acpi::DmarRegister::SendQueuedInvalidation(QI_CMD cmd)
{
    QI_REG nextCmd = *(QI_REG*)((DWORD64)_mappedRegister + R_IQ_TAIL_REG);
    *(QI_CMD*)((DWORD64)_mappedQIRegister + nextCmd.Offset) = cmd;
    ((QI_REG*)((DWORD64)_mappedRegister + R_IQ_HEAD_REG))->Offset -= sizeof(cmd);
}

void acpi::DmarRegister::SetRootTable(PVOID pTable)
{
    VTD_ROOT_TABLE_ADDRESS_REGISTER rootTableAddressReg = { 0 };
    rootTableAddressReg.AsUInt64 = 0;

    rootTableAddressReg.Bits.RootTable = (UINT64)Memory::VirtToPhy(pTable) >> 12;
    *(DWORD64*)((DWORD64)_mappedRegister + R_RTADDR_REG) = rootTableAddressReg.AsUInt64;

    SendGlobalCmdSerialized(B_GMCD_REG_SRTP, true);
}

PVOID acpi::DmarRegister::GetRootTable()
{
    return *(PVOID*)((DWORD64)_mappedRegister + R_RTADDR_REG);
}

PVOID acpi::DmarRegister::GetMappedRegister()
{
    return _mappedRegister;
}

PVOID acpi::DmarRegister::GetMappedQIRegister() {
    return _mappedQIRegister;
}

void acpi::DmarRegister::InvalidateIoTlb(DWORD64 mask)
{
    if (!mask)
        return;

    VTD_ECAP_REG ExtendedCapability = { 0 };
    ExtendedCapability.Uint64 = *(DWORD64*)((DWORD64)_mappedRegister + R_ECAP_REG);
    DWORD64 iotlbRegOffset = (UINT64)ExtendedCapability.Bits.IRO * 16;

    *(DWORD64*)((DWORD64)_mappedRegister + iotlbRegOffset + R_IOTLB_REG) = (mask | B_IOTLB_REG_IVT);
    
    threading::Sleep(1);
}

acpi::McfgRegister::McfgRegister(MCFG_TABLE* table)
{
    _mcfgTable = table;
    _entries = (table->headers.Header.Length - sizeof(table->headers)) / sizeof(*table->entry);
}

int acpi::McfgRegister::size()
{
    return _entries;
}

PPCI_CONFIG_SPACE acpi::McfgRegister::GetPCIeConfigSpace(ACPI_BDF bdf)
{
    PVOID pConfigSpace = nullptr;
    for (int i = 0; i < _entries; i++) {
        if ((*this)[i].StartBusNumber <= bdf.bits.bus
            && (*this)[i].EndBusNumber >= bdf.bits.bus) {
            PHYSICAL_ADDRESS pa = { 0 };
            pa.QuadPart = (*this)[i].BaseAddress + ((bdf.bits.bus - (*this)[i].StartBusNumber) << 20 | bdf.bits.device << 15 | bdf.bits.function << 12);
            pConfigSpace = MmMapIoSpace(pa, PAGE_SIZE, MEMORY_CACHING_TYPE::MmNonCached);
            break;
        }
    }
    return (PPCI_CONFIG_SPACE)pConfigSpace;
}

PPCI_CONFIG_SPACE acpi::McfgRegister::AllPCIeConfigSpace(int index)
{
    PHYSICAL_ADDRESS pa = { 0 };
    pa.QuadPart = (*this)[index].BaseAddress;
    return (PPCI_CONFIG_SPACE)MmMapIoSpace(pa, SIZE_2MB, MEMORY_CACHING_TYPE::MmNonCached);
}

MCFG_CFG_SPACE_ADDR& acpi::McfgRegister::operator[](int index)
{
    if (index >= _entries) {
        return _mcfgTable->entry[_entries - 1];
    }
    else if (index <= 0) {
        return _mcfgTable->entry[0];
    }
    return _mcfgTable->entry[index];
}
