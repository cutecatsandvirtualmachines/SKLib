#include "smbiosspoof.h"
#include "registry.h"

char* pCopySMBios = nullptr;
char* pOrigSMBios = nullptr;

bool smbios::Spoof(DWORD64 seed)
{
    rnd.setSeed(seed);
    rnd.setSecLevel(random::SecurityLevel::PREDICTABLE);

    PPHYSICAL_ADDRESS pWmipSMBiosTablePhysicalAddress = (PPHYSICAL_ADDRESS)((DWORD64)winternl::ntoskrnlBase + offsets.WmipSMBiosTablePhysicalAddress);

    DWORD32* smbiosTableLen = (DWORD32*)((DWORD64)winternl::ntoskrnlBase + offsets.WmipSMBiosTableLength);

    static bool bSuccess = true;
    auto pa = *pWmipSMBiosTablePhysicalAddress;
    DWORD64 totLen = *smbiosTableLen + PAGE_SIZE;
    pa.QuadPart = (DWORD64)PAGE_ALIGN(pa.QuadPart);
    char* pOrigSMBiosTable = (char*)MmMapIoSpaceEx(pa, totLen, 4);
    if (!pCopySMBios) {
        DbgMsg("[SMBIOS] Base original at: %p", pOrigSMBiosTable);
        pCopySMBios = (char*)cpp::kMalloc(totLen);
        pOrigSMBios = (char*)cpp::kMalloc(totLen);
        Memory::WriteProtected(pCopySMBios, pOrigSMBiosTable, totLen);
        Memory::WriteProtected(pOrigSMBios, pOrigSMBiosTable, totLen);

        for (DWORD64 pageOffset = 0; pageOffset < totLen; pageOffset += PAGE_SIZE) {
            PVOID pTarget = (PVOID)(pOrigSMBiosTable + pageOffset);
            HOOK_SECONDARY_INFO hkSecondaryInfo = { 0 };
            PAGE_PERMISSIONS pgPermissions = { 0 };
            pgPermissions.Exec = true;
            hkSecondaryInfo.pSubstitutePage = pCopySMBios + pageOffset;
            if (!EPT::Hook(pTarget, hkSecondaryInfo.pSubstitutePage, hkSecondaryInfo, pgPermissions)) {
                DbgMsg("[DRIVER] Failed shadowing memory page: %p", pTarget);
                bSuccess = false;
                break;
            }
        }

        MmUnmapIoSpace(pOrigSMBiosTable, totLen);
    }

    if (!bSuccess) {
        DbgMsg("[SMBIOS] Failed shadowing!");
        pWmipSMBiosTablePhysicalAddress->QuadPart = 0;
        *smbiosTableLen = 0;
    }
    else {
        RtlCopyMemory(pCopySMBios, pOrigSMBios, totLen);
        smbios::Parser parser(pCopySMBios + ADDRMASK_EPT_PML1_OFFSET(pWmipSMBiosTablePhysicalAddress->QuadPart), *smbiosTableLen, (winternl::WmipSMBiosVersionInfo->SMBiosMajorVersion << 8) | winternl::WmipSMBiosVersionInfo->SMBiosMinorVersion);
        DbgMsg("[SMBIOS] Base at: %p", pCopySMBios + ADDRMASK_EPT_PML1_OFFSET(pWmipSMBiosTablePhysicalAddress->QuadPart));

        int parsed = 0;
        auto entry = parser.next();
        while (entry) {
            parsed++;
            if (parsed > 0x100)
                break;

            switch (entry->type) {
            case TYPE_SYSTEM_INFO: {
                rnd.bytes(entry->data.sysinfo.UUID + 4, 12);

                if (strcmp("Default string", entry->data.sysinfo.SerialNumber) == 0) {
                    entry = parser.next();
                    continue;
                }
                int serialLen = strlen(entry->data.sysinfo.SerialNumber);
                DbgMsg("[SMBIOS] SYSTEM_INFO serial: %s", entry->data.sysinfo.SerialNumber);
                rnd.setSeed(seed);
                rnd.random_shuffle_ignore_chars(entry->data.sysinfo.SerialNumber, serialLen, (char*)" _-.", 4);
                break;
            }
            case TYPE_BASEBOARD_INFO: {
                if (strcmp("Default string", entry->data.baseboard.SerialNumber) == 0) {
                    entry = parser.next();
                    continue;
                }
                int serialLen = strlen(entry->data.baseboard.SerialNumber);
                DbgMsg("[SMBIOS] SYSTEM_INFO serial: %s", entry->data.baseboard.SerialNumber);
                rnd.setSeed(seed);
                rnd.random_shuffle_ignore_chars(entry->data.baseboard.SerialNumber, serialLen, (char*)" _-.", 4);
                break;
            }
            case TYPE_SYSTEM_ENCLOSURE: {
                if (strcmp("Default string", entry->data.sysenclosure.SerialNumber) == 0) {
                    entry = parser.next();
                    continue;
                }
                int serialLen = strlen(entry->data.sysenclosure.SerialNumber);
                DbgMsg("[SMBIOS] SYSTEM_INFO serial: %s", entry->data.sysenclosure.SerialNumber);
                rnd.setSeed(seed);
                rnd.random_shuffle_ignore_chars(entry->data.sysenclosure.SerialNumber, serialLen, (char*)" _-.", 4);
                break;
            }
            case TYPE_MEMORY_DEVICE: {
                int serialLen = strlen(entry->data.memory.SerialNumber);
                int partLen = strlen(entry->data.memory.PartNumber);
                rnd.setSeed(seed);
                DbgMsg("[SMBIOS] SYSTEM_INFO serial: %s", entry->data.memory.SerialNumber);
                rnd.random_shuffle_ignore_chars(entry->data.memory.SerialNumber, serialLen, (char*)" _-.", 4);
                rnd.random_shuffle_ignore_chars(entry->data.memory.PartNumber, partLen, (char*)" _-.", 4);
                break;
            }
            case TYPE_PROCESSOR_INFO: {
                if (
                    strcmp("To Be Filled By O.E.M.", entry->data.processor.SerialNumber) == 0
                    || strcmp("Unknown", entry->data.processor.SerialNumber) == 0
                    ) {
                    entry = parser.next();
                    continue;
                }
                int serialLen = strlen(entry->data.processor.SerialNumber);
                DbgMsg("[SMBIOS] SYSTEM_INFO serial: %s", entry->data.processor.SerialNumber);
                rnd.setSeed(seed);
                rnd.random_shuffle_ignore_chars(entry->data.processor.SerialNumber, serialLen, (char*)" _-.", 4);
                break;
            }
            }

            entry = parser.next();
        }
    }

    char* temp = (char*)cpp::kMalloc(*smbiosTableLen + 8);
    memcpy(temp, winternl::WmipSMBiosVersionInfo, 4);
    memcpy(temp + 4, smbiosTableLen, 4);
    memcpy(temp + 8, pCopySMBios, *smbiosTableLen);
    registry::DeleteKeyValueEx("SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data", "SMBiosData");
    registry::SetKeyValueEx("SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data", "SMBiosData", temp, REG_BINARY, *smbiosTableLen + 8);
    cpp::kFree(temp);

    return true;
}
