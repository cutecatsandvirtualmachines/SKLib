#include "efispoof.h"

bool SpoofFirmwareEntry(string entryName) {
    string guidString("{eaec226f-c9a3-477a-a826-ddc716cdc0e3}");
    GUID guid = { 0 };
    NTSTATUS ntStatus = RtlGUIDFromString(&guidString.unicode(), &guid);

    if (!NT_SUCCESS(ntStatus)) {
        return false;
    }

    char buffer[0x100] = { 0 };
    char bufferCheck[0x100] = { 0 };
    ULONG length = 0xff;
    ULONG attributes = 0;

    ntStatus = ExGetFirmwareEnvironmentVariable(&entryName.unicode(), &guid, buffer, &length, &attributes);
    if (!NT_SUCCESS(ntStatus)) {
        DbgMsg("[EFI] Could not get firmware env variable: 0x%x", ntStatus);
        return false;
    }

    memcpy(bufferCheck, buffer, length);
    rnd.c_str(buffer, length);

    if (!memcmp(buffer, bufferCheck, length)) {
        DbgMsg("[EFI] All %d bytes are equal, failed to generate spoofed value", length);
        return false;
    }

    DbgMsg("[EFI] Spoofed entry %s to %s", entryName.c_str(), buffer);

    attributes |= VARIABLE_ATTRIBUTE_NON_VOLATILE;
    ntStatus = ExSetFirmwareEnvironmentVariable(&entryName.unicode(), &guid, buffer, length, attributes);
    if (!NT_SUCCESS(ntStatus)) {
        DbgMsg("[EFI] Could not set firmware env variable: 0x%x", ntStatus);
        return false;
    }

    length = 0xff;
    ntStatus = ExGetFirmwareEnvironmentVariable(&entryName.unicode(), &guid, buffer, &length, NULL);
    if (!NT_SUCCESS(ntStatus)) {
        DbgMsg("[EFI] Could not get firmware env variable: 0x%x", ntStatus);
        return false;
    }

    if (!memcmp(buffer, bufferCheck, length)) {
        return false;
    }

    return true;
}

bool efi::Spoof(DWORD64 seed)
{
    rnd.setSeed(seed);
    rnd.setSecLevel(random::SecurityLevel::PREDICTABLE);

    PGUID pExpBootEnvironmentInformation = (PGUID)((DWORD64)winternl::ntoskrnlBase + offsets.ExpBootEnvironmentInformation);

    //_disable();
    //bool bEnableCET = CPU::DisableWriteProtection();
    //pExpBootEnvironmentInformation->Data1 = (LONG)rnd.Next(0, MAXULONG);
    //pExpBootEnvironmentInformation->Data2 = (SHORT)rnd.Next(0, MAXUSHORT);
    //pExpBootEnvironmentInformation->Data3 = (SHORT)rnd.Next(0, MAXUSHORT);
    //CPU::EnableWriteProtection(bEnableCET);
    //_enable();

    if (!SpoofFirmwareEntry("UnlockIDCopy")) {
        DbgMsg("[EFI] Failed spoofing UnlockIDCopy");
    }
    if (!SpoofFirmwareEntry("OfflineUniqueIDRandomSeed")) {
        DbgMsg("[EFI] Failed spoofing OfflineUniqueIDRandomSeed");
    }
    if (!SpoofFirmwareEntry("OfflineUniqueIDRandomSeedCRC")) {
        DbgMsg("[EFI] Failed spoofing OfflineUniqueIDRandomSeedCRC");
    }
    if (!SpoofFirmwareEntry("OfflineUniqueIDEKPub")) {
        DbgMsg("[EFI] Failed spoofing OfflineUniqueIDEKPub");
    }
    if (!SpoofFirmwareEntry("OfflineUniqueIDEKPubCRC")) {
        DbgMsg("[EFI] Failed spoofing OfflineUniqueIDEKPubCRC");
    }
    if (!SpoofFirmwareEntry("PlatformModuleData")) {
        DbgMsg("[EFI] Failed spoofing PlatformModuleData");
    }

    return true;
}
