#include "diskspoof.h"
#include <scsi.h>
#include <nvme.h>
#include <ata.h>
#include <Vmcall.h>

typedef struct _DISK_SERIAL_DATA {
    char* spoofed;
    char* orig;
    size_t sz;

    __forceinline bool operator==(_DISK_SERIAL_DATA& rhs) {
        return memcmp(this, &rhs, sizeof(*this)) == 0;
    }
    __forceinline bool operator!=(_DISK_SERIAL_DATA& rhs) {
        return !(*this == rhs);
    }
} DISK_SERIAL_DATA, * PDISK_SERIAL_DATA;

NTSTATUS(*PartmgrIoCtrlOrig)(PDEVICE_OBJECT pDeviceObj, PIRP pIrp);
NTSTATUS(*NvmeIoCtrlOrig)(PDEVICE_OBJECT pDeviceObj, PIRP pIrp);
NTSTATUS(*StorahciIoCtrlOrig)(PDEVICE_OBJECT pDeviceObj, PIRP pIrp);
NTSTATUS(*Scsi0IoCtrlOrig)(PDEVICE_OBJECT pDeviceObj, PIRP pIrp);
NTSTATUS(*Scsi1IoCtrlOrig)(PDEVICE_OBJECT pDeviceObj, PIRP pIrp);

NTSTATUS(*DumpStorportIoCtrlOrig)(PDEVICE_OBJECT pDeviceObj, PIRP pIrp);
NTSTATUS(*DumpStorahciIoCtrlOrig)(PDEVICE_OBJECT pDeviceObj, PIRP pIrp);
NTSTATUS(*DumpStornvmeIoCtrlOrig)(PDEVICE_OBJECT pDeviceObj, PIRP pIrp);

typedef NTSTATUS(__fastcall* RaidUnitRegisterInterfaces)(PHDD_EXTENSION a1);
typedef NTSTATUS(__fastcall* DiskEnableDisableFailPrediction)(PVOID device_extension, BYTE enable);
RaidUnitRegisterInterfaces pRaidUnitRegisterInterfaces = NULL;
DiskEnableDisableFailPrediction pDiskEnableDisableFailPrediction = NULL;

ULONG diskCount = 0;
PDEVICE_OBJECT* devices = nullptr;
vector<DISK_SERIAL_DATA>* vDiskSerials = nullptr;
vector<char*>* vDiskModels = nullptr;
vector<GUID*>* vGUIDs = nullptr;
vector<WWN*>* vWWNs = nullptr;
vector<IEEE*>* vIEEEs = nullptr;
DISK_HOOKS diskHooks = { 0 };

bool FindFakeDiskSerial(char* pOriginal, bool bCappedString = true) {
#ifdef DUMMY_SERIAL
    bool bFound = true;
    RtlCopyMemory(pOriginal, DUMMY_SERIAL, DISK_SERIAL_MAX_LENGTH);
#else
    bool bFound = false;
    if (!vDiskSerials
        || !MmIsAddressValid(pOriginal))
        return false;

    if (pOriginal[0] == 0)
        pOriginal++;

    for (auto& serial : *vDiskSerials) {
        if (!memcmp(serial.orig, pOriginal, serial.sz)) {
            Memory::WriteProtected(pOriginal, serial.spoofed, serial.sz);
            bFound = true;
            break;
        }
    }

    if (!bFound) {
        DISK_SERIAL_DATA data{ 0 };
        rnd.setSeed(spoofer::seed);
        int serialLen = DISK_SERIAL_MAX_LENGTH;
        if (!bCappedString) {
            serialLen = strlen(pOriginal);
        }
        data.orig = (char*)cpp::kMallocZero(serialLen + 1, PAGE_READWRITE);
        data.spoofed = (char*)cpp::kMallocZero(serialLen + 1, PAGE_READWRITE);
        data.sz = serialLen;
        RtlCopyMemory(data.orig, pOriginal, serialLen);
        RtlCopyMemory(data.spoofed, pOriginal, serialLen);

        rnd.random_shuffle_ignore_chars(data.spoofed + 2, serialLen - 2, (char*)" _-.", 4);

        vDiskSerials->Append(data);

        Memory::WriteProtected(pOriginal + 2, data.spoofed + 2, serialLen - 2);
    }
#endif

    return bFound;
}

bool FindFakeDiskSerialReset(char* pSpoofed) {
    if (!vDiskSerials
        || !MmIsAddressValid(pSpoofed))
        return false;

    for (auto& serial : *vDiskSerials) {
        if (!memcmp(serial.spoofed, pSpoofed, serial.sz)) {
            Memory::WriteProtected(pSpoofed, serial.orig, serial.sz);
            break;
        }
    }

    return true;
}

void SaveDiskModel(char* pModel) {
    if (!pModel)
        return;

    char* model = (char*)cpp::kMalloc(41, PAGE_READWRITE);
    memcpy(model, pModel, 40);
    model[40] = 0;
    vDiskModels->Append((char*)model);
    DbgMsg("[DISK] Found new disk model: %s", model);
}

bool FindFakeGUID(GUID* pOriginal) {
    if (winternl::IsNtoskrnlAddress((DWORD64)pOriginal)) {
        DbgMsg("[DISK] Trying to write GUID in ntoskrnl");
        return false;
    }

    bool bFound = false;
    for (auto& serial : *vGUIDs) {
        if (serial->Data1 == pOriginal->Data1) {
            Memory::WriteProtected(pOriginal, serial, sizeof(*pOriginal));
            bFound = true;
            break;
        }
    }
    if (!bFound) {
        rnd.setSeed(spoofer::seed);
        GUID* pBuf = (GUID*)cpp::kMalloc(sizeof(*pBuf), PAGE_READWRITE);
        RtlCopyMemory(pBuf, pOriginal, sizeof(*pBuf));
        DWORD64 data4 = rnd.Next(0ull, ~0ull);
        pBuf->Data2 = (USHORT)rnd.Next(0, MAXUSHORT);
        pBuf->Data3 = (USHORT)rnd.Next(0, MAXUSHORT);
        memcpy(pBuf->Data4, &data4, sizeof(pBuf->Data4));
        vGUIDs->Append(pBuf);

        DbgMsg("[DISK] Spoofed GUID from %x-%2x-%2x-%llx to %x-%2x-%2x-%llx",
            pOriginal->Data1, pOriginal->Data2, pOriginal->Data3, *(DWORD64*)pOriginal->Data4,
            pBuf->Data1, pBuf->Data2, pBuf->Data3, *(DWORD64*)pBuf->Data4);

        Memory::WriteProtected(pOriginal, pBuf, sizeof(*pOriginal));
        bFound = true;
    }

    return bFound;
}

bool FindFakeWWN(WWN* pOriginal) {
    if (winternl::IsNtoskrnlAddress((DWORD64)pOriginal)) {
        DbgMsg("[DISK] Trying to write WWN in ntoskrnl");
        return false;
    }

    bool bFound = false;
    for (auto& wwn : *vWWNs) {
        if (wwn->WorldWideName[0] == pOriginal->WorldWideName[0]) {
            Memory::WriteProtected(pOriginal, wwn, sizeof(*pOriginal));
            bFound = true;
            break;
        }
    }
    if (!bFound) {
        rnd.setSeed(spoofer::seed);
        WWN* pBuf = (WWN*)cpp::kMalloc(sizeof(*pBuf), PAGE_READWRITE);
        *pBuf = *pOriginal;
        rnd.random_shuffle((char*)&pBuf->WorldWideName[1], 14);
        vWWNs->Append(pBuf);
        DbgMsg("Changed WWN from %llx to %llx",
            *(DWORD64*)&pOriginal->WorldWideName[0],
            *(DWORD64*)&pBuf->WorldWideName[0]);

        Memory::WriteProtected(pOriginal, pBuf, sizeof(*pOriginal));
        bFound = true;
    }

    return bFound;
}

bool FindFakeIEEE(IEEE* pOriginal) {
    if (winternl::IsNtoskrnlAddress((DWORD64)pOriginal)) {
        DbgMsg("[DISK] Trying to write IEEE in ntoskrnl");
        return false;
    }

    bool bFound = false;
    for (auto& ieee : *vIEEEs) {
        if (ieee->ieee[0] == pOriginal->ieee[0]) {
            Memory::WriteProtected(pOriginal, ieee, sizeof(*pOriginal));
            bFound = true;
            break;
        }
    }
    if (!bFound) {
        rnd.setSeed(spoofer::seed);
        IEEE* pBuf = (IEEE*)cpp::kMalloc(sizeof(*pBuf), PAGE_READWRITE);
        *pBuf = *pOriginal;
        rnd.random_shuffle((char*)&pBuf->ieee[1], 2);
        vIEEEs->Append(pBuf);
        DbgMsg("Changed IEE from %02X%02X%02X to %02X%02X%02X",
            pOriginal->ieee[0], pOriginal->ieee[1], pOriginal->ieee[2],
            pBuf->ieee[0], pBuf->ieee[1], pBuf->ieee[2]);

        Memory::WriteProtected(pOriginal, pBuf, sizeof(*pOriginal));
        bFound = true;
    }

    return bFound;
}

#pragma region "PartmgrHook"

NTSTATUS PartInfoIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
    if (MmIsAddressValid(context)) {
        IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        if (request.BufferLength == sizeof(PARTITION_INFORMATION_EX)) {
            PPARTITION_INFORMATION_EX info = (PPARTITION_INFORMATION_EX)request.Buffer;
            if (MmIsAddressValid(info) &&
                PARTITION_STYLE_GPT == info->PartitionStyle) {
                FindFakeGUID(&info->Gpt.PartitionId);
            }
        }

        if (request.OldRoutine && irp->StackCount > 1) {
            return request.OldRoutine(device, irp, request.OldContext);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS PartLayoutIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
    if (MmIsAddressValid(context)) {
        IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        if (request.BufferLength == sizeof(DRIVE_LAYOUT_INFORMATION_EX)) {
            PDRIVE_LAYOUT_INFORMATION_EX info = (PDRIVE_LAYOUT_INFORMATION_EX)request.Buffer;
            if (MmIsAddressValid(info) &&
                PARTITION_STYLE_GPT == info->PartitionStyle) {
                FindFakeGUID(&info->Gpt.DiskId);
            }
        }

        if (request.OldRoutine && irp->StackCount > 1) {
            return request.OldRoutine(device, irp, request.OldContext);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS PartmgrIoCtrlHook(PDEVICE_OBJECT pDeviceObj, PIRP pIrp) {
    if (MmIsAddressValid(pIrp)) {
        PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(pIrp);
        switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_DISK_GET_PARTITION_INFO_EX:
            LogCaller(pIrp, HookedDriver::DriverPartmgr);
            ChangeIoc(ioc, pIrp, PartInfoIoc);
            break;
        case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:
            LogCaller(pIrp, HookedDriver::DriverPartmgr);
            ChangeIoc(ioc, pIrp, PartLayoutIoc);
            break;
        }
    }
    else {
        LogCaller(pIrp, HookedDriver::DriverPartmgr);
    }

    return PartmgrIoCtrlOrig(pDeviceObj, pIrp);
}

#pragma endregion

#pragma region "ScsiHook"

NTSTATUS ScsiMiniportIdentifyIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
    if (MmIsAddressValid(context)) {
        IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        const auto data = (SENDCMDOUTPARAMS*)(request.Buffer);

        if (MmIsAddressValid(data)) {
            const auto params = reinterpret_cast<SENDCMDOUTPARAMS*>(data->bBuffer + sizeof(SRB_IO_CONTROL));
            if (!MmIsAddressValid(params)) {
                goto _end;
            }
            const auto info = reinterpret_cast<IDINFO*>(params->bBuffer);
            if (!MmIsAddressValid(info)) {
                goto _end;
            }

            auto serial = reinterpret_cast<char*>(info->sSerialNumber);
            if (!MmIsAddressValid(serial)) {
                goto _end;
            }
            FindFakeDiskSerial(serial);
        }

    _end:
        if (request.OldRoutine && irp->StackCount > 1) {
            return request.OldRoutine(device, irp, request.OldContext);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS ScsiMiniportIdentifyThroughIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
    if (MmIsAddressValid(context)) {
        IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        const auto data = (SENDCMDINPARAMS*)(request.Buffer);

        if (MmIsAddressValid(data)) {
            SCSI_PASS_THROUGH_WITH_BUFFERS24* sptwb = (SCSI_PASS_THROUGH_WITH_BUFFERS24*)data->bBuffer;
            if (MmIsAddressValid(sptwb)
                && (sptwb->Spt.Cdb[0] == 0xa1 // NVME PASS THROUGH
                    || sptwb->Spt.Cdb[0] == 0xe4  // SCSI READ
                    || sptwb->Spt.Cdb[0] == 0xe6  // NVME READ
                    )
                ) {
                NVME_IDENTIFY_DEVICE* nvmeIdentify = sptwb->Spt.DataBufferOffset == sizeof(*sptwb) ?
                    (NVME_IDENTIFY_DEVICE*)&sptwb->DataBuf :
                    (NVME_IDENTIFY_DEVICE*)((SCSI_PASS_THROUGH_WITH_BUFFERS*)sptwb)->DataBuf;
                char serialBuf[21] = { 0 };
                if (!MmIsAddressValid(nvmeIdentify)) {
                    goto _end;
                }
                if (!MmIsAddressValid(nvmeIdentify->SerialNumber)) {
                    goto _end;
                }
                RtlCopyMemory(serialBuf, nvmeIdentify->SerialNumber, 20);
                FindFakeDiskSerial(serialBuf);
                RtlCopyMemory(nvmeIdentify->SerialNumber, serialBuf, 20);
            }
        }

    _end:
        if (request.OldRoutine && irp->StackCount > 1) {
            return request.OldRoutine(device, irp, request.OldContext);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS ScsiMiniportIdentifyThroughExIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
    if (MmIsAddressValid(context)) {
        IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        const auto data = (SENDCMDINPARAMS*)(request.Buffer);

        if (MmIsAddressValid(data)) {
            SCSI_PASS_THROUGH_WITH_BUFFERS_EX* sptwb = (SCSI_PASS_THROUGH_WITH_BUFFERS_EX*)data->bBuffer;
            if (MmIsAddressValid(sptwb)
                && (sptwb->Spt.Cdb[0] == 0xa1 // NVME PASS THROUGH
                    || sptwb->Spt.Cdb[0] == 0xe4 // SCSI READ
                    || sptwb->Spt.Cdb[0] == 0xe6 // NVME READ
                    )
                ) {
                NVME_IDENTIFY_DEVICE* nvmeIdentify = (NVME_IDENTIFY_DEVICE*)&sptwb->ucDataBuf;
                char serialBuf[21] = { 0 };
                if (!MmIsAddressValid(nvmeIdentify)) {
                    goto _end;
                }
                if (!MmIsAddressValid(nvmeIdentify->SerialNumber)) {
                    goto _end;
                }
                RtlCopyMemory(serialBuf, nvmeIdentify->SerialNumber, 20);
                FindFakeDiskSerial(serialBuf);
                RtlCopyMemory(nvmeIdentify->SerialNumber, serialBuf, 20);
            }
        }

    _end:
        if (request.OldRoutine && irp->StackCount > 1) {
            return request.OldRoutine(device, irp, request.OldContext);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS ScsiMiniportIdentifyThroughDirectIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
    if (MmIsAddressValid(context)) {
        IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        const auto data = (SENDCMDINPARAMS*)(request.Buffer);

        if (MmIsAddressValid(data)) {
            SCSI_PASS_THROUGH_DIRECT* sptd = (SCSI_PASS_THROUGH_DIRECT*)data->bBuffer;
            if (MmIsAddressValid(sptd)
                && (sptd->Cdb[0] == 0xa1 // NVME PASS THROUGH
                    || sptd->Cdb[0] == 0xe4 // SCSI READ
                    || sptd->Cdb[0] == 0xe6 // NVME READ
                    )
                )
            {
                NVME_IDENTIFY_DEVICE* nvmeIdentify = (NVME_IDENTIFY_DEVICE*)sptd->DataBuffer;
                if (!MmIsAddressValid(nvmeIdentify)) {
                    goto _end;
                }
                if (!MmIsAddressValid(nvmeIdentify->SerialNumber)) {
                    goto _end;
                }
                char serialBuf[21] = { 0 };
                RtlCopyMemory(serialBuf, nvmeIdentify->SerialNumber, 20);
                FindFakeDiskSerial(serialBuf);
                RtlCopyMemory(nvmeIdentify->SerialNumber, serialBuf, 20);
            }
        }

    _end:
        if (request.OldRoutine && irp->StackCount > 1) {
            return request.OldRoutine(device, irp, request.OldContext);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS ScsiMiniportIdentifyThroughDirectExIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
    if (MmIsAddressValid(context)) {
        IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        const auto data = (SENDCMDINPARAMS*)(request.Buffer);

        if (MmIsAddressValid(data)) {
            SCSI_PASS_THROUGH_DIRECT_EX* sptd = (SCSI_PASS_THROUGH_DIRECT_EX*)data->bBuffer;
            if (MmIsAddressValid(sptd)
                && (sptd->Cdb[0] == 0xa1 // NVME PASS THROUGH
                    || sptd->Cdb[0] == 0xe4 // SCSI READ
                    || sptd->Cdb[0] == 0xe6 // NVME READ
                    )
                )
            {
                NVME_IDENTIFY_DEVICE* nvmeIdentify = (NVME_IDENTIFY_DEVICE*)sptd->DataOutBuffer;
                if (!MmIsAddressValid(nvmeIdentify)) {
                    goto _end;
                }
                if (!MmIsAddressValid(nvmeIdentify->SerialNumber)) {
                    goto _end;
                }
                char serialBuf[21] = { 0 };
                RtlCopyMemory(serialBuf, nvmeIdentify->SerialNumber, 20);
                FindFakeDiskSerial(serialBuf);
                RtlCopyMemory(nvmeIdentify->SerialNumber, serialBuf, 20);
            }
        }

    _end:
        if (request.OldRoutine && irp->StackCount > 1) {
            return request.OldRoutine(device, irp, request.OldContext);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS NvmePassthroughIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
    if (MmIsAddressValid(context)) {
        IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        INTEL_NVME_PASS_THROUGH* data = (INTEL_NVME_PASS_THROUGH*)(request.Buffer);

        if (MmIsAddressValid(data)) {
            NVME_IDENTIFY_DEVICE* nvmeId = (NVME_IDENTIFY_DEVICE*)data->DataBuffer;

            char serialBuf[21] = { 0 };
            RtlCopyMemory(serialBuf, nvmeId->SerialNumber, 20);
            FindFakeDiskSerial(serialBuf);
            RtlCopyMemory(nvmeId->SerialNumber, serialBuf, 20);
        }

        if (request.OldRoutine && irp->StackCount > 1) {
            return request.OldRoutine(device, irp, request.OldContext);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS StorageQueryNamespaceIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
    if (MmIsAddressValid(context)) {
        IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        NVME_IDENTIFY_CONTROLLER_DATA* pNvmeNamespace = nullptr;
        STORAGE_PROTOCOL_SPECIFIC_QUERY_WITH_BUFFER* spsq = (STORAGE_PROTOCOL_SPECIFIC_QUERY_WITH_BUFFER*)request.Buffer;
        PSTORAGE_DEVICE_DESCRIPTOR_DATA psdd = (PSTORAGE_DEVICE_DESCRIPTOR_DATA)request.Buffer;
        PSTORAGE_PROTOCOL_DATA_DESCRIPTOR ptdd = (PSTORAGE_PROTOCOL_DATA_DESCRIPTOR)request.Buffer;
        if (!MmIsAddressValid(ptdd))
            goto _end;

        if (spsq->ProtocolSpecific.DataType == NVMeDataTypeLogPage) {
            //RtlZeroMemory(spsq->DataBuffer, 512);
            goto _end;
        }
        else if (spsq->ProtocolSpecific.DataType == NVMeDataTypeIdentify) {
            nvme_id_ctrl* ctrl = (nvme_id_ctrl*)spsq->DataBuffer;
            FindFakeDiskSerial((char*)ctrl->sn);
            FindFakeIEEE((IEEE*)ctrl->ieee);
            goto _end;
        }

        if (ptdd->ProtocolSpecificData.ProtocolType != ProtocolTypeNvme
            || ptdd->ProtocolSpecificData.DataType != NVMeDataTypeIdentify) {

            if (psdd->desc.Size == (sizeof(*psdd) + psdd->desc.RawPropertiesLength)
                && MmIsAddressValid((PVOID)((DWORD64)psdd->desc.RawDeviceProperties + psdd->desc.SerialNumberOffset))
                ) {
                FindFakeDiskSerial((char*)((DWORD64)psdd->desc.RawDeviceProperties + psdd->desc.SerialNumberOffset));
            }
            goto _end;
        }

        pNvmeNamespace = (NVME_IDENTIFY_CONTROLLER_DATA*)((DWORD64)ptdd + ptdd->ProtocolSpecificData.ProtocolDataOffset + offsetof(STORAGE_PROPERTY_QUERY, AdditionalParameters));
        FindFakeDiskSerial((char*)pNvmeNamespace->SN);
        FindFakeIEEE((IEEE*)pNvmeNamespace->IEEE);

    _end:
        if (request.OldRoutine && irp->StackCount > 1) {
            return request.OldRoutine(device, irp, request.OldContext);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS StorageQueryPropertyIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
    if (MmIsAddressValid(context)) {
        IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        PSTORAGE_PROTOCOL_DATA_DESCRIPTOR ptdd = (PSTORAGE_PROTOCOL_DATA_DESCRIPTOR)request.Buffer;
        if (MmIsAddressValid(ptdd) &&
            request.BufferLength == sizeof(STORAGE_DEVICE_DESCRIPTOR)
            ) {
            DWORD64 protDataOffset = ptdd->ProtocolSpecificData.ProtocolDataOffset;
            DWORD64 protDataLen = ptdd->ProtocolSpecificData.ProtocolDataLength;
            char* pSerial = (char*)((DWORD64)ptdd + protDataOffset);

            if (ptdd->ProtocolSpecificData.ProtocolType != ProtocolTypeNvme
                || ptdd->ProtocolSpecificData.DataType != NVMeDataTypeIdentify) {
                goto _end;
            }

            if (pSerial[12]) {
                FindFakeDiskSerial(pSerial + 12);
            }
        }

    _end:
        if (request.OldRoutine && irp->StackCount > 1) {
            return request.OldRoutine(device, irp, request.OldContext);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS AtaPassIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
    if (MmIsAddressValid(context)) {
        IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        if (!MmIsAddressValid(request.Buffer)) {
            goto _end;
        }
        if (request.BufferLength == (sizeof(ATA_PASS_THROUGH_EX) + sizeof(PIDENTIFY_DEVICE_DATA))) {
            PATA_PASS_THROUGH_EX pte = (PATA_PASS_THROUGH_EX)request.Buffer;
            ULONG offset = (ULONG)pte->DataBufferOffset;
            if (MmIsAddressValid(pte) && offset && offset < request.BufferLength) {
                PIDENTIFY_DEVICE_DATA pDeviceData = ((PIDENTIFY_DEVICE_DATA)((PBYTE)request.Buffer + offset));
                PCHAR serial = (PCHAR)pDeviceData->SerialNumber;
                FindFakeDiskSerial(serial);

                char serialBuf[31] = { 0 };
                memcpy(serialBuf, pDeviceData->CurrentMediaSerialNumber, 30);
                FindFakeDiskSerial(serialBuf);
                memcpy(pDeviceData->CurrentMediaSerialNumber, serialBuf, 30);

                WWN* pWwn = (WWN*)&pDeviceData->WorldWideName;
                FindFakeWWN(pWwn);
            }
        }
        else if ((offsetof(ATA_PASS_THROUGH_EX_WITH_BUFFERS, ucDataBuf) + SMART_LOG_SECTOR_SIZE) == request.BufferLength) {
            ATA_PASS_THROUGH_EX_WITH_BUFFERS* ab = (ATA_PASS_THROUGH_EX_WITH_BUFFERS*)request.Buffer;
            if (ab->apt.AtaFlags == ATA_FLAGS_DATA_IN
                && ab->apt.DataTransferLength == SMART_LOG_SECTOR_SIZE
                ) {
                ata_identify_device* aid = (ata_identify_device*)((DWORD64)request.Buffer + ab->apt.DataBufferOffset);
                FindFakeDiskSerial((char*)aid->serial_no);
            }
        }

    _end:
        if (request.OldRoutine && irp->StackCount > 1) {
            return request.OldRoutine(device, irp, request.OldContext);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS AtaPassDirectIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
    if (MmIsAddressValid(context)) {
        IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        if (request.BufferLength == (sizeof(ATA_PASS_THROUGH_EX) + sizeof(PIDENTIFY_DEVICE_DATA))) {
            PATA_PASS_THROUGH_DIRECT pte = (PATA_PASS_THROUGH_DIRECT)request.Buffer;
            if (MmIsAddressValid(pte) && pte->Length < request.BufferLength) {
                PIDENTIFY_DEVICE_DATA pDeviceData = (PIDENTIFY_DEVICE_DATA)pte->DataBuffer;
                PCHAR serial = (PCHAR)pDeviceData->SerialNumber;
                FindFakeDiskSerial(serial);

                char serialBuf[31] = { 0 };
                memcpy(serialBuf, pDeviceData->CurrentMediaSerialNumber, 30);
                FindFakeDiskSerial(serialBuf);
                memcpy(pDeviceData->CurrentMediaSerialNumber, serialBuf, 30);

                WWN* pWwn = (WWN*)&pDeviceData->WorldWideName;
                FindFakeWWN(pWwn);
            }
        }

        if (request.OldRoutine && irp->StackCount > 1) {
            return request.OldRoutine(device, irp, request.OldContext);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS SmartDataIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
    if (MmIsAddressValid(context)) {
        IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        if (!MmIsAddressValid(request.Buffer)) {
            goto _end;
        }
        if (request.BufferLength == sizeof(SENDCMDOUTPARAMS)) {
            PCHAR serial = ((PIDSECTOR)((PSENDCMDOUTPARAMS)request.Buffer)->bBuffer)->sSerialNumber;
            FindFakeDiskSerial(serial);
        }
        else if (request.BufferLength == (sizeof(SENDCMDOUTPARAMS) - 1 + SMART_LOG_SECTOR_SIZE)) {
            SENDCMDOUTPARAMS* outParam = (SENDCMDOUTPARAMS*)request.Buffer;
            ata_identify_device* aid = (ata_identify_device*)((DWORD64)outParam->bBuffer);
            if (MmIsAddressValid(aid) && MmIsAddressValid(aid->serial_no))
                FindFakeDiskSerial((char*)aid->serial_no);
        }

    _end:
        if (request.OldRoutine && irp->StackCount > 1) {
            return request.OldRoutine(device, irp, request.OldContext);
        }
    }

    return STATUS_SUCCESS;
}

#pragma endregion

#pragma region "DiskHook"

NTSTATUS DiskControlEx(PDRIVER_DISPATCH pOriginal, PDEVICE_OBJECT pDeviceObj, PIRP pIrp, HookedDriver hookedDriver) {
    if (!MmIsAddressValid(pOriginal))
        return STATUS_NOT_IMPLEMENTED;

    if (MmIsAddressValid(pIrp)) {
        PSTORAGE_PROPERTY_QUERY pQuery;
        PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(pIrp);
        if (!MmIsAddressValid(ioc))
            return pOriginal(pDeviceObj, pIrp);

        SRB_IO_CONTROL* miniport_query = nullptr;
        switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_ATA_PASS_THROUGH_DIRECT:
            ChangeIoc(ioc, pIrp, AtaPassDirectIoc);
            break;
        case IOCTL_ATA_PASS_THROUGH:
            ChangeIoc(ioc, pIrp, AtaPassIoc);
            break;
        case IOCTL_STORAGE_QUERY_PROPERTY:
            pQuery = (PSTORAGE_PROPERTY_QUERY)pIrp->AssociatedIrp.SystemBuffer;
            if (MmIsAddressValid(pQuery)) {
                if (StorageDeviceProperty == pQuery->PropertyId
                    || StorageAdapterProtocolSpecificProperty == pQuery->PropertyId
                    || StorageDeviceProtocolSpecificProperty == pQuery->PropertyId) {
                    if (PropertyStandardQuery == pQuery->QueryType) {
                        ChangeIoc(ioc, pIrp, StorageQueryNamespaceIoc);
                    }
                    else {
                        ChangeIoc(ioc, pIrp, StorageQueryPropertyIoc);
                    }
                }
            }

            break;
        case IOCTL_STORAGE_PROTOCOL_COMMAND:
            break;
        case SMART_RCV_DRIVE_DATA:
            ChangeIoc(ioc, pIrp, SmartDataIoc);
            break;
        case IOCTL_SCSI_PASS_THROUGH_DIRECT:
            ChangeIoc(ioc, pIrp, ScsiMiniportIdentifyThroughDirectIoc);
            break;
        case IOCTL_SCSI_PASS_THROUGH:
            ChangeIoc(ioc, pIrp, ScsiMiniportIdentifyThroughIoc);
            break;
        case IOCTL_SCSI_PASS_THROUGH_DIRECT_EX:
            ChangeIoc(ioc, pIrp, ScsiMiniportIdentifyThroughDirectExIoc);
            break;
        case IOCTL_SCSI_PASS_THROUGH_EX:
            ChangeIoc(ioc, pIrp, ScsiMiniportIdentifyThroughExIoc);
            break;
        case IOCTL_IDE_PASS_THROUGH:
            pIrp->IoStatus.Information = 0;
            pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
            IofCompleteRequest(pIrp, 0);
            return STATUS_NOT_SUPPORTED;
        case IOCTL_SCSI_MINIPORT:
            miniport_query = (SRB_IO_CONTROL*)(pIrp->AssociatedIrp.SystemBuffer);

            if (MmIsAddressValid(miniport_query)) {
                switch (miniport_query->ControlCode) {
                case IOCTL_SCSI_MINIPORT_IDENTIFY:
                    ChangeIoc(ioc, pIrp, ScsiMiniportIdentifyIoc);
                    break;
                case IOCTL_INTEL_NVME_PASS_THROUGH:
                    ChangeIoc(ioc, pIrp, NvmePassthroughIoc);
                    break;
                    //case CTL_CODE(FILE_DEVICE_CONTROLLER, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS):
                case NVME_PASS_THROUGH_SRB_IO_CODE:
                    pIrp->IoStatus.Information = 0;
                    pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
                    IofCompleteRequest(pIrp, 0);
                    return STATUS_NOT_SUPPORTED;
                }
            }
            break;
        }
    }

    return pOriginal(pDeviceObj, pIrp);
}

NTSTATUS Scsi0IoCtrlHook(PDEVICE_OBJECT pDeviceObj, PIRP pIrp) {
    return DiskControlEx(Scsi0IoCtrlOrig, pDeviceObj, pIrp, HookedDriver::DriverScsi);
}

NTSTATUS Scsi1IoCtrlHook(PDEVICE_OBJECT pDeviceObj, PIRP pIrp) {
    return DiskControlEx(Scsi1IoCtrlOrig, pDeviceObj, pIrp, HookedDriver::DriverScsi);
}

NTSTATUS DiskControl(PDEVICE_OBJECT pDeviceObj, PIRP pIrp) {
    for (ULONG i = 0; i < diskHooks.length; i++) {
        DISK_DRIVER_HOOK_INFO hookInfo = diskHooks.hookInfo[i];
        if (hookInfo.DeviceObject == pDeviceObj) {
            return DiskControlEx(hookInfo.Original, pDeviceObj, pIrp, DriverDisk);
        }
    }
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NvmeControl(PDEVICE_OBJECT pDeviceObj, PIRP pIrp) {
    return DiskControlEx(NvmeIoCtrlOrig, pDeviceObj, pIrp, DriverNvme);
}

NTSTATUS StorahciControl(PDEVICE_OBJECT pDeviceObj, PIRP pIrp) {
    return DiskControlEx(StorahciIoCtrlOrig, pDeviceObj, pIrp, DriverScsi);
}

NTSTATUS DumpStornvmeControl(PDEVICE_OBJECT pDeviceObj, PIRP pIrp) {
    return DiskControlEx(DumpStornvmeIoCtrlOrig, pDeviceObj, pIrp, DriverDump);
}

NTSTATUS DumpStorahciControl(PDEVICE_OBJECT pDeviceObj, PIRP pIrp) {
    return DiskControlEx(DumpStorahciIoCtrlOrig, pDeviceObj, pIrp, DriverDump);
}

NTSTATUS DumpStorportControl(PDEVICE_OBJECT pDeviceObj, PIRP pIrp) {
    return DiskControlEx(DumpStorportIoCtrlOrig, pDeviceObj, pIrp, DriverDump);
}

#pragma endregion

#pragma region "SpoofRaid"

PDEVICE_OBJECT GetRaidDevice(const wchar_t* deviceName)
{
    UNICODE_STRING raidPort;
    RtlInitUnicodeString(&raidPort, deviceName);
    PFILE_OBJECT fileObject = nullptr;
    PDEVICE_OBJECT deviceObject = nullptr;
    auto status = IoGetDeviceObjectPointer(&raidPort, FILE_READ_DATA, &fileObject, &deviceObject);
    if (!NT_SUCCESS(status))
    {
        return nullptr;
    }
    return deviceObject->DriverObject->DeviceObject;
}

#define IDE_COMMAND_IDENTIFY                  0xEC

BOOLEAN PrintAndSaveSerialATA(PDEVICE_OBJECT pDevice) {
    if (!pDevice)
        return FALSE;

    BOOLEAN bRes = FALSE;
    ULONG aptelen;
    ATA_PASS_THROUGH_EX* apte;
    NTSTATUS Status;
    IDENTIFY_DEVICE_DATA* idd;
    aptelen = sizeof(ATA_PASS_THROUGH_EX) + 512;

    apte = (ATA_PASS_THROUGH_EX*)cpp::kMalloc(aptelen, PAGE_READWRITE);
    RtlZeroMemory(apte, aptelen);
    apte->Length = sizeof(ATA_PASS_THROUGH_EX);
    apte->AtaFlags = ATA_FLAGS_DATA_IN;
    apte->DataTransferLength = aptelen - sizeof(ATA_PASS_THROUGH_EX);
    apte->TimeOutValue = 3;
    apte->DataBufferOffset = apte->Length;
    apte->CurrentTaskFile[6] = IDE_COMMAND_IDENTIFY;

    Status = IOCTL::SendIoctl(pDevice, IOCTL_ATA_PASS_THROUGH, apte, aptelen, apte, aptelen);

    if (NT_SUCCESS(Status)) {
        idd = (IDENTIFY_DEVICE_DATA*)((char*)apte + sizeof(ATA_PASS_THROUGH_EX));
        DbgMsg("[IOCTL] Got serial from IOCTL_ATA_PASS_THROUGH for %wZ: %s", pDevice->DriverObject->DriverName, idd->SerialNumber);
        SaveDiskModel((char*)idd->ModelNumber);
        //FindFakeDiskSerial((char*)idd->SerialNumber);
        bRes = TRUE;
    }

    cpp::kFree(apte);
    return bRes;
}

BOOLEAN PrintAndSaveSerialQueryStorageProperty(PDEVICE_OBJECT pDevice) {
    if (!pDevice)
        return FALSE;

    BOOLEAN bRes = FALSE;
    STORAGE_PROPERTY_QUERY query = { StorageDeviceProperty, PropertyStandardQuery, {0} };
    STORAGE_DEVICE_DESCRIPTOR_DATA data = { 0 };
    memset(&data, 0, sizeof(data));

    DWORD num_out;
    if (NT_SUCCESS(IOCTL::SendIoctl(pDevice, IOCTL_STORAGE_QUERY_PROPERTY,
        &query, sizeof(query), &data, sizeof(data)))) {
        DbgMsg("[IOCT] Got serial from IOCTL_STORAGE_QUERY_PROPERTY for %wZ: %s",
            pDevice->DriverObject->DriverName,
            (char*)(data.raw + data.desc.SerialNumberOffset));
        SaveDiskModel((char*)(data.raw + data.desc.ProductIdOffset));
        //FindFakeDiskSerial((char*)(data.raw + data.desc.SerialNumberOffset));
        bRes = TRUE;
    }
    return bRes;
}

bool SpoofRaid() {
    bool bRes = false;

    UINT64 IdentityOffset = offsets.RaidIdentity;
    if (!IdentityOffset) {
        DbgMsg("[DISK] Error: failed getting _RAID_UNIT_EXTENSION!Identity offset");
        return false;
    }

    UINT64 StorSerialNumberOffset = offsets.ScsiSerialNumber;
    if (!StorSerialNumberOffset) {
        DbgMsg("[DISK] Error: failed getting _STOR_SCSI_IDENTITY!SerialNumber offset");
        return false;
    }

    UINT64 RaidSerialNumberOffset = offsets.RaidSerialNumber;
    if (!RaidSerialNumberOffset) {
        DbgMsg("[DISK] Error: failed getting _RAID_UNIT_EXTENSION!SerialNumber offset");
        return false;
    }

    wchar_t raidBuffer[] = L"\\Device\\RaidPort0";
    for (auto i = 0; i < 64; i++)
    {
        raidBuffer[16] = i + '0';
        auto* device = GetRaidDevice(raidBuffer);
        if (!device) {
            DbgMsg("[RAID] Failed referencing device object for %ws", raidBuffer);
            continue;
        }

        HOOK_SECONDARY_INFO hkSecondaryInfo = { 0 };
        hkSecondaryInfo.pOrigFn = i == 0 ? (PVOID*)&Scsi0IoCtrlOrig : (PVOID*)&Scsi1IoCtrlOrig;

        if (!EPT::HookExec(device->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL], i == 0 ? Scsi0IoCtrlHook : Scsi1IoCtrlHook, hkSecondaryInfo)) {
            DbgMsg("[RAID] Failed hooking %ws IoDeviceCtrl", raidBuffer);
            bRes = false;
            //ObDereferenceObject(device);
            break;
        }
        else {
            DbgMsg("[RAID] Hooked %ws IoDeviceCtrl", raidBuffer);
        }

        //Windows 11 does not seem to have this offset
        if (VALID_OFFSET(StorSerialNumberOffset)) {
            DWORD64* pIdentity = (DWORD64*)((DWORD64)device->DeviceExtension + IdentityOffset);
            if (MmIsAddressValid(pIdentity)) {
                char* pSerialNumber = (char*)(*pIdentity + StorSerialNumberOffset);

                if (MmIsAddressValid(pSerialNumber)
                    && cpp::isalnumstr_s(pSerialNumber, DISK_SERIAL_MAX_LENGTH)
                    )
                    FindFakeDiskSerial(pSerialNumber);
            }
        }

        char* pSerialNumber2 = (char*)((DWORD64)device->DeviceExtension + RaidSerialNumberOffset);
        if (MmIsAddressValid(pSerialNumber2)
            && cpp::isalnumstr(pSerialNumber2)
            )
            FindFakeDiskSerial(pSerialNumber2);

        //if (!PrintAndSaveSerialATA(device))
        //    PrintAndSaveSerialQueryStorageProperty(device);

        //ObDereferenceObject(device);
        bRes = true;
    }

    return bRes;
}

#pragma endregion

#pragma region "DisableFailurePrediction"

bool DisableFailurePrediction() {
    NTSTATUS ntStatus;
    ULONG success = 0, total = 0;

    for (ULONG i = 0; i < diskCount; ++i) {
        PDEVICE_OBJECT device = devices[i];

        HOOK_SECONDARY_INFO hkSecondaryInfo = { 0 };
        diskHooks.hookInfo[diskHooks.length].DeviceObject = device;
        hkSecondaryInfo.pOrigFn = (PVOID*)&diskHooks.hookInfo[diskHooks.length++].Original;

        if (!EPT::HookExec(device->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL], DiskControl, hkSecondaryInfo)) {
            DbgMsg("[DISK] Failed hooking %ws IoDeviceCtrl", device->DriverObject->DriverName.Buffer);
        }
        else {
            DbgMsg("[DISK] Hooked %ws IoDeviceCtrl", device->DriverObject->DriverName.Buffer);
        }

        IOCTL::SendIoctl(device, IOCTL_DISK_UPDATE_PROPERTIES);
        //ObDereferenceObject(device);
    }

    return true;
}

#pragma endregion

bool disks::Spoof(DWORD64 seed)
{
    bool bRes = true;
    NTSTATUS ntStatus;
    PDRIVER_OBJECT pDiskObj = IOCTL::GetDriverObj("\\Driver\\Disk");
    if (!(STATUS_BUFFER_TOO_SMALL == (ntStatus = IoEnumerateDeviceObjectList(pDiskObj, 0, 0, &diskCount)) && diskCount)) {
        DbgMsg("[DISK] Failed to get disk device list size (got %d): %x", diskCount, ntStatus);
        return false;
    }

    ULONG size = diskCount * sizeof(PDEVICE_OBJECT);
    if (!devices) {
        devices = (PDEVICE_OBJECT*)cpp::kMalloc(size, PAGE_READWRITE);
        RtlZeroMemory(devices, size);
        if (!(NT_SUCCESS(ntStatus = IoEnumerateDeviceObjectList(pDiskObj, devices, size, &diskCount)) && diskCount)) {
            DbgMsg("[DISK] IoEnumerateDeviceObjectList failed: 0x%x", ntStatus);
            return false;
        }
    }
    else {
        UINT64 IdentityOffset = offsets.RaidIdentity;
        if (!IdentityOffset) {
            DbgMsg("[DISK] Error: failed getting _RAID_UNIT_EXTENSION!Identity offset");
            return false;
        }

        UINT64 StorSerialNumberOffset = offsets.ScsiSerialNumber;
        if (!StorSerialNumberOffset) {
            DbgMsg("[DISK] Error: failed getting _STOR_SCSI_IDENTITY!SerialNumber offset");
            return false;
        }

        UINT64 RaidSerialNumberOffset = offsets.RaidSerialNumber;
        if (!RaidSerialNumberOffset) {
            DbgMsg("[DISK] Error: failed getting _RAID_UNIT_EXTENSION!SerialNumber offset");
            return false;
        }

        PDEVICE_OBJECT pObject = NULL;
        PFILE_OBJECT pFileObj = NULL;
        wchar_t raidBuffer[] = L"\\Device\\RaidPort0";
        for (auto i = 0; i < 64; i++)
        {
            raidBuffer[16] = i + '0';
            string DestinationString(raidBuffer);
            NTSTATUS status = IoGetDeviceObjectPointer(&DestinationString.unicode(), FILE_READ_DATA, &pFileObj, &pObject);
            if (!NT_SUCCESS(status)) {
                DbgMsg("[RAID] Failed referencing device object for %ws: 0x%x", raidBuffer, status);
                continue;
            }

            PDRIVER_OBJECT pDriver = pObject->DriverObject;
            PDEVICE_OBJECT pDevice = pDriver->DeviceObject;
            while (pDevice->NextDevice != NULL)
            {
                if (pDevice->DeviceType == FILE_DEVICE_DISK)
                {
                    PHDD_EXTENSION pDeviceHDD = (PHDD_EXTENSION)pDevice->DeviceExtension;
                    FindFakeDiskSerialReset(pDeviceHDD->pHDDSerial);
                }
                pDevice = pDevice->NextDevice;
            }

            //Windows 11 does not seem to have this offset
            if (VALID_OFFSET(StorSerialNumberOffset)) {
                DWORD64* pIdentity = (DWORD64*)((DWORD64)pDevice->DeviceExtension + IdentityOffset);
                if (MmIsAddressValid(pIdentity)) {
                    char* pSerialNumber = (char*)(*pIdentity + StorSerialNumberOffset);

                    if (MmIsAddressValid(pSerialNumber)
                        && cpp::isalnumstr_s(pSerialNumber, DISK_SERIAL_MAX_LENGTH)
                        )
                        FindFakeDiskSerialReset(pSerialNumber);
                }
            }

            char* pSerialNumber2 = (char*)((DWORD64)pDevice->DeviceExtension + RaidSerialNumberOffset);
            if (MmIsAddressValid(pSerialNumber2)
                && cpp::isalnumstr(pSerialNumber2)
                )
                FindFakeDiskSerialReset(pSerialNumber2);

            ObDereferenceObject(pObject);
            ObDereferenceObject(pFileObj);
        }

        for (auto& serial : *vDiskSerials) {
            rnd.setSeed(spoofer::seed);
            int serialLen = serial.sz;
            serial.spoofed = (char*)cpp::kMallocZero(serialLen + 1, PAGE_READWRITE);
            RtlCopyMemory(serial.spoofed, serial.orig, serialLen);
            rnd.random_shuffle_ignore_chars(serial.spoofed + 2, serialLen - 2, (char*)" _-.", 4);
        }

        for (auto i = 0; i < 2; i++)
        {
            raidBuffer[16] = i + '0';
            string DestinationString(raidBuffer);
            NTSTATUS status = IoGetDeviceObjectPointer(&DestinationString.unicode(), FILE_READ_DATA, &pFileObj, &pObject);
            if (!NT_SUCCESS(status)) {
                DbgMsg("[RAID] Failed referencing device object for %ws: 0x%x", raidBuffer, status);
                continue;
            }

            PDRIVER_OBJECT pDriver = pObject->DriverObject;
            PDEVICE_OBJECT pDevice = pDriver->DeviceObject;
            while (pDevice->NextDevice != NULL)
            {
                if (pDevice->DeviceType == FILE_DEVICE_DISK)
                {
                    PHDD_EXTENSION pDeviceHDD = (PHDD_EXTENSION)pDevice->DeviceExtension;
                    if(pDeviceHDD && pDeviceHDD->pHDDSerial)
                        FindFakeDiskSerial(pDeviceHDD->pHDDSerial, !cpp::isalnumstr(pDeviceHDD->pHDDSerial));
                }
                pDevice = pDevice->NextDevice;
            }

            //Windows 11 does not seem to have this offset
            if (VALID_OFFSET(StorSerialNumberOffset)) {
                DWORD64* pIdentity = (DWORD64*)((DWORD64)pDevice->DeviceExtension + IdentityOffset);
                if (MmIsAddressValid(pIdentity)) {
                    char* pSerialNumber = (char*)(*pIdentity + StorSerialNumberOffset);

                    if (MmIsAddressValid(pSerialNumber)
                        && cpp::isalnumstr_s(pSerialNumber, DISK_SERIAL_MAX_LENGTH)
                        )
                        FindFakeDiskSerial(pSerialNumber);
                }
            }

            char* pSerialNumber2 = (char*)((DWORD64)pDevice->DeviceExtension + RaidSerialNumberOffset);
            if (MmIsAddressValid(pSerialNumber2)
                && cpp::isalnumstr(pSerialNumber2)
                )
                FindFakeDiskSerial(pSerialNumber2);

            ObDereferenceObject(pObject);
            ObDereferenceObject(pFileObj);
        }

        DisableFailurePrediction();
        return true;
    }
    //ObDereferenceObject(pDiskObj);

    rnd.setSeed(seed);
    rnd.setSecLevel(random::SecurityLevel::PREDICTABLE);

    vDiskSerials = (vector<DISK_SERIAL_DATA>*)cpp::kMalloc(sizeof(*vDiskSerials), PAGE_READWRITE);
    RtlZeroMemory(vDiskSerials, sizeof(*vDiskSerials));
    vDiskSerials->Init();
    vDiskSerials->reserve(64);

    vDiskModels = (vector<char*>*)cpp::kMalloc(sizeof(*vDiskModels), PAGE_READWRITE);
    RtlZeroMemory(vDiskModels, sizeof(*vDiskModels));
    vDiskModels->Init();
    vDiskModels->reserve(64);

    vGUIDs = (vector<GUID*>*)cpp::kMalloc(sizeof(*vGUIDs), PAGE_READWRITE);
    RtlZeroMemory(vGUIDs, sizeof(*vGUIDs));
    vGUIDs->Init();
    vGUIDs->reserve(64);

    vWWNs = (vector<WWN*>*)cpp::kMalloc(sizeof(*vWWNs), PAGE_READWRITE);
    RtlZeroMemory(vWWNs, sizeof(*vWWNs));
    vWWNs->Init();
    vWWNs->reserve(64);

    vIEEEs = (vector<IEEE*>*)cpp::kMalloc(sizeof(*vIEEEs), PAGE_READWRITE);
    RtlZeroMemory(vIEEEs, sizeof(*vIEEEs));
    vIEEEs->Init();
    vIEEEs->reserve(64);

    vmm::vHooks->reserve(10);
#pragma region "Partmgr"
    HOOK_SECONDARY_INFO hkSecondaryInfo = { 0 };
    hkSecondaryInfo.pOrigFn = (PVOID*)&PartmgrIoCtrlOrig;
    PDRIVER_OBJECT pDrivObj = IOCTL::GetDriverObj("\\Driver\\partmgr");

    if (!EPT::HookExec(pDrivObj->MajorFunction[IRP_MJ_DEVICE_CONTROL], &PartmgrIoCtrlHook, hkSecondaryInfo)) {
        DbgMsg("[DISK] Failed hooking partmgr IoDeviceCtrl");
        bRes = false;
    }
    else {
        DbgMsg("[DISK] Hooked partmgr IoDeviceCtrl");
        bRes = true;
    }
    //ObDereferenceObject(pDrivObj);
    if (!bRes)
        return false;
#pragma endregion

#pragma region "HDD"
    INT HDD_count = 0;

    PVOID pStorport = Memory::GetKernelAddress((PCHAR)"storport.sys");
    UINT64 RegDevIntOFF = offsets.RaidUnitRegInterface;
    if (RegDevIntOFF == ~0ull
        || !pStorport) {
        DbgMsg("[DISK] Failed getting RaidUnitRegisterInterfaces offset, probably windows 11 build!");
        pRaidUnitRegisterInterfaces = nullptr;
    }
    else {
        pRaidUnitRegisterInterfaces = (RaidUnitRegisterInterfaces)((UINT64)pStorport + RegDevIntOFF);
    }

    PDEVICE_OBJECT pObject = NULL;
    PFILE_OBJECT pFileObj = NULL;
    wchar_t raidBuffer[] = L"\\Device\\RaidPort0";
    for (auto i = 0; i < 64; i++)
    {
        raidBuffer[16] = i + '0';
        string DestinationString(raidBuffer);
        NTSTATUS status = IoGetDeviceObjectPointer(&DestinationString.unicode(), FILE_READ_DATA, &pFileObj, &pObject);
        if (!NT_SUCCESS(status)) {
            DbgMsg("[RAID] Failed referencing device object for %ws: 0x%x", raidBuffer, status);
            continue;
        }

        PDRIVER_OBJECT pDriver = pObject->DriverObject;
        PDEVICE_OBJECT pDevice = pDriver->DeviceObject;
        while (pDevice->NextDevice != NULL)
        {
            if (pDevice->DeviceType == FILE_DEVICE_DISK)
            {
                PHDD_EXTENSION pDeviceHDD = (PHDD_EXTENSION)pDevice->DeviceExtension;
                if (pDeviceHDD && pDeviceHDD->pHDDSerial) {
                    FindFakeDiskSerial(pDeviceHDD->pHDDSerial, !cpp::isalnumstr(pDeviceHDD->pHDDSerial));
                    //reset the registry entries to the faked serials
                    if (pRaidUnitRegisterInterfaces)
                        status = pRaidUnitRegisterInterfaces(pDeviceHDD);
                    HDD_count++;
                }
            }
            pDevice = pDevice->NextDevice;
        }

        ObDereferenceObject(pObject);
        ObDereferenceObject(pFileObj);
    }
#pragma endregion

#pragma region "NVME"

    pDrivObj = IOCTL::GetDriverObj("\\Driver\\stornvme");
    if (pDrivObj) {
        hkSecondaryInfo.pOrigFn = (PVOID*)&NvmeIoCtrlOrig;
        if (!EPT::HookExec(pDrivObj->MajorFunction[IRP_MJ_DEVICE_CONTROL], &NvmeControl, hkSecondaryInfo)) {
            DbgMsg("[DISK] Failed hooking stornvme IoDeviceCtrl");
        }
        else {
            DbgMsg("[DISK] Hooked stornvme IoDeviceCtrl");
        }
        //ObDereferenceObject(pDrivObj);
        if (!bRes)
            return false;
    }
    else {
        DbgMsg("[DISK] Could not get stornvme pointer");
    }

#pragma endregion

#pragma region "Storahci"

    pDrivObj = IOCTL::GetDriverObj("\\Driver\\storahci");
    if (pDrivObj) {
        hkSecondaryInfo.pOrigFn = (PVOID*)&StorahciIoCtrlOrig;
        if (!EPT::HookExec(pDrivObj->MajorFunction[IRP_MJ_DEVICE_CONTROL], &StorahciControl, hkSecondaryInfo)) {
            DbgMsg("[DISK] Failed hooking storahci IoDeviceCtrl");
        }
        else {
            DbgMsg("[DISK] Hooked storahci IoDeviceCtrl");
        }
        //ObDereferenceObject(pDrivObj);
        if (!bRes)
            return false;
    }
    else {
        DbgMsg("[DISK] Could not get storahci pointer");
    }

#pragma endregion

#pragma region "Raid"
    bRes = SpoofRaid();
    if (!bRes)
        return false;
#pragma endregion

#pragma region "DiskFailurePrediction"
    bRes = DisableFailurePrediction();
#pragma endregion

    return bRes;
}
