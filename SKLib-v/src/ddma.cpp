#include "ddma.h"

#include <ntddscsi.h>
#include <scsi.h>

#define ATA_IO_TIMEOUT (2)
#define ATA_CMD_READ_SECTORS (0x20)
#define ATA_CMD_WRITE_SECTORS (0x30)
#define ATA_DEVICE_TRANSPORT_LBA (0x40)
#define ATA_SECTOR_SIZE (0x200)
#define SCSI_SECTOR_SIZE ATA_SECTOR_SIZE

NTSTATUS AtaIssueCommand(IN PDEVICE_OBJECT device, IN USHORT flag, IN UCHAR command, IN PVOID buffer) {
    KEVENT event;
    KeInitializeEvent(&event, SynchronizationEvent, FALSE);

    ATA_PASS_THROUGH_DIRECT request = { 0 };
    request.Length = sizeof(request);
    request.AtaFlags = flag | ATA_FLAGS_USE_DMA;
    request.DataTransferLength = PAGE_SIZE;
    request.TimeOutValue = ATA_IO_TIMEOUT;
    request.DataBuffer = buffer;

    // For the sake of brevity this uses the first sectors (unsafe!)
    request.CurrentTaskFile[1] = PAGE_SIZE / ATA_SECTOR_SIZE;
    request.CurrentTaskFile[5] = ATA_DEVICE_TRANSPORT_LBA;
    request.CurrentTaskFile[6] = command;

    IO_STATUS_BLOCK ioStatusBlock;
    PIRP irp = IoBuildDeviceIoControlRequest(IOCTL_ATA_PASS_THROUGH_DIRECT, device, &request,
        sizeof(request), &request, sizeof(request), FALSE,
        &event, &ioStatusBlock);

    if (!irp) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS status = IoCallDriver(device, irp);

    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatusBlock.Status;
    }

    return status;
}

// Build the 10-bytes SCSI command descriptor block

BOOLEAN SCSIBuild10CDB(PSCSI_PASS_THROUGH_DIRECT srb, ULONGLONG offset, ULONG length, BOOLEAN Write) {
    if (!srb || offset >= 0x20000000000 || length < 1)
        return FALSE;

    LPCH cdb = (LPCH)srb->Cdb;

    if (Write == FALSE) {
        cdb[0] = SCSIOP_READ;
        cdb[1] = 0;
    }
    else {
        cdb[0] = SCSIOP_WRITE;
        cdb[1] = 0;
    }
    DWORD32 LBA = (DWORD32)(offset / SCSI_SECTOR_SIZE);

    cdb[2] = ((LPCH)&LBA)[3];
    cdb[3] = ((LPCH)&LBA)[2];
    cdb[4] = ((LPCH)&LBA)[1];
    cdb[5] = ((LPCH)&LBA)[0];
    cdb[6] = 0x00;

    SHORT CDBTLen = (SHORT)(length / SCSI_SECTOR_SIZE);
    cdb[7] = ((LPCH)&CDBTLen)[1];
    cdb[8] = ((LPCH)&CDBTLen)[0];
    cdb[9] = 0x00;
    return TRUE;
}

NTSTATUS ScsiIssueCommand(IN PDEVICE_OBJECT device, IN UCHAR operationCode, IN PVOID buffer) {
    KEVENT event;
    KeInitializeEvent(&event, SynchronizationEvent, FALSE);

    SCSI_PASS_THROUGH_DIRECT Srb = { 0 };
    CDB Cdb = { 0 };

    Srb.Length = sizeof(Srb);
    Srb.CdbLength = 10;
    Srb.SenseInfoLength = 0;
    Srb.SenseInfoOffset = sizeof(Srb);
    Srb.DataTransferLength = PAGE_SIZE;
    Srb.TimeOutValue = 5;
    Srb.DataBuffer = buffer;

    SCSIBuild10CDB(&Srb, 0, Srb.DataTransferLength, operationCode == SCSIOP_WRITE);

    IO_STATUS_BLOCK ioStatusBlock;
    PIRP irp = IoBuildDeviceIoControlRequest(IOCTL_SCSI_PASS_THROUGH_DIRECT, device, &Srb,
        sizeof(Srb), 0, 0, FALSE,
        &event, &ioStatusBlock);

    if (!irp) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS status = IoCallDriver(device, irp);

    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatusBlock.Status;
    }

    return status;
}

NTSTATUS AtaReadPage(IN PDEVICE_OBJECT device, OUT PVOID dest) {
    NTSTATUS ntStatus = AtaIssueCommand(device, ATA_FLAGS_DATA_IN, ATA_CMD_READ_SECTORS, dest);
    if (!NT_SUCCESS(ntStatus)) {
        DbgPrintEx(0, 0, "Failed ATA read: 0x%x", ntStatus);
    }
    return ntStatus;
}

NTSTATUS AtaWritePage(IN PDEVICE_OBJECT device, IN PVOID src) {
    NTSTATUS ntStatus = AtaIssueCommand(device, ATA_FLAGS_DATA_OUT, ATA_CMD_WRITE_SECTORS, src);
    if (!NT_SUCCESS(ntStatus)) {
        DbgPrintEx(0, 0, "Failed ATA write: 0x%x", ntStatus);
    }
    return ntStatus;
}

NTSTATUS ScsiReadPage(IN PDEVICE_OBJECT device, OUT PVOID dest) {
    NTSTATUS ntStatus = ScsiIssueCommand(device, SCSIOP_READ, dest);
    if (!NT_SUCCESS(ntStatus)) {
        DbgPrintEx(0, 0, "Failed SCSI read: 0x%x", ntStatus);
    }
    return ntStatus;
}

NTSTATUS ScsiWritePage(IN PDEVICE_OBJECT device, IN PVOID src) {
    NTSTATUS ntStatus = ScsiIssueCommand(device, SCSIOP_WRITE, src);
    if (!NT_SUCCESS(ntStatus)) {
        DbgPrintEx(0, 0, "Failed SCSI write: 0x%x", ntStatus);
    }
    return ntStatus;
}

NTSTATUS DdmaProvider::ReadPage(OUT PVOID dest) {
    if (!pDisk) {
        DbgPrintEx(0, 0, "No disk registered!\n");
        return STATUS_NOT_FOUND;
    }
    if (bScsi)
        return ScsiReadPage(pDisk->Device, dest);
    return AtaReadPage(pDisk->Device, dest);
}

NTSTATUS DdmaProvider::WritePage(IN PVOID src) {
    if (!pDisk) {
        DbgPrintEx(0, 0, "No disk registered!\n");
        return STATUS_NOT_FOUND;
    }
    if (bScsi)
        return ScsiWritePage(pDisk->Device, src);
    return AtaWritePage(pDisk->Device, src);
}

extern "C" POBJECT_TYPE * IoDriverObjectType;
extern "C" NTSTATUS ObReferenceObjectByName(IN PUNICODE_STRING objectName, IN ULONG attributes,
    IN PACCESS_STATE passedAccessState,
    IN ACCESS_MASK desiredAccess,
    IN POBJECT_TYPE objectType,
    IN KPROCESSOR_MODE accessMode,
    IN OUT PVOID parseContext, OUT PVOID * object);

NTSTATUS GetDeviceObjectList(IN PDRIVER_OBJECT driverObject, OUT PDEVICE_OBJECT** outDevices,
    OUT PULONG outDeviceCount) {

    ULONG count = 0;
    NTSTATUS status = IoEnumerateDeviceObjectList(driverObject, NULL, 0, &count);

    if (status != STATUS_BUFFER_TOO_SMALL) {
        return status;
    }

    ULONG size = count * sizeof(PDEVICE_OBJECT);
    PDEVICE_OBJECT* devices = (PDEVICE_OBJECT*)ExAllocatePool(NonPagedPoolNx, size);
    if (devices) {
        *outDeviceCount = count;

        status = IoEnumerateDeviceObjectList(driverObject, devices, size, &count);
        if (NT_SUCCESS(status)) {
            *outDevices = devices;
        }
        else {
            ExFreePool(devices);
        }
    }
    else {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }

    return status;
}

NTSTATUS DiskFind(OUT PDISK* outDisk, OUT PBOOLEAN bScsi) {
    PDISK disk = (PDISK)ExAllocatePool(NonPagedPoolNx, sizeof(DISK));
    if (!disk) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(disk, sizeof(*disk));

    UNICODE_STRING diskStr = RTL_CONSTANT_STRING(L"\\Driver\\Disk");
    PDRIVER_OBJECT diskObject;

    NTSTATUS status = ObReferenceObjectByName(&diskStr, OBJ_CASE_INSENSITIVE, NULL, 0,
        *IoDriverObjectType, KernelMode, NULL, (PVOID*)&diskObject);

    if (NT_SUCCESS(status)) {
        PDEVICE_OBJECT* devices;
        ULONG deviceCount;

        status = GetDeviceObjectList(diskObject, &devices, &deviceCount);

        if (NT_SUCCESS(status)) {
            status = STATUS_NOT_FOUND;

            for (ULONG i = 0; i < deviceCount; ++i) {
                PDEVICE_OBJECT device = devices[i];

                if (status == STATUS_NOT_FOUND && NT_SUCCESS(ScsiReadPage(device, disk->Buffer))) {
                    disk->Device = device;
                    if (bScsi)
                        *bScsi = true;
                    status = STATUS_SUCCESS;
                    DbgPrintEx(0, 0, "Found SCSI device!\n");
                    continue;
                }
                else if (status == STATUS_NOT_FOUND && NT_SUCCESS(AtaReadPage(device, disk->Buffer))) {
                    disk->Device = device;
                    if (bScsi)
                        *bScsi = false;
                    status = STATUS_SUCCESS;
                    continue;
                }

                ObDereferenceObject(device);
            }

            ExFreePool(devices);
        }

        ObDereferenceObject(diskObject);
    }

    if (NT_SUCCESS(status)) {
        *outDisk = disk;
    }
    else {
        ExFreePool(disk);
    }

    return status;
}

NTSTATUS DdmaProvider::DiskCopyPage(PVOID dest, PVOID src) {
    if (!MmIsAddressValid(pDisk)
        || !pDisk->Device)
        return STATUS_NOT_IMPLEMENTED;

    // Read from src by writing to disk
    NTSTATUS status = WritePage(src);
    if (NT_SUCCESS(status)) {
        // Write to dest by reading from disk
        status = ReadPage(dest);

        // Restore original sectors
        WritePage(pDisk->Buffer);
    }

    return status;
}

DdmaProvider::DdmaProvider()
{
    pDisk = 0;
    DiskFind(&pDisk, &bScsi);
}

DdmaProvider::~DdmaProvider()
{
    if (MmIsAddressValid(pDisk)
        && pDisk->Device) {
        ObDereferenceObject(pDisk->Device);
        ExFreePool(pDisk);
    }
}
