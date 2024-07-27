#include "volumespoof.h"

typedef NTSTATUS(*fnMountControl)(PDEVICE_OBJECT device, PIRP irp);
fnMountControl pMountControl = nullptr;

typedef struct _MOUNT_SERIAL_DATA {
	wchar_t* spoofed;
	wchar_t* orig;

	__forceinline bool operator==(_MOUNT_SERIAL_DATA& rhs) {
		return memcmp(this, &rhs, sizeof(*this)) == 0;
	}
	__forceinline bool operator!=(_MOUNT_SERIAL_DATA& rhs) {
		return !(*this == rhs);
	}
} MOUNT_SERIAL_DATA, * PMOUNT_SERIAL_DATA;

vector<MOUNT_SERIAL_DATA>* vVolGUIDs = nullptr;

#define VOLUME_GUID_MAX_LENGTH (0x24)
#define GUID_OFFSET				22

/*
* Enable to use hardcoded volume GUID value
*/
//#define DUMMY_VOLUME_GUID L"12345678-1234-1234-1234-123456789123"

bool FindFakeVolumeGUID(wchar_t* pOriginal) {
	if (winternl::IsNtoskrnlAddress((DWORD64)pOriginal)) {
		DbgMsg("[DISK] Trying to write volume GUID in ntoskrnl");
		return false;
	}

#ifdef DUMMY_VOLUME_GUID
	bool bFound = true;
	RtlCopyMemory(pOriginal, DUMMY_VOLUME_GUID, VOLUME_GUID_MAX_LENGTH * 2);
#else
	bool bFound = false;
	for (auto& serial : *vVolGUIDs) {
		if (!memcmp(serial.orig, pOriginal, 4)) {
			Memory::WriteProtected(pOriginal, serial.spoofed, VOLUME_GUID_MAX_LENGTH * 2);
			bFound = true;
			break;
		}
	}
	if (!bFound) {
		rnd.setSeed(spoofer::seed);
		wchar_t* pBuf = (wchar_t*)cpp::kMalloc((VOLUME_GUID_MAX_LENGTH + 1) * 2);
		wchar_t* pBufOrig = (wchar_t*)cpp::kMalloc((VOLUME_GUID_MAX_LENGTH + 1) * 2);
		pBuf[VOLUME_GUID_MAX_LENGTH] = 0;
		pBufOrig[VOLUME_GUID_MAX_LENGTH] = 0;
		RtlCopyMemory(pBuf, pOriginal, VOLUME_GUID_MAX_LENGTH * 2);
		RtlCopyMemory(pBufOrig, pOriginal, VOLUME_GUID_MAX_LENGTH * 2);
		rnd.w_str_hex(pBuf + 2, 2);
		rnd.w_str_hex(pBuf + 9, 4);
		rnd.w_str_hex(pBuf + 14, 4);
		rnd.random_shuffle(pBuf + 19, 4);

		MOUNT_SERIAL_DATA serial = { 0 };
		serial.orig = pBufOrig;
		serial.spoofed = pBuf;
		vVolGUIDs->Append(serial);

		Memory::WriteProtected(pOriginal, pBuf, VOLUME_GUID_MAX_LENGTH * 2);
		bFound = true;
	}
#endif

	return bFound;
}

NTSTATUS MountPointsIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (MmIsAddressValid(context)) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(MOUNTMGR_MOUNT_POINTS)) {
			PMOUNTMGR_MOUNT_POINTS points = (PMOUNTMGR_MOUNT_POINTS)request.Buffer;
			if (MmIsAddressValid(points)) {
				for (DWORD32 i = 0; i < points->NumberOfMountPoints; ++i) {
					volatile PMOUNTMGR_MOUNT_POINT point = points->MountPoints + i;
					if (*(wchar_t*)((DWORD64)points + point->SymbolicLinkNameOffset + GUID_OFFSET - 2) == L'{') {
						FindFakeVolumeGUID((wchar_t*)((char*)points + point->SymbolicLinkNameOffset + GUID_OFFSET));
					}
				}
			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS MountUniqueIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (MmIsAddressValid(context)) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(MOUNTDEV_UNIQUE_ID)) {
			PMOUNTDEV_UNIQUE_ID point = (PMOUNTDEV_UNIQUE_ID)request.Buffer;
			if(MmIsAddressValid(point))
				FindFakeVolumeGUID((wchar_t*)point->UniqueId);
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS MountControl(PDEVICE_OBJECT device, PIRP irp) {
	if (cpp::IsKernelAddress(irp)) {
		PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
		if (!cpp::IsKernelAddress(ioc))
			return pMountControl(device, irp);

		switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_MOUNTMGR_QUERY_POINTS:
			LogCaller(irp, HookedDriver::DriverVolume);
			ChangeIoc(ioc, irp, MountPointsIoc);
			break;
		case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
			LogCaller(irp, HookedDriver::DriverVolume);
			ChangeIoc(ioc, irp, MountUniqueIoc);
			break;
		}
	}

	return pMountControl(device, irp);
}

bool volumes::Spoof(DWORD64 seed)
{
	bool bRes = false;

	rnd.setSeed(seed);
	rnd.setSecLevel(random::SecurityLevel::PREDICTABLE);

	if (!vVolGUIDs) {
		vVolGUIDs = (vector<MOUNT_SERIAL_DATA>*)cpp::kMalloc(sizeof(*vVolGUIDs), PAGE_READWRITE);
		vVolGUIDs->Init();
		vVolGUIDs->reserve(64);
	}
	else {
		for (auto& guid : *vVolGUIDs) {
			rnd.setSeed(seed);
			wchar_t* pBuf = (wchar_t*)cpp::kMalloc((VOLUME_GUID_MAX_LENGTH + 1) * 2);
			pBuf[VOLUME_GUID_MAX_LENGTH] = 0;
			rnd.w_str_hex(pBuf + 2, 2);
			rnd.w_str_hex(pBuf + 9, 4);
			rnd.w_str_hex(pBuf + 14, 4);
			rnd.random_shuffle(pBuf + 19, 4);
			guid.spoofed = pBuf;
		}
		return true;
	}

	HOOK_SECONDARY_INFO hkSecondaryInfo = { 0 };
	hkSecondaryInfo.pOrigFn = (PVOID*)&pMountControl;
	PDRIVER_OBJECT pDrivObj = IOCTL::GetDriverObj("\\Driver\\mountmgr");

	if (!EPT::HookExec(pDrivObj->MajorFunction[IRP_MJ_DEVICE_CONTROL], MountControl, hkSecondaryInfo)) {
		DbgMsg("[DISK] Failed hooking mountmgr IoDeviceCtrl");
		bRes = false;
	}
	else {
		DbgMsg("[DISK] Hooked mountmgr IoDeviceCtrl");
		bRes = true;
	}
	ObDereferenceObject(pDrivObj);

	return bRes;
}
