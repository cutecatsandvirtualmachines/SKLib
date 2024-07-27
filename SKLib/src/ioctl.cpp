#include "ioctl.h"

PDRIVER_OBJECT pDriverObj = nullptr;

vector<DispatchHandler>* pHandlers = nullptr;

void DispatchHandler::Init(char* pDeviceName, fnCallback fnCallback) {
	NTSTATUS ntStatus = STATUS_SUCCESS;
	if (!pDeviceName) {
		DbgMsg("[IOCTL] Error: a device name was not specified, aborting...");
		return;
	}

	currentDeviceName = pDeviceName;
	string sDeviceName("\\DosDevices\\");
	string sDrivName("\\Device\\");
	sDrivName += pDeviceName;

	ntStatus = IoCreateDevice(pDriverObj, 0, &sDrivName.unicode(), FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObj);
	if (!NT_SUCCESS(ntStatus)) {
		DbgMsg("[IOCTL] Error: Failed to create device %s: %x", sDrivName.c_str(), ntStatus);
		goto __end;
	}
	sDeviceName += pDeviceName;

	ntStatus = IoCreateSymbolicLink(&sDeviceName.unicode(), &sDrivName.unicode());
	if (!NT_SUCCESS(ntStatus)) {
		DbgMsg("[IOCTL] Error: Failed to create symbolic link %s: %x", sDeviceName.c_str(), ntStatus);
		goto __end;
	}
	bSymLinkExists = true;

__end:
	auto fnUnsupported = fnCallback == nullptr ? &defaultHandler : fnCallback;
	for (size_t i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		pDriverObj->MajorFunction[i] = fnUnsupported;
	dispatcherBitMask = 0;

	DbgMsg("[IOCTL] Successfully initialized IOCTL handler!");
}

DispatchHandler::DispatchHandler(char* pDeviceName, fnCallback fnCallback) {
	Init(pDeviceName, fnCallback);
}

DispatchHandler::DispatchHandler() {
	this->bSymLinkExists = false;
	this->pDeviceObj = nullptr;
	this->dispatcherBitMask = 0;
}

void DispatchHandler::addHandler(DWORD dwIrpMj, fnCallback fnCallback) {
	if (!pDriverObj) {
		DbgMsg("[IOCTL] Error: a driver object pointer was not specified!");
		return;
	}
	pDriverObj->MajorFunction[dwIrpMj] = fnCallback;

	dispatcherBitMask &= 1 << dwIrpMj;
	DbgMsg("[IOCTL] Added handler: Irp = 0x%x", dwIrpMj);
};

void DispatchHandler::addUnsupportedHandler(fnCallback fnCallback) {
	if (!pDriverObj) {
		DbgMsg("[IOCTL] Error: a driver object pointer was not specified!");
		return;
	}
	for (size_t i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		if (((1 << i) & dispatcherBitMask) == 0)
			pDriverObj->MajorFunction[i] = fnCallback;
}

void DispatchHandler::Dispose() {
	if (pDeviceObj) {
		if (bSymLinkExists) {
			string sDeviceName("\\DosDevices\\");
			sDeviceName += currentDeviceName;
			IoDeleteSymbolicLink(&sDeviceName.unicode());
		}
		IoDeleteDevice(pDeviceObj);
	}
}

NTSTATUS DispatchHandler::defaultHandler(PDEVICE_OBJECT, PIRP pIrp)
{
    DbgMsg("[IOCTL] This function is not supported!");

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

void IOCTL::Init(PDRIVER_OBJECT _pDriverObj)
{
	pHandlers = (vector<DispatchHandler>*)cpp::kMalloc(sizeof(*pHandlers), PAGE_READWRITE);
	RtlZeroMemory(pHandlers, sizeof(*pHandlers));
	pHandlers->Init();
	pDriverObj = _pDriverObj;
}

IOCTL_HANDLE IOCTL::Add(char* pDeviceName, fnCallback fnCallback)
{
	return pHandlers->emplace_back(pDeviceName, fnCallback);
}

DispatchHandler& IOCTL::GetHandler(IOCTL_HANDLE hHandler)
{
	return pHandlers->at((int)hHandler);
}

PDRIVER_DISPATCH* IOCTL::GetMJFunctions(string driverName)
{
	PDRIVER_OBJECT pObj = GetDriverObj(driverName);
	PDRIVER_DISPATCH* pRet = &pObj->MajorFunction[0];
	ObDereferenceObject(pObj);
	return pRet;
}

PDRIVER_OBJECT IOCTL::GetDriverObj(string driverName) {
	PDRIVER_OBJECT pObj = nullptr;
	NTSTATUS ntStatus = ObReferenceObjectByName(
		&driverName.unicode(),
		OBJ_CASE_INSENSITIVE,
		0,
		0,
		*IoDriverObjectType,
		KernelMode,
		0,
		(PVOID*)&pObj
	);
	if (!NT_SUCCESS(ntStatus)) {
		DbgMsg("[IOCTL] Failed to reference driver object: 0x%x", ntStatus);
		return nullptr;
	}
	return pObj;
}

PDEVICE_OBJECT IOCTL::GetDevice(string deviceName) {
	DEVICE_OBJECT* device_object = nullptr;
	FILE_OBJECT* file = nullptr;

	IoGetDeviceObjectPointer(&deviceName.unicode(), 0, &file, &device_object);

	return device_object;
}

PDEVICE_OBJECT IOCTL::GetDeviceFromIName(string deviceName) {
	NTSTATUS Status;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatusBlock;
	PFILE_OBJECT LocalFileObject;
	HANDLE DeviceHandle;
	PDEVICE_OBJECT pDeviceObject = nullptr;

	/* Open a file object handle to the device */
	InitializeObjectAttributes(&ObjectAttributes,
		&deviceName.unicode(),
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	Status = ZwCreateFile(&DeviceHandle,
		FILE_ALL_ACCESS,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		0,
		NULL,
		0);
	if (NT_SUCCESS(Status))
	{
		Status = ObReferenceObjectByHandle(DeviceHandle,
			0,
			*IoFileObjectType,
			KernelMode,
			(PVOID*)&LocalFileObject,
			NULL);
		if (NT_SUCCESS(Status))
		{
			pDeviceObject = IoGetRelatedDeviceObject(LocalFileObject);
		}

		ZwClose(DeviceHandle);
	}

	return pDeviceObject;
}

NTSTATUS IOCTL::SendIoctl(string driverName, DWORD64 dwIoctlCode, PVOID pInBuf, ULONG ulInBufLen, PVOID pOutBuffer, ULONG ulOutBufLen)
{
	PDEVICE_OBJECT pDeviceObj = GetDriverObj(driverName)->DeviceObject;
	if (!pDeviceObj)
		return STATUS_UNSUCCESSFUL;

	return SendIoctl(pDeviceObj, dwIoctlCode, pInBuf, ulInBufLen, pOutBuffer, ulOutBufLen);
}

NTSTATUS IOCTL::SendIoctl(PDEVICE_OBJECT pDeviceObj, DWORD64 dwIoctlCode, PVOID pInBuf, ULONG ulInBufLen, PVOID pOutBuffer, ULONG ulOutBufLen) {
	IO_STATUS_BLOCK StatusBlock;
	PIRP Irp;
	KEVENT Event;

	KeInitializeEvent(&Event, NotificationEvent, FALSE);

	Irp = IoBuildDeviceIoControlRequest(
		(ULONG)dwIoctlCode,
		pDeviceObj,
		pInBuf,
		ulInBufLen,
		pOutBuffer,
		ulOutBufLen,
		FALSE,
		&Event,
		&StatusBlock
	);

	if (!Irp)
		return STATUS_UNSUCCESSFUL;

	NTSTATUS ntStatus = IoCallDriver(pDeviceObj, Irp);

	if(ntStatus == STATUS_PENDING) 
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, 0);

	ObDereferenceObject(pDeviceObj);

	return ntStatus;
}

void IOCTL::Dispose()
{
	if (!pHandlers)
		return;
	for (auto& handler : *pHandlers) {
		handler.Dispose();
	}

	pHandlers->Dispose();
	cpp::kFree(pHandlers);
}
