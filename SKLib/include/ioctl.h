#pragma once

#ifdef _KERNEL_MODE
#ifndef _WDMDDK_
#include <ntifs.h>
#endif
#include <minwindef.h>
#endif

#include "macros.h"
#include "StringEx.h"
#include "VectorEx.h"

#ifdef _KERNEL_MODE

extern "C" POBJECT_TYPE * IoDriverObjectType;
extern "C" NTKERNELAPI NTSTATUS ObReferenceObjectByName(
	IN PUNICODE_STRING ObjectName, 
	IN ULONG Attributes, 
	IN PACCESS_STATE PassedAccessState, 
	IN ACCESS_MASK DesiredAccess, 
	IN POBJECT_TYPE ObjectType, 
	IN KPROCESSOR_MODE AccessMode, 
	IN OUT PVOID ParseContext, 
	OUT PVOID* Object
);

typedef DWORD64 IOCTL_HANDLE;

typedef NTSTATUS(*fnCallback) (
	PDEVICE_OBJECT pDeviceObj,
	PIRP pIrp
	);

class DispatchHandler
{
private:
	DWORD32 dispatcherBitMask;
	bool bSymLinkExists;
	
	string currentDeviceName;
	PDEVICE_OBJECT pDeviceObj;

	static NTSTATUS defaultHandler(PDEVICE_OBJECT pDeviceObj, PIRP pIrp);

public:
	void Init(char* pDeviceName, fnCallback fnCallback = &defaultHandler);
	DispatchHandler();
	DispatchHandler(char* pDeviceName, fnCallback fnCallback = nullptr);
	void addHandler(DWORD dwIrpMj, fnCallback fnCallback);
	void addUnsupportedHandler(fnCallback fnCallback);
	void Dispose();

	bool operator==(DispatchHandler& rhs) {
		return currentDeviceName == rhs.currentDeviceName;
	}

	bool operator!=(DispatchHandler& rhs) {
		return !(*this == rhs);
	}
};

namespace IOCTL {
	void Init(PDRIVER_OBJECT pDriverObj);
	IOCTL_HANDLE Add(char* pDeviceName, fnCallback fnCallback = nullptr);
	DispatchHandler& GetHandler(IOCTL_HANDLE hHandler);
	PDRIVER_DISPATCH* GetMJFunctions(string driverName);

	PDRIVER_OBJECT GetDriverObj(string driverName);
	PDEVICE_OBJECT GetDevice(string deviceName);
	PDEVICE_OBJECT GetDeviceFromIName(string deviceName);

	NTSTATUS SendIoctl(string driverName, DWORD64 dwIoctlCode, PVOID pInBuf = nullptr, ULONG ulInBufLen = 0, PVOID pOutBuffer = nullptr, ULONG ulOutBufLen = 0);
	NTSTATUS SendIoctl(PDEVICE_OBJECT pDeviceObj, DWORD64 dwIoctlCode, PVOID pInBuf = nullptr, ULONG ulInBufLen = 0, PVOID pOutBuffer = nullptr, ULONG ulOutBufLen = 0);

	void Dispose();
}
#endif