#include "wmispoof.h"

vector<wchar_t*>* vMonitorSerials = nullptr;
typedef NTSTATUS (*fnWmipQueryAllData)(
	IN PWMIGUIDOBJECT GuidObject,
	IN PIRP Irp,
	IN KPROCESSOR_MODE AccessMode,
	IN PWNODE_ALL_DATA Wnode,
	IN ULONG OutBufferLen,
	OUT PULONG RetSize
);

fnWmipQueryAllData pWmipQueryAllData = nullptr;

bool FindFakeMonitorSerial(USHORT* pOriginal) {
#ifdef DUMMY_SERIAL
	bool bFound = true;
	RtlCopyMemory(pOriginal, DUMMY_SERIAL, MONITOR_SERIAL_LENGTH * sizeof(USHORT));
#else
	bool bFound = false;
	for (auto& serial : *vMonitorSerials) {
		if (!memcmp(serial, pOriginal, 4)) {
			Memory::WriteProtected(pOriginal, serial, MONITOR_SERIAL_LENGTH * sizeof(USHORT));
			bFound = true;
			break;
		}
	}
	if (!bFound) {
		rnd.setSeed(spoofer::seed);
		wchar_t* pBuf = (wchar_t*)cpp::kMalloc((MONITOR_SERIAL_LENGTH + 1) * sizeof(USHORT), PAGE_READWRITE);
		RtlCopyMemory(pBuf, pOriginal, (MONITOR_SERIAL_LENGTH + 1) * sizeof(USHORT));
		rnd.w_str(pBuf, MONITOR_SERIAL_LENGTH);
		vMonitorSerials->Append(pBuf);
		Memory::WriteProtected(pOriginal, pBuf, MONITOR_SERIAL_LENGTH * sizeof(USHORT));
		bFound = true;
	}
#endif

	return bFound;
}

NTSTATUS WmipQueryAllDataHook(
	IN PWMIGUIDOBJECT GuidObject,
	IN PIRP Irp,
	IN KPROCESSOR_MODE AccessMode,
	IN PWNODE_ALL_DATA Wnode,
	IN ULONG OutBufferLen,
	OUT PULONG RetSize
	) 
{
	NTSTATUS ntStatus = pWmipQueryAllData(GuidObject, Irp, AccessMode, Wnode, OutBufferLen, RetSize);
	if (NT_SUCCESS(ntStatus)) {
		PWNODE_ALL_DATA pAllData = (PWNODE_ALL_DATA)Wnode;
		if (!MmIsAddressValid(pAllData))
			return ntStatus;

		PWmiMonitorID MonitorID;
		if (pAllData->WnodeHeader.Guid == WmiMonitorID_GUID) {
			if (pAllData->WnodeHeader.Flags & WNODE_FLAG_FIXED_INSTANCE_SIZE)
				MonitorID = (PWmiMonitorID) &((UCHAR*)pAllData)[pAllData->DataBlockOffset];
			else
				MonitorID = (PWmiMonitorID) &((UCHAR*)pAllData)[pAllData->OffsetInstanceDataAndLength[0].OffsetInstanceData];
			
			if (MmIsAddressValid(MonitorID)) {
				RtlFillBytes(MonitorID->SerialNumberID, sizeof(MonitorID->SerialNumberID), 0);
				RtlFillBytes(MonitorID->ProductCodeID, sizeof(MonitorID->ProductCodeID), 0);
			}
		}
	}

	return ntStatus;
}

bool wmi::SpoofMonitor(DWORD64 seed)
{
	bool bRes = false;

	rnd.setSeed(seed);
	rnd.setSecLevel(random::SecurityLevel::PREDICTABLE);

	vMonitorSerials = (vector<wchar_t*>*)cpp::kMalloc(sizeof(*vMonitorSerials), PAGE_READWRITE);
	RtlZeroMemory(vMonitorSerials, sizeof(*vMonitorSerials));
	vMonitorSerials->Init();
	vMonitorSerials->reserve(64);

	//DWORD64 EDIDBootCopy =
	//	(DWORD64)Memory::FindPatternImage(winternl::ntoskrnlBase, (PCHAR)"\x0F\x10\x05\x00\x00\x00\x00\x0F\x11\x02", (PCHAR)"xxx????xxx");
	//
	//if (!EDIDBootCopy) {
	//	DbgMsg("[WMI] Could not find EDID boot copy offset");
	//	return false;
	//}
	//char* pEDIDBoot = (char*)(EDIDBootCopy + 7 + *(PINT)(EDIDBootCopy + 3));
	//_disable();
	//bool bEnableCET = CPU::DisableWriteProtection();
	//RtlZeroMemory(pEDIDBoot, 0x80);
	//CPU::EnableWriteProtection(bEnableCET);
	//_enable();
	//
	//DbgMsg("[MONITOR] Zeroed EDID boot copy at: %p", pEDIDBoot);

	DWORD64 WmipQueryAllData = ((DWORD64)winternl::ntoskrnlBase + offsets.WmipQueryAllData);
	HOOK_SECONDARY_INFO hkSecondaryInfo = { 0 };
	hkSecondaryInfo.pOrigFn = (PVOID*)&pWmipQueryAllData;

	if (!EPT::HookExec((PVOID)WmipQueryAllData, WmipQueryAllDataHook, hkSecondaryInfo)) {
		DbgMsg("[MONITOR] Failed hooking WmipQueryAllData");
		bRes = false;
	}
	else {
		DbgMsg("[MONITOR] Hooked WmipQueryAllData");
		bRes = true;
	}

	return bRes;
}
