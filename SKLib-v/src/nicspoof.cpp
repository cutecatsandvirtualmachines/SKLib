#include "nicspoof.h"

#define MAC_MAX_LENGTH 6
typedef struct _NETADDR_STANDARD {
	char raw[MAC_MAX_LENGTH];
} NETADDR_STANDARD, * PNETADDR_STANDARD;

typedef struct _MAC_MODIFICATION_DATA {
	NETADDR_STANDARD spoofed;
	NETADDR_STANDARD orig;

	__forceinline bool operator==(_MAC_MODIFICATION_DATA& rhs) {
		return memcmp(this, &rhs, sizeof(*this)) == 0;
	}
	__forceinline bool operator!=(_MAC_MODIFICATION_DATA& rhs) {
		return !(*this == rhs);
	}
} MAC_MODIFICATION_DATA, * PMAC_MODIFICATION_DATA;

vector<PMAC_MODIFICATION_DATA>* vMACs = nullptr;

typedef NTSTATUS(*fnNicCtrl)(PDEVICE_OBJECT device, PIRP irp);
fnNicCtrl pTcpCtrlOrig = nullptr;
NICS NICs = { 0 };
NICS NSIs = { 0 };

bool FindFakeNicMac(char* pOriginal, bool bAddIfNotFound = true) {
#ifdef DUMMY_SERIAL
	bool bFound = true;
	RtlCopyMemory(pOriginal, DUMMY_SERIAL, MAC_MAX_LENGTH);
#else
	bool bFound = false;
	for (auto& MAC : *vMACs) {
		if (!memcmp(MAC->orig.raw, pOriginal, sizeof(MAC->orig))) {
			Memory::WriteProtected(pOriginal, MAC->spoofed.raw, sizeof(MAC->orig));
			bFound = true;
			break;
		}
	}
	if (!bFound && bAddIfNotFound) {
		PMAC_MODIFICATION_DATA pBuf = (PMAC_MODIFICATION_DATA)cpp::kMallocZero(sizeof(*pBuf), PAGE_READWRITE);
		RtlCopyMemory(pBuf->orig.raw, pOriginal, sizeof(pBuf->orig));
		RtlCopyMemory(pBuf->spoofed.raw, pOriginal, sizeof(pBuf->spoofed));
		rnd.bytes(pBuf->spoofed.raw + 3, sizeof(pBuf->spoofed) - 3);

		DbgMsg("[NIC] Changed MAC from %1x-%1x-%1x-%1x-%1x-%1x to %1x-%1x-%1x-%1x-%1x-%1x",
			(unsigned char)pBuf->orig.raw[0], (unsigned char)pBuf->orig.raw[1], (unsigned char)pBuf->orig.raw[2], (unsigned char)pBuf->orig.raw[3], (unsigned char)pBuf->orig.raw[4], (unsigned char)pBuf->orig.raw[5],
			(unsigned char)pBuf->spoofed.raw[0], (unsigned char)pBuf->spoofed.raw[1], (unsigned char)pBuf->spoofed.raw[2], (unsigned char)pBuf->spoofed.raw[3], (unsigned char)pBuf->spoofed.raw[4], (unsigned char)pBuf->spoofed.raw[5]
		);

		Memory::WriteProtected(pOriginal, pBuf->spoofed.raw, sizeof(pBuf->spoofed));
		vMACs->Append(pBuf);

		bFound = true;
	}
#endif

	return bFound;
}

bool FindFakeNicMacReset(char* pSpoofed) {
	for (auto& MAC : *vMACs) {
		if (!memcmp(MAC->spoofed.raw, pSpoofed, sizeof(MAC->orig))) {
			Memory::WriteProtected(pSpoofed, MAC->orig.raw, sizeof(MAC->orig));
			break;
		}
	}

	return true;
}

#pragma warning (disable: 4995)
NTSTATUS NICIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (MmIsAddressValid(context)) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (irp->MdlAddress) {
			FindFakeNicMac((char*)MmGetSystemAddressForMdl(irp->MdlAddress));
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS NICControl(PDEVICE_OBJECT device, PIRP irp) {
	for (DWORD i = 0; i < NICs.Length; ++i) {
		PNIC_DRIVER driver = &NICs.Drivers[i];

		if (driver->Original &&
			driver->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] == device->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]) {
			if (cpp::IsKernelAddress(irp)) {
				PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
				if (!MmIsAddressValid(ioc))
					return driver->Original(device, irp);

				switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
				case IOCTL_NDIS_QUERY_GLOBAL_STATS: {
					switch (*(PDWORD)irp->AssociatedIrp.SystemBuffer) {
					case OID_802_3_PERMANENT_ADDRESS:
					case OID_802_3_CURRENT_ADDRESS:
					case OID_802_5_PERMANENT_ADDRESS:
					case OID_802_5_CURRENT_ADDRESS:
					case OID_WAN_PERMANENT_ADDRESS:
					case OID_WAN_CURRENT_ADDRESS:
					case OID_ARCNET_PERMANENT_ADDRESS:
					case OID_ARCNET_CURRENT_ADDRESS:
						LogCaller(irp, HookedDriver::DriverNIC);
						ChangeIoc(ioc, irp, NICIoc);
						break;
					}

					break;
				}
				}
			}

			return driver->Original(device, irp);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS NsiControl(PDEVICE_OBJECT device, PIRP irp) {
	for (DWORD i = 0; i < NSIs.Length; ++i) {
		PNIC_DRIVER driver = &NSIs.Drivers[i];

		if (driver->Original &&
			driver->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] == device->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]) {
			if (cpp::IsKernelAddress(irp)) {
				PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
				if (!MmIsAddressValid(ioc))
					return driver->Original(device, irp);
				
				switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
				case IOCTL_NSI_GETALLPARAM: {
					DWORD length = ioc->Parameters.DeviceIoControl.OutputBufferLength;
					NTSTATUS ret = driver->Original(device, irp);

					PNSI_PARAMS params = (PNSI_PARAMS)irp->UserBuffer;
					if (MmIsAddressValid(params)
						&& ((NSI_GET_IP_NET_TABLE == params->Type))
						) {
						memset(irp->UserBuffer, 0, length);
						return STATUS_ACCESS_DENIED;
					}

					LogCaller(irp, HookedDriver::DriverNSI);
					return ret;
				}
										  //case IOCTL_NSI_ARP_SOMETHING: {
										  //	NTSTATUS ret = driver->Original(device, irp);
										  //	if (NT_SUCCESS(ret)) {
										  //		char* buffer = (char*)irp->UserBuffer;
										  //		
										  //		if (MmIsAddressValid(buffer) 
										  //			&& MmIsAddressValid(*(PULONG*)(buffer + 0x10))
										  //			&& **(PULONG*)(buffer + 0x10) == 24) { //SendARP Spoof
										  //			buffer += 0x128;
										  //			FindFakeNicMac(buffer);
										  //		}
										  //	}
										  //	return ret;
										  //}
				}
			}

			return driver->Original(device, irp);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS TcpControl(PDEVICE_OBJECT device, PIRP irp) {
	if (cpp::IsKernelAddress(irp)) {
		PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
		if (!MmIsAddressValid(ioc))
			return pTcpCtrlOrig(device, irp);

		switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_TCP_QUERY_INFORMATION_EX:
		{
			LogCaller(irp, HookedDriver::DriverTCP);
			NTSTATUS ntStatus = pTcpCtrlOrig(device, irp);
			if (NT_SUCCESS(ntStatus)) {
				IFEntry* IfEntry = (IFEntry*)irp->UserBuffer;
				if (MmIsAddressValid(IfEntry))
					FindFakeNicMac((char*)IfEntry->if_physaddr);
			}
			return ntStatus;
		}
		}
	}
	else {
		LogCaller(irp, HookedDriver::DriverTCP);
	}

	return pTcpCtrlOrig(device, irp);
}

bool nics::Spoof(DWORD64 seed)
{
	bool bRes = false;
	vector<PVOID> filterList;
	filterList.reserve(64);

	auto pDeviceObj = IOCTL::GetDevice("\\Device\\ndis");
	if (!pDeviceObj) {
		DbgMsg("[IOCTL] Could not find ndis driver object!");
		return false;
	}

	PVOID pNdisBase = pDeviceObj->DriverObject->DriverStart;
	if (!pNdisBase) {
		DbgMsg("[MEMORY] Failed getting ndis.sys base");
		return false;
	}

	DWORD64 ndisFilterBlockOffset = offsets.NdisGlobalFilterList;
	if (!VALID_OFFSET(ndisFilterBlockOffset)) {
		DbgMsg("[REGISTRY] Failed getting ndisGlobalFilterList offset");
		return false;
	}
	PVOID ndisGlobalFilterList = *(PVOID*)((DWORD64)pNdisBase + ndisFilterBlockOffset);

	DWORD64 nextFilterOffset = offsets.FilterBlockNextFilter;
	if (!VALID_OFFSET(nextFilterOffset)) {
		DbgMsg("[REGISTRY] Failed getting _NDIS_FILTER_BLOCK!NextFilter offset");
		return false;
	}

	DWORD64 miniportOffset = offsets.FilterBlockMiniport;
	if (!VALID_OFFSET(miniportOffset)) {
		DbgMsg("[REGISTRY] Failed getting _NDIS_FILTER_BLOCK!Miniport offset");
		return false;
	}

	DWORD64 filterInstanceNameOffset = offsets.FilterBlockInstanceName;
	if (!VALID_OFFSET(filterInstanceNameOffset)) {
		DbgMsg("[REGISTRY] Failed getting _NDIS_FILTER_BLOCK!FilterInstanceName offset");
		return false;
	}

	DWORD64 ifBlockOffset = offsets.FilterBlockIfBlock;
	if (!VALID_OFFSET(ifBlockOffset)) {
		DbgMsg("[REGISTRY] Failed getting _NDIS_FILTER_BLOCK!IfBlock offset");
		return false;
	}

	DWORD64 ifBlockMiniportOffset = offsets.MiniportIfBlock;

	DWORD64 ifInterfaceGuid = offsets.MiniportBlockInterfaceGuid;
	if (!VALID_OFFSET(ifInterfaceGuid)) {
		DbgMsg("[REGISTRY] Failed getting _NDIS_MINIPORT_BLOCK!InterfaceGuid offset");
		return false;
	}

	DWORD64 miniportLowestFilterOffset = offsets.MiniportBlockLowestFilter;
	if (!VALID_OFFSET(miniportLowestFilterOffset)) {
		DbgMsg("[REGISTRY] Failed getting _NDIS_MINIPORT_BLOCK!LowestFilter offset");
		return false;
	}

	DWORD64 miniportHighestFilterOffset = offsets.MiniportBlockHighestFilter;
	if (!VALID_OFFSET(miniportHighestFilterOffset)) {
		DbgMsg("[REGISTRY] Failed getting _NDIS_MINIPORT_BLOCK!HighestFilter offset");
		return false;
	}

	DWORD64 ifPhyAddressOffset = offsets.IfBlockPhy;
	if (!VALID_OFFSET(ifPhyAddressOffset)) {
		DbgMsg("[REGISTRY] Failed getting _NDIS_IF_BLOCK!ifPhysAddress offset");
		return false;
	}

	DWORD64 PermanentPhysAddressOffset = offsets.IfBlockPermanentPhy;
	if (!VALID_OFFSET(PermanentPhysAddressOffset)) {
		DbgMsg("[REGISTRY] Failed getting _NDIS_IF_BLOCK!PermanentPhysAddress offset");
		return false;
	}

	DWORD64 PendingMacAddressOffset = offsets.MiniportPendingMacAddress;
	if (!VALID_OFFSET(PendingMacAddressOffset)) {
		DbgMsg("[REGISTRY] Failed getting _NDIS_MINIPORT_BLOCK!PendingMacAddress offset");
		return false;
	}

	rnd.setSeed(seed);
	rnd.setSecLevel(random::SecurityLevel::PREDICTABLE);

	if (!vMACs) {
		vMACs = (vector<PMAC_MODIFICATION_DATA>*)cpp::kMalloc(sizeof(*vMACs), PAGE_READWRITE);
		RtlZeroMemory(vMACs, sizeof(*vMACs));
		vMACs->Init();
		vMACs->reserve(64);
	}
	else {
		while (ndisGlobalFilterList) {
			PCHAR pCurrentFilter = (PCHAR)ndisGlobalFilterList;
			ndisGlobalFilterList = *(PVOID*)((DWORD64)ndisGlobalFilterList + nextFilterOffset);

			PVOID pLowestMiniportFilter = *(PVOID*)(pCurrentFilter + miniportLowestFilterOffset);
			PVOID pHighestMiniportFilter = *(PVOID*)(pCurrentFilter + miniportHighestFilterOffset);

			filterList.emplace_back(pCurrentFilter);
			filterList.emplace_back(pLowestMiniportFilter);
			filterList.emplace_back(pHighestMiniportFilter);

			DWORD64 pMiniportBlock = *(DWORD64*)(pCurrentFilter + miniportOffset);
			if (MmIsAddressValid((PVOID)pMiniportBlock)) {
				auto pNdisIfBlock = *(PNDIS_IF_BLOCK*)(pMiniportBlock + ifBlockMiniportOffset);
				if (MmIsAddressValid(pNdisIfBlock)) {
					auto pIfPhysAddress = (PIF_PHYSICAL_ADDRESS_LH)(&pNdisIfBlock->ifPhysAddress);
					auto pPermanentPhysAddress = (PIF_PHYSICAL_ADDRESS_LH)(&pNdisIfBlock->PermanentPhysAddress);

					if (MmIsAddressValid(pIfPhysAddress)) {
						FindFakeNicMacReset((char*)pIfPhysAddress->Address);
					}
					if (MmIsAddressValid(pPermanentPhysAddress)) {
						FindFakeNicMacReset((char*)pPermanentPhysAddress->Address);
					}
				}

				GUID* pGuid = (PGUID)(pMiniportBlock + ifInterfaceGuid);
				if (pGuid) {
					rnd.setSeed(spoofer::seed);
					_disable();
					//rnd.random_shuffle((char*)&pGuid->Data1, sizeof(pGuid->Data1));
					rnd.bytes((char*)&pGuid->Data2, sizeof(pGuid->Data2));
					rnd.bytes((char*)&pGuid->Data3, sizeof(pGuid->Data3));
					//rnd.random_shuffle((char*)&pGuid->Data4[0], sizeof(pGuid->Data4));
					_enable();
				}
			}
		}

		for (auto pFilter : filterList) {
			PVOID pLastFilter = nullptr;
			while (MmIsAddressValid(pFilter)
				&& (pFilter != pLastFilter)) {
				PCHAR pCurrentFilter = (PCHAR)pFilter;
				if (MmIsAddressValid((PVOID)((DWORD64)pFilter + nextFilterOffset))) {
					pFilter = *(PVOID*)((DWORD64)pFilter + nextFilterOffset);
				}
				else {
					DbgMsg("[NIC] pFilter not valid: %p", pFilter);
					pFilter = nullptr;
				}
				pLastFilter = pFilter;

				PNDIS_IF_BLOCK pNdisIfBlock = nullptr;
				pNdisIfBlock = *(PNDIS_IF_BLOCK*)(pCurrentFilter + ifBlockOffset);
				if (!MmIsAddressValid(pNdisIfBlock)) {
					DbgMsg("[NIC] NDIS block not valid: %p", pNdisIfBlock);
					continue;
				}
				PIF_PHYSICAL_ADDRESS_LH pIfPhysAddress = (PIF_PHYSICAL_ADDRESS_LH)(&pNdisIfBlock->ifPhysAddress);
				PIF_PHYSICAL_ADDRESS_LH pPermanentPhysAddress = (PIF_PHYSICAL_ADDRESS_LH)(&pNdisIfBlock->PermanentPhysAddress);

				if (MmIsAddressValid(pIfPhysAddress)) {
					FindFakeNicMacReset((char*)pIfPhysAddress->Address);
				}
				if (MmIsAddressValid(pPermanentPhysAddress)) {
					FindFakeNicMacReset((char*)pPermanentPhysAddress->Address);
				}
			}
		}

		for (auto& mac : *vMACs) {
			memcpy(mac->spoofed.raw, mac->orig.raw, sizeof(mac->spoofed));
		}

		while (ndisGlobalFilterList) {
			PCHAR pCurrentFilter = (PCHAR)ndisGlobalFilterList;
			ndisGlobalFilterList = *(PVOID*)((DWORD64)ndisGlobalFilterList + nextFilterOffset);

			PVOID pLowestMiniportFilter = *(PVOID*)(pCurrentFilter + miniportLowestFilterOffset);
			PVOID pHighestMiniportFilter = *(PVOID*)(pCurrentFilter + miniportHighestFilterOffset);

			DWORD64 pMiniportBlock = *(DWORD64*)(pCurrentFilter + miniportOffset);
			if (MmIsAddressValid((PVOID)pMiniportBlock)) {
				//auto pNdisIfBlock = *(PNDIS_IF_BLOCK*)(pMiniportBlock + ifBlockMiniportOffset);
				//if (MmIsAddressValid(pNdisIfBlock)) {
				//	auto pIfPhysAddress = (PIF_PHYSICAL_ADDRESS_LH)(&pNdisIfBlock->ifPhysAddress);
				//	auto pPermanentPhysAddress = (PIF_PHYSICAL_ADDRESS_LH)(&pNdisIfBlock->PermanentPhysAddress);
				//
				//	if (MmIsAddressValid(pIfPhysAddress)) {
				//		FindFakeNicMac((char*)pIfPhysAddress->Address);
				//	}
				//	if (MmIsAddressValid(pPermanentPhysAddress)) {
				//		FindFakeNicMac((char*)pPermanentPhysAddress->Address);
				//	}
				//}

				GUID* pGuid = (PGUID)(pMiniportBlock + ifInterfaceGuid);
				if (pGuid) {
					rnd.setSeed(spoofer::seed);
					_disable();
					//rnd.random_shuffle((char*)&pGuid->Data1, sizeof(pGuid->Data1));
					rnd.bytes((char*)&pGuid->Data2, sizeof(pGuid->Data2));
					rnd.bytes((char*)&pGuid->Data3, sizeof(pGuid->Data3));
					//rnd.random_shuffle((char*)&pGuid->Data4[0], sizeof(pGuid->Data4));
					_enable();
				}
			}
		}

		for (auto pFilter : filterList) {
			PVOID pLastFilter = nullptr;
			while (MmIsAddressValid(pFilter)
				&& (pFilter != pLastFilter)) {
				PCHAR pCurrentFilter = (PCHAR)pFilter;
				if (MmIsAddressValid((PVOID)((DWORD64)pFilter + nextFilterOffset))) {
					pFilter = *(PVOID*)((DWORD64)pFilter + nextFilterOffset);
				}
				else {
					DbgMsg("[NIC] pFilter not valid: %p", pFilter);
					pFilter = nullptr;
				}
				pLastFilter = pFilter;

				PNDIS_IF_BLOCK pNdisIfBlock = nullptr;
				pNdisIfBlock = *(PNDIS_IF_BLOCK*)(pCurrentFilter + ifBlockOffset);
				if (!MmIsAddressValid(pNdisIfBlock)) {
					DbgMsg("[NIC] NDIS block not valid: %p", pNdisIfBlock);
					continue;
				}
				PIF_PHYSICAL_ADDRESS_LH pIfPhysAddress = (PIF_PHYSICAL_ADDRESS_LH)(&pNdisIfBlock->ifPhysAddress);
				PIF_PHYSICAL_ADDRESS_LH pPermanentPhysAddress = (PIF_PHYSICAL_ADDRESS_LH)(&pNdisIfBlock->PermanentPhysAddress);

				if (MmIsAddressValid(pIfPhysAddress)) {
					FindFakeNicMac((char*)pIfPhysAddress->Address);
				}
				if (MmIsAddressValid(pPermanentPhysAddress)) {
					FindFakeNicMac((char*)pPermanentPhysAddress->Address);
				}
			}
		}
		return true;
	}

	HOOK_SECONDARY_INFO hkSecondaryInfo = { 0 };
	PDRIVER_OBJECT pDrivObj = IOCTL::GetDriverObj("\\Driver\\nsiproxy");
	NSIs.Drivers[NSIs.Length].DriverObject = pDrivObj;
	hkSecondaryInfo.pOrigFn = (PVOID*)&NSIs.Drivers[NSIs.Length].Original;

	vmm::vHooks->reserve(20);

	if (!EPT::HookExec(pDrivObj->MajorFunction[IRP_MJ_DEVICE_CONTROL], NsiControl, hkSecondaryInfo)) {
		DbgMsg("[NIC] Failed hooking nsiproxy IoDeviceCtrl");
		bRes = false;
	}
	else {
		DbgMsg("[NIC] Hooked nsiproxy IoDeviceCtrl");
		NSIs.Length++;
		bRes = true;
	}
	ObDereferenceObject(pDrivObj);
	if (!bRes)
		return false;

#pragma region "registry"

	//vector<string> toDeleteKeys;
	//string rootKey("SYSTEM\\CurrentControlSet\\Control\\Nsi");
	//string subKey;
	//registry::KeyEnumerator keyEnum(rootKey.c_str());
	//while (keyEnum.Next(subKey)) {
	//	toDeleteKeys.Append(rootKey + "\\" + subKey);
	//}
	//
	//for (auto& key : toDeleteKeys) {
	//	registry::Delete(key);
	//}

#pragma endregion

#pragma region "Filters"

	DWORD spoofedNICs = 0;

	while (ndisGlobalFilterList) {
		PCHAR pCurrentFilter = (PCHAR)ndisGlobalFilterList;
		ndisGlobalFilterList = *(PVOID*)((DWORD64)ndisGlobalFilterList + nextFilterOffset);

		PVOID pLowestMiniportFilter = *(PVOID*)(pCurrentFilter + miniportLowestFilterOffset);
		PVOID pHighestMiniportFilter = *(PVOID*)(pCurrentFilter + miniportHighestFilterOffset);

		filterList.emplace_back(pCurrentFilter);
		filterList.emplace_back(pLowestMiniportFilter);
		filterList.emplace_back(pHighestMiniportFilter);

		DWORD64 pMiniportBlock = *(DWORD64*)(pCurrentFilter + miniportOffset);
		if (MmIsAddressValid((PVOID)pMiniportBlock)) {
			//auto pNdisIfBlock = *(PNDIS_IF_BLOCK*)(pMiniportBlock + ifBlockMiniportOffset);
			//if (MmIsAddressValid(pNdisIfBlock)) {
			//	auto pIfPhysAddress = (PIF_PHYSICAL_ADDRESS_LH)(&pNdisIfBlock->ifPhysAddress);
			//	auto pPermanentPhysAddress = (PIF_PHYSICAL_ADDRESS_LH)(&pNdisIfBlock->PermanentPhysAddress);
			//
			//	if (MmIsAddressValid(pIfPhysAddress)) {
			//		FindFakeNicMac((char*)pIfPhysAddress->Address);
			//	}
			//	if (MmIsAddressValid(pPermanentPhysAddress)) {
			//		FindFakeNicMac((char*)pPermanentPhysAddress->Address);
			//	}
			//}

			GUID* pGuid = (PGUID)(pMiniportBlock + ifInterfaceGuid);
			if (pGuid) {
				_disable();
				//rnd.random_shuffle((char*)&pGuid->Data1, sizeof(pGuid->Data1));
				rnd.bytes((char*)&pGuid->Data2, sizeof(pGuid->Data2));
				rnd.bytes((char*)&pGuid->Data3, sizeof(pGuid->Data3));
				//rnd.random_shuffle((char*)&pGuid->Data4[0], sizeof(pGuid->Data4));
				_enable();
			}
		}
	}

	for (auto pFilter : filterList) {
		PVOID pLastFilter = nullptr;
		while (MmIsAddressValid(pFilter)
			&& (pFilter != pLastFilter)) {
			PCHAR pCurrentFilter = (PCHAR)pFilter;
			if (MmIsAddressValid((PVOID)((DWORD64)pFilter + nextFilterOffset))) {
				pFilter = *(PVOID*)((DWORD64)pFilter + nextFilterOffset);
			}
			else {
				DbgMsg("[NIC] pFilter not valid: %p", pFilter);
				pFilter = nullptr;
			}
			pLastFilter = pFilter;

			PNDIS_IF_BLOCK pNdisIfBlock = nullptr;
			pNdisIfBlock = *(PNDIS_IF_BLOCK*)(pCurrentFilter + ifBlockOffset);
			if (!MmIsAddressValid(pNdisIfBlock)) {
				DbgMsg("[NIC] NDIS block not valid: %p", pNdisIfBlock);
				continue;
			}
			PIF_PHYSICAL_ADDRESS_LH pIfPhysAddress = (PIF_PHYSICAL_ADDRESS_LH)(&pNdisIfBlock->ifPhysAddress);
			PIF_PHYSICAL_ADDRESS_LH pPermanentPhysAddress = (PIF_PHYSICAL_ADDRESS_LH)(&pNdisIfBlock->PermanentPhysAddress);
	
			if (MmIsAddressValid(pIfPhysAddress)) {
				FindFakeNicMac((char*)pIfPhysAddress->Address);
			}
			if (MmIsAddressValid(pPermanentPhysAddress)) {
				FindFakeNicMac((char*)pPermanentPhysAddress->Address);
			}
		}
		spoofedNICs++;
	}

	DbgMsg("[NIC] Spoofed %d network filters", spoofedNICs);

#pragma endregion

#pragma region "ndiswan"

	PNIC_DRIVER nic = &NICs.Drivers[NICs.Length];
	pDeviceObj = IOCTL::GetDevice("\\Device\\ndiswan");
	if (pDeviceObj) {
		nic->DriverObject = pDeviceObj->DriverObject;
		hkSecondaryInfo.pOrigFn = (PVOID*)&nic->Original;
		++NICs.Length;

		if (!EPT::HookExec(pDeviceObj->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL], NICControl, hkSecondaryInfo)) {
			DbgMsg("[NIC] Failed hooking ndiswan IoDeviceCtrl");
			return false;
		}
		else {
			DbgMsg("[NIC] Hooked ndiswan IoDeviceCtrl");
		}

		ObDereferenceObject(pDeviceObj);
	}
	else {
		DbgMsg("[IOCTL] Could not find ndiswan driver object!");
	}

#pragma endregion

#pragma region "nsi"

	nic = &NSIs.Drivers[NSIs.Length];
	pDeviceObj = IOCTL::GetDevice("\\Device\\nsi");
	if (pDeviceObj) {
		nic->DriverObject = pDeviceObj->DriverObject;
		hkSecondaryInfo.pOrigFn = (PVOID*)&nic->Original;

		++NSIs.Length;
		if (!EPT::HookExec(pDeviceObj->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL], NsiControl, hkSecondaryInfo)) {
			DbgMsg("[NIC] Failed hooking nsi IoDeviceCtrl");
			return false;
		}
		else {
			DbgMsg("[NIC] Hooked nsi IoDeviceCtrl");
		}

		ObDereferenceObject(pDeviceObj);
	}
	else {
		DbgMsg("[IOCTL] Could not find nsi driver object!");
	}

#pragma endregion

#pragma region "Tcp"

	hkSecondaryInfo.pOrigFn = (PVOID*)&pTcpCtrlOrig;
	pDeviceObj = IOCTL::GetDevice("\\Device\\Tcp");
	pDrivObj = pDeviceObj->DriverObject;

	if (!EPT::HookExec(pDrivObj->MajorFunction[IRP_MJ_DEVICE_CONTROL], TcpControl, hkSecondaryInfo)) {
		DbgMsg("[NIC] Failed hooking nsiproxy IoDeviceCtrl");
		bRes = false;
	}
	else {
		DbgMsg("[NIC] Hooked nsiproxy IoDeviceCtrl");
		bRes = true;
	}
	ObDereferenceObject(pDeviceObj);

#pragma endregion

#pragma region "ScanDeviceList"

	PWCHAR pDeviceNames = nullptr;
	const static GUID GUID_DEVINTERFACE_NET = { 0xcac88484, 0x7515, 0x4c03, { 0x82, 0xe6, 0x71, 0xa8, 0x7a, 0xba, 0xc3, 0x61 } };
	NTSTATUS ntStatus = IoGetDeviceInterfaces(&GUID_DEVINTERFACE_NET, nullptr, DEVICE_INTERFACE_INCLUDE_NONACTIVE, &pDeviceNames);
	if (!NT_SUCCESS(ntStatus)) {
		DbgMsg("[NIC] Failed enumerating net device interfaces: 0x%x", ntStatus);
		return false;
	}

	list<string> netInterfaces;
	while (true) {
		int strLen = wcslen(pDeviceNames);
		if (!strLen)
			break;
		netInterfaces.emplace_back(pDeviceNames);
		pDeviceNames += (strLen)+1;
	}

	for (auto& interface : netInterfaces) {
		PDEVICE_OBJECT pCurrDevObj = IOCTL::GetDeviceFromIName(interface);
		if (!pCurrDevObj) {
			continue;
		}
		DbgMsg("[NIC] Found device interface: %s", interface.c_str());

		nic = &NICs.Drivers[NICs.Length];
		nic->DriverObject = pCurrDevObj->DriverObject;
		hkSecondaryInfo.pOrigFn = (PVOID*)&nic->Original;

		NICs.Length++;
		if (!EPT::HookExec(pCurrDevObj->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL], NICControl, hkSecondaryInfo)) {
			DbgMsg("[NIC] Failed hooking %s IoDeviceCtrl", interface.c_str());
			NICs.Length--;
		}
		else {
			DbgMsg("[NIC] Hooked %s IoDeviceCtrl", interface.c_str());
		}
	}

#pragma endregion

	return bRes;
}
