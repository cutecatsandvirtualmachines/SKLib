#include "usbspoof.h"

typedef struct _USB_DRIVER {
	PDRIVER_OBJECT DriverObject;
	PDRIVER_DISPATCH Original;
} USB_DRIVER, * PUSB_DRIVER;

struct USBS {
	DWORD Length;
	USB_DRIVER Drivers[0xFF];
} USBs = { 0 };

NTSTATUS GetNodeConnectionInfoExIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (MmIsAddressValid(context)) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		PUSB_NODE_CONNECTION_INFORMATION_EX pUsbInfo = (PUSB_NODE_CONNECTION_INFORMATION_EX)request.Buffer;
		if (MmIsAddressValid(pUsbInfo)) {
			pUsbInfo->DeviceDescriptor.iSerialNumber = 0;
			//pUsbInfo->DeviceDescriptor.iProduct = 0;
			//pUsbInfo->DeviceDescriptor.iManufacturer = 0;
			//pUsbInfo->DeviceDescriptor.idProduct = 0;
			//pUsbInfo->DeviceDescriptor.idVendor = 0;
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS GetNodeConnectionInfoIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (MmIsAddressValid(context)) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		PUSB_NODE_CONNECTION_INFORMATION pUsbInfo = (PUSB_NODE_CONNECTION_INFORMATION)request.Buffer;
		if (MmIsAddressValid(pUsbInfo)) {
			pUsbInfo->DeviceDescriptor.iSerialNumber = 0;
			//pUsbInfo->DeviceDescriptor.iProduct = 0;
			//pUsbInfo->DeviceDescriptor.iManufacturer = 0;
			//pUsbInfo->DeviceDescriptor.idProduct = 0;
			//pUsbInfo->DeviceDescriptor.idVendor = 0;
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS UsbHubControl(PDEVICE_OBJECT device, PIRP irp) {
	for (size_t i = 0; i < USBs.Length; i++) {
		PUSB_DRIVER driver = &USBs.Drivers[i];

		if (driver->Original &&
			MmIsAddressValid(driver->DriverObject) &&
			driver->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] == device->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]) {
			if (cpp::IsKernelAddress(irp)) {
				PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
				if (!MmIsAddressValid(ioc))
					return driver->Original(device, irp);

				switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
				case IOCTL_USB_GET_NODE_CONNECTION_INFORMATION:
					LogCaller(irp, HookedDriver::DriverUSB);
					ChangeIoc(ioc, irp, GetNodeConnectionInfoIoc);
					break;
				case IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX:
					LogCaller(irp, HookedDriver::DriverUSB);
					ChangeIoc(ioc, irp, GetNodeConnectionInfoExIoc);
					break;
				case IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION:
					LogCaller(irp, HookedDriver::DriverUSB);
					return STATUS_SUCCESS;
				}
			}

			return driver->Original(device, irp);
		}
	}

	return STATUS_UNSUCCESSFUL;
}

bool usb::Spoof(DWORD64 seed)
{
	rnd.setSeed(seed);
	rnd.setSecLevel(random::SecurityLevel::PREDICTABLE);

	//vector<string> toDeleteKeys;
	//
	//registry::KeyEnumerator usbEnum("SYSTEM\\CurrentControlSet\\Enum\\USB");
	//string subKey;
	//while (usbEnum.Next(subKey)) {
	//	string fullSubPath = string("SYSTEM\\CurrentControlSet\\Enum\\USB\\") + subKey;
	//	registry::KeyEnumerator subEnum(fullSubPath.c_str());
	//	string deviceInstanceId;
	//	while (subEnum.Next(deviceInstanceId)) {
	//		fullSubPath += "\\";
	//		fullSubPath += deviceInstanceId;
	//		toDeleteKeys.Append(fullSubPath);
	//	}
	//}
	//
	//for (auto& key : toDeleteKeys) {
	//	registry::Delete(key);
	//}

	HOOK_SECONDARY_INFO hkSecondaryInfo = { 0 };
	PAGE_PERMISSIONS pgPermissions = { 0 };

	PWCHAR pDeviceNames = nullptr;
	const GUID GUID_USB_HUB = { 0xf18a0e88, 0xc30c, 0x11d0, 0x88, 0x15, 0x00, 0xa0, 0xc9, 0x06, 0xbe, 0xd8 };
	NTSTATUS ntStatus = IoGetDeviceInterfaces(&GUID_USB_HUB, nullptr, DEVICE_INTERFACE_INCLUDE_NONACTIVE, &pDeviceNames);
	if (!NT_SUCCESS(ntStatus)) {
		DbgMsg("[USB] Failed enumerating usb device interfaces: 0x%x", ntStatus);
		return false;
	}

	list<string> usbInterfaces;
	while (true) {
		int strLen = wcslen(pDeviceNames);
		if (!strLen)
			break;
		usbInterfaces.emplace_back(pDeviceNames);
		pDeviceNames += (strLen)+1;
	}

	vmm::vHooks->reserve(20);

	for (auto& interface : usbInterfaces) {
		PDEVICE_OBJECT pCurrDevObj = IOCTL::GetDeviceFromIName(interface);
		if (!pCurrDevObj) {
			continue;
		}
		DbgMsg("[USB] Found device interface: %s", interface.c_str());

		auto usb = &USBs.Drivers[USBs.Length];
		usb->DriverObject = pCurrDevObj->DriverObject;
		hkSecondaryInfo.pOrigFn = (PVOID*)&usb->Original;

		if (!EPT::HookExec(pCurrDevObj->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL], UsbHubControl, hkSecondaryInfo)) {
			DbgMsg("[USB] Failed hooking %s IoDeviceCtrl", interface.c_str());
		}
		else {
			DbgMsg("[USB] Hooked %s IoDeviceCtrl", interface.c_str());
		}
		USBs.Length++;
	}

    return true;
}
