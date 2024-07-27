#include "registry.h"

HANDLE registry::GetKeyHandleEx(string& path) {
	OBJECT_ATTRIBUTES KeyAttributes;
	UNICODE_STRING ValueName;
	HANDLE hKey;
	path = string("\\Registry\\Machine\\") + path;

	InitializeObjectAttributes(&KeyAttributes,
		&path.unicode(),
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	ULONG keyFlag = REG_OPENED_EXISTING_KEY;
	NTSTATUS ntStatus = ZwCreateKey(&hKey, KEY_ALL_ACCESS, &KeyAttributes, 0, NULL, REG_OPTION_NON_VOLATILE, &keyFlag);
	if (ntStatus != STATUS_SUCCESS) {
		DbgMsg("[REGISTRY] Could not open registry key: %x - %s", ntStatus, path.c_str());
		return INVALID_KEY_VALUE;
	}
	DbgMsg("[REGISTRY] Opened registry key: %x - %wZ", ntStatus, path.unicode());

	return hKey;
}

bool registry::RenameEx(string path, string newName)
{
	OBJECT_ATTRIBUTES KeyAttributes;
	UNICODE_STRING Name;
	UNICODE_STRING ValueName;
	HANDLE hKey = GetKeyHandleEx(path);
	if (hKey == INVALID_KEY_VALUE) {
		return false;
	}

	NTSTATUS ntStatus = ZwRenameKey(hKey, &newName.unicode());
	if (ntStatus != STATUS_SUCCESS) {
		DbgMsg("[REGISTRY] Could not change registry key name: %x:%s", ntStatus, path.c_str());
		return false;
	}

	ZwClose(hKey);

	return true;
}

bool registry::Delete(string path) {
	OBJECT_ATTRIBUTES KeyAttributes;
	UNICODE_STRING Name;
	UNICODE_STRING ValueName;
	HANDLE hKey = GetKeyHandleEx(path);
	if (hKey == INVALID_KEY_VALUE) {
		return false;
	}
	
	ULONG keyIndex = 0;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	while (NT_SUCCESS(ntStatus)) {
		KEY_BASIC_INFORMATION* pKeyInfo = (KEY_BASIC_INFORMATION*)cpp::kMalloc(0x100, PAGE_READWRITE);
		RtlZeroMemory(pKeyInfo, 0x100);
		ULONG realLength = 0;
		ntStatus = ZwEnumerateKey(hKey, keyIndex, KeyBasicInformation, pKeyInfo, 0x100, &realLength);
		if (ntStatus == STATUS_BUFFER_TOO_SMALL) {
			cpp::kFree(pKeyInfo);
			pKeyInfo = (KEY_BASIC_INFORMATION*)cpp::kMalloc(realLength, PAGE_READWRITE);
			ntStatus = ZwEnumerateKey(hKey, keyIndex, KeyBasicInformation, pKeyInfo, realLength, &realLength);
			if (!NT_SUCCESS(ntStatus)) {
				//DbgMsg("[REGISTRY] Failed enumerating key: 0%x - %s", ntStatus, path.c_str());
				return false;
			}
		}
		if (pKeyInfo->NameLength) {
			string strName((wchar_t*)pKeyInfo->Name);
			string newPath = path;
			newPath += "\\";
			newPath += strName;
			if (!Delete(newPath))
				keyIndex++;
		}

		cpp::kFree(pKeyInfo);
	}

	KEY_VALUE_BASIC_INFORMATION* pKeyValueInfo = (KEY_VALUE_BASIC_INFORMATION*)cpp::kMalloc(0x100, PAGE_READWRITE);
	while (NT_SUCCESS(ntStatus)) {
		ULONG valueLength = 0;
		RtlZeroMemory(pKeyValueInfo, 0x100);
		ntStatus = ZwEnumerateValueKey(hKey, 0, KeyValueBasicInformation, pKeyValueInfo, 0x100, &valueLength);
		if (ntStatus == STATUS_BUFFER_TOO_SMALL) {
			cpp::kFree(pKeyValueInfo);
			pKeyValueInfo = (KEY_VALUE_BASIC_INFORMATION*)cpp::kMalloc(valueLength, PAGE_READWRITE);
			ntStatus = ZwEnumerateValueKey(hKey, 0, KeyValueBasicInformation, pKeyValueInfo, valueLength, &valueLength);
			if (!NT_SUCCESS(ntStatus)) {
				//DbgMsg("[REGISTRY] Failed enumerating key values: 0%x - %s", ntStatus, path.c_str());
				return false;
			}
		}

		if (!pKeyValueInfo->NameLength) {
			break;
		}
		string keyValueName(pKeyValueInfo->Name);
		ntStatus = ZwDeleteValueKey(hKey, &keyValueName.unicode());
		if (!NT_SUCCESS(ntStatus)) {
			//DbgMsg("[REGISTRY] Failed deleting key value: 0%x - %s\\%s", ntStatus, path.c_str(), keyValueName.c_str());
			return false;
		}
	}
	cpp::kFree(pKeyValueInfo);

	ntStatus = ZwDeleteKey(hKey);
	if (ntStatus != STATUS_SUCCESS) {
		//DbgMsg("[REGISTRY] Could not delete registry key: %x", ntStatus);
		return false;
	}

	ZwClose(hKey);

	return true;
}

bool registry::DeleteKeyValueEx(string path, string valueName)
{
	HANDLE hKey = GetKeyHandleEx(path);
	if (hKey == INVALID_KEY_VALUE) {
		return false;
	}

	NTSTATUS ntStatus = ZwDeleteValueKey(hKey, &valueName.unicode());
	if (ntStatus != STATUS_SUCCESS) {
		DbgMsg("[REGISTRY] Could not delete registry key value: %x", ntStatus);
		return false;
	}
	else {
		//DbgMsg("[REGISTRY] Set registry key %s", valueName.c_str());
	}

	ZwClose(hKey);

	return true;
}

registry::KeyEnumerator::KeyEnumerator(const char* pKeyPath)
{
	string str(pKeyPath);
	hRootKey = GetKeyHandleEx(str);
	currentKeyIndex = 0;
}

registry::KeyEnumerator::~KeyEnumerator()
{
	ZwClose(hRootKey);
}

bool registry::KeyEnumerator::Next(string& outSubkeyName)
{
	OBJECT_ATTRIBUTES KeyAttributes;
	UNICODE_STRING Name;
	UNICODE_STRING ValueName;
	if (hRootKey == INVALID_KEY_VALUE)
		return false;

	BOOLEAN bRes = FALSE;

	KEY_BASIC_INFORMATION* pKeyInfo = (KEY_BASIC_INFORMATION*)cpp::kMalloc(0x100, PAGE_READWRITE);
	RtlZeroMemory(pKeyInfo, 0x100);
	ULONG realLength = 0;
	NTSTATUS ntStatus = ZwEnumerateKey(hRootKey, currentKeyIndex, KeyBasicInformation, pKeyInfo, 0x100, &realLength);
	if (ntStatus == STATUS_BUFFER_TOO_SMALL) {
		cpp::kFree(pKeyInfo);
		pKeyInfo = (KEY_BASIC_INFORMATION*)cpp::kMalloc(realLength, PAGE_READWRITE);
		ntStatus = ZwEnumerateKey(hRootKey, currentKeyIndex, KeyBasicInformation, pKeyInfo, realLength, &realLength);
		if (!NT_SUCCESS(ntStatus)) {
			DbgMsg("[REGISTRY] Failed enumerating key: 0%x", ntStatus);
			bRes = false;
		}
	}
	if (pKeyInfo->NameLength) {
		outSubkeyName = (wchar_t*)pKeyInfo->Name;
		currentKeyIndex++;
		bRes = true;
	}
	else
		bRes = false;

	cpp::kFree(pKeyInfo);

	return bRes;
}
