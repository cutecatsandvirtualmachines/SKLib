#pragma once

#include "cpp.h"
#include "data.h"
#include "StringEx.h"

#ifdef _KERNEL_MODE

#define INVALID_KEY_VALUE ((HANDLE)-1)

namespace registry {
	HANDLE GetKeyHandleEx(string& path);
	bool RenameEx(string path, string newName);
	bool Delete(string path);
	bool DeleteKeyValueEx(string path, string valueName);

	template<typename F>
	bool DeleteIf(string path, F callback) {
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
			KEY_BASIC_INFORMATION* pKeyInfo = (KEY_BASIC_INFORMATION*)cpp::kMalloc(0x100);
			RtlZeroMemory(pKeyInfo, 0x100);
			ULONG realLength = 0;
			ntStatus = ZwEnumerateKey(hKey, keyIndex, KeyBasicInformation, pKeyInfo, 0x100, &realLength);
			if (ntStatus == STATUS_BUFFER_TOO_SMALL) {
				cpp::kFree(pKeyInfo);
				pKeyInfo = (KEY_BASIC_INFORMATION*)cpp::kMalloc(realLength);
				ntStatus = ZwEnumerateKey(hKey, keyIndex, KeyBasicInformation, pKeyInfo, realLength, &realLength);
				if (!NT_SUCCESS(ntStatus)) {
					DbgMsg("[REGISTRY] Failed enumerating key: 0%x - %s", ntStatus, path.c_str());
					return false;
				}
			}
			if (pKeyInfo->NameLength) {
				string strName((wchar_t*)pKeyInfo->Name);
				string newPath = path;
				newPath += "\\";
				newPath += strName;
				if (!DeleteIf(newPath, callback))
					keyIndex++;
			}

			cpp::kFree(pKeyInfo);
		}

		KEY_VALUE_BASIC_INFORMATION* pKeyValueInfo = (KEY_VALUE_BASIC_INFORMATION*)cpp::kMalloc(0x100);
		while (NT_SUCCESS(ntStatus)) {
			ULONG valueLength = 0;
			RtlZeroMemory(pKeyValueInfo, 0x100);
			ntStatus = ZwEnumerateValueKey(hKey, 0, KeyValueBasicInformation, pKeyValueInfo, 0x100, &valueLength);
			if (ntStatus == STATUS_BUFFER_TOO_SMALL) {
				cpp::kFree(pKeyValueInfo);
				pKeyValueInfo = (KEY_VALUE_BASIC_INFORMATION*)cpp::kMalloc(valueLength);
				ntStatus = ZwEnumerateValueKey(hKey, 0, KeyValueBasicInformation, pKeyValueInfo, valueLength, &valueLength);
				if (!NT_SUCCESS(ntStatus)) {
					DbgMsg("[REGISTRY] Failed enumerating key values: 0%x - %s", ntStatus, path.c_str());
					return false;
				}
			}

			if (!pKeyValueInfo->NameLength) {
				break;
			}
			string keyValueName(pKeyValueInfo->Name);
			ntStatus = ZwDeleteValueKey(hKey, &keyValueName.unicode());
			if (!NT_SUCCESS(ntStatus)) {
				DbgMsg("[REGISTRY] Failed deleting key value: 0%x - %s\\%s", ntStatus, path.c_str(), keyValueName.c_str());
				return false;
			}
		}
		cpp::kFree(pKeyValueInfo);

		ntStatus = callback(path) ? ZwDeleteKey(hKey) : STATUS_UNSUCCESSFUL;
		if (ntStatus != STATUS_SUCCESS) {
			DbgMsg("[REGISTRY] Could not delete registry key name: %x:%s", ntStatus, path.c_str());
			return false;
		}

		ZwClose(hKey);

		return true;
	}

	template<typename T>
	bool SetKeyValueEx(string path, string valueName, T* value, ULONG valueType, ULONG valueSize = 0) {
		HANDLE hKey = GetKeyHandleEx(path);
		if (hKey == INVALID_KEY_VALUE) {
			DbgMsg("[REGISTRY] INVALID_KEY_VALUE");
			return false;
		}

		ULONG out = valueSize ? valueSize : sizeof(T);

		NTSTATUS ntStatus = ZwSetValueKey(hKey, &valueName.unicode(), 0, valueType, value, out);
		if (!NT_SUCCESS(ntStatus)) {
			DbgMsg("[REGISTRY] Could not set registry key value: %x", ntStatus);
			return false;
		}
		else {
			DbgMsg("[REGISTRY] Set registry key %s: 0x%x", valueName.c_str(), ntStatus);
		}

		ZwClose(hKey);

		return true;
	}

	class KeyEnumerator {
	private:
		HANDLE hRootKey;
		ULONG currentKeyIndex;
	public:
		KeyEnumerator(const char* pKeyPath);
		~KeyEnumerator();

		bool Next(string& outSubkeyName);
	};
}

#endif