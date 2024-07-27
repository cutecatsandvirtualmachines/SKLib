#pragma once

#ifndef _KERNEL_MODE
#include "umutils.hpp"

#include <Windows.h>
#include <stdlib.h>
#include <thread>

namespace spoofer {
	__forceinline void SpoofLogs() {
		system("for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\"");
	}

	__forceinline void ExtraCleanup() {
		system("vssadmin delete shadows /All /Quiet");

		system("net stop winmgmt /Y");
		system("ipconfig /flushdns");
		system("certutil -URLCache * delete");

		system("taskkill /F /IM WmiPrvSE.exe /T");
		system("powershell -c \"Reset-PhysicalDisk *\"");
		system("getmac /v");
	}

	__forceinline void SpoofDisplays() {
		OpenThen(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY", {
			ForEachSubkey(key, {
				OpenThen(key, name, {
					ForEachSubkey(key, {
						OpenThen(key, name, {
							ForEachSubkey(key, {
								if (_wcsicmp(name, L"device parameters") == 0) {
									DeleteValue(key, name, L"EDID");
									DeleteValue(key, name, L"EDID_Override");
								}
							});
						});
					});
				});
			});
		});
	}

	__forceinline void SpoofNICs() {
		OpenThen(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}", {
			ForEachSubkey(key, {
				if (_wcsicmp(name, L"configuration") && _wcsicmp(name, L"properties")) {
					DeleteValue(key, name, L"OriginalNetworkAddress");
					DeleteValue(key, name, L"NetworkAddress");
					SpoofQWORD(key, name, L"NetworkInterfaceInstallTimestamp");
				}
			});
		});
	}

	__forceinline void SpoofSMBIOS() {
		//DeleteValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data", L"SMBiosData");
	}

	__forceinline void SpoofMB() {
		SpoofUniqueThen(HKEY_LOCAL_MACHINE, L"SYSTEM\\HardwareConfig", L"LastConfig", {
			ForEachSubkey(key, {
				if (_wcsicmp(name, L"current")) {
					RenameSubkey(key, name, spoof);
					break;
				}
			});
		});
	}

	__forceinline void SpoofNVIDIA() {
		SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\NVIDIA Corporation\\Global", L"ClientUUID");
		SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\NVIDIA Corporation\\Global", L"PersistenceIdentifier");
		SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\NVIDIA Corporation\\Global\\CoProcManager", L"ChipsetMatchID");
	}

	__forceinline void SpoofMisc() {
		DeleteKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\MountedDevices");
		DeleteKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Dfrg\\Statistics");
		DeleteKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume");
		DeleteKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume");
		DeleteKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2");
		DeleteValue(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket", L"LastEnum");

		SpoofBinary(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI", L"WindowsAIKHash");
		//SpoofBinary(HKEY_CURRENT_USER, L"Software\\Microsoft\\Direct3D", L"WHQLClass");
		SpoofBinary(HKEY_CURRENT_USER, L"Software\\Classes\\Installer\\Dependencies", L"MSICache");

		SpoofBinary(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TPM\\ODUID", L"RandomSeed");
		SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
		SpoofUnique(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001", L"HwProfileGuid");
		SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate", L"AccountDomainSid");
		SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate", L"PingID");
		SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate", L"SusClientId");
		SpoofBinary(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate", L"SusClientIdValidation");
		SpoofBinary(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters", L"Dhcpv6DUID");
		SpoofUnique(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation", L"ComputerHardwareId");
		SpoofUniques(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation", L"ComputerHardwareIds");
		SpoofBinary(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Internet Explorer\\Migration", L"IE Installed Date");
		SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\SQMClient", L"MachineId");
		SpoofQWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\SQMClient", L"WinSqmFirstSessionStartTime");
		SpoofQWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"InstallTime");
		SpoofQWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"InstallDate");
		SpoofBinary(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"DigitalProductId");
		SpoofBinary(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"DigitalProductId4");
		SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"BuildGUID");
		SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductId");
		SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"BuildLab");
		SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"BuildLabEx");
		SpoofUnique(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", L"_DriverProviderInfo");
		SpoofUnique(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", L"UserModeDriverGUID");
		SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Win32kWPP\\Parameters", L"UserModeDriverGUID");
		SpoofUnique(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Activation Technologies\\AdminObject\\Store", L"MachineId");

		DeleteKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SettingsRequests");
		SpoofQWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SevilleEventlogManager", L"LastEventlogWrittenTime");
		SpoofQWORD(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform\\Activation", L"ProductActivationTime");
		DeleteValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform", L"BackupProductKeyDefault");
		DeleteValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform", L"actionlist");
		DeleteValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform", L"ServiceSessionId");
		SpoofUnique(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
		DeleteKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist");
		DeleteKey(HKEY_CURRENT_USER, L"Software\\Hex-Rays\\IDA\\History");
		DeleteKey(HKEY_CURRENT_USER, L"Software\\Hex-Rays\\IDA\\History64");
		DeleteKey(HKEY_CURRENT_USER, L"Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache");
		DeleteValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OneSettings\\WSD\\UpdateAgent\\QueryParameters", L"deviceId ");
		DeleteValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OneSettings\\WSD\\Setup360\\QueryParameters", L"deviceId ");
	}

	__forceinline void SpoofDisks() {
		OpenThen(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral", {
			ForEachSubkey(key, {
				DeleteValue(key, name, L"Identifier");
			});
			});
		OpenThen(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\KeyboardController\\0\\KeyboardPeripheral", {
			ForEachSubkey(key, {
				DeleteValue(key, name, L"Identifier");
			});
			});
		//OpenThen(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\Scsi", {
		//ForEachSubkey(key, {
		//	OpenThen(key, name, {
		//		ForEachSubkey(key, {
		//			OpenThen(key, name, {
		//				ForEachSubkey(key, {
		//					if (wcsstr(name, L"arget")) {
		//						OpenThen(key, name, {
		//							ForEachSubkey(key, {
		//								DeleteValue(key, name, L"SerialNumber");
		//								DeleteValue(key, name, L"Identifier");
		//								DeleteValue(key, name, L"DeviceIdentifierPage");
		//								DeleteValue(key, name, L"InquiryData");
		//							});
		//						});
		//					}
		//				});
		//			});
		//		});
		//	});
		//});
		//});
	}

	__forceinline void SpoofUEFI() {
		OpenThen(HKEY_LOCAL_MACHINE, L"HARDWARE\\UEFI\\ESRT", {
			WCHAR subkeys[0xFF][MAX_PATH] = { 0 };
			DWORD subkeys_length = 0;

			ForEachSubkey(key, {
				wcscpy(subkeys[subkeys_length++], name);
			});

			for (DWORD i = 0; i < subkeys_length; ++i) {
				WCHAR spoof[MAX_PATH] = { 0 };
				wcscpy(spoof, subkeys[i]);
				OutSpoofUnique(spoof);
				RenameSubkey(key, subkeys[i], spoof);
			}
		});
	}

	__forceinline void SpoofTracking() {
		WCHAR path[MAX_PATH] = { 0 };
		WCHAR temp[MAX_PATH] = { 0 };
		WCHAR appdata[MAX_PATH] = { 0 };
		WCHAR localappdata[MAX_PATH] = { 0 };
		GetTempPath(MAX_PATH, temp);

		SHGetFolderPath(0, CSIDL_APPDATA, 0, SHGFP_TYPE_DEFAULT, appdata);
		SHGetFolderPath(0, CSIDL_LOCAL_APPDATA, 0, SHGFP_TYPE_DEFAULT, localappdata);

		wsprintf(path, L"%ws\\ConnectedDevicesPlatform", localappdata);
		ForceDeleteFile(path);

		wsprintf(path, L"%ws\\NVIDIA Corporation\\GfeSDK", localappdata);
		ForceDeleteFile(path);

		wsprintf(path, L"%ws\\Microsoft\\Feeds", localappdata);
		ForceDeleteFile(path);

		wsprintf(path, L"%ws\\Microsoft\\Feeds Cache", localappdata);
		ForceDeleteFile(path);

		wsprintf(path, L"%ws\\Microsoft\\Windows\\INetCache", localappdata);
		ForceDeleteFile(path);

		wsprintf(path, L"%ws\\Microsoft\\Windows\\INetCookies", localappdata);
		ForceDeleteFile(path);

		wsprintf(path, L"%ws\\Microsoft\\Windows\\WebCache", localappdata);
		ForceDeleteFile(path);

		wsprintf(path, L"%ws\\Microsoft\\XboxLive\\AuthStateCache.dat", localappdata);
		ForceDeleteFile(path);

		for (DWORD drives = GetLogicalDrives(), drive = L'C', index = 0; drives; drives >>= 1, ++index) {
			if (drives & 1) {
				printf("\n-- DRIVE: %c --\n\n", drive);

				wsprintf(path, L"%c:\\Windows\\System32\\restore\\MachineGuid.txt", drive);
				ForceDeleteFile(path);

				wsprintf(path, L"%c:\\Users\\Public\\Libraries\\collection.dat", drive);
				ForceDeleteFile(path);

				wsprintf(path, L"%c:\\System Volume Information\\IndexerVolumeGuid", drive);
				ForceDeleteFile(path);

				wsprintf(path, L"%c:\\System Volume Information\\WPSettings.dat", drive);
				ForceDeleteFile(path);

				wsprintf(path, L"%c:\\System Volume Information\\tracking.log", drive);
				ForceDeleteFile(path);

				wsprintf(path, L"%c:\\ProgramData\\Microsoft\\Windows\\WER", drive);
				ForceDeleteFile(path);

				wsprintf(path, L"%c:\\Users\\Public\\Shared Files", drive);
				ForceDeleteFile(path);

				wsprintf(path, L"%c:\\Windows\\INF\\setupapi.dev.log", drive);
				ForceDeleteFile(path);

				wsprintf(path, L"%c:\\Windows\\INF\\setupapi.setup.log", drive);
				ForceDeleteFile(path);

				wsprintf(path, L"%c:\\Users\\Public\\Libraries", drive);
				ForceDeleteFile(path);

				wsprintf(path, L"%c:\\MSOCache", drive);
				ForceDeleteFile(path);

				wsprintf(path, L"%c:\\ProgramData\\ntuser.pol", drive);
				ForceDeleteFile(path);

				wsprintf(path, L"%c:\\Users\\Default\\NTUSER.DAT", drive);
				ForceDeleteFile(path);

				wsprintf(path, L"%c:\\Recovery\\ntuser.sys", drive);
				ForceDeleteFile(path);

				wsprintf(path, L"%c:\\desktop.ini", drive);
				ForceDeleteFile(path);

				wsprintf(path, L"%c:\\Users", drive);
				RecursiveDelete(path, (LPWSTR)L"desktop.ini");

				CHAR journal[MAX_PATH] = { 0 };
				sprintf(journal, "fsutil usn deletejournal /d %c:", drive);
				system(journal);

				++drive;
			}
		}
	}

	__forceinline bool SpoofAll() {
		srand(GetTickCount64());
		LoadLibrary(L"ntdll.dll");
		NtQueryKey = (NTQK)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryKey");
		if (!AdjustCurrentPrivilege(SE_TAKE_OWNERSHIP_NAME)) {
			printf("failed to adjust privilege\n");
			return false;
		}

		//{
		//	std::thread spoofThread(SpoofLogs);
		//	spoofThread.detach();
		//}

		{
			std::thread spoofThread(ExtraCleanup);
			spoofThread.detach();
		}

		//{
		//	std::thread spoofThread(SpoofDisplays);
		//	spoofThread.detach();
		//}

		{
			std::thread spoofThread(SpoofNICs);
			spoofThread.detach();
		}

		{
			std::thread spoofThread(SpoofSMBIOS);
			spoofThread.detach();
		}

		{
			std::thread spoofThread(SpoofMB);
			spoofThread.detach();
		}

		{
			std::thread spoofThread(SpoofNVIDIA);
			spoofThread.detach();
		}

		{
			std::thread spoofThread(SpoofMisc);
			spoofThread.detach();
		}

		{
			std::thread spoofThread(SpoofDisks);
			spoofThread.detach();
		}

		{
			std::thread spoofThread(SpoofUEFI);
			spoofThread.detach();
		}

		//{
		//	std::thread spoofThread(SpoofTracking);
		//	spoofThread.detach();
		//}

		return true;
	}
}

#endif