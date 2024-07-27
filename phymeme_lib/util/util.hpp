#pragma once
#include <Windows.h>
#include <cstdint>
#include <string_view>
#include <iterator>
#include <fstream>
#include <string>
#include <map>
#include <vector>
#include <ntstatus.h>
#include <winternl.h>
#include <array>
#include <algorithm>
#include <string_view>

#include "nt.hpp"

namespace util
{ 
	//--- ranges of physical memory
	static std::map<std::uintptr_t, std::size_t> pmem_ranges{};

	//--- validates the address
	static bool is_valid(std::uintptr_t addr)
	{
		for (auto range : pmem_ranges)
			if (addr >= range.first && addr <= range.first + range.second)
				return true;
		return false;
	}

	// Author: Remy Lebeau
	// taken from here: https://stackoverflow.com/questions/48485364/read-reg-resource-list-memory-values-incorrect-value
	static const auto init_ranges = ([]() -> bool
	{
			HKEY h_key;
			DWORD type, size;
			LPBYTE data;
			RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory", 0, KEY_READ, &h_key);
			RegQueryValueExA(h_key, ".Translated", NULL, &type, NULL, &size); //get size
			data = new BYTE[size];
			RegQueryValueExA(h_key, ".Translated", NULL, &type, data, &size);
			DWORD count = *(DWORD*)(data + 16);
			auto pmi = data + 24;
			for (int dwIndex = 0; dwIndex < count; dwIndex++)
			{
				pmem_ranges.emplace(*(uint64_t*)(pmi + 0), *(uint64_t*)(pmi + 8));
				pmi += 20;
			}
			delete[] data;
			RegCloseKey(h_key);
			return true;
	})();

	inline PIMAGE_FILE_HEADER get_file_header(void* base_addr)
	{
		if (!base_addr || *(short*)base_addr != 0x5A4D)
			return NULL;

		PIMAGE_DOS_HEADER dos_headers =
			reinterpret_cast<PIMAGE_DOS_HEADER>(base_addr);

		PIMAGE_NT_HEADERS nt_headers =
			reinterpret_cast<PIMAGE_NT_HEADERS>(
				reinterpret_cast<DWORD_PTR>(base_addr) + dos_headers->e_lfanew);

		return &nt_headers->FileHeader;
	}

	// this was taken from wlan's drvmapper:
	// https://github.com/not-wlan/drvmap/blob/98d93cc7b5ec17875f815a9cb94e6d137b4047ee/drvmap/util.cpp#L7
	static void open_binary_file(const std::string& file, std::vector<uint8_t>& data)
	{
		std::ifstream fstr(file, std::ios::binary);
		fstr.unsetf(std::ios::skipws);
		fstr.seekg(0, std::ios::end);

		const auto file_size = fstr.tellg();

		fstr.seekg(NULL, std::ios::beg);
		data.reserve(static_cast<uint32_t>(file_size));
		data.insert(data.begin(), std::istream_iterator<uint8_t>(fstr), std::istream_iterator<uint8_t>());
	}

	// get base address of kernel module
	//
	// taken from: https://github.com/z175/kdmapper/blob/master/kdmapper/utils.cpp#L30
	static std::uintptr_t get_module_base(const char* module_name)
	{
		void* buffer = nullptr;
		DWORD buffer_size = NULL;

		NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation), buffer, buffer_size, &buffer_size);

		while (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			VirtualFree(buffer, NULL, MEM_RELEASE);
			buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation), buffer, buffer_size, &buffer_size);
		}

		if (!NT_SUCCESS(status))
		{
			VirtualFree(buffer, NULL, MEM_RELEASE);
			return NULL;
		}

		const auto modules = static_cast<PRTL_PROCESS_MODULES>(buffer);
		for (auto idx = 0u; idx < modules->NumberOfModules; ++idx)
		{
			const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[idx].FullPathName) + modules->Modules[idx].OffsetToFileName);
			if (!_stricmp(current_module_name.c_str(), module_name))
			{
				const uint64_t result = reinterpret_cast<uint64_t>(modules->Modules[idx].ImageBase);
				VirtualFree(buffer, NULL, MEM_RELEASE);
				return result;
			}
		}

		VirtualFree(buffer, NULL, MEM_RELEASE);
		return NULL;
	}

	// get base address of kernel module
	//
	// taken from: https://github.com/z175/kdmapper/blob/master/kdmapper/utils.cpp#L30
	static void* get_kernel_export(const char* module_name, const char* export_name, bool rva = false)
	{
		void* buffer = nullptr;
		DWORD buffer_size = NULL;

		NTSTATUS status = NtQuerySystemInformation(
			static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation),
			buffer,
			buffer_size,
			&buffer_size
		);

		while (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			VirtualFree(buffer, 0, MEM_RELEASE);
			buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			status = NtQuerySystemInformation(
				static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation), 
				buffer, 
				buffer_size, 
				&buffer_size
			);
		}

		if (!NT_SUCCESS(status))
		{
			VirtualFree(buffer, 0, MEM_RELEASE);
			return 0;
		}

		const auto modules = static_cast<PRTL_PROCESS_MODULES>(buffer);
		for (auto idx = 0u; idx < modules->NumberOfModules; ++idx)
		{
			// find module and then load library it
			const std::string current_module_name = 
				std::string(reinterpret_cast<char*>(
					modules->Modules[idx].FullPathName) +
					modules->Modules[idx].OffsetToFileName
				);

			if (!_stricmp(current_module_name.c_str(), module_name))
			{
				// had to shoot the tires off of "\\SystemRoot\\"
				std::string full_path = reinterpret_cast<char*>(modules->Modules[idx].FullPathName);
				full_path.replace(
					full_path.find("\\SystemRoot\\"),
					sizeof("\\SystemRoot\\") - 1,
					std::string(getenv("SYSTEMROOT")).append("\\")
				);

				const auto module_base = 
					LoadLibraryExA(
						full_path.c_str(),
						NULL, 
						DONT_RESOLVE_DLL_REFERENCES
					);

				PIMAGE_DOS_HEADER p_idh;
				PIMAGE_NT_HEADERS p_inh;
				PIMAGE_EXPORT_DIRECTORY p_ied;

				PDWORD addr, name;
				PWORD ordinal;

				p_idh = (PIMAGE_DOS_HEADER)module_base;
				if (p_idh->e_magic != IMAGE_DOS_SIGNATURE)
					return NULL;

				p_inh = (PIMAGE_NT_HEADERS)((LPBYTE)module_base + p_idh->e_lfanew);
				if (p_inh->Signature != IMAGE_NT_SIGNATURE)
					return NULL;

				if (p_inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
					return NULL;

				p_ied = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module_base +
					p_inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

				addr = (PDWORD)((LPBYTE)module_base + p_ied->AddressOfFunctions);
				name = (PDWORD)((LPBYTE)module_base + p_ied->AddressOfNames);
				ordinal = (PWORD)((LPBYTE)module_base + p_ied->AddressOfNameOrdinals);

				// find exported function
				for (auto i = 0; i < p_ied->AddressOfFunctions; i++)
					if (!strcmp(export_name, (char*)module_base + name[i]))
					{
						if (!rva)
						{
							auto result = (void*)((std::uintptr_t)modules->Modules[idx].ImageBase + addr[ordinal[i]]);
							VirtualFree(buffer, NULL, MEM_RELEASE);
							return result;
						}
						else
						{
							auto result = (void*)addr[ordinal[i]];
							VirtualFree(buffer, NULL, MEM_RELEASE);
							return result;
						}
					}
			}
		}
		VirtualFree(buffer, NULL, MEM_RELEASE);
		return NULL;
	}

	namespace memory 
	{
		template<std::size_t pattern_length>
		inline std::uintptr_t pattern_scan_kernel(const char(&signature)[pattern_length], const char(&mask)[pattern_length])
		{
			static const auto kernel_addr = 
				LoadLibraryExA(
					"ntoskrnl.exe",
					NULL, 
					DONT_RESOLVE_DLL_REFERENCES
				);

			static const auto p_idh = reinterpret_cast<PIMAGE_DOS_HEADER>(kernel_addr);
			if (p_idh->e_magic != IMAGE_DOS_SIGNATURE)
				return NULL;

			static const auto p_inh = reinterpret_cast<PIMAGE_NT_HEADERS>((LPBYTE)kernel_addr + p_idh->e_lfanew);
			if (p_inh->Signature != IMAGE_NT_SIGNATURE)
				return NULL;

			static auto current_section = reinterpret_cast<PIMAGE_SECTION_HEADER>(p_inh + 1);
			static const auto first_section = current_section;
			static const auto num_sec = p_inh->FileHeader.NumberOfSections;
			static std::atomic<bool> ran_before = false;

			//
			// only run this once.
			//
			if(!ran_before.exchange(true))
				for (; current_section < first_section + num_sec; ++current_section)
					if(!strcmp(reinterpret_cast<char*>(current_section->Name), "PAGE"))
						break;

			static const auto page_section_begin = 
				reinterpret_cast<std::uint64_t>(kernel_addr) + current_section->VirtualAddress;

			const auto pattern_view = std::string_view{ 
				reinterpret_cast<char*>(page_section_begin),
				current_section->SizeOfRawData
			};

			std::array<std::pair<char, char>, pattern_length - 1> pattern{};

			for (std::size_t index = 0; index < pattern_length - 1; index++)
				pattern[index] = { signature[index], mask[index] };

			auto resultant_address = std::search(
				pattern_view.cbegin(),
				pattern_view.cend(),
				pattern.cbegin(),
				pattern.cend(),
				[](char left, std::pair<char, char> right) -> bool {
					return (right.second == '?' || left == right.first);
				});

			return resultant_address == pattern_view.cend() ? 0 : reinterpret_cast<std::uintptr_t>(resultant_address.operator->());
		}

		//
		// be aware that this may not work for win8 or win7!
		//
		inline void* get_piddb_lock()
		{
			static auto absolute_addr_instruction =
				pattern_scan_kernel(
					piddb_lock_sig,
					piddb_lock_mask
				);
			if (!absolute_addr_instruction) {
				absolute_addr_instruction =
					pattern_scan_kernel(
						piddb_lock_sig2,
						piddb_lock_mask2
					);
				absolute_addr_instruction += 16;
			}
			else {
				absolute_addr_instruction += 28;
			}

			static const auto ntoskrnl_in_my_process =
				reinterpret_cast<std::uintptr_t>(GetModuleHandleA("ntoskrnl.exe"));

			if (!absolute_addr_instruction || !ntoskrnl_in_my_process)
				return {};

			const auto lea_rip_rva = *(PLONG)(absolute_addr_instruction + 3);
			const auto real_rva = (absolute_addr_instruction + 7 + lea_rip_rva) - ntoskrnl_in_my_process;
			static const auto kernel_base = util::get_module_base("ntoskrnl.exe");

			if (!kernel_base)
				return {};

			return reinterpret_cast<void*>(kernel_base + real_rva);
		}

		//
		// be aware that this may not work for win8 or win7!
		//
		inline void* get_piddb_table()
		{
			static auto absolute_addr_instruction = 
				pattern_scan_kernel(
					piddb_table_sig,
					piddb_table_mask
				);

			static const auto ntoskrnl_in_my_process =
				reinterpret_cast<std::uintptr_t>(GetModuleHandleA("ntoskrnl.exe"));

			if (!absolute_addr_instruction || !ntoskrnl_in_my_process)
				return {};

			const auto lea_rip_rva = *(PLONG)(absolute_addr_instruction + 6);
			const auto real_rva = (absolute_addr_instruction + 10 + lea_rip_rva) - ntoskrnl_in_my_process;
			static const auto kernel_base = util::get_module_base("ntoskrnl.exe");

			if (!kernel_base)
				return {};

			return reinterpret_cast<void*>(kernel_base + real_rva);
		}
	}
}