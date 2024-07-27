#include "kernel_ctx/kernel_ctx.h"
#include "drv_image/drv_image.h"
#include "map_driver.hpp"
#include "kernel_ctx/dbrequest.h"


namespace physmeme
{
	bool bInit = false;
	void Init()
	{
		if(!bInit)
			physmeme::load_drv();
		bInit = true;
	}

	std::string DriverName()
	{
		return physmeme::drv_key;
	}

	DWORD32 DriverTimestamp()
	{
		return util::get_file_header((void*)raw_driver)->TimeDateStamp;
	}

	HANDLE DriverHandle()
	{
		return physmeme::drv_handle;
	}

	NTSTATUS __cdecl map_driver(std::string driver_name, uintptr_t param1, uintptr_t param2, bool bAllocationPtrParam1, bool bAllocationSizeParam2, uintptr_t* allocBase)
	{
		std::vector<std::uint8_t> drv_buffer;
		util::open_binary_file(driver_name.c_str(), drv_buffer);
		if (!drv_buffer.size())
		{
			std::perror("[-] invalid drv_buffer size\n");
			return -1;
		}
		return map_driver(drv_buffer, param1, param2, bAllocationPtrParam1, bAllocationSizeParam2, allocBase);
	}

	NTSTATUS __cdecl map_driver(const std::vector<std::uint8_t>& driver, uintptr_t param1, uintptr_t param2, bool bAllocationPtrParam1, bool bAllocationSizeParam2, uintptr_t* allocBase)
	{
		Init();

		physmeme::drv_image image(driver);
		physmeme::kernel_ctx ctx;
		const auto drv_timestamp = util::get_file_header((void*)raw_driver)->TimeDateStamp;
		ctx.clear_piddb_cache(physmeme::drv_key, drv_timestamp);

		const auto _get_export_name = [&](const char* base, const char* name)
		{
			return reinterpret_cast<std::uintptr_t>(util::get_kernel_export(base, name));
		};

		image.fix_imports(_get_export_name);
		image.map();

		void* pool_base = 0;

		if (!*allocBase) {
			pool_base =
				ctx.allocate_pool(
					image.size(),
					NonPagedPool
				);
			*allocBase = (uintptr_t)pool_base;
		}
		else {
			pool_base = (void*)*allocBase;
		}

		image.relocate(pool_base);
		ctx.write_kernel(pool_base, image.data(), image.size());
		auto entry_point = reinterpret_cast<std::uintptr_t>(pool_base) + image.entry_point();

		auto result = ctx.syscall<DRIVER_INITIALIZE>
		(
			(PVOID)entry_point,
			bAllocationPtrParam1 ? (uintptr_t)(pool_base) : (uintptr_t)(param1),
			bAllocationSizeParam2 ? (uintptr_t)(image.size()) : (uintptr_t)(param2)
		);

		return result;
	}
}