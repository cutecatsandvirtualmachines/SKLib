#include "kernel_ctx.h"
#include "dbrequest.h"

namespace physmeme
{
	kernel_ctx::kernel_ctx()
	{
		if (psyscall_func.load() || nt_page_offset || ntoskrnl_buffer)
			return;

		nt_rva = reinterpret_cast<std::uint32_t>(
			util::get_kernel_export(
				"ntoskrnl.exe",
				syscall_hook.first.data(),
				true
			));

		nt_page_offset = nt_rva % page_size;
		ntoskrnl_buffer = reinterpret_cast<std::uint8_t*>(
			LoadLibraryEx("ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES));

		std::vector<std::thread> search_threads;
		//--- for each physical memory range, make a thread to search it
		for (auto ranges : util::pmem_ranges)
			search_threads.emplace_back(std::thread(
				&kernel_ctx::map_syscall,
				this,
				ranges.first,
				ranges.second
			));

		for (std::thread& search_thread : search_threads)
			search_thread.join();
		bPiddbClear = false;
	}

	void kernel_ctx::map_syscall(std::uintptr_t begin, std::uintptr_t end) const
	{
		//if the physical memory range is less then or equal to 2mb
		if (begin + end <= 0x1000 * 512)
		{
			auto page_va = physmeme::map_phys(begin + nt_page_offset, end);
			if (page_va)
			{
				// scan every page of the physical memory range
				for (auto page = page_va; page < page_va + end; page += 0x1000)
				{
					if (!is_page_found.load()) // keep scanning until its found
					{
						__try
						{
							if (!memcmp(reinterpret_cast<void*>(page), ntoskrnl_buffer + nt_rva, 32))
							{
								//
								// this checks to ensure that the syscall does indeed work. if it doesnt, we keep looking!
								//
								psyscall_func.store((void*)page);
								auto my_proc_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(NULL));
								auto my_proc_base_from_syscall = reinterpret_cast<std::uintptr_t>(get_proc_base(GetCurrentProcessId()));

								if (my_proc_base != my_proc_base_from_syscall)
									continue;

								is_page_found.store(true);
								return;
							}
						}
						__except (EXCEPTION_EXECUTE_HANDLER) {}
					}
				}
				physmeme::unmap_phys(page_va, end);
			}
		}
		else // else the range is bigger then 2mb
		{
			auto remainder = (begin + end) % (0x1000 * 512);

			// loop over 2m chunks
			for (auto range = begin; range < begin + end; range += 0x1000 * 512)
			{
				auto page_va = physmeme::map_phys(range + nt_page_offset, 0x1000 * 512);
				if (page_va)
				{
					// loop every page of 2mbs (512)
					for (auto page = page_va; page < page_va + 0x1000 * 512; page += 0x1000)
					{
						if (!is_page_found.load())
						{
							__try
							{
								if (!memcmp(reinterpret_cast<void*>(page), ntoskrnl_buffer + nt_rva, 32))
								{
									//
									// this checks to ensure that the syscall does indeed work. if it doesnt, we keep looking!
									//
									psyscall_func.store((void*)page);
									auto my_proc_base = reinterpret_cast<std::uintptr_t>(GetModuleHandle(NULL));
									auto my_proc_base_from_syscall = reinterpret_cast<std::uintptr_t>(get_proc_base(GetCurrentProcessId()));

									if (my_proc_base != my_proc_base_from_syscall)
										continue;

									is_page_found.store(true);
									return;
								}
							}
							__except (EXCEPTION_EXECUTE_HANDLER) {}
						}
					}
					physmeme::unmap_phys(page_va, 0x1000 * 512);
				}
			}

			// map the remainder and check each page of it
			auto page_va = physmeme::map_phys(begin + end - remainder + nt_page_offset, remainder);
			if (page_va)
			{
				for (auto page = page_va; page < page_va + remainder; page += 0x1000)
				{
					if (!is_page_found.load())
					{
						__try
						{
							if (!memcmp(reinterpret_cast<void*>(page), ntoskrnl_buffer + nt_rva, 32))
							{
								//
								// this checks to ensure that the syscall does indeed work. if it doesnt, we keep looking!
								//
								psyscall_func.store((void*)page);
								auto my_proc_base = reinterpret_cast<std::uintptr_t>(GetModuleHandle(NULL));
								auto my_proc_base_from_syscall = reinterpret_cast<std::uintptr_t>(get_proc_base(GetCurrentProcessId()));

								if (my_proc_base != my_proc_base_from_syscall)
									continue;

								is_page_found.store(true);
								return;
							}
						}
						__except (EXCEPTION_EXECUTE_HANDLER) {}
					}
				}
				physmeme::unmap_phys(page_va, remainder);
			}
		}
	}

	bool kernel_ctx::clear_piddb_cache(const std::string& file_name, const std::uint32_t timestamp)
	{
		if (bPiddbClear)
			return true;

		static const auto piddb_lock =
			util::memory::get_piddb_lock();

		static const auto piddb_table =
			util::memory::get_piddb_table();

		if (!piddb_lock || !piddb_table) {
			printf("[-] Failed to acquire PIDDB table or lock\n");
			return false;
		}

		static const auto ex_acquire_resource =
			util::get_kernel_export(
				"ntoskrnl.exe",
				"ExAcquireResourceExclusiveLite"
			);

		static const auto lookup_element_table =
			util::get_kernel_export(
				"ntoskrnl.exe",
				"RtlLookupElementGenericTableAvl"
			);

		static const auto release_resource =
			util::get_kernel_export(
				"ntoskrnl.exe",
				"ExReleaseResourceLite"
			);

		static const auto delete_table_entry =
			util::get_kernel_export(
				"ntoskrnl.exe",
				"RtlDeleteElementGenericTableAvl"
			);

		if (!ex_acquire_resource || !lookup_element_table || !release_resource) {
			printf("[-] Failed to acquire PIDDB related function ptrs\n");
			return false;
		}

		PiDDBCacheEntry cache_entry;
		const auto drv_name = std::wstring(file_name.begin(), file_name.end());
		cache_entry.time_stamp = timestamp;
		RtlInitUnicodeString(&cache_entry.driver_name, drv_name.data());

		//
		// ExAcquireResourceExclusiveLite
		//
		if (!syscall<ExAcquireResourceExclusiveLite>(ex_acquire_resource, piddb_lock, true)) {
			printf("[-] Failed to acquire resource PIDDB\n");
			return false;
		}

		//
		// RtlLookupElementGenericTableAvl
		//
		PIDCacheobj* found_entry_ptr =
			syscall<RtlLookupElementGenericTableAvl>(
				lookup_element_table,
				piddb_table,
				reinterpret_cast<void*>(&cache_entry)
			);

		if (found_entry_ptr)
		{

			//
			// unlink entry.
			//
			PIDCacheobj found_entry = read_kernel<PIDCacheobj>(found_entry_ptr);
			LIST_ENTRY NextEntry = read_kernel<LIST_ENTRY>(found_entry.list.Flink);
			LIST_ENTRY PrevEntry = read_kernel<LIST_ENTRY>(found_entry.list.Blink);

			PrevEntry.Flink = found_entry.list.Flink;
			NextEntry.Blink = found_entry.list.Blink;

			write_kernel<LIST_ENTRY>(found_entry.list.Blink, PrevEntry);
			write_kernel<LIST_ENTRY>(found_entry.list.Flink, NextEntry);

			//
			// delete entry.
			//
			syscall<RtlDeleteElementGenericTableAvl>(delete_table_entry, piddb_table, found_entry_ptr);

			//
			// ensure the entry is 0
			//
			auto result = syscall<RtlLookupElementGenericTableAvl>(
				lookup_element_table,
				piddb_table,
				reinterpret_cast<void*>(&cache_entry)
			);

			syscall<ExReleaseResourceLite>(release_resource, piddb_lock);
			printf("[-] Result clearing: 0x%p\n", result);
			bPiddbClear = true;
			return !result;
		}
		syscall<ExReleaseResourceLite>(release_resource, piddb_lock);
		printf("[-] Could not find element in PIDDB cache!\n");
		return false;
	}

	void* kernel_ctx::allocate_pool(std::size_t size, POOL_TYPE pool_type)
	{
		static const auto ex_alloc_pool = 
			util::get_kernel_export(
				"ntoskrnl.exe", 
				"ExAllocatePool"
			);

		return syscall<ExAllocatePool>(
			ex_alloc_pool, 
			pool_type,
			size
		);
	}

	void* kernel_ctx::allocate_pool_db(std::size_t size)
	{
		volatile PVOID pOut = 0;
		PDB_INFO pDbInfo = (PDB_INFO)_aligned_malloc(sizeof(*pDbInfo), 0x1000);
		if (!pDbInfo)
			return nullptr;

		pDbInfo->allocate.pOut = (PVOID*)&pOut;
		pDbInfo->allocate.sz = size;

		db::DbRequest(DB_ALLOCATE, pDbInfo);

		while (!pOut) {
			Sleep(1);
		}

		_aligned_free(pDbInfo);
		return pOut;
	}

	void* kernel_ctx::allocate_pool(std::size_t size, ULONG pool_tag, POOL_TYPE pool_type)
	{
		static const auto ex_alloc_pool_with_tag = 
			util::get_kernel_export(
				"ntoskrnl.exe", 
				"ExAllocatePoolWithTag"
			);

		return syscall<ExAllocatePoolWithTag>(
			ex_alloc_pool_with_tag,
			pool_type,
			size,
			pool_tag
		);
	}

	void kernel_ctx::read_kernel(void* addr, void* buffer, std::size_t size)
	{
		static const auto mm_copy_memory = 
			util::get_kernel_export(
				"ntoskrnl.exe", 
				"RtlCopyMemory"
			);

		syscall<decltype(&memcpy)>(
			mm_copy_memory,
			buffer,
			addr,
			size
		);
	}

	void kernel_ctx::write_kernel(void* addr, void* buffer, std::size_t size)
	{
		static const auto mm_copy_memory = 
			util::get_kernel_export(
				"ntoskrnl.exe",
				"RtlCopyMemory"
			);

		syscall<decltype(&memcpy)>(
			mm_copy_memory,
			addr,
			buffer,
			size
		);
	}

	void kernel_ctx::zero_kernel_memory(void* addr, std::size_t size)
	{
		static const auto rtl_zero_memory = 
			util::get_kernel_export(
				"ntoskrnl.exe",
				"RtlZeroMemory"
			);

		syscall<decltype(&RtlSecureZeroMemory)>(
			rtl_zero_memory, 
			addr,
			size
		);
	}

	PEPROCESS kernel_ctx::get_peprocess(unsigned pid) const
	{
		if (!pid)
			return {};

		PEPROCESS proc;
		static auto get_peprocess_from_pid =
			util::get_kernel_export(
				"ntoskrnl.exe",
				"PsLookupProcessByProcessId"
			);

		syscall<PsLookupProcessByProcessId>(
			get_peprocess_from_pid,
			(HANDLE)pid,
			&proc
		);
		return proc;
	}

	void* kernel_ctx::get_proc_base(unsigned pid) const
	{
		if (!pid)
			return  {};

		const auto peproc = get_peprocess(pid);

		if (!peproc)
			return {};

		static auto get_section_base = 
			util::get_kernel_export(
				"ntoskrnl.exe",
				"PsGetProcessSectionBaseAddress"
			);

		return syscall<PsGetProcessSectionBaseAddress>(
			get_section_base,
			peproc
		);
	}
}