#pragma once
#include <windows.h>
#include <iostream>
#include <string_view>
#include <vector>
#include <thread>
#include <atomic>

#include "../util/util.hpp"
#include "../physmeme/physmeme.hpp"
#include "../util/hook.hpp"

namespace physmeme
{
	//
	// offset of function into a physical page
	// used for comparing bytes when searching
	//
	inline std::uint16_t nt_page_offset{};

	//
	// rva of nt function we are going to hook
	//
	inline std::uint32_t nt_rva{};

	//
	// base address of ntoskrnl (inside of this process)
	//
	inline const std::uint8_t* ntoskrnl_buffer{};

	//
	// has the page been found yet?
	//
	inline std::atomic<bool> is_page_found = false;

	//
	// mapping of a syscalls physical memory (for installing hooks)
	//
	inline std::atomic<void*> psyscall_func{};

	//
	// you can edit this how you choose, im hooking NtShutdownSystem.
	//
	inline const std::pair<std::string_view, std::string_view> syscall_hook = { "NtShutdownSystem", "ntdll.dll" };

	class kernel_ctx
	{
	public:
		//
		// default constructor
		//
		kernel_ctx();

		//
		// allocate kernel pool of desired size and type
		//
		void* allocate_pool(std::size_t size, POOL_TYPE pool_type = NonPagedPool);
		void* allocate_pool_db(std::size_t size);

		//
		// allocate kernel pool of size, pool tag, and type
		//
		void* allocate_pool(std::size_t size, ULONG pool_tag = 'MEME', POOL_TYPE pool_type = NonPagedPool);

		//
		// read kernel memory with RtlCopyMemory
		//
		void read_kernel(void* addr, void* buffer, std::size_t size);

		//
		// write kernel memory with RtlCopyMemory
		//
		void write_kernel(void* addr, void* buffer, std::size_t size);

		//
		// zero kernel memory using RtlZeroMemory
		//
		void zero_kernel_memory(void* addr, std::size_t size);

		//
		// clear piddb cache of a specific driver
		//
		bool clear_piddb_cache(const std::string& file_name, const std::uint32_t timestamp);

		template <class T>
		T read_kernel(void* addr)
		{
			if (!addr)
				return {};
			T buffer;
			read_kernel(addr, (void*)&buffer, sizeof(T));
			return buffer;
		}

		template <class T>
		void write_kernel(void* addr, const T& data)
		{
			if (!addr)
				return;
			write_kernel(addr, (void*)&data, sizeof(T));
		}

		template <class T, class ... Ts>
		std::invoke_result_t<T, Ts...> syscall(void* addr, Ts ... args) const
		{
			static const auto proc = 
				GetProcAddress(
					GetModuleHandleA("ntdll.dll"),
					syscall_hook.first.data()
				);

			hook::make_hook(psyscall_func, addr);
			auto result = reinterpret_cast<T>(proc)(args ...);
			hook::remove(psyscall_func);
			return result;
		}
	private:

		//
		// find and map the physical page of a syscall into this process
		//
		void map_syscall(std::uintptr_t begin, std::uintptr_t end) const;

		//
		// used in conjunction with get_process_base.
		//
		PEPROCESS get_peprocess(unsigned pid) const;

		//
		// get base address of process (used to compare and ensure we find the right page).
		//
		void* get_proc_base(unsigned pid) const;

		bool bPiddbClear;
	};
}