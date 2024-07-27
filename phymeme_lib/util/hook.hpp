/*
    MIT License
    
    Copyright (c) 2020 xerox
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

#pragma once
#include <Windows.h>
#include <map>
#include <atomic>
#include <memory>

#if _M_IX86
	#define OFFSET_TO_ADDRESS 0x1
#elif _M_X64
	#define OFFSET_TO_ADDRESS 0x2
#endif

namespace hook
{
	static void write_to_readonly(void* addr, void* data, int size)
	{
		DWORD old_flags;
		VirtualProtect((LPVOID)addr, size, PAGE_EXECUTE_READWRITE, &old_flags);
		memcpy((void*)addr, data, size);
		VirtualProtect((LPVOID)addr, size, old_flags, &old_flags);
	}

	class detour
	{
	public:
		detour(void* addr_to_hook, void* jmp_to, bool enable = true)
			: hook_addr(addr_to_hook), detour_addr(jmp_to), hook_installed(false)
		{
			//setup hook
			memcpy(
				jmp_code + OFFSET_TO_ADDRESS,
				&jmp_to,
				sizeof(jmp_to)
			);

			//save bytes
			memcpy(
				org_bytes,
				hook_addr,
				sizeof(org_bytes)
			);
			if(enable)
				install();
		}

		void install()
		{
			if (hook_installed.load())
				return;

			// mapped page is already read/write
			memcpy(hook_addr, jmp_code, sizeof(jmp_code));
			hook_installed.exchange(true);
		}
		void uninstall()
		{
			if (!hook_installed.load())
				return;

			// mapped page is already read/write
			memcpy(hook_addr, org_bytes, sizeof(org_bytes));
			hook_installed.exchange(false);
		}

		~detour() { uninstall(); }
		bool installed() { return hook_installed; }
		void* hook_address() { return hook_addr; }
		void* detour_address() { return detour_addr; }
	private:
		std::atomic<bool> hook_installed;
		void *hook_addr, *detour_addr;

#if _M_IX86
		/*
			0:  b8 ff ff ff ff          mov    eax, 0xffffffff
			5:  ff e0                   jmp    eax
		*/
		unsigned char jmp_code[7] = {
			0xb8, 0x0, 0x0, 0x0, 0x0,
			0xFF, 0xE0
		};
#elif _M_X64
		/*
			0:  48 b8 ff ff ff ff ff ff ff ff   movabs rax,0xffffffffffffffff
			7:  ff e0							jmp    rax
		*/
		unsigned char jmp_code[12] = {
			0x48, 0xb8,						
			0x0,							
			0x0,
			0x0,
			0x0,
			0x0,
			0x0,
			0x0,
			0x0,
			0xff, 0xe0						
		};
#endif
		std::uint8_t org_bytes[sizeof(jmp_code)];
	};

	static std::map<void*, std::unique_ptr<detour>> hooks{};

	/*
	Author: xerox
	Date: 12/19/2019

	Create Hook without needing to deal with objects
	*/
	static void make_hook(void* addr_to_hook, void* jmp_to_addr, bool enable = true)
	{	
		if (!addr_to_hook)
			return;

		hooks.insert({
			addr_to_hook,
			std::make_unique<detour>(
				addr_to_hook,
				jmp_to_addr,
				enable
			)}
		);
	}

	/*
	Author: xerox
	Date: 12/19/2019

	Enable hook given the address to hook
	*/
	static void enable(void* addr)
	{
		if (!addr)
			return;
		hooks.at(addr)->install();
	}

	/*
	Author: xerox
	Date: 12/19/2019

	Disable hook givent the address of the hook
	*/
	static void disable(void* addr)
	{
		if (!addr)
			return;
		hooks.at(addr)->uninstall();
	}


	/*
	Author: xerox
	Date: 12/19/2019

	Remove hook completely from vector
	*/
	static void remove(void* addr)
	{
		if (!addr)
			return;
		hooks.at(addr)->~detour();
		hooks.erase(addr);
	}
}