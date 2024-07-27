/*
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org>


!!!!!!!!!!!!!!!!!!!!!!!!!!! This code was created by not-wlan (wlan). all credit for this header and source file goes to him !!!!!!!!!!!!!!!!!!!!!!!!!!!!!
*/

#pragma once
#include <vector>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <Winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include <functional>
#include <DbgHelp.h>
#include <variant>
#include "../util/nt.hpp"

#pragma comment(lib, "Dbghelp.lib")
namespace physmeme
{
	class drv_image
	{
		std::vector<uint8_t> m_image;
		std::vector<uint8_t> m_image_mapped;
		PIMAGE_DOS_HEADER m_dos_header = nullptr;
		PIMAGE_NT_HEADERS64 m_nt_headers = nullptr;
		PIMAGE_SECTION_HEADER m_section_header = nullptr;
	public:
		explicit drv_image(std::vector<uint8_t> image);

		void map();
		void* data();
		size_t size() const;
		size_t header_size();
		uintptr_t entry_point() const;
		void relocate(void* base) const;
		void fix_imports(const std::function<uintptr_t(const char*, const char*)> get_function);
		static bool process_relocation(size_t image_base_delta, uint16_t data, uint8_t* relocation_base);

		template<typename T>
		__forceinline T* get_rva(const unsigned long offset)
		{
			return (T*)::ImageRvaToVa(m_nt_headers, m_image.data(), offset, nullptr);
		}
	};
}