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
#include "../drv_image/drv_image.h"

namespace physmeme
{
	drv_image::drv_image(std::vector<uint8_t> image) : m_image(std::move(image))
	{
		m_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_image.data());
		m_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>((uintptr_t)m_dos_header + m_dos_header->e_lfanew);
		m_section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>((uintptr_t)(&m_nt_headers->OptionalHeader) + m_nt_headers->FileHeader.SizeOfOptionalHeader);
	}

	size_t drv_image::size() const
	{
		return m_nt_headers->OptionalHeader.SizeOfImage;
	}

	uintptr_t drv_image::entry_point() const
	{
		return m_nt_headers->OptionalHeader.AddressOfEntryPoint;
	}

	void drv_image::map()
	{
		m_image_mapped.clear();
		m_image_mapped.resize(m_nt_headers->OptionalHeader.SizeOfImage);
		std::copy_n(m_image.begin(), m_nt_headers->OptionalHeader.SizeOfHeaders, m_image_mapped.begin());

		for (size_t i = 0; i < m_nt_headers->FileHeader.NumberOfSections; ++i)
		{
			const auto& section = m_section_header[i];
			const auto target = (uintptr_t)m_image_mapped.data() + section.VirtualAddress;
			const auto source = (uintptr_t)m_dos_header + section.PointerToRawData;
			std::copy_n(m_image.begin() + section.PointerToRawData, section.SizeOfRawData, m_image_mapped.begin() + section.VirtualAddress);
		}
	}

	bool drv_image::process_relocation(uintptr_t image_base_delta, uint16_t data, uint8_t* relocation_base)
	{
#define IMR_RELOFFSET(x)			(x & 0xFFF)
		switch (data >> 12 & 0xF)
		{
			case IMAGE_REL_BASED_HIGH:
			{
				const auto raw_address = reinterpret_cast<int16_t*>(relocation_base + IMR_RELOFFSET(data));
				*raw_address += static_cast<unsigned long>(HIWORD(image_base_delta));
				break;
			}
			case IMAGE_REL_BASED_LOW:
			{
				const auto raw_address = reinterpret_cast<int16_t*>(relocation_base + IMR_RELOFFSET(data));
				*raw_address += static_cast<unsigned long>(LOWORD(image_base_delta));
				break;
			}
			case IMAGE_REL_BASED_HIGHLOW:
			{
				const auto raw_address = reinterpret_cast<size_t*>(relocation_base + IMR_RELOFFSET(data));
				*raw_address += static_cast<size_t>(image_base_delta);
				break;
			}
			case IMAGE_REL_BASED_DIR64:
			{
				auto UNALIGNED raw_address = reinterpret_cast<DWORD_PTR UNALIGNED*>(relocation_base + IMR_RELOFFSET(data));
				*raw_address += image_base_delta;
				break;
			}
			case IMAGE_REL_BASED_ABSOLUTE: // No action required
			case IMAGE_REL_BASED_HIGHADJ: // no action required
			{
				break;
			}
			default:
			{
				return false;
			}
		}
#undef IMR_RELOFFSET
		return true;
	}


	void drv_image::relocate(void* base) const
	{
		if (m_nt_headers->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
			return;

		ULONG total_count_bytes;
		const auto nt_headers = ImageNtHeader((void*)m_image_mapped.data());
		auto relocation_directory = (PIMAGE_BASE_RELOCATION)::ImageDirectoryEntryToData(nt_headers, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &total_count_bytes);
		auto image_base_delta = static_cast<uintptr_t>(reinterpret_cast<uintptr_t>(base) - (nt_headers->OptionalHeader.ImageBase));
		auto relocation_size = total_count_bytes;

		// This should check (DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) 
		// too but lots of drivers do not have it set due to WDK defaults
		if (!(image_base_delta != 0 && relocation_size > 0))
			return;

		void* relocation_end = reinterpret_cast<uint8_t*>(relocation_directory) + relocation_size;
		while (relocation_directory < relocation_end)
		{
			auto relocation_base = ::ImageRvaToVa(nt_headers, (void*)m_image_mapped.data(), relocation_directory->VirtualAddress, nullptr);
			auto num_relocs = (relocation_directory->SizeOfBlock - 8) >> 1;
			auto relocation_data = reinterpret_cast<PWORD>(relocation_directory + 1);

			for (unsigned long i = 0; i < num_relocs; ++i, ++relocation_data)
				if (process_relocation(image_base_delta, *relocation_data, (uint8_t*)relocation_base) == FALSE)
					return;

			relocation_directory = reinterpret_cast<PIMAGE_BASE_RELOCATION>(relocation_data);
		}
	}

	template<typename T>
	__forceinline T* ptr_add(void* base, uintptr_t offset)
	{
		return (T*)(uintptr_t)base + offset;
	}

	void drv_image::fix_imports(const std::function<uintptr_t(const char*, const char*)> get_function) 
	{
		ULONG size;
		auto import_descriptors = static_cast<PIMAGE_IMPORT_DESCRIPTOR>(::ImageDirectoryEntryToData(m_image.data(), FALSE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size));

		if (!import_descriptors) 
			return;

		for (; import_descriptors->Name; import_descriptors++)
		{
			IMAGE_THUNK_DATA* image_thunk_data;
			const auto module_name = get_rva<char>(import_descriptors->Name);

			if (import_descriptors->OriginalFirstThunk)
				image_thunk_data = get_rva<IMAGE_THUNK_DATA>(import_descriptors->OriginalFirstThunk);
			else
				image_thunk_data = get_rva<IMAGE_THUNK_DATA>(import_descriptors->FirstThunk);
			auto image_func_data = get_rva<IMAGE_THUNK_DATA64>(import_descriptors->FirstThunk);

			for (; image_thunk_data->u1.AddressOfData; image_thunk_data++, image_func_data++)
			{
				uintptr_t function_address;
				const auto ordinal = (image_thunk_data->u1.Ordinal & IMAGE_ORDINAL_FLAG64) != 0;
				const auto image_import_by_name = get_rva<IMAGE_IMPORT_BY_NAME>(*(DWORD*)image_thunk_data);
				const auto name_of_import = static_cast<char*>(image_import_by_name->Name);
				function_address = get_function(module_name, name_of_import);

				image_func_data->u1.Function = function_address;
			}
		}
	}

	void* drv_image::data()
	{
		return m_image_mapped.data();
	}

	size_t drv_image::header_size()
	{
		return m_nt_headers->OptionalHeader.SizeOfHeaders;
	}
}