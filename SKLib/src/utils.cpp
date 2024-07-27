#include "utils.h"

UNICODE_STRING GetModuleNameFromPath(PUNICODE_STRING path)
{
	UNICODE_STRING s;
	
	char* char_arr = (char*)ExAllocatePool(NonPagedPoolNx, (size_t)path->Length + 1);
	wcstombs(char_arr, path->Buffer, (size_t)path->Length);
	string* full_path = string::create(char_arr);

	int index = full_path->last_of('\\');
	string modName = full_path->substring(index + 1);
	PCWSTR wstr = (PCWSTR)cpp::kMalloc(((size_t)modName.Length() + 1) * 2, PAGE_READWRITE);
	mbstowcs((wchar_t*)wstr, (char*)modName.pBuffer, modName.Length());
	RtlInitUnicodeString(&s, wstr);

	full_path->Dispose();
	modName.Dispose();
	cpp::kFree(full_path);
	ExFreePool(char_arr);

	return s;
}