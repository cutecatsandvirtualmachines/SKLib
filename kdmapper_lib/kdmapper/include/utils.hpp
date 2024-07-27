#pragma once

#define Log(content, ...) printf(content "\n", __VA_ARGS__)

#include <Windows.h>
#include <TlHelp32.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <debugapi.h>

#include "nt.hpp"

namespace kdmapper_utils
{
	std::wstring GetFullTempPath();
	bool ReadFileToMemory(const std::wstring& file_path, std::vector<uint8_t>* out_buffer);
	bool CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size);
	uint64_t GetKernelModuleAddress(const std::string& module_name);
	BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
	uintptr_t FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, char* szMask);
	PVOID FindSection(char* sectionName, uintptr_t modulePtr, PULONG size);
}

void DbgPrint(const char* FormatString, ...);