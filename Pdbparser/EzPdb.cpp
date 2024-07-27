#include "EzPdb.h"


std::string random_string(size_t length)
{
	auto randchar = []() -> char
	{
		const char charset[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	std::string str(length, 0);
	std::generate_n(str.begin(), length, randchar);
	return str;
}

// download pdb file from symbol server
// return pdb path if success, 
// or return empty string if failed, user can call GetLastError() to know wth is going on
std::string EzPdbDownload(
	IN std::string pePath,
	IN OPTIONAL std::string pdbDownloadPath,
	IN OPTIONAL std::string symbolServer)
{
	// pdb download directory
	// if not specify, then pdb will download to current directory
	if (pdbDownloadPath == "")
	{
		char szDownloadDir[MAX_PATH] = { 0 };
		if (!GetCurrentDirectoryA(sizeof(szDownloadDir), szDownloadDir))
		{
			return "";
		}
		pdbDownloadPath = szDownloadDir;
	}

	if (pdbDownloadPath[pdbDownloadPath.size() - 1] != '\\')
	{
		pdbDownloadPath += "\\";
	}

	// make sure the directory exist
	if (!CreateDirectoryA(pdbDownloadPath.c_str(), NULL))
	{
		if (GetLastError() != ERROR_ALREADY_EXISTS)
		{
			return "";
		}
	}

	// read pe file

#ifndef _AMD64_
	PVOID OldValue = NULL;
	Wow64DisableWow64FsRedirection(&OldValue);
#endif

	std::ifstream file(pePath, std::ios::binary | std::ios::ate);
	if (!file.is_open())
		return "";
	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);
	std::vector<char> buffer(size);

#ifndef _AMD64_
	Wow64RevertWow64FsRedirection(&OldValue);
#endif

	if (!file.read(buffer.data(), size) || size == 0)
	{
		SetLastError(ERROR_ACCESS_DENIED);
		return "";
	}

	size_t start = pePath.find_last_of('\\');
	size_t end = pePath.find_last_of('.');
	std::string pdbPath = pdbDownloadPath + pePath.substr(start + 1, end - start - 1) + ".pdb";

	// get pdb info from debug info directory
	IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)buffer.data();
	IMAGE_NT_HEADERS* pNT = (IMAGE_NT_HEADERS*)(buffer.data() + pDos->e_lfanew);
	IMAGE_FILE_HEADER* pFile = &pNT->FileHeader;
	IMAGE_OPTIONAL_HEADER64* pOpt64 = NULL;
	IMAGE_OPTIONAL_HEADER32* pOpt32 = NULL;
	BOOL x86 = FALSE;
	if (pFile->Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		pOpt64 = (IMAGE_OPTIONAL_HEADER64*)(&pNT->OptionalHeader);
	}
	else if (pFile->Machine == IMAGE_FILE_MACHINE_I386)
	{
		pOpt32 = (IMAGE_OPTIONAL_HEADER32*)(&pNT->OptionalHeader);
		x86 = TRUE;
	}
	else
	{
		SetLastError(ERROR_NOT_SUPPORTED);
		return "";
	}
	DWORD ImageSize = x86 ? pOpt32->SizeOfImage : pOpt64->SizeOfImage;

	// file buffer to image buffer
	PBYTE ImageBuffer = (PBYTE)malloc(ImageSize);
	if (!ImageBuffer)
	{
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return "";
	}
	memcpy(ImageBuffer, buffer.data(), x86 ? pOpt32->SizeOfHeaders : pOpt64->SizeOfHeaders);
	IMAGE_SECTION_HEADER* pCurrentSectionHeader = IMAGE_FIRST_SECTION(pNT);
	for (UINT i = 0; i != pFile->NumberOfSections; ++i, ++pCurrentSectionHeader)
	{
		if (pCurrentSectionHeader->SizeOfRawData)
		{
			memcpy(ImageBuffer + pCurrentSectionHeader->VirtualAddress, buffer.data() + pCurrentSectionHeader->PointerToRawData, pCurrentSectionHeader->SizeOfRawData);
		}
	}
	IMAGE_DATA_DIRECTORY* pDataDir = nullptr;
	if (x86)
	{
		pDataDir = &pOpt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	}
	else
	{
		pDataDir = &pOpt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	}
	IMAGE_DEBUG_DIRECTORY* pDebugDir = (IMAGE_DEBUG_DIRECTORY*)(ImageBuffer + pDataDir->VirtualAddress);
	if (!pDataDir->Size || IMAGE_DEBUG_TYPE_CODEVIEW != pDebugDir->Type)
	{
		// invalid debug dir
		free(ImageBuffer);
		SetLastError(ERROR_NOT_SUPPORTED);
		return "";
	}
	PdbInfo* pdb_info = (PdbInfo*)(ImageBuffer + pDebugDir->AddressOfRawData);
	if (pdb_info->Signature != 0x53445352)
	{
		// invalid debug dir
		free(ImageBuffer);
		SetLastError(ERROR_NOT_SUPPORTED);
		return "";
	}

	if (!std::filesystem::exists(pdbPath))
	{
		// download pdb
		printf("Downloading %s pdb\n", pePath.c_str());
		wchar_t w_GUID[100] = { 0 };
		if (!StringFromGUID2(pdb_info->Guid, w_GUID, 100))
		{
			free(ImageBuffer);
			SetLastError(ERROR_NOT_SUPPORTED);
			return "";
		}
		char a_GUID[100]{ 0 };
		size_t l_GUID = 0;
		if (wcstombs_s(&l_GUID, a_GUID, w_GUID, sizeof(a_GUID)) || !l_GUID)
		{
			free(ImageBuffer);
			SetLastError(ERROR_NOT_SUPPORTED);
			return "";
		}

		char guid_filtered[256] = { 0 };
		for (UINT i = 0; i != l_GUID; ++i)
		{
			if ((a_GUID[i] >= '0' && a_GUID[i] <= '9') || (a_GUID[i] >= 'A' && a_GUID[i] <= 'F') || (a_GUID[i] >= 'a' && a_GUID[i] <= 'f'))
			{
				guid_filtered[strlen(guid_filtered)] = a_GUID[i];
			}
		}

		char age[3] = { 0 };
		_itoa_s(pdb_info->Age, age, 10);

		// url
		std::string url = symbolServer;
		url += pdb_info->PdbFileName;
		url += "/";
		url += guid_filtered;
		url += age;
		url += "/";
		url += pdb_info->PdbFileName;
		url += "?";
		url += random_string(5);

		// download
		HRESULT hr = URLDownloadToFileA(NULL, url.c_str(), pdbPath.c_str(), NULL, NULL);
		if (FAILED(hr))
		{
			free(ImageBuffer);
			return "";
		}

		printf("Downloaded %s pdb\n", pePath.c_str());
		free(ImageBuffer);
	}

	return pdbPath;
}