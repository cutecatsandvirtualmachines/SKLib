#include "PE.h"

PIMAGE_NT_HEADERS64 GetNtHeaders(void* image_base) {
	const auto dos_header = (PIMAGE_DOS_HEADER)(image_base);
	const auto nt_headers = (PIMAGE_NT_HEADERS64)((DWORD64)(image_base) + dos_header->e_lfanew);
	return nt_headers;
}

PE::PE(PVOID pImageBase)
{
	this->pNtHeaders = GetNtHeaders(pImageBase);
	this->szHeader = pNtHeaders->OptionalHeader.SizeOfHeaders;
	this->pImageBase = (DWORD64)pImageBase;
}

PIMAGE_NT_HEADERS64 PE::ntHeaders()
{
	return pNtHeaders;
}

DWORD64 PE::imageSize()
{
	if (!pNtHeaders)
		return 0;
	return pNtHeaders->OptionalHeader.SizeOfImage;
}

DWORD64 PE::sizeOfCode()
{
	if (!pNtHeaders)
		return 0;
	return pNtHeaders->OptionalHeader.SizeOfCode;
}

DWORD64 PE::headerSize()
{
	return szHeader;
}

DWORD64 PE::entryPoint() {
	return this->pImageBase + ntHeaders()->OptionalHeader.AddressOfEntryPoint;
}

vector<IMAGE_SECTION_HEADER>& PE::sections()
{
	if (vSections.length() == 0) {
		const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(pNtHeaders);

		for (auto i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
			vSections.Append(current_image_section[i]);
		}
	}
	return vSections;
}

string ResolveAPISet(uintptr_t pPeb, char* pImport) {
	PPEB_SKLIB peb = (PPEB_SKLIB)pPeb;
	PAPISET_NAMESPACE_ARRAY pApiSetMap = (PAPISET_NAMESPACE_ARRAY)(peb->ApiSetMap);

	// Iterate api set map
	for (ULONG i = 0; i < pApiSetMap->Count; i++)
	{
		PAPISET_NAMESPACE_ENTRY pDescriptor = NULL;
		PAPISET_VALUE_ARRAY pHostArray = NULL;
		wchar_t apiNameBuf[255] = { 0 };

		pDescriptor = (PAPISET_NAMESPACE_ENTRY)((PUCHAR)pApiSetMap + pApiSetMap->End + i * sizeof(API_SET_NAMESPACE_ENTRY_10));
		pHostArray = (PAPISET_VALUE_ARRAY)((PUCHAR)pApiSetMap + pApiSetMap->Start + sizeof(API_SET_VALUE_ARRAY_10) * pDescriptor->Size);

		memcpy(apiNameBuf, (PUCHAR)pApiSetMap + pHostArray->NameOffset, pHostArray->NameLength);
		string apiName(apiNameBuf);

		if (apiName != pImport) {
			continue;
		}
		DbgMsg("[PE] Found API name: %s", apiName.c_str());

		PAPISET_VALUE_ENTRY pHost = NULL;
		wchar_t apiHostNameBuf[255] = { 0 };

		pHost = (PAPISET_VALUE_ENTRY)((PUCHAR)pApiSetMap + pHostArray->DataOffset);
		// Sanity check
		if (pHostArray->Count < 1) {
			DbgMsg("[PE] Sanity check failed: 0x%llx", pHostArray->Count);
			break;
		}

		memcpy(apiHostNameBuf, (PUCHAR)pApiSetMap + pHost->ValueOffset, pHost->ValueLength);

		return apiHostNameBuf;
	}

	return "";
}

PVOID PE::DataDir(ULONG entry) {
	IMAGE_OPTIONAL_HEADER64* opt_header = &ntHeaders()->OptionalHeader;
	if (!MmIsAddressValid(opt_header))
		return nullptr;

	IMAGE_DATA_DIRECTORY* dir = &opt_header->DataDirectory[entry];
	if (!MmIsAddressValid(dir)
		|| !dir->Size
		|| !dir->VirtualAddress)
		return nullptr;

	return (PVOID)(this->pImageBase + dir->VirtualAddress);
}

char* PE::pdbPath()
{
	PDB_INFO* pdbInfo = this->pdbInfo();
	if (pdbInfo
		&& 0 == memcmp(&pdbInfo->Signature, "RSDS", 4))
	{
		return pdbInfo->PdbFileName;
	}
	return (char*)"";
}

PDB_INFO* PE::pdbInfo()
{
	// Straight after that is the optional header (which technically is optional, but in practice always there.)
	IMAGE_OPTIONAL_HEADER64* opt_header = &ntHeaders()->OptionalHeader;

	// Grab the debug data directory which has an indirection to its data
	IMAGE_DATA_DIRECTORY* dir = &opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

	// Convert that data to the right type.
	IMAGE_DEBUG_DIRECTORY* dbgDir = (IMAGE_DEBUG_DIRECTORY*)(this->pImageBase + dir->VirtualAddress);

	// Check to see that the data has the right type
	if (IMAGE_DEBUG_TYPE_CODEVIEW == dbgDir->Type)
	{
		PDB_INFO* pdbInfo = (PDB_INFO*)(this->pImageBase + dbgDir->AddressOfRawData);
		return pdbInfo;
	}

	return nullptr;
}

void PE::relocate(DWORD64 delta) {
	auto* pOpt = &ntHeaders()->OptionalHeader;

	//Do any eventual relocation, if necessary
	if (!delta) {
		delta = pImageBase - (DWORD64)pOpt->ImageBase;
	}
	if (delta) {
		DbgMsg("[PE] Fixing relocations for injected module: %p - %p - 0x%llx", pImageBase, delta, pOpt->ImageBase);
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			//Each IMAGE_BASE_RELOCATION is an object with a VA offset and a list members that rely on that offset base.
			//Therefore to adjust everything you must go through all the .reloc section and shift every "member" by delta
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pImageBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			while (pRelocData->VirtualAddress) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);
				for (UINT i = 0; i != AmountOfEntries; i++, pRelativeInfo++) {
					if (RELOC_FLAG(*pRelativeInfo)) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pImageBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += delta;
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
			DbgMsg("[PE] Fixed relocations for injected module: 0x%llx", delta);
		}
	}
}

void PE::fixImports(DWORD64 pPeb) {
	auto* pOpt = &ntHeaders()->OptionalHeader;

	//Fixing imports
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pImageBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* pImportName = reinterpret_cast<char*>(pImageBase + pImportDescr->Name); //szMod contains the name of the module to be loaded
			uintptr_t hDll = pe::GetModuleHandle(pPeb, pImportName);
			if (!hDll) {
				DbgMsg("[PE] Module is not loaded: %s", pImportName);
				ResolveAPISet(pPeb, pImportName);
				++pImportDescr;
				continue;
			}
			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pImageBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pImageBase + pImportDescr->FirstThunk);

			if (!pThunkRef) {
				pThunkRef = pFuncRef;
			}

			string lastForwardDll("");

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					//In this case pThunkRef contains the ordinal number which represents the function
					*pFuncRef = pe::GetProcAddress(pPeb, hDll, reinterpret_cast<char*>(*pThunkRef & 0xffff));
				}
				else {
					//Else pThunkRef contains an offset that will point to the Import where the name can be taken from for the loading
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pImageBase + (*pThunkRef));
					*pFuncRef = pe::GetProcAddress(pPeb, hDll, (char*)pImport->Name);
					DbgMsg("[PE] Import %s at: %p", pImport->Name, *pFuncRef);

					bool bString = true;
					for (int i = 0; i < 4; i++) {
						char currChar = ((char*)*pFuncRef)[i];
						if (
							(currChar >= 'A' && currChar <= 'Z') 
							|| (currChar >= 'a' && currChar <= 'z') 
							|| (currChar >= '0' && currChar <= '9')
							) {
							continue;
						}
						bString = false;
						break;
					}
					if (!bString)
						continue;

					string funcName((char*)*pFuncRef);
					string dllName((char*)*pFuncRef);
					if (dllName.Length() == 0)
						dllName = lastForwardDll;

					dllName = dllName.substring(0, dllName.first_of('.'));
					dllName += ".dll";
					DbgMsg("[PE] Forwarded import: %s", dllName.c_str());
					uintptr_t hDllFw = pe::GetModuleHandle(pPeb, (char*)dllName.to_lower());
					if (!hDllFw) {
						DbgMsg("[PE] Forwarded module is not loaded: %s", dllName.c_str());
						continue;
					}
					else {
						lastForwardDll = dllName;
						funcName = funcName.substring(funcName.first_of('.') + 1, (int)funcName.Length());
					}

					*pFuncRef = pe::GetProcAddress(pPeb, hDllFw, (char*)funcName.c_str());
					DbgMsg("[PE] Forwarded function: %s - %p - %p", funcName.c_str(), *pFuncRef, pFuncRef);
				}
			}
			DbgMsg("[PE] Fixed imports for : %s", pImportName);
			++pImportDescr;
		}
		DbgMsg("[PE] Fixed imports for injected module");
	}
}

uintptr_t pe::GetModuleHandle(uintptr_t pPeb, char* pModName)
{
	uintptr_t pMod = 0;
	PPEB_SKLIB CurrentPEB = (PPEB_SKLIB)pPeb;
	PLIST_ENTRY pListEntry = CurrentPEB->Ldr->MemoryOrder.Flink;

	string sName(pModName);
	sName.to_lower();
	DbgMsg("[PE] Looking for module: %s", pModName);

	for (; pListEntry != &CurrentPEB->Ldr->MemoryOrder;) {
		if (!pListEntry) {
			DbgMsg("[PE] List entry is null!");
			break;
		}

		auto moduleEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, LoadOrder);
		string modName(&moduleEntry->ModuleName);

		if (sName == modName.to_lower()) {
			pMod = (uintptr_t)moduleEntry->ModuleBaseAddress;
			break;
		}
		pListEntry = pListEntry->Flink;
	}

	return pMod;
}

//This function will get the VA of the function, but doesn't work for forwarded exports (function is imported from another module)
uintptr_t pe::GetProcAddress(uintptr_t pPeb, uintptr_t pBase, char* pImport)
{
	//Load the export table
	void* procAddr = nullptr;
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((BYTE*)pBase)->e_lfanew)->OptionalHeader;
	auto* pExportTable = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	if (*(DWORD64*)pImport <= 0xffff) {
		//This is an ordinal query
		unsigned int addr = ((unsigned int*)(pBase + pExportTable->AddressOfFunctions))[*(DWORD32*)pImport & 0xffff];

		procAddr = (void*)(pBase + addr);
		return (uintptr_t)procAddr;
	}

	//Load the function name array (AddressOfNames member)
	unsigned int* NameRVA = (unsigned int*)(pBase + pExportTable->AddressOfNames);

	//Iterate over AddressOfNames
	for (ULONG i = 0; i < pExportTable->NumberOfNames; i++) {
		//Calculate Absolute Address and cast
		char* name = (char*)(pBase + NameRVA[i]);
		if (strcmp(pImport, name) == 0) {
			//Lookup Ordinal
			unsigned short NameOrdinal = ((unsigned short*)(pBase + pExportTable->AddressOfNameOrdinals))[i];

			//Use Ordinal to Lookup Function Address and Calculate Absolute
			unsigned int addr = ((unsigned int*)(pBase + pExportTable->AddressOfFunctions))[NameOrdinal];

			procAddr = (void*)(pBase + addr);

			break;
		}
	}

	return (uintptr_t)procAddr;
}
