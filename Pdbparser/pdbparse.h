#pragma once
#include <combaseapi.h>
#include <string>
#include <iostream>
#include <vector>
#include <map>

#include "dia2.h"
#include "EzPdb.h"

typedef struct _OFFSET_DATA {
	std::string name;
	size_t offset;
} OFFSET_DATA, * POFFSET_DATA;

#define INVALID_OFFSET ((DWORD64)-1)

class PdbParser {
private:
	IDiaDataSource* pDiaDataSource;
	IDiaSession* pDiaSession;
	IDiaSymbol* pGlobalSymbol;

public:
	PdbParser(std::wstring path);
	~PdbParser();

	bool IsInit();

	bool GetAllRVA(std::vector<OFFSET_DATA>& vRVAs);
	size_t GetSymbolRVA(std::wstring funcName);
	size_t GetStructMemberOffset(std::wstring structName, std::wstring memberName);
};
