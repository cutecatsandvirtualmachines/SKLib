#include "pdbparse.h"
#include <atlstr.h>
#include <filesystem>

DWORD g_dwMachineType = CV_CFL_80386;

PdbParser::PdbParser(std::wstring path)
{
    DWORD dwMachType = 0;
    HRESULT hr = CoInitialize(NULL);

    // Obtain access to the provider

    hr = CoCreateInstance(__uuidof(DiaSource),
        NULL,
        CLSCTX_INPROC_SERVER,
        __uuidof(IDiaDataSource),
        (void**)&pDiaDataSource);

    if (FAILED(hr)) {
        wprintf(L"CoCreateInstance failed - HRESULT = %08X, path: %ls\n", hr, path.c_str());
        printf("Trying to register COM object...\n");
        system("regsvr32 /s msdia140.dll");
        printf("Try to restart the application\n");
        return;
    }

    hr = pDiaDataSource->loadDataFromPdb(path.c_str());

    if (FAILED(hr)) {
        wprintf(L"loadDataFromPdb failed - HRESULT = %08X\n", hr);

        return;
    }

    hr = pDiaDataSource->openSession(&pDiaSession);

    if (FAILED(hr)) {
        wprintf(L"openSession failed - HRESULT = %08X\n", hr);

        return;
    }

    hr = pDiaSession->get_globalScope(&pGlobalSymbol);

    if (hr != S_OK) {
        wprintf(L"get_globalScope failed\n");

        return;
    }

    if (pGlobalSymbol->get_machineType(&dwMachType) == S_OK) {
        switch (dwMachType) {
        case IMAGE_FILE_MACHINE_I386: g_dwMachineType = CV_CFL_80386; break;
        case IMAGE_FILE_MACHINE_IA64: g_dwMachineType = CV_CFL_IA64; break;
        case IMAGE_FILE_MACHINE_AMD64: g_dwMachineType = CV_CFL_AMD64; break;
        }
    }
}

PdbParser::~PdbParser()
{
    if (pGlobalSymbol) {
        pGlobalSymbol->Release();
        pGlobalSymbol = NULL;
    }

    if (pDiaSession) {
        pDiaSession->Release();
        pDiaSession = NULL;
    }

    CoUninitialize();
}

bool PdbParser::IsInit()
{
    return pDiaDataSource
        && pDiaSession
        && pGlobalSymbol;
}

bool PdbParser::GetAllRVA(std::vector<OFFSET_DATA>& vRVAs)
{
    size_t rva = 0;

    IDiaEnumSymbols* pEnumSymbols;

    if (FAILED(pGlobalSymbol->findChildren(SymTagPublicSymbol, NULL, nsNone, &pEnumSymbols))) {
        return false;
    }

    IDiaSymbol* pSymbol;
    ULONG celt = 0;

    int i = 0;
    while (SUCCEEDED(pEnumSymbols->Next(1, &pSymbol, &celt)) && (celt == 1)) {
        BSTR bstrUndname;

        if (pSymbol->get_undecoratedNameEx(0x1000, &bstrUndname) == S_OK) {
            pSymbol->get_relativeVirtualAddress((DWORD*)&rva);
            const std::wstring ws(bstrUndname);
            const std::string s(ws.begin(), ws.end());

            vRVAs.emplace_back(s, rva);
        }

        pSymbol->Release();
        i++;
    }

    pEnumSymbols->Release();

    return rva;
}

size_t PdbParser::GetSymbolRVA(std::wstring funcName)
{
    size_t rva = 0;

    IDiaEnumSymbols* pEnumSymbols;

    if (FAILED(pGlobalSymbol->findChildren(SymTagPublicSymbol, NULL, nsNone, &pEnumSymbols))) {
        return false;
    }

    IDiaSymbol* pSymbol;
    ULONG celt = 0;

    int i = 0;
    while (SUCCEEDED(pEnumSymbols->Next(1, &pSymbol, &celt)) && (celt == 1)) {
        BSTR bstrUndname;

        if (pSymbol->get_undecoratedNameEx(0x1000, &bstrUndname) == S_OK) {
            //printf("%ls\n", bstrUndname);
            if (!wcscmp(funcName.c_str(), bstrUndname)) {

                pSymbol->get_relativeVirtualAddress((DWORD*)&rva);

                break;
            }
        }


        pSymbol->Release();
        i++;
    }

    pEnumSymbols->Release();

    return rva;
}

size_t PdbParser::GetStructMemberOffset(std::wstring structName, std::wstring memberName)
{
    size_t offset = 0;

    IDiaEnumSymbols* pEnumSymbols;

    if (FAILED(pGlobalSymbol->findChildren(SymTagNull, NULL, nsNone, &pEnumSymbols))) {
        return INVALID_OFFSET;
    }

    CComPtr<IDiaSymbol> pSymudt;
    CComPtr<IDiaSymbol> pSymTags;
    IDiaSymbol* pSymbolChild;
    ULONG celt = 0;

    int i = 0;
    bool bFound = false;
    while (SUCCEEDED(pEnumSymbols->Next(1, &pSymudt, &celt)) && (celt == 1)) {
        BSTR bstrUndname;

        if (pSymudt->get_name(&bstrUndname) == S_OK) {
            if (!wcscmp(structName.c_str(), bstrUndname)) {
                //This is the correct struct
                LONG ulMemberCount = 0;
                IDiaEnumSymbols* pEnumMembers;
                pSymudt->findChildren(SymTagNull, NULL, nsNone, &pEnumMembers);
                pEnumMembers->get_Count(&ulMemberCount);

                for (int i = 0; i < ulMemberCount; i++) {
                    pEnumMembers->Next(1, &pSymbolChild, &celt);
                    pSymbolChild->get_offset((LONG*)&offset);
                    pSymbolChild->get_name(&bstrUndname);

                    if (!wcscmp(memberName.c_str(), bstrUndname)) {
                        bFound = true;
                        break;
                    }
                }
                break;
            }
        }

        pSymudt.Release();
        i++;
    }

    pEnumSymbols->Release();

    if (!bFound)
        return INVALID_OFFSET;

    return offset;
}
