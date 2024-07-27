#pragma once
#include "data.h"
#include "cpp.h"
#include "macros.h"
#include "utils.h"
#include "RandEx.h"
#include "collector.h"
#include "threading.h"
#include "identity.h"

//Global strings
wchar_t SKLib::UniHideKeysPath[] = L"SOFTWARE\\UniHide";
wchar_t SKLib::CurrentDriverName[64] = { 0 };
bool SKLib::IsInitialized = false;

PUSERMODE_INFO SKLib::pUserInfo = nullptr;

//Logging
EventLogger SKLib::Log::evLogger;

OffsetDump offsets = { 0 };
CLEANUP_DATA cleanupData = { 0 };

void SKLib::Init(PDRIVER_OBJECT pDriverObj)
{
    if (IsInitialized)
        return;
    IsInitialized = true;

    Collector::Init();

    if (pDriverObj) {
        IOCTL::Init(pDriverObj);
        Log::evLogger.pDriverObj = pDriverObj;
    }

    CPU::Init();

    random::rnd.setSecLevel(random::SecurityLevel::SECURE);
    InitName();

    sharedpool::Init();

    pUserInfo = (PUSERMODE_INFO)cpp::kMalloc(sizeof(*pUserInfo), PAGE_READWRITE);

    identity::Init();

    DbgMsg("[GLOBALS] Successfully initialized global variables");
}

void SKLib::InitName(wchar_t* pDriverName) {
    wchar_t SPOOFER_TMP[32] = { 0x0 };
    wchar_t* pName = SPOOFER_TMP;
    if (!pDriverName)
        random::w_str(pName, 8);
    else
        pName = pDriverName;

    size_t strLen = wcslen(pName);
    memcpy(SKLib::CurrentDriverName, L"\\Driver\\", 8 * 2);
    memcpy(SKLib::CurrentDriverName + 8, pName, strLen * 2);
}

void SKLib::Dispose()
{
    IOCTL::Dispose();
    Power::Dispose();

    while (threading::AreThreadsRunning()) {
        threading::Sleep(10);
    }
    Collector::Dispose();
    DbgMsg("[GLOBALS] Successfully disposed of global variables");
}
