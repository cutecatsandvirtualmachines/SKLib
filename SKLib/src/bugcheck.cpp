#include "bugcheck.h"
#include <intrin.h>
#include <threading.h>

bool bCustomBugcheckInit = false;

fnKiDisplayBlueScreen bugcheck::pKiDisplayBlueScreen = 0;
fnKiDisplayBlueScreen pKiDisplayBlueScreenOrig = 0;
fnBgpGxFillRectangle bugcheck::pBgpGxFillRectangle = 0;
fnBgpGxFillRectangle pBgpGxFillRectangleOrig = 0;
fnBgpFwDisplayBugCheckScreen pBgpFwDisplayBugCheckScreen = 0;
fnBgpRasPrintGlyph pBgpRasPrintGlyph = 0;
fnBgpRasPrintGlyph pBgpRasPrintGlyphOrig = 0;
fnBgpClearScreen pBgpClearScreen = 0;
fnBgpClearScreen pBgpClearScreenOrig = 0;
fnWriteBitmapDump pWriteBitmapDump = 0;
fnWriteBitmapDump pWriteBitmapDumpOrig = 0;
DWORD64* bugcheck::pBugCheckListHead = 0;
DWORD64* bugcheck::pTriageDumpListHead = 0;
DWORD64* bugcheck::KiBugCheckData = nullptr;
UNICODE_STRING* pSadEmoji = 0;
PKSPIN_LOCK* pHeadlessGlobal = nullptr;

fnBgpGxProcessQrCodeBitmap pBgpGxProcessQrCodeBitmap = 0;
DWORD64** pQrRectangle = 0;
BYTE* pBmpBuffer = nullptr;

PWCH pBugCheckCaption = nullptr;
PWCH pBugCheckMessage = nullptr;
PWCH pBugCheckLink = nullptr;
UNICODE_STRING* pBsodStrings = nullptr;
constexpr size_t BugCheckStringSize = 0x1000;

fnBugCheckEx pBugCheckTrampoline = nullptr;
bool bCustomBgActive = false;
DWORD bgColor = 0xff4b634e;

VOID BgpClearScreen(DWORD argb) {
    pBgpClearScreenOrig(bgColor);
}

DWORD64 BgpGxFillRectangle(
    DWORD64 a1,
    DWORD32 color
) {
    return pBgpGxFillRectangleOrig(a1, bgColor);
}

DWORD64 BgpRasPrintGlyph(
    __int64 a1,
    __int64 pColor,
    __int16 a3,
    unsigned int a4,
    int a5,
    char a6,
    __int64 a7,
    __int64 a8,
    __int64* a9
) {
    *(DWORD64*)pColor = bgColor;
    return pBgpRasPrintGlyphOrig(a1, pColor, a3, a4, a5, a6, a7, a8, a9);
}

DWORD64 WriteBitmapDump(
    DWORD64 pDumpStack,
    DWORD64 a2,
    DWORD64 a3
) {
    //Give enough time to the user to see the bsod
    threading::Sleep(5000);
    return STATUS_SUCCESS;
}

VOID
KiDisplayBlueScreen(
    IN ULONG PssMessage,
    IN BOOLEAN HardErrorCalled,
    IN PCHAR HardErrorCaption,
    IN PCHAR HardErrorMessage,
    IN PCHAR StateString
    ) {
    bugcheck::Setup();
    return pKiDisplayBlueScreenOrig(PssMessage, HardErrorCalled, HardErrorCaption, HardErrorMessage, StateString);
}

VOID bugcheck::Init()
{
#ifdef CUSTOMIZE_BSOD
    if (bCustomBugcheckInit)
        return;

    ULONG64 KiDisplayBlueScreenOffset = (ULONG64)Memory::FindPatternImage(
        winternl::GetNtoskrnlBaseAddress(), 
        (PCHAR)"\x8B\xC8\x83\xC9\x01\x45\x84\xF6\x0F\x45\xC8\xE8", 
        (PCHAR)"xxxxxxxxxxxx"
    );
    pKiDisplayBlueScreen = (fnKiDisplayBlueScreen)(KiDisplayBlueScreenOffset + 16 + *(PINT)(KiDisplayBlueScreenOffset + 12));

    if (!pKiDisplayBlueScreen) {
        DbgMsg("[BUGCHECK] Failed getting KiDisplayBlueScreen!");
        return;
    }

    ULONG64 BugCheckListHeadOffset = (ULONG64)Memory::FindPatternImage(
        winternl::GetNtoskrnlBaseAddress(),
        (PCHAR)"\x45\x8B\xF0\x4C\x8B\xFA\x8B\xF1\x48\x8D\x3D",
        (PCHAR)"xxxxxxxxxxx"
    );
    pBugCheckListHead = (DWORD64*)(BugCheckListHeadOffset + 15 + *(PINT)(BugCheckListHeadOffset + 11));

    if (!pBugCheckListHead) {
        DbgMsg("[BUGCHECK] Failed getting BugCheckListHead!");
        return;
    }

    ULONG64 TriageDumpListHeadOffset = (ULONG64)Memory::FindPatternImage(
        winternl::GetNtoskrnlBaseAddress(),
        (PCHAR)"\x48\x8D\x0D\x00\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x89\x48\x10\x48\x8D\x0D",
        (PCHAR)"xxx????xxx????xxxxxxx"
    );
    pTriageDumpListHead = (DWORD64*)(TriageDumpListHeadOffset + 25 + *(PINT)(TriageDumpListHeadOffset + 21));

    if (!pTriageDumpListHead) {
        DbgMsg("[BUGCHECK] Failed getting TriageDumpListHead!");
        return;
    }

    ULONG64 BugCheckDataOffset = (ULONG64)Memory::FindPatternImage(
        winternl::GetNtoskrnlBaseAddress(),
        (PCHAR)"\x44\x8D\x42\x60\xE8\x00\x00\x00\x00\x8B\x05",
        (PCHAR)"xxxxx????xx"
    );
    KiBugCheckData = (DWORD64*)(BugCheckDataOffset + 15 + *(PINT)(BugCheckDataOffset + 11));

    if (!KiBugCheckData) {
        DbgMsg("[BUGCHECK] Failed getting KiBugCheckData!");
        return;
    }

    ULONG64 BgpClearScreenOffset = (ULONG64)Memory::FindPatternImage(
        winternl::GetNtoskrnlBaseAddress(),
        (PCHAR)"\xB9\x00\x00\x00\xFF\xE8\x00\x00\x00\x00\xB9\x84\x00\x00\x00",
        (PCHAR)"xxxxxx????xxxxx"
    );
    pBgpClearScreen = (fnBgpClearScreen)(BgpClearScreenOffset + 10 + *(PINT)(BgpClearScreenOffset + 6));

    if (!pBgpClearScreen) {
        DbgMsg("[BUGCHECK] Failed getting BgpClearScreen!");
        return;
    }

    ULONG64 BugCheckStringsOffset = (ULONG64)Memory::FindPatternImage(
        winternl::GetNtoskrnlBaseAddress(),
        (PCHAR)"\x41\x8B\x4C\xF7\x24\x4C\x8D\x15",
        (PCHAR)"xxxxxxxx"
    );
    pBsodStrings = (UNICODE_STRING*)(BugCheckStringsOffset + 12 + *(PINT)(BugCheckStringsOffset + 8));

    if (!pBsodStrings) {
        DbgMsg("[BUGCHECK] Failed getting bsod strings!");
        return;
    }

    ULONG64 BgpGxFillRectangleOffset = (ULONG64)Memory::FindPatternImage(
        winternl::GetNtoskrnlBaseAddress(),
        (PCHAR)"\x8B\xD0\x89\x43\x28\xE8\x00\x00\x00\x00\x8B\x47",
        (PCHAR)"xxxxxx????xx"
    );
    pBgpGxFillRectangle = (fnBgpGxFillRectangle)(BgpGxFillRectangleOffset + 10 + *(PINT)(BgpGxFillRectangleOffset + 6));

    if (!pBgpGxFillRectangle) {
        DbgMsg("[BUGCHECK] Failed getting BgpGxFillRectangle!");
        return;
    }

    ULONG64 BgpRasPrintGlyphOffset = (ULONG64)Memory::FindPatternImage(
        winternl::GetNtoskrnlBaseAddress(),
        (PCHAR)"\xC7\x44\x24\x28\x01\x00\x00\x00\x89\x44\x24\x20\xE8\x00\x00\x00\x00\x8B\xF8",
        (PCHAR)"xxxxxxxxxxxxx????xx"
    );
    pBgpRasPrintGlyph = (fnBgpRasPrintGlyph)(BgpRasPrintGlyphOffset + 17 + *(PINT)(BgpRasPrintGlyphOffset + 13));

    if (!pBgpRasPrintGlyph) {
        DbgMsg("[BUGCHECK] Failed getting BgpRasPrintGlyph!");
        return;
    }

    ULONG64 SadEmojiOffset = (ULONG64)Memory::FindPatternImage(
        winternl::GetNtoskrnlBaseAddress(),
        (PCHAR)"\x44\x8B\xCB\x48\x8D\x0D\x00\x00\x00\x00\x3B\xEF",
        (PCHAR)"xxxxxx????xx"
    );
    pSadEmoji = (UNICODE_STRING*)(SadEmojiOffset + 10 + *(PINT)(SadEmojiOffset + 6));

    if (!pSadEmoji) {
        DbgMsg("[BUGCHECK] Failed getting text emoji!");
    }

    ULONG64 QrOffset = (ULONG64)Memory::FindPatternImage(
        winternl::GetNtoskrnlBaseAddress(),
        (PCHAR)"\x48\x85\xC9\x74\x14\x48\x8D\x15\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x85\xC0",
        (PCHAR)"xxxxxxxx????x????xx"
    );
    pQrRectangle = (DWORD64**)(QrOffset + 12 + *(PINT)(QrOffset + 8));
    pBgpGxProcessQrCodeBitmap = (fnBgpGxProcessQrCodeBitmap)(QrOffset + 17 + *(PINT)(QrOffset + 13));

    if (!pQrRectangle) {
        DbgMsg("[BUGCHECK] Failed getting qr rectangle!");
    }

    ULONG64 BgpFwDisplayBugCheckScreenOffset = (ULONG64)Memory::FindPatternImage(
        winternl::GetNtoskrnlBaseAddress(),
        (PCHAR)"\x4C\x8B\xC3\x48\x8B\xD6\x41\x8B\xCF\xE8",
        (PCHAR)"xxxxxxxxxx"
    );
    pBgpFwDisplayBugCheckScreen = (fnBgpFwDisplayBugCheckScreen)(BgpFwDisplayBugCheckScreenOffset + 14 + *(PINT)(BgpFwDisplayBugCheckScreenOffset + 10));

    ULONG64 HeadlessGlobalOffset = (ULONG64)Memory::FindPatternImage(
        winternl::GetNtoskrnlBaseAddress(),
        (PCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\x8B\x41\x30",
        (PCHAR)"xxx????xxx"
    );
    pHeadlessGlobal = (PKSPIN_LOCK*)(HeadlessGlobalOffset + 7 + *(PINT)(HeadlessGlobalOffset + 3));

    PVOID pCrashdmp = Memory::GetKernelAddress((PCHAR)"crashdmp.sys");
    if (!pCrashdmp) {
        DbgMsg("[BUGCHECK] Failed getting crashdmp.sys address");
        return;
    }

#ifdef DISABLE_FULL_DUMPS
    ULONG64 WriteBitmapDumpOffset = (ULONG64)Memory::FindPatternImage(
        pCrashdmp,
        (PCHAR)"\x4D\x8B\xC5\x49\x8B\xD4\x48\x8B\xCB\xE8",
        (PCHAR)"xxxxxxxxxx"
    );
    pWriteBitmapDump = (fnWriteBitmapDump)(WriteBitmapDumpOffset + 14 + *(PINT)(WriteBitmapDumpOffset + 10));
#endif

    pBugCheckCaption = (PWCH)cpp::kMalloc(BugCheckStringSize);
    pBugCheckMessage = (PWCH)cpp::kMalloc(BugCheckStringSize);
    pBugCheckLink = (PWCH)cpp::kMalloc(BugCheckStringSize);

    RtlZeroMemory(pBugCheckCaption, BugCheckStringSize);
    RtlZeroMemory(pBugCheckMessage, BugCheckStringSize);
    RtlZeroMemory(pBugCheckLink, BugCheckStringSize);
    
    HOOK_SECONDARY_INFO hkSecondaryInfo = { 0 };
    hkSecondaryInfo.pOrigFn = (PVOID*)&pBgpClearScreenOrig;
    PAGE_PERMISSIONS pgPermissions = { 0 };
    if (!EPT::Hook(pBgpClearScreen, BgpClearScreen, hkSecondaryInfo, pgPermissions)) {
        DbgMsg("[BUGCHECK] Failed hooking BgpClearScreen");
        return;
    }
    
    hkSecondaryInfo.pOrigFn = (PVOID*)&pBgpGxFillRectangleOrig;
    if (!EPT::Hook(pBgpGxFillRectangle, BgpGxFillRectangle, hkSecondaryInfo, pgPermissions)) {
        DbgMsg("[BUGCHECK] Failed hooking BgpGxFillRectangle");
        return;
    }
    
    hkSecondaryInfo.pOrigFn = (PVOID*)&pBgpRasPrintGlyphOrig;
    if (!EPT::Hook(pBgpRasPrintGlyph, BgpRasPrintGlyph, hkSecondaryInfo, pgPermissions)) {
        DbgMsg("[BUGCHECK] Failed hooking BgpRasPrintGlyph");
        return;
    }

#ifdef DISABLE_FULL_DUMPS
    hkSecondaryInfo.pOrigFn = (PVOID*)&pWriteBitmapDumpOrig;
    if (!EPT::Hook(pWriteBitmapDump, WriteBitmapDump, hkSecondaryInfo, pgPermissions)) {
        DbgMsg("[BUGCHECK] Failed hooking WriteBitmapDump");
        return;
    }
#endif

    hkSecondaryInfo.pOrigFn = (PVOID*)&pKiDisplayBlueScreenOrig;
    if (!EPT::Hook(pKiDisplayBlueScreen, KiDisplayBlueScreen, hkSecondaryInfo, pgPermissions)) {
        DbgMsg("[BUGCHECK] Failed hooking KiDisplayBlueScreen");
        return;
    }

    pBugCheckTrampoline = (fnBugCheckEx)cpp::kMalloc(0x100);
    memset(pBugCheckTrampoline, 0xcc, 0x100);

    DbgMsg("[BUGCHECK] Setup successful");
    
    bCustomBugcheckInit = true;
#endif
}

VOID bugcheck::Update(PBUGCHECK_INFO pBugCheckInfo)
{
    if (!bCustomBugcheckInit
        || !pBugCheckInfo)
        return;

    if (pBugCheckInfo->pCaption) {
        wcscpy(pBugCheckCaption, pBugCheckInfo->pCaption);
    }
    if (pBugCheckInfo->pMessage) {
        wcscpy(pBugCheckMessage, pBugCheckInfo->pMessage);
    }
    if (pBugCheckInfo->pLink) {
        wcscpy(pBugCheckLink, pBugCheckInfo->pLink);
    }
    if (pBugCheckInfo->bgColor) {
        bgColor = (pBugCheckInfo->bgColor | 0xff000000);
    }
    if (pBugCheckTrampoline) {
        CPU::WriteAbsJmp((PCHAR)pBugCheckTrampoline, (size_t)KeBugCheckEx);
        pBugCheckInfo->pBugCheckTrampoline = (ULONG64)pBugCheckTrampoline;
    }
}

VOID bugcheck::Setup()
{
    if (!bCustomBugcheckInit)
        return;
    DWORD64 oldBugCheckListHead = 0;
    DWORD64 oldTriageDumpListHead = 0;
    if (pBugCheckListHead) {
        oldBugCheckListHead = *pBugCheckListHead;
        *pBugCheckListHead = 0;
    }
    if (pTriageDumpListHead) {
        oldTriageDumpListHead = *pTriageDumpListHead;
        *pTriageDumpListHead = 0;
    }
    if (pSadEmoji) {
        wchar_t value[] = { L':', L')' };
        bool bEnableCET = CPU::DisableWriteProtection();
        memcpy(pSadEmoji->Buffer, &value, 4);
        CPU::EnableWriteProtection(bEnableCET);
    }
    if (pQrRectangle) {
        bool bEnableCET = CPU::DisableWriteProtection();
        memset(pQrRectangle, 0, 0x8);
        CPU::EnableWriteProtection(bEnableCET);
    }
    if (pBsodStrings) {
        if (pBugCheckCaption && pBugCheckCaption[0]) {
            pBsodStrings[0].Length = (USHORT)wcslen(pBugCheckCaption) * 2;
            pBsodStrings[0].MaximumLength = max(pBsodStrings[0].Length, BugCheckStringSize);
            pBsodStrings[0].Buffer = pBugCheckCaption;
        }
    
        if (pBugCheckMessage && pBugCheckMessage[0]) {
            pBsodStrings[1].Length = (USHORT)wcslen(pBugCheckMessage) * 2;
            pBsodStrings[1].MaximumLength = max(pBsodStrings[0].Length, BugCheckStringSize);
            pBsodStrings[1].Buffer = pBugCheckMessage;
        }
    
        if (pBugCheckLink && pBugCheckLink[0]) {
            pBsodStrings[0xd].Length = (USHORT)wcslen(pBugCheckLink) * 2;
            pBsodStrings[0xd].MaximumLength = max(pBsodStrings[0].Length, BugCheckStringSize);
            pBsodStrings[0xd].Buffer = pBugCheckLink;
        }
    }
}
