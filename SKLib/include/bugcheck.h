#pragma once

#pragma pack(push, 1)
typedef struct _BUGCHECK_INFO {
    unsigned int ulBugCheckCode;
    wchar_t* pCaption;
    wchar_t* pMessage;
    wchar_t* pLink;
    unsigned int bgColor;

    __int64 pBugCheckTrampoline;
} BUGCHECK_INFO, *PBUGCHECK_INFO;
#pragma pack(pop)

#ifdef _KERNEL_MODE
#include "cpp.h"
#include "winternlex.h"
#include "MemoryEx.h"

typedef VOID
(*fnKiDisplayBlueScreen)(
	IN ULONG PssMessage,
	IN BOOLEAN HardErrorCalled,
	IN PCHAR HardErrorCaption,
	IN PCHAR HardErrorMessage,
	IN PCHAR StateString
);

typedef DWORD64
(*fnBgpFwDisplayBugCheckScreen) (
    DWORD32 BugCheckDataFirstDword,
    DWORD64* BugCheckData_0x8_ptr,
    DWORD32 BugCheckDriverFirstDword,
    DWORD64* someArray0xA0,
    char bugCheckCode_maybe
);

typedef VOID
(*fnBgpClearScreen) (
    DWORD argb
);

typedef DWORD64
(*fnBgpDisplayCharacterEx) (
    unsigned __int16 a1, 
    __int64 a2, 
    unsigned int a3, 
    unsigned int a4, 
    unsigned int color,
    int a6, 
    __int64 a7, 
    __int64 a8, 
    unsigned __int64 a9
);

typedef DWORD64
(*fnBgpGxFillRectangle) (
    DWORD64 a1,
    DWORD32 color
);

typedef DWORD64 
(*fnBgpRasPrintGlyph) (
    __int64 a1, 
    __int64 pColor, 
    __int16 a3, 
    unsigned int a4, 
    int a5, 
    char a6, 
    __int64 a7, 
    __int64 a8, 
    __int64* a9
);

typedef DWORD64
(*fnBgpGxProcessQrCodeBitmap) (
    BYTE* pBitmap, 
    DWORD64** outRect
);

typedef DWORD64
(*fnInbvAcquireDisplayOwnership) (
    DWORD64 a1,
    DWORD64 a2,
    DWORD64 a3,
    DWORD64 a4
);

typedef void
(*fnBugCheckEx) (
    DWORD64 dwBugCheckCode,
    DWORD64 dwBugCheckParam1,
    DWORD64 dwBugCheckParam2,
    DWORD64 dwBugCheckParam3,
    DWORD64 dwBugCheckParam4
);

typedef DWORD64
(*fnDumpWrite) (
    DWORD* dumpStack_maybe,
    DWORD64 a2,
    DWORD64 a3
);

typedef DWORD64 (*fnWriteBitmapDump) (
    DWORD64 pDumpStack,
    DWORD64 a2,
    DWORD64 a3
);

typedef DWORD64(*fnWriteMiniDump) (
    DWORD64 pDumpStack,
    DWORD64 a2
);

namespace bugcheck {
	VOID Init();
    VOID Update(
        PBUGCHECK_INFO pBugCheckInfo
    );
    VOID Setup();

	extern fnKiDisplayBlueScreen pKiDisplayBlueScreen;
    extern fnBgpGxFillRectangle pBgpGxFillRectangle;
    extern DWORD64* pBugCheckListHead;
    extern DWORD64* pTriageDumpListHead;
    extern DWORD64* KiBugCheckData;
}
#endif