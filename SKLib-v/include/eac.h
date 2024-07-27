#pragma once

#include "cpp.h"
#include "winternlex.h"
#include "MapEx.h"
#include "paging.h"

namespace eac {
	typedef struct _CR3_TRACKING {
		union {
			PVOID pImageBase;
			DWORD64 dwNmiQueue[64];
		};
		DWORD64* pCr3;
		DWORD64 srcCr3;

		_CR3_TRACKING() {
			memset(this, 0, sizeof(*this));
		};
		_CR3_TRACKING(PVOID _pImageBase, DWORD64* _pCr3, DWORD64 _srcCr3) {
			memset(this, 0, sizeof(*this));
			pImageBase = _pImageBase;
			pCr3 = _pCr3;
			srcCr3 = _srcCr3;
		};

		__forceinline bool operator==(_CR3_TRACKING& rhs) {
			return !memcmp(&rhs, this, sizeof(rhs));
		}
		__forceinline bool operator!=(_CR3_TRACKING& rhs) {
			return !(*this == rhs);
		}
	} CR3_TRACKING;

	void Init();

	void UpdateCr3(CR3 cr3);
	void TrackCr3(DWORD64* pCr3, PVOID pAddressToCheck, DWORD64 srcCr3);
	void UntrackCr3(DWORD64* pCr3);

	void BlockNmi(CR3 cr3);
	void UnblockNmi(CR3 cr3);
	bool IsNmiBlocked(CR3 cr3);
	int GetAndDecreaseNmiCount(CR3 cr3);
	void IncreaseNmiCount(CR3 cr3);
}