#pragma once

#include "cpp.h"

namespace bitmap {
	typedef struct _LARGE_BITMAP {
		DWORD64 low;
		DWORD64 high;
	} LARGE_BITMAP, *PLARGE_BITMAP;

	VOID SetBit(PVOID va, DWORD32 bit, BOOLEAN bSet);
	BOOLEAN GetBit(PVOID va, DWORD32 bit);

	template<typename T>
	T bits(DWORD64 value, DWORD64 start, DWORD64 end) {
		if (end <= start)
			return 0;
		DWORD64 bitmask = 0;
		for (DWORD32 i = 0; i < sizeof(bitmask) * 8; i++) {
			if(i <= end && i >= start)
				SetBit(&bitmask, i, true);
		}
		
		return (T)((value & bitmask) >> start);
	}
}