#pragma once

#ifdef _KERNEL_MODE
#include "Vmexit.h"
#include "bitmap.h"

typedef void (*fnVmOperation)(ONEXIT_DATA data);

typedef struct _OPERATION_DATA {
	fnVmOperation operation;
	bitmap::LARGE_BITMAP executedBitmap;
	bitmap::LARGE_BITMAP executionBitmap;

	__forceinline bool operator==(_OPERATION_DATA& rhs) {
		return memcmp(this, &rhs, sizeof(rhs)) == 0;
	}
	__forceinline bool operator!=(_OPERATION_DATA& rhs) {
		return !(*this == rhs);
	}
} OPERATION_DATA, *POPERATION_DATA;

namespace vmoperations {
	void Init();

	void ExecuteOperations(ONEXIT_DATA data);
	void InsertOperation(bitmap::LARGE_BITMAP executionBitmap, fnVmOperation operation);
}
#endif