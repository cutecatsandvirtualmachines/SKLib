#pragma once

#ifdef _KERNEL_MODE
#include "cpp.h"
#include "cpu.h"
#include "VMMDef.h"

typedef union _ONEXIT_DATA {
	SVM::SVMState* svm;
	PREGS intel;

	_ONEXIT_DATA(SVM::SVMState* pState) : svm(pState) {}
	_ONEXIT_DATA(PREGS pRegs) : intel(pRegs) {}
} ONEXIT_DATA, * PONEXIT_DATA;

typedef bool (*fnVmexitHandler)(ONEXIT_DATA data);

typedef struct _VMEXIT_DATA {
	ULONG64 exitCode;
	fnVmexitHandler handler;

	__forceinline bool operator==(_VMEXIT_DATA& rhs) {
		return memcmp(this, &rhs, sizeof(rhs)) == 0;
	}
	__forceinline bool operator!=(_VMEXIT_DATA& rhs) {
		return !(*this == rhs);
	}
} VMEXIT_DATA, *PVMEXIT_DATA;

namespace vmexit {
	void Init();
	bool OnVmexit(ULONG64 vmexitCode, ONEXIT_DATA data);

	void InsertHandler(ULONG64 vmexitCode, fnVmexitHandler handler);
	void RemoveHandler(ULONG64 vmexitCode);
	fnVmexitHandler FindHandler(ULONG64 vmexitCode);
}
#endif