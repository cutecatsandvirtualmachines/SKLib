#pragma once
#ifdef _KERNEL_MODE

#include "cpp.h"
#include "StringEx.h"
#include "ListEx.h"

typedef void (*fnPowerCallback)(PVOID, PVOID, PVOID);

namespace Power {
	extern bool bInit;

	extern list<PCALLBACK_OBJECT>* vCallbackObjs;
	extern list<PVOID>* vRegistrationObjs;

	void Init();
	void Dispose();

	//The returned index is necessary to unregister the callback later on
	NTSTATUS RegisterCallback(fnPowerCallback fnCallback, int* index = nullptr);
	void UnregisterCallback(int index);
}
#endif