#include "Vmexit.h"

bool bVmexitHandlerInit = false;
vector<VMEXIT_DATA>* vVmexitHandlers = 0;

void vmexit::Init()
{
	if (bVmexitHandlerInit)
		return;

	if (!vVmexitHandlers) {
		vVmexitHandlers = (vector<VMEXIT_DATA>*)cpp::kMalloc(sizeof(*vVmexitHandlers), PAGE_READWRITE);
		RtlZeroMemory(vVmexitHandlers, sizeof(*vVmexitHandlers));
		vVmexitHandlers->Init();
		vVmexitHandlers->reserve(64);
		vVmexitHandlers->DisableLock();
	}

	bVmexitHandlerInit = true;
}

bool vmexit::OnVmexit(ULONG64 vmexitCode, ONEXIT_DATA data)
{
	if (!vVmexitHandlers)
		return false;

	for (auto& exitData : *vVmexitHandlers) {
		if (exitData.exitCode == vmexitCode) {
			if(exitData.handler(data))
				return true;
		}
	}
	return false;
}

void vmexit::InsertHandler(ULONG64 vmexitCode, fnVmexitHandler handler)
{
	if (!bVmexitHandlerInit
		|| !handler)
		return;

	for (auto& exitHandler : *vVmexitHandlers) {
		if (exitHandler.exitCode == vmexitCode) {
			exitHandler.handler = handler;
			return;
		}
	}

	VMEXIT_DATA exitData = { 0 };
	exitData.exitCode = vmexitCode;
	exitData.handler = handler;

	vVmexitHandlers->Append(exitData);
}

void vmexit::RemoveHandler(ULONG64 vmexitCode)
{
	if (!bVmexitHandlerInit)
		return;

	bool bFound = false;
	int i = 0;
	for (auto& exitHandlers : *vVmexitHandlers) {
		if (exitHandlers.exitCode == vmexitCode) {
			bFound = true;
			break;
		}
		i++;
	}

	if(bFound)
		vVmexitHandlers->RemoveAt(i);
}

fnVmexitHandler vmexit::FindHandler(ULONG64 vmexitCode)
{
	if (!bVmexitHandlerInit)
		return nullptr;

	for (auto& exitHandlers : *vVmexitHandlers) {
		if (exitHandlers.exitCode == vmexitCode) {
			return exitHandlers.handler;
		}
	}

	return nullptr;
}
