#include "power.h"

bool Power::bInit = false;

list<PCALLBACK_OBJECT>* Power::vCallbackObjs = nullptr;
list<PVOID>* Power::vRegistrationObjs = nullptr;

void Power::Init()
{
	if (bInit) {
		return;
	}

	if (!vCallbackObjs) {
		vCallbackObjs = (list<PCALLBACK_OBJECT>*)cpp::kMalloc(sizeof(*vCallbackObjs), PAGE_READWRITE);
		vCallbackObjs->Init();
	}
	if (!vRegistrationObjs) {
		vRegistrationObjs = (list<PVOID>*)cpp::kMalloc(sizeof(*vRegistrationObjs), PAGE_READWRITE);
		vRegistrationObjs->Init();
	}

	bInit = true;
}

void Power::Dispose()
{
	if (!bInit) {
		DbgMsg("[POWER] Error: cannot dispose of uninitialized objects!");
		return;
	}
	if (!vRegistrationObjs)
		return;
	forEach(itRegisterObj, (*vRegistrationObjs)) {
		ExUnregisterCallback(*itRegisterObj);
	}
	if (!vCallbackObjs)
		return;
	forEach(itCallbackObj, (*vCallbackObjs)) {
		ObDereferenceObject(*itCallbackObj);
	}

	vRegistrationObjs->Dispose();
	vCallbackObjs->Dispose();

	cpp::kFree(vRegistrationObjs);
	cpp::kFree(vCallbackObjs);

	vRegistrationObjs = nullptr;
	vCallbackObjs = nullptr;
}

NTSTATUS Power::RegisterCallback(fnPowerCallback fnCallback, int* index)
{
	Init();

	string cbName("\\Callback\\PowerState");
	OBJECT_ATTRIBUTES oa = RTL_CONSTANT_OBJECT_ATTRIBUTES(&cbName.unicode(), OBJ_CASE_INSENSITIVE);

	PCALLBACK_OBJECT pCallbackObj = nullptr;
	NTSTATUS ntStatus = ExCreateCallback(&pCallbackObj, &oa, FALSE, TRUE);
	if (!NT_SUCCESS(ntStatus)) {
		ObDereferenceObject(pCallbackObj);
		cpp::kFree(pCallbackObj);
		return STATUS_UNSUCCESSFUL;
	}

	PVOID pRegistrationObj = ExRegisterCallback(pCallbackObj, fnCallback, nullptr);
	if (!pRegistrationObj) {
		return STATUS_UNSUCCESSFUL;
	}

	vCallbackObjs->Append(pCallbackObj);
	vRegistrationObjs->Append(pRegistrationObj);

	if (index) {
		*index = vRegistrationObjs->Length() - 1;
	}

	return ntStatus;
}

void Power::UnregisterCallback(int index)
{
	ExUnregisterCallback(vRegistrationObjs->at(index));
	vRegistrationObjs->RemoveAt(index);
	ObDereferenceObject(vCallbackObjs->at(index));
	vCallbackObjs->RemoveAt(index);
}
