#include "Vmoperations.h"

bool bVmOperationsInit = false;
vector<OPERATION_DATA>* vVmOperations = nullptr;

void vmoperations::Init()
{
	if (bVmOperationsInit)
		return;

	if (!vVmOperations) {
		vVmOperations = (vector<OPERATION_DATA>*)cpp::kMalloc(sizeof(*vVmOperations), PAGE_READWRITE);
		RtlZeroMemory(vVmOperations, sizeof(*vVmOperations));
		vVmOperations->Init();
		vVmOperations->reserve(64);
		vVmOperations->DisableLock();
	}

	bVmOperationsInit = true;
}

void vmoperations::ExecuteOperations(ONEXIT_DATA data)
{
	if (!bVmOperationsInit)
		return;

	ULONG dwCore = CPU::GetCPUIndex(true);
	int operationIdx = 0;
	for (auto& operation : *vVmOperations) {
		if (!bitmap::GetBit(&operation.executionBitmap, dwCore))
			continue;

		operation.operation(data);
		bitmap::SetBit(&operation.executedBitmap, dwCore, true);

		size_t executedCores = 0;
		for (int i = 0; i < sizeof(bitmap::LARGE_BITMAP) * 8; i++) {
			if (bitmap::GetBit(&operation.executedBitmap, i))
				executedCores++;
		}
		if (executedCores == CPU::GetCPUCount()) {
			vVmOperations->RemoveAt(operationIdx);
			break;
		}
			
		operationIdx++;
	}
}

void vmoperations::InsertOperation(bitmap::LARGE_BITMAP executionBitmap, fnVmOperation operation)
{
	if (!bVmOperationsInit)
		return;

	OPERATION_DATA data = { 0 };
	data.executionBitmap = executionBitmap;
	data.operation = operation;
	vVmOperations->Append(data);
}
