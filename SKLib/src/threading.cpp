#include "threading.h"

int activeThreads = 0;

threading::Thread::~Thread()
{
	DbgMsg("[THREAD] Disposing of thread object: h = %p", hThread);
	ZwClose(hThread);
	ObDereferenceObjectDeferDelete(pThreadObj);
	hThread = NULL;
	pThreadObj = NULL;
}

VOID threading::Thread::Join()
{
	DbgMsg("[THREAD] Joining thread: %p", hThread);
	NTSTATUS ntStatus = KeWaitForSingleObject(
		pThreadObj,
		Executive,
		KernelMode,
		FALSE,
		NULL
	);

	if (!NT_SUCCESS(ntStatus)) {
		DbgMsg("[THREAD] Join failed with code: %x", ntStatus);
	}
}

BOOLEAN threading::Thread::IsRunning()
{
	return bRunning;
}

HANDLE threading::Thread::Handle()
{
	return hThread;
}

PVOID threading::Thread::TObject()
{
	return pThreadObj;
}

void threading::Thread::ThreadStartWrapper(ThreadStartContext* pStartContext)
{
	Thread* pThread = pStartContext->pThread;
	if (MmIsAddressValid(pThread))
		pThread->bRunning = true;
	activeThreads++;

	pStartContext->pFn(pStartContext->pContext);

	if (MmIsAddressValid(pThread))
		pThread->bRunning = false;
	activeThreads--;

	ExFreePool(pStartContext);

	PsTerminateSystemThread(0);
}

void threading::Sleep(int ms)
{
	//Negative values represent a relative interval
	LARGE_INTEGER lInt;
	int wait = ms >= 0 ? ms : MAXINT32;
	lInt.QuadPart = -10000 * (size_t)wait;
	do {
		KeDelayExecutionThread(KernelMode, FALSE, &lInt);
	} while (ms == SLEEP_FOREVER);
}

bool threading::AreThreadsRunning()
{
	return activeThreads > 0;
}
