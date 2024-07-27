#pragma once
#ifdef _KERNEL_MODE

#include "cpp.h"
#include "spinlock.h"

#define SLEEP_FOREVER -1
#define INVALID_HANDLE_VALUE ((HANDLE)-1)

#pragma warning (disable:26495)

namespace threading {
	class Thread {
	public:
		Thread(PKSTART_ROUTINE fnEntry, PVOID pContext) {
			OBJECT_ATTRIBUTES objAttrb;
			InitializeObjectAttributes(&objAttrb, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

			bRunning = false;
			hThread = NULL;
			pThreadObj = nullptr;

			ThreadStartContext* pStartContext = (ThreadStartContext*)ExAllocatePool(NonPagedPool, sizeof(*pStartContext));
			pStartContext->pFn = fnEntry;
			pStartContext->pContext = pContext;
			pStartContext->pThread = this;

			NTSTATUS ntStatus = PsCreateSystemThread(
				&hThread,
				THREAD_ALL_ACCESS,
				&objAttrb,
				NULL,
				NULL,
				(PKSTART_ROUTINE)ThreadStartWrapper,
				pStartContext
			);

			if (!NT_SUCCESS(ntStatus)) {
				DbgMsg("[THREAD] Error: cannot create thread - 0x%x", ntStatus);
			}
			else {
				DbgMsg("[THREAD] Created thread with handle: %p", hThread);
			}

			ntStatus = ObReferenceObjectByHandle(
				hThread,
				THREAD_ALL_ACCESS,
				NULL,
				KernelMode,
				(PVOID*)&pThreadObj,
				NULL);
			if (!NT_SUCCESS(ntStatus)) {
				DbgMsg("[THREAD] Error: cannot reference object - 0x%x", ntStatus);
			}
		}
		~Thread();

		VOID Join();

		BOOLEAN IsRunning();
		HANDLE Handle();
		PVOID TObject();
	private:
		HANDLE hThread;
		PVOID pThreadObj;
		BOOLEAN bRunning;

		struct ThreadStartContext {
			Thread* pThread;
			PKSTART_ROUTINE pFn;
			PVOID pContext;
		};

		static void ThreadStartWrapper(ThreadStartContext* pStartContext);
	};

	void Sleep(int ms);
	bool AreThreadsRunning();
}

#pragma warning (default:26495)
#endif