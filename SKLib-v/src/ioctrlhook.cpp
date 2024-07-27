#include "ioctlhook.h"
#include <Vmcall.h>

random::Random rnd(random::SecurityLevel::PREDICTABLE);
bool spoofer::bLogHooks = false;

void ChangeIoc(PIO_STACK_LOCATION ioc, PIRP irp, PIO_COMPLETION_ROUTINE routine) {
    PIOC_REQUEST request = (PIOC_REQUEST)ExAllocatePool(POOL_TYPE::NonPagedPoolNx, sizeof(IOC_REQUEST));
    if (!request) {
        DbgMsg("! failed to allocate IOC_REQUEST !");
        return;
    }

    request->Buffer = irp->AssociatedIrp.SystemBuffer;
    request->BufferLength = ioc->Parameters.DeviceIoControl.OutputBufferLength;
    request->OldContext = ioc->Context;
    request->OldRoutine = ioc->CompletionRoutine;

    ioc->Control = SL_INVOKE_ON_SUCCESS;
    ioc->Context = request;
    ioc->CompletionRoutine = routine;
}

PWCHAR TrimGUID(PWCHAR guid, DWORD max) {
    DWORD i = 0;
    PWCHAR start = guid;

    --max;
    for (; i < max && *start != L'{'; ++i, ++start);
    for (; i < max && guid[i++] != L'}';);

    guid[i] = 0;
    return start;
}