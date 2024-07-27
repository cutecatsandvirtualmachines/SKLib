#include "Vmcall.h"

unordered_map<ULONG64, fnVmcallCallback>* vmcall::vVmcallCallbacks = nullptr;
bool bVmcallHandlerInit = false;

constexpr int maxVmcallHandlers = 64;
ULONG64 communicationKey = 0;
ULONG64 lastCr3 = 0;

bool vmcall::Init()
{
	if (bVmcallHandlerInit)
		return true;

	if (!vVmcallCallbacks) {
		vVmcallCallbacks = (unordered_map<ULONG64, fnVmcallCallback>*)cpp::kMalloc(sizeof(*vVmcallCallbacks), PAGE_READWRITE);
		RtlZeroMemory(vVmcallCallbacks, sizeof(*vVmcallCallbacks));
		vVmcallCallbacks->Init();
		vVmcallCallbacks->reserve(maxVmcallHandlers);
		vVmcallCallbacks->DisableLock();
	}

	bVmcallHandlerInit = true;
	return true;
}

void vmcall::Dispose()
{
	if (!bVmcallHandlerInit)
		return;

	vVmcallCallbacks->Dispose();
	cpp::kFree(vVmcallCallbacks);
	bVmcallHandlerInit = false;
}

fnVmcallCallback vmcall::FindHandler(ULONG64 vmcallCode)
{
	if(vVmcallCallbacks->Contains(vmcallCode))
		return vVmcallCallbacks->Value(vmcallCode);
	return nullptr;
}

void vmcall::InsertHandler(fnVmcallCallback pCallback, ULONG64 vmcallCode)
{
	vVmcallCallbacks->Append(vmcallCode, pCallback);
}

void vmcall::RemoveHandler(ULONG64 vmcallCode)
{
	vVmcallCallbacks->Value(vmcallCode) = nullptr;
}

bool vmcall::ValidateCommunicationKey(ULONG64 key)
{
	return !communicationKey || communicationKey == key;
}

ULONG64 vmcall::GetCommunicationKey()
{
	return communicationKey;
}

bool vmcall::IsVmcall(ULONG64 r9)
{
	return r9 == (communicationKey ^ 0xdeada55);
}

NTSTATUS vmcall::HandleVmcall(ULONG64 ulCallNum, ULONG64& ulOpt1, ULONG64& ulOpt2, ULONG64& ulOpt3)
{
	ULONG dwCore = CPU::GetCPUIndex(true);
	NTSTATUS ntVmcallStatus;
	ntVmcallStatus = STATUS_UNSUCCESSFUL;
	lastCr3 = vmm::GetGuestCR3().Flags;

	switch (ulCallNum)
	{
	case VMCALL_SET_COMM_KEY:
	{
		if (!communicationKey || communicationKey == ulOpt2) {
			communicationKey = ulOpt1;
			ntVmcallStatus = STATUS_SUCCESS;
		}
		break;
	}
	case VMCALL_TEST:
	{
		ntVmcallStatus = (NTSTATUS)'ImON';
		break;
	}
	case VMCALL_GET_CR3:
	{
		DWORD64* pOutCr3 = (DWORD64*)paging::vmmhost::MapGuestToHost(vmm::GetGuestCR3().Flags, (PVOID)ulOpt1);
		if(pOutCr3)
			*pOutCr3 = vmm::GetGuestCR3().Flags;
		ntVmcallStatus = STATUS_SUCCESS;
		break;
	}
	case VMCALL_VMXOFF:
	{
		//Deprecated
		ntVmcallStatus = STATUS_SUCCESS;
		break;
	}
	case VMCALL_HOOK_PAGE:
	{
		//Deprecated
		ntVmcallStatus = STATUS_SUCCESS;
		break;
	}
	case VMCALL_UNHOOK_PAGE:
	{
		//Deprecated
		ntVmcallStatus = STATUS_SUCCESS;
		break;
	}
	case VMCALL_HOOK_PAGE_RANGE:
	{
		//Deprecated
		ntVmcallStatus = STATUS_SUCCESS;
		break;
	}
	case VMCALL_HOOK_PAGE_INDEX:
	{
		//Deprecated
		ntVmcallStatus = STATUS_SUCCESS;
		break;
	}
	case VMCALL_SUBSTITUTE_PAGE:
	{
		//Deprecated
		ntVmcallStatus = STATUS_SUCCESS;
		break;
	}
	case VMCALL_INVEPT_CONTEXT:
	{
		EPT::InvalidateEPT(dwCore);
		ntVmcallStatus = STATUS_SUCCESS;
		break;
	}
	case VMCALL_DISABLE_EPT:
	{
		//Deprecated
		ntVmcallStatus = STATUS_SUCCESS;
		break;
	}
	case VMCALL_CRASH:
	{
		bugcheck::Update((BUGCHECK_INFO*)paging::vmmhost::MapGuestToHost(vmm::GetGuestCR3().Flags, (PVOID)ulOpt1));
		ntVmcallStatus = STATUS_SUCCESS;
		break;
	}
	case VMCALL_PROBE:
	{
		//Deprecated
		ntVmcallStatus = STATUS_SUCCESS;
		break;
	}
	case VMCALL_READ_VIRT:
	{
#ifdef PROPRIETARY_PAGE_TABLES
		CR3 guestCr3 = vmm::GetGuestCR3();

		CR3 cr3 = { 0 };
		if (ulOpt2 == TARGET_CR3_SYSTEM) {
			cr3.Flags = vmm::guestCR3.Flags;
		}
		else if (ulOpt2 == TARGET_CR3_CURRENT) {
			cr3.Flags = guestCr3.Flags;
		}
		else {
			cr3.Flags = ulOpt2;
		}
		vmm::PREAD_DATA readData = (vmm::PREAD_DATA)paging::vmmhost::MapGuestToHost(
			guestCr3.Flags,
			(PVOID)ulOpt1,
			MAP_TYPE::src);
		if (!readData) {
			DebugBreak();
			ntVmcallStatus = EXIT_ERRORS::ERROR_CANNOT_MAP_PARAM;
			break;
		}

		SIZE_T length = readData->length;
		PVOID pOutBuf = readData->pOutBuf;
		PVOID pTarget = readData->pTarget;

		if (!pOutBuf || !pTarget)
		{
			ntVmcallStatus = EXIT_ERRORS::ERROR_INVALID_PARAM;
			break;
		}

		ntVmcallStatus = paging::vmmhost::ReadVirtMemory(pOutBuf, pTarget, length, cr3);
#endif
		break;
	}
	case VMCALL_WRITE_VIRT:
	{
#ifdef PROPRIETARY_PAGE_TABLES
		CR3 guestCr3 = vmm::GetGuestCR3();

		CR3 cr3 = { 0 };
		if (ulOpt2 == TARGET_CR3_SYSTEM) {
			cr3.Flags = vmm::guestCR3.Flags;
		}
		else if (ulOpt2 == TARGET_CR3_CURRENT) {
			cr3.Flags = guestCr3.Flags;
		}
		else {
			cr3.Flags = ulOpt2;
		}
		vmm::PWRITE_DATA readData = (vmm::PWRITE_DATA)paging::vmmhost::MapGuestToHost(
			guestCr3.Flags,
			(PVOID)ulOpt1,
			MAP_TYPE::src);
		if (!readData) {
			DebugBreak();
			ntVmcallStatus = EXIT_ERRORS::ERROR_CANNOT_MAP_PARAM;
			break;
		}

		SIZE_T length = readData->length;
		PVOID pInBuf = readData->pInBuf;
		PVOID pTarget = readData->pTarget;

		if (!pInBuf || !pTarget)
		{
			ntVmcallStatus = EXIT_ERRORS::ERROR_INVALID_PARAM;
			break;
		}

		ntVmcallStatus = paging::vmmhost::WriteVirtMemory(pTarget, pInBuf, length, cr3);
#endif
		break;
	}
	case VMCALL_READ_PHY:
	{
#ifdef PROPRIETARY_PAGE_TABLES
		CR3 guestCr3 = vmm::GetGuestCR3();

		vmm::PREAD_DATA readData = (vmm::PREAD_DATA)paging::vmmhost::MapGuestToHost(
			guestCr3.Flags,
			(PVOID)ulOpt1,
			MAP_TYPE::src);
		if (!readData) {
			DebugBreak();
			ntVmcallStatus = EXIT_ERRORS::ERROR_CANNOT_MAP_PARAM;
			break;
		}

		SIZE_T length = readData->length;
		PVOID pOutBuf = readData->pOutBuf;
		PVOID pTarget = readData->pTarget;

		if (!pOutBuf)
		{
			ntVmcallStatus = EXIT_ERRORS::ERROR_INVALID_PARAM;
			break;
		}

		ntVmcallStatus = paging::vmmhost::ReadPhyMemory(pOutBuf, pTarget, length);
#endif
		break;
	}
	case VMCALL_WRITE_PHY:
	{
#ifdef PROPRIETARY_PAGE_TABLES
		CR3 guestCr3 = vmm::GetGuestCR3();

		vmm::PWRITE_DATA readData = (vmm::PWRITE_DATA)paging::vmmhost::MapGuestToHost(
			guestCr3.Flags,
			(PVOID)ulOpt1,
			MAP_TYPE::src);
		if (!readData) {
			DebugBreak();
			ntVmcallStatus = EXIT_ERRORS::ERROR_CANNOT_MAP_PARAM;
			break;
		}

		SIZE_T length = readData->length;
		PVOID pInBuf = readData->pInBuf;
		PVOID pTarget = readData->pTarget;

		if (!pInBuf)
		{
			ntVmcallStatus = EXIT_ERRORS::ERROR_INVALID_PARAM;
			break;
		}

		ntVmcallStatus = paging::vmmhost::WritePhyMemory(pTarget, pInBuf, length);
#endif
		break;
	}
	case VMCALL_VIRT_TO_PHY: 
	{
		CR3 guestCr3 = vmm::GetGuestCR3();

		vmm::PTRANSLATION_DATA translationData = (vmm::PTRANSLATION_DATA)paging::vmmhost::MapGuestToHost(
			guestCr3.Flags,
			(PVOID)ulOpt1,
			MAP_TYPE::src);
		if (!translationData) {
			DebugBreak();
			ntVmcallStatus = EXIT_ERRORS::ERROR_CANNOT_MAP_PARAM;
			break;
		}

		translationData->pa = (DWORD64)paging::vmmhost::GuestVirtToPhy(translationData->va, (PVOID)(guestCr3.AddressOfPageDirectory * PAGE_SIZE));

		ntVmcallStatus = translationData->pa ? EXIT_ERRORS::ERROR_SUCCESS : EXIT_ERRORS::ERROR_CANNOT_MAP_DST;

		break;
	}
	default:
	{
		fnVmcallCallback pCallback = FindHandler(ulCallNum);
		if (!pCallback) {
			ntVmcallStatus = STATUS_UNSUCCESSFUL;
		}
		else {
			ntVmcallStatus = pCallback(ulOpt1, ulOpt2, ulOpt3);
		}
		break;
	}
	}
	return ntVmcallStatus;
}

ULONG64 vmcall::GetLastGuestCr3()
{
	return lastCr3;
}
