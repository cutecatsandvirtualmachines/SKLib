#include "winternlex.h"

#include "PE.h"
#include <MemoryEx.h>

#define PAGE_ALIGN_2MB(_VAR_) (((DWORD64)_VAR_) & 0xFFFFFFFFFFE00000ULL)

//Driver image info
PVOID  winternl::pDriverBase = nullptr;
size_t winternl::szDriver = 0;
DWORD64 winternl::ntoskrnlSize = 0;
PVOID winternl::ntoskrnlBase = nullptr;
PVOID winternl::pExtraBuffer = nullptr;
fnZwQueryInformationProcess winternl::ZwQueryInformationProcess;
fnZwSetInformationProcess winternl::ZwSetInformationProcess;
winternl::fnPsEnumProcesses winternl::PsEnumProcesses = 0;
winternl::fnPspSetQuotaLimits winternl::PspSetQuotaLimits = 0;
winternl::fnMmQueryWorkingSetInformation winternl::MmQueryWorkingSetInformation = 0;
winternl::fnMmAdjustWorkingSetSizeEx winternl::MmAdjustWorkingSetSizeEx = 0;
winternl::fnGetProcessImageFileName winternl::GetProcessImageFileName = 0;
winternl::fnPsGetProcessSectionBaseAddress winternl::PsGetProcessSectionBaseAddress = 0;
winternl::fnPspInsertProcess winternl::PspInsertProcess = 0;
winternl::fnPspInsertThread winternl::PspInsertThread = 0;
winternl::fnNtLockVirtualMemory winternl::NtLockVirtualMemory = 0;
winternl::fnPsEnumProcessThreads winternl::PsEnumProcessThreads = 0;
winternl::fnPsGetThreadTeb winternl::PsGetThreadTeb = 0;
winternl::fnPspCreateThread winternl::PspCreateThread = 0;
winternl::fnPspTerminateProcess winternl::PspTerminateProcess = 0;
winternl::fnPspRundownSingleProcess winternl::PspRundownSingleProcess = 0;
winternl::fnPspGetContextThreadInternal winternl::PspGetContextThreadInternal = 0;
winternl::fnPsQueryFullProcessImageName winternl::PsQueryFullProcessImageName = 0;
winternl::fnBgpFwQueryBootGraphicsInformation winternl::BgpFwQueryBootGraphicsInformation = 0;
winternl::fnMmQueryVirtualMemory winternl::MmQueryVirtualMemory = 0;
winternl::fnKiNmiInterruptStart winternl::KiNmiInterruptStart = 0;
winternl::PSMBIOSVERSIONINFO winternl::WmipSMBiosVersionInfo = 0;
fnRtlPcToFileHeader RtlPcToFileHeader = 0;

NTSTATUS ProcEnumFindByName(PEPROCESS pEprocess, PVOID pCtx) {
    CHAR* ProcessName = *(CHAR**)pCtx;

    UNICODE_STRING imgName = { 0 };
    unsigned int nameLen = PAGE_SIZE;
    PVOID pName = cpp::kMalloc(nameLen);
    NTSTATUS status = winternl::PsQueryFullProcessImageName(pEprocess, &imgName, pName, &nameLen);
    if (!NT_SUCCESS(status)) {
        DbgMsg("[DRIVER] Failed getting full process image name: 0x%x", status);
        cpp::kFree(pName);
        //Status success so it can continue
        return STATUS_SUCCESS;
    }

    string fullName(&imgName);
    cpp::kFree(pName);

    if (fullName.contains(ProcessName)) {
        *(PEPROCESS*)pCtx = pEprocess;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS ProcEnumFindById(PEPROCESS pEprocess, PVOID pCtx) {
    HANDLE pid = *(HANDLE*)pCtx;
    if (PsGetProcessId(pEprocess) == pid) {
        *(PEPROCESS*)pCtx = pEprocess;
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

NTSTATUS winternl::PsLookupProcessByProcessName(CHAR* ProcessName, PEPROCESS* Process)
{
    if (!MmIsAddressValid(Process))
        return STATUS_INVALID_PARAMETER_2;

    CHAR* ProcessNameOrig = ProcessName;
    winternl::PsEnumProcesses(ProcEnumFindByName, &ProcessName);
    *Process = (PEPROCESS)ProcessName;
    return ProcessNameOrig == ProcessName ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

NTSTATUS winternl::PsLookupProcessByProcessId(HANDLE pid, PEPROCESS* Process)
{
    if (!MmIsAddressValid(Process))
        return STATUS_INVALID_PARAMETER_2;
    HANDLE origPid = pid;
    winternl::PsEnumProcesses(ProcEnumFindById, &pid);
    *Process = (PEPROCESS)pid;
    return origPid == pid ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

string winternl::GetImageNameByHandle(HANDLE hProc) {
    PEPROCESS pEprocess = 0;
    NTSTATUS ntStatus = ObReferenceObjectByHandle(hProc, GENERIC_ALL, *PsProcessType, KernelMode, (PVOID*)&pEprocess, NULL);
    if (!NT_SUCCESS(ntStatus)) {
        DbgMsg("[WINTERNL] Failed getting process object from handle: 0x%x - %p", ntStatus, hProc);
        return "";
    }

    string fullName = GetImageNameByProcess(pEprocess);
    ObDereferenceObject(pEprocess);
    return fullName;
}

string winternl::GetImageNameByAddress(PVOID pAddress)
{
    NTSTATUS status;
    ULONG bufferSize = 0;
    PVOID buffer = NULL;

    // Determine the required buffer size
    status = ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemModuleInformation, buffer, 0, &bufferSize);

    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, NULL);
        if (buffer) {
            status = ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemModuleInformation, buffer, bufferSize, NULL);
            if (NT_SUCCESS(status)) {
                PSYSTEM_MODULE_INFORMATION modules = (PSYSTEM_MODULE_INFORMATION)buffer;

                for (ULONG i = 0; i < modules->ulModuleCount; i++) {
                    SIZE_T sz = modules->Modules[i].Size;
                    DWORD64 end = ((DWORD64)modules->Modules[i].Base + sz);
                    if (cpp::IsInRange(pAddress, (DWORD64)modules->Modules[i].Base, end)) {
                        return modules->Modules[i].ImageName;
                    }
                }
            }
            ExFreePool(buffer);
        }
    }
    return "";
}

string winternl::GetImageNameByProcess(PEPROCESS pEprocess) {
    UNICODE_STRING imgName = { 0 };
    unsigned int nameLen = PAGE_SIZE;
    PVOID pName = cpp::kMalloc(nameLen);
    NTSTATUS status = winternl::PsQueryFullProcessImageName(pEprocess, &imgName, pName, &nameLen);
    if (!NT_SUCCESS(status)) {
        DbgMsg("[DRIVER] Failed getting full process image name: 0x%x", status);
        cpp::kFree(pName);
        //Status success so it can continue
        return "";
    }

    string fullName(&imgName);
    cpp::kFree(pName);

    return fullName;
}

PVOID winternl::PsGetThreadStackBase(PETHREAD pEthread)
{
    return *(PVOID*)((DWORD64)pEthread + 0x38);
}

void* winternl::GetNtoskrnlBaseAddress()
{
    if (ntoskrnlBase)
        return ntoskrnlBase;
    if (!RtlPcToFileHeader)
    {
        string routineName("RtlPcToFileHeader");
        RtlPcToFileHeader = (fnRtlPcToFileHeader)MmGetSystemRoutineAddress(&routineName.unicode());
    }
    PVOID pBaseOfImage = nullptr;
    PVOID pBase = RtlPcToFileHeader(RtlPcToFileHeader, &pBaseOfImage);
    ntoskrnlBase = pBase;

    return pBase;
}

PPIDDB_CACHE_ENTRY LookupEntry(PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t* name) {

    PIDDB_CACHE_ENTRY localentry{};
    localentry.TimeDateStamp = timestamp;
    localentry.DriverName.Buffer = (PWSTR)name;
    localentry.DriverName.Length = (USHORT)(wcslen(name) * 2);
    localentry.DriverName.MaximumLength = localentry.DriverName.Length + 2;

    return (PIDDB_CACHE_ENTRY*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, (PVOID)&localentry);
}

bool winternl::ClearPIDDBCacheTable(string driverName, DWORD32 timestamp)
{
    PVOID PiDDBLock = (PVOID)((DWORD64)ntoskrnlBase + offsets.PiDDBLock);
    PRTL_AVL_TABLE PiDDBCacheTable = (PRTL_AVL_TABLE)((DWORD64)ntoskrnlBase + offsets.PiDDBCacheTable);

    DbgMsg("[CLEANUP] PiDDBLock: %p", PiDDBLock);
    DbgMsg("[CLEANUP] PiDDBCacheTable: %p", PiDDBCacheTable);

    //context part is not used by lookup, lock or delete why we should use it?

    if (!ExAcquireResourceExclusiveLite((PERESOURCE)PiDDBLock, true)) {
        DbgMsg("[CLEANUP] Can't lock PiDDBCacheTable");
        return false;
    }
    DbgMsg("[CLEANUP] PiDDBLock Locked");

    // search our entry in the table
    PPIDDB_CACHE_ENTRY pFoundEntry = (PPIDDB_CACHE_ENTRY)LookupEntry(PiDDBCacheTable, timestamp, driverName.w_str());
    if (pFoundEntry == nullptr) {
        DbgMsg("[CLEANUP] Not found in cache");
        ExReleaseResourceLite((PERESOURCE)PiDDBLock);
        return false;
    }

    // first, unlink from the list
    PLIST_ENTRY prev = pFoundEntry->List.Blink;
    PLIST_ENTRY next = pFoundEntry->List.Flink;

    DbgMsg("[+] Found Table Entry = %p", pFoundEntry);

    prev->Flink = next;
    next->Blink = prev;

    // then delete the element from the avl table
    if (!RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry)) {
        DbgMsg("[CLEANUP] Can't delete from PiDDBCacheTable");
        ExReleaseResourceLite((PERESOURCE)PiDDBLock);
        return false;
    }

    //Decrement delete count
    ULONG cacheDeleteCount = PiDDBCacheTable->DeleteCount;
    if (cacheDeleteCount > 0) {
        cacheDeleteCount--;
        PiDDBCacheTable->DeleteCount = cacheDeleteCount;
    }

    pFoundEntry = (PPIDDB_CACHE_ENTRY)LookupEntry(PiDDBCacheTable, timestamp, driverName.w_str());
    if (pFoundEntry != nullptr) {
        DbgMsg("[CLEANUP] Could not clear PIDDB cache!");
        ExReleaseResourceLite((PERESOURCE)PiDDBLock);
        return false;
    }

    // release the ddb resource lock
    ExReleaseResourceLite((PERESOURCE)PiDDBLock);

    DbgMsg("[CLEANUP] PiDDBCacheTable Cleaned");

    return true;
}

bool winternl::ClearKernelHashBucketList(string driverName)
{
    PVOID ciDll = Memory::GetKernelAddress((PCHAR)"CI.dll");

    if (!ciDll) {
        DbgMsg("[CLEANUP] Can't find CI.dll module address");
        return false;
    }
    const DWORD64 KernelHashBucketList = (DWORD64)ciDll + offsets.g_KernelHashBucketList;
    const DWORD64 HashCacheLock = (DWORD64)ciDll + offsets.g_HashCacheLock;

    if (!KernelHashBucketList || !HashCacheLock)
    {
        DbgMsg("[CLEANUP] Can't find HashCacheLock relative address");
        return false;
    }

    DbgMsg("[CLEANUP] KernelHashBucketList found: 0x%llx", KernelHashBucketList);

    if (!ExAcquireResourceExclusiveLite((PERESOURCE)HashCacheLock, true)) {
        DbgMsg("[CLEANUP] Can't lock HashCacheLock");
    }
    else {
        DbgMsg("[CLEANUP] HashCacheLock locked");
    }

    PHASH_BUCKET_ENTRY prev = (PHASH_BUCKET_ENTRY)KernelHashBucketList;
    PHASH_BUCKET_ENTRY entry = prev->Next;

    if (!entry) {
        DbgMsg("[CLEANUP] KernelHashBucketList looks empty!");
        ExReleaseResourceLite((PERESOURCE)HashCacheLock);
        return true;
    }

    while (entry) {
        string wsName(&entry->DriverName);
        DbgMsg("[CLEANUP] Found in KernelHashBucketList: %ls", wsName.w_str());

        if (wcsstr(wsName.w_str(), driverName.w_str())) {
            PHASH_BUCKET_ENTRY Next = 0;

            Next = entry->Next;
            prev->Next = Next;

            ExFreePool(entry);

            DbgMsg("[CLEANUP] KernelHashBucketList Cleaned");
            break;
        }

        prev = entry;
        //read next
        entry = entry->Next;
    }

    ExReleaseResourceLite((PERESOURCE)HashCacheLock);

    return true;
}

bool winternl::ClearMmUnloadedDrivers(HANDLE hDevice)
{
    ULONG buffer_size = 0;
    void* buffer = nullptr;

    NTSTATUS status = ZwQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);

    while (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        buffer = cpp::kMalloc(buffer_size, PAGE_READWRITE);
        status = ZwQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);
    }

    if (!NT_SUCCESS(status) || buffer == 0)
    {
        if (buffer != 0)
            cpp::kFree(buffer);
        DbgMsg("[CLEANUP] ZwQuerySystemInformation failed: 0x%x", status);
        return false;
    }

    DWORD64 object = 0;

    auto system_handle_inforamtion = static_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buffer);

    for (auto i = 0u; i < system_handle_inforamtion->HandleCount; ++i)
    {
        const SYSTEM_HANDLE current_system_handle = system_handle_inforamtion->Handles[i];

        if (current_system_handle.UniqueProcessId != PsGetCurrentProcessId())
            continue;

        if (current_system_handle.HandleValue == hDevice)
        {
            object = reinterpret_cast<DWORD64>(current_system_handle.Object);
            break;
        }
    }

    cpp::kFree(buffer);

    if (!object)
        return false;

    DWORD64 device_object = *(DWORD64*)(object + 0x8);

    if (!MmIsAddressValid((PVOID)device_object)) {
        DbgMsg("[CLEANUP] Failed to find device_object: 0x%llx", device_object);
        return false;
    }

    DWORD64 driver_object = *(DWORD64*)(device_object + 0x8);

    if (!MmIsAddressValid((PVOID)driver_object)) {
        DbgMsg("[CLEANUP] Failed to find driver_object: 0x%llx", driver_object);
        return false;
    }

    DWORD64 driver_section = *(DWORD64*)(driver_object + 0x28);

    if (!MmIsAddressValid((PVOID)driver_section)) {
        DbgMsg("[CLEANUP] Failed to find driver_section: 0x%llx", driver_section);
        return false;
    }

    UNICODE_STRING us_driver_base_dll_name = *(UNICODE_STRING*)(driver_section + 0x58);

    if (us_driver_base_dll_name.Length == 0) {
        DbgMsg("[CLEANUP] Failed to find driver name");
        return false;
    }

    wchar_t* unloadedName = (wchar_t*)cpp::kMalloc(us_driver_base_dll_name.Length + 2, PAGE_READWRITE);

    RtlCopyMemory(unloadedName, us_driver_base_dll_name.Buffer, us_driver_base_dll_name.Length);

    us_driver_base_dll_name.Length = 0; //MiRememberUnloadedDriver will check if the length > 0 to save the unloaded driver

    *(UNICODE_STRING*)(driver_section + 0x58) = us_driver_base_dll_name;

    DbgMsg("[CLEANUP] MmUnloadedDrivers Cleaned: %ls", unloadedName);

    cpp::kFree(unloadedName);

    return true;
}

bool winternl::LockMemory(PVOID pBase, SIZE_T sz)
{
    NTSTATUS ntStatus = winternl::NtLockVirtualMemory(NtCurrentProcess(), &pBase, &sz, 1);
    return NT_SUCCESS(ntStatus);
}

NTSTATUS winternl::KeMessageBox(PCWSTR title, PCWSTR text, ULONG_PTR type)
{
    UNICODE_STRING uTitle = { 0 };
    UNICODE_STRING uText = { 0 };

    RtlInitUnicodeString(&uTitle, title);
    RtlInitUnicodeString(&uText, text);

    ULONG_PTR args[] = { (ULONG_PTR)&uText, (ULONG_PTR)&uTitle, type };
    NTSTATUS response = 0;

    ExRaiseHardError(STATUS_SERVICE_NOTIFICATION, 3, 3, args, 2, &response);
    return response;
}

vector<DEVICE_MEMORY_RANGE> winternl::GetDeviceRanges(PDEVICE_OBJECT pDevice)
{
    vector<DEVICE_MEMORY_RANGE> ranges = { 0 };
    if (!MmIsAddressValid(pDevice)) {
        return ranges;
    }
    ULONG outLen = 0;
    NTSTATUS ntStatus = IoGetDeviceProperty(pDevice, DevicePropertyBootConfiguration, 0, 0, &outLen);

    PCM_RESOURCE_LIST resList = (PCM_RESOURCE_LIST)cpp::kMallocZero(outLen);
    ntStatus = IoGetDeviceProperty(pDevice, DevicePropertyBootConfiguration, outLen, resList, &outLen);
    if (!NT_SUCCESS(ntStatus)) {
        DbgMsg("[WINTERNL] IoGetDeviceProperty failed: 0x%x", ntStatus);
        return ranges;
    }

    for (ULONG resIdx = 0; resIdx < resList->Count; resIdx++) {
        auto& res = resList->List[resIdx];
        for (ULONG partResIdx = 0; partResIdx < res.PartialResourceList.Count; partResIdx++) {
            auto& partRes = res.PartialResourceList.PartialDescriptors[partResIdx];
            if (partRes.Type != CmResourceTypeMemory)
                continue;

            DEVICE_MEMORY_RANGE range = { 0 };
            range.low = partRes.u.Memory.Start.QuadPart;
            range.high = partRes.u.Memory.Start.QuadPart + partRes.u.Memory.Length;
            ranges.Append(range);
        }
    }
    return ranges;
}

void winternl::InitImageInfo(PVOID pImageBase)
{
    winternl::pDriverBase = pImageBase;
    winternl::szDriver = PE(pImageBase).imageSize();
    winternl::ntoskrnlBase = GetNtoskrnlBaseAddress();
    PE peNtoskrnl(GetNtoskrnlBaseAddress());
    winternl::ntoskrnlSize = peNtoskrnl.imageSize();
    winternl::pExtraBuffer = 0;

    DbgMsg("[WINTERNL] Driver base: %p", pDriverBase);
    DbgMsg("[WINTERNL] Driver size: 0x%llx", szDriver);
    DbgMsg("[WINTERNL] NTOSKRNL base: %p", ntoskrnlBase);

    UNICODE_STRING sPsGetProcessImageFileName = RTL_CONSTANT_STRING(
        L"PsGetProcessImageFileName");
    winternl::GetProcessImageFileName = (winternl::fnGetProcessImageFileName)
        MmGetSystemRoutineAddress(&sPsGetProcessImageFileName);
    if (!winternl::GetProcessImageFileName) {
        DbgMsg("[HOOK] Could not find PsGetProcessImageFileName");
        DebugBreak();
    }
    else {
        DbgMsg("[HOOK] PsGetProcessImageFileName: %p", winternl::GetProcessImageFileName);
    }

    UNICODE_STRING sPsGetProcessSectionBaseAddress = RTL_CONSTANT_STRING(
        L"PsGetProcessSectionBaseAddress");
    winternl::PsGetProcessSectionBaseAddress = (winternl::fnPsGetProcessSectionBaseAddress)
        MmGetSystemRoutineAddress(&sPsGetProcessSectionBaseAddress);
    if (!winternl::PsGetProcessSectionBaseAddress) {
        DbgMsg("[HOOK] Could not find PsGetProcessSectionBaseAddress");
        DebugBreak();
    }
    else {
        DbgMsg("[HOOK] PsGetProcessSectionBaseAddress: %p", winternl::PsGetProcessSectionBaseAddress);
    }

    UNICODE_STRING sZwQueryInformationProcess = RTL_CONSTANT_STRING(
        L"ZwQueryInformationProcess");
    winternl::ZwQueryInformationProcess = (fnZwQueryInformationProcess)
        MmGetSystemRoutineAddress(&sZwQueryInformationProcess);
    if (!winternl::ZwQueryInformationProcess) {
        DbgMsg("[HOOK] Could not find ZwQueryInformationProcess");
        DebugBreak();
    }
    else {
        DbgMsg("[HOOK] ZwQueryInformationProcess: %p", winternl::ZwQueryInformationProcess);
    }

    UNICODE_STRING sPsGetThreadTeb = RTL_CONSTANT_STRING(
        L"PsGetThreadTeb");
    winternl::PsGetThreadTeb = (winternl::fnPsGetThreadTeb)
        MmGetSystemRoutineAddress(&sPsGetThreadTeb);
    if (!winternl::PsGetThreadTeb) {
        DbgMsg("[HOOK] Could not find PsGetThreadTeb");
        DebugBreak();
    }
    else {
        DbgMsg("[HOOK] ZwLockVirtualMemory: %p", winternl::NtLockVirtualMemory);
    }

    winternl::PsEnumProcesses = (fnPsEnumProcesses)((ULONG64)winternl::ntoskrnlBase + offsets.PsEnumProcesses);
    if (!offsets.PsEnumProcesses) {
        DbgMsg("[WINTERNL] Failed getting PsEnumProcesses!");
        DebugBreak();
    }
    winternl::PspSetQuotaLimits = (fnPspSetQuotaLimits)((ULONG64)winternl::ntoskrnlBase + offsets.PspSetQuotaLimits);
    if (!offsets.PspSetQuotaLimits) {
        DbgMsg("[WINTERNL] Failed getting PspSetQuotaLimits!");
        DebugBreak();
    }
    winternl::MmAdjustWorkingSetSizeEx = (fnMmAdjustWorkingSetSizeEx)((ULONG64)winternl::ntoskrnlBase + offsets.MmAdjustWorkingSetSizeEx);
    if (!offsets.MmAdjustWorkingSetSizeEx) {
        DbgMsg("[WINTERNL] Failed getting MmAdjustWorkingSetSizeEx!");
        DebugBreak();
    }
    winternl::MmQueryWorkingSetInformation = (fnMmQueryWorkingSetInformation)((ULONG64)winternl::ntoskrnlBase + offsets.MmQueryWorkingSetInformation);
    if (!offsets.MmQueryWorkingSetInformation) {
        DbgMsg("[WINTERNL] Failed getting MmQueryWorkingSetInformation!");
        DebugBreak();
    }

    winternl::PsEnumProcessThreads = (winternl::fnPsEnumProcessThreads)((DWORD64)winternl::GetNtoskrnlBaseAddress() + offsets.PsEnumProcessThreads);
    if (!offsets.PsEnumProcessThreads) {
        DbgMsg("[WINTERNL] Failed getting PsEnumProcessThreads!");
        DebugBreak();
    }

    winternl::PspInsertProcess = (winternl::fnPspInsertProcess)((DWORD64)winternl::GetNtoskrnlBaseAddress() + offsets.PspInsertProcess);
    if (!offsets.PspInsertProcess) {
        DbgMsg("[WINTERNL] Failed getting PspInsertProcess!");
        DebugBreak();
    }

    winternl::PspInsertThread = (winternl::fnPspInsertThread)((DWORD64)winternl::GetNtoskrnlBaseAddress() + offsets.PspInsertThread);
    if (!offsets.PspInsertThread) {
        DbgMsg("[WINTERNL] Failed getting PspInsertThread!");
        DebugBreak();
    }

    winternl::PspCreateThread = (winternl::fnPspCreateThread)((DWORD64)winternl::GetNtoskrnlBaseAddress() + offsets.PspCreateThread);
    if (!offsets.PspCreateThread) {
        DbgMsg("[WINTERNL] Failed getting PspCreateThread!");
        DebugBreak();
    }

    winternl::PspTerminateProcess = (winternl::fnPspTerminateProcess)((DWORD64)winternl::GetNtoskrnlBaseAddress() + offsets.PspTerminateProcess);
    if (!offsets.PspTerminateProcess) {
        DbgMsg("[WINTERNL] Failed getting PspTerminateProcess!");
        DebugBreak();
    }

    winternl::PspRundownSingleProcess = (winternl::fnPspRundownSingleProcess)((DWORD64)winternl::GetNtoskrnlBaseAddress() + offsets.PspRundownSingleProcess);
    if (!offsets.PspRundownSingleProcess) {
        DbgMsg("[WINTERNL] Failed getting PspRundownSingleProcess!");
        DebugBreak();
    }

    winternl::PspGetContextThreadInternal = (winternl::fnPspGetContextThreadInternal)((DWORD64)winternl::GetNtoskrnlBaseAddress() + offsets.PspGetContextThreadInternal);
    if (!offsets.PspGetContextThreadInternal) {
        DbgMsg("[WINTERNL] Failed getting PspGetContextThreadInternal!");
        DebugBreak();
    }

    winternl::PsQueryFullProcessImageName = (winternl::fnPsQueryFullProcessImageName)((DWORD64)winternl::GetNtoskrnlBaseAddress() + offsets.PsQueryFullProcessImageName);
    if (!offsets.PsQueryFullProcessImageName) {
        DbgMsg("[WINTERNL] Failed getting PsQueryFullProcessImageName!");
        DebugBreak();
    }

    winternl::KiNmiInterruptStart = (winternl::fnKiNmiInterruptStart)((DWORD64)winternl::GetNtoskrnlBaseAddress() + offsets.KiNmiInterruptStart);
    if (!offsets.KiNmiInterruptStart) {
        DbgMsg("[WINTERNL] Failed getting KiNmiInterruptStart!");
        DebugBreak();
    }

    winternl::WmipSMBiosVersionInfo = (winternl::PSMBIOSVERSIONINFO)((DWORD64)winternl::GetNtoskrnlBaseAddress() + offsets.WmipSMBiosVersionInfo);

    winternl::ZwSetInformationProcess = (fnZwSetInformationProcess)((DWORD64)winternl::GetNtoskrnlBaseAddress() + offsets.ZwSetInformationProcess);
    if (!offsets.ZwSetInformationProcess) {
        DbgMsg("[WINTERNL] Failed getting ZwSetInformationProcess!");
        DebugBreak();
    }

    winternl::BgpFwQueryBootGraphicsInformation = (winternl::fnBgpFwQueryBootGraphicsInformation)((DWORD64)winternl::GetNtoskrnlBaseAddress() + offsets.BgpFwQueryBootGraphicsInformation);
    if (!offsets.BgpFwQueryBootGraphicsInformation) {
        DbgMsg("[WINTERNL] Failed getting BgpFwQueryBootGraphicsInformation!");
        DebugBreak();
    }

    winternl::MmQueryVirtualMemory = (winternl::fnMmQueryVirtualMemory)((DWORD64)winternl::GetNtoskrnlBaseAddress() + offsets.MmQueryVirtualMemory);
    if (!offsets.MmQueryVirtualMemory) {
        DbgMsg("[WINTERNL] Failed getting MmQueryVirtualMemory!");
        DebugBreak();
    }
}

void winternl::FixSectionPermissions() {
    PE pe(winternl::pDriverBase);
    for (auto& section : pe.sections()) {
        if (!section.SizeOfRawData)
            continue;

        ULONG protect = section.Characteristics & IMAGE_SCN_MEM_EXECUTE ? PAGE_EXECUTE_READ : PAGE_READWRITE;
        PVOID pBase = (PVOID)((char*)winternl::pDriverBase + section.VirtualAddress);
        cpp::kProtect(pBase, section.SizeOfRawData, protect);
    }
    DbgMsg("[WINTERNL] Adjusted page permissions");
}
