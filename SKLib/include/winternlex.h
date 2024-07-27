#pragma once

#include "cpp.h"
#include "cpu.h"
#include "sharedpool.h"
#include "registry.h"
#include "signatures.h"

#ifdef _KERNEL_MODE

#define 	MM_WORKING_SET_MAX_HARD_ENABLE		0x1
#define 	MM_WORKING_SET_MAX_HARD_DISABLE		0x2
#define 	MM_WORKING_SET_MIN_HARD_ENABLE		0x4
#define 	MM_WORKING_SET_MIN_HARD_DISABLE		0x8

#define DEFINE_SKLIB_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
        constexpr GUID name \
                = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }

/*
 * MessageBox() Flags
 */
#define MB_OK                       0x00000000L
#define MB_OKCANCEL                 0x00000001L
#define MB_ABORTRETRYIGNORE         0x00000002L
#define MB_YESNOCANCEL              0x00000003L
#define MB_YESNO                    0x00000004L
#define MB_RETRYCANCEL              0x00000005L
#if(WINVER >= 0x0500)
#define MB_CANCELTRYCONTINUE        0x00000006L
#endif /* WINVER >= 0x0500 */


#define MB_ICONHAND                 0x00000010L
#define MB_ICONQUESTION             0x00000020L
#define MB_ICONEXCLAMATION          0x00000030L
#define MB_ICONASTERISK             0x00000040L

#if(WINVER >= 0x0400)
#define MB_USERICON                 0x00000080L
#define MB_ICONWARNING              MB_ICONEXCLAMATION
#define MB_ICONERROR                MB_ICONHAND
#endif /* WINVER >= 0x0400 */

#define MB_ICONINFORMATION          MB_ICONASTERISK
#define MB_ICONSTOP                 MB_ICONHAND

#define MB_DEFBUTTON1               0x00000000L
#define MB_DEFBUTTON2               0x00000100L
#define MB_DEFBUTTON3               0x00000200L
#if(WINVER >= 0x0400)
#define MB_DEFBUTTON4               0x00000300L
#endif /* WINVER >= 0x0400 */

#define MB_APPLMODAL                0x00000000L
#define MB_SYSTEMMODAL              0x00001000L
#define MB_TASKMODAL                0x00002000L
#if(WINVER >= 0x0400)
#define MB_HELP                     0x00004000L // Help Button
#endif /* WINVER >= 0x0400 */

#define MB_NOFOCUS                  0x00008000L
#define MB_SETFOREGROUND            0x00010000L
#define MB_DEFAULT_DESKTOP_ONLY     0x00020000L

#if(WINVER >= 0x0400)
#define MB_TOPMOST                  0x00040000L
#define MB_RIGHT                    0x00080000L
#define MB_RTLREADING               0x00100000L

#endif /* WINVER >= 0x0400 */

#ifdef _WIN32_WINNT
#if (_WIN32_WINNT >= 0x0400)
#define MB_SERVICE_NOTIFICATION          0x00200000L
#else
#define MB_SERVICE_NOTIFICATION          0x00040000L
#endif
#define MB_SERVICE_NOTIFICATION_NT3X     0x00040000L
#endif

#define MB_TYPEMASK                 0x0000000FL
#define MB_ICONMASK                 0x000000F0L
#define MB_DEFMASK                  0x00000F00L
#define MB_MODEMASK                 0x00003000L
#define MB_MISCMASK                 0x0000C000L

 // bitmask values for CodeIntegrityOptions
#define CODEINTEGRITY_OPTION_ENABLED                        0x01
#define CODEINTEGRITY_OPTION_TESTSIGN                       0x02
#define CODEINTEGRITY_OPTION_UMCI_ENABLED                   0x04
#define CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED         0x08
#define CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED    0x10
#define CODEINTEGRITY_OPTION_TEST_BUILD                     0x20
#define CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD            0x40
#define CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED              0x80
#define CODEINTEGRITY_OPTION_FLIGHT_BUILD                   0x100
#define CODEINTEGRITY_OPTION_FLIGHTING_ENABLED              0x200
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED              0x400
#define CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED    0x800
#define CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED   0x1000
#define CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED               0x2000

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemInformationClassMin = 0,
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemNotImplemented1 = 4,
	SystemProcessInformation = 5,
	SystemProcessesAndThreadsInformation = 5,
	SystemCallCountInfoInformation = 6,
	SystemCallCounts = 6,
	SystemDeviceInformation = 7,
	SystemConfigurationInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemProcessorTimes = 8,
	SystemFlagsInformation = 9,
	SystemGlobalFlag = 9,
	SystemCallTimeInformation = 10,
	SystemNotImplemented2 = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemLockInformation = 12,
	SystemStackTraceInformation = 13,
	SystemNotImplemented3 = 13,
	SystemPagedPoolInformation = 14,
	SystemNotImplemented4 = 14,
	SystemNonPagedPoolInformation = 15,
	SystemNotImplemented5 = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemPagefileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemInstructionEmulationCounts = 19,
	SystemVdmBopInformation = 20,
	SystemInvalidInfoClass1 = 20,
	SystemFileCacheInformation = 21,
	SystemCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemProcessorStatistics = 23,
	SystemDpcBehaviourInformation = 24,
	SystemDpcInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemNotImplemented6 = 25,
	SystemLoadImage = 26,
	SystemUnloadImage = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemTimeAdjustment = 28,
	SystemSummaryMemoryInformation = 29,
	SystemNotImplemented7 = 29,
	SystemNextEventIdInformation = 30,
	SystemNotImplemented8 = 30,
	SystemEventIdsInformation = 31,
	SystemNotImplemented9 = 31,
	SystemCrashDumpInformation = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemLoadAndCallImage = 38,
	SystemPrioritySeparation = 39,
	SystemPlugPlayBusInformation = 40,
	SystemNotImplemented10 = 40,
	SystemDockInformation = 41,
	SystemNotImplemented11 = 41,
	/* SystemPowerInformation = 42, Conflicts with POWER_INFORMATION_LEVEL 1 */
	SystemInvalidInfoClass2 = 42,
	SystemProcessorSpeedInformation = 43,
	SystemInvalidInfoClass3 = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemSetTimeSlipEvent = 46,
	SystemCreateSession = 47,
	SystemDeleteSession = 48,
	SystemInvalidInfoClass4 = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemAddVerifier = 52,
	SystemSessionProcessesInformation = 53,
	SystemCodeIntegrityInformation = 103,
	SystemPolicyInformation = 134,
	SystemCodeIntegrityCertificateInformation = 0xB7,
	SystemInformationClassMax
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
{
	HANDLE ImageFile;
	ULONG Type;
} SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION, * PSYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY     LoadOrder;
	LIST_ENTRY     MemoryOrder;
	LIST_ENTRY     InitializationOrder;
	PVOID          ModuleBaseAddress;
	PVOID          Entry;
	ULONG          ModuleSize;
	UNICODE_STRING FullModuleName;
	UNICODE_STRING ModuleName;
	ULONG          Flags;
	USHORT         LoadCount;
	USHORT         TlsIndex;
	union {
		LIST_ENTRY Hash;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	ULONG   TimeStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS_SKLIB {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS_SKLIB, * PRTL_USER_PROCESS_PARAMETERS_SKLIB;

typedef struct _PEB_SKLIB {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PLDR_DATA_TABLE_ENTRY Ldr;
	PRTL_USER_PROCESS_PARAMETERS_SKLIB ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB_SKLIB, * PPEB_SKLIB;

typedef struct _HASH_BUCKET_ENTRY
{
	struct _HASH_BUCKET_ENTRY* Next;
	UNICODE_STRING DriverName;
	ULONG CertHash[5];
} HASH_BUCKET_ENTRY, * PHASH_BUCKET_ENTRY;

typedef struct _PIDDB_CACHE_ENTRY
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[16]; // data from the shim engine, or uninitialized memory for custom drivers
} PIDDB_CACHE_ENTRY, * PPIDDB_CACHE_ENTRY;

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PWCHAR Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PROCESS_AFFINITY {
	ULONG procAffinity;
	ULONG threadAffinity;
} PROCESS_AFFINITY, * PPROCESS_AFFINITY;

typedef enum _PNP_DEVNODE_STATE
{
	DeviceNodeUnspecified = 0x300,
	DeviceNodeUninitialized = 0x301,
	DeviceNodeInitialized = 0x302,
	DeviceNodeDriversAdded = 0x303,
	DeviceNodeResourcesAssigned = 0x304,
	DeviceNodeStartPending = 0x305,
	DeviceNodeStartCompletion = 0x306,
	DeviceNodeStartPostWork = 0x307,
	DeviceNodeStarted = 0x308,
	DeviceNodeQueryStopped = 0x309,
	DeviceNodeStopped = 0x30a,
	DeviceNodeRestartCompletion = 0x30b,
	DeviceNodeEnumeratePending = 0x30c,
	DeviceNodeEnumerateCompletion = 0x30d,
	DeviceNodeAwaitingQueuedDeletion = 0x30e,
	DeviceNodeAwaitingQueuedRemoval = 0x30f,
	DeviceNodeQueryRemoved = 0x310,
	DeviceNodeRemovePendingCloses = 0x311,
	DeviceNodeRemoved = 0x312,
	DeviceNodeDeletePendingCloses = 0x313,
	DeviceNodeDeleted = 0x314,
	MaxDeviceNodeState = 0x315,
} PNP_DEVNODE_STATE;

typedef struct _DEVICE_NODE
{
	struct _DEVICE_NODE* Parent;
	struct _DEVICE_NODE* PrevSibling;
	struct _DEVICE_NODE* NextSibling;
	struct _DEVICE_NODE* Child;
	ULONG Level;
	struct _PO_DEVICE_NOTIFY* Notify;
	PNP_DEVNODE_STATE State;
	PNP_DEVNODE_STATE PreviousState;
	PNP_DEVNODE_STATE StateHistory[20];
	ULONG StateHistoryEntry;
	INT CompletionStatus;
	PIRP PendingIrp;
	ULONG Flags;
	ULONG UserFlags;
	ULONG Problem;
	PDEVICE_OBJECT PhysicalDeviceObject;
	PCM_RESOURCE_LIST ResourceList;
	PCM_RESOURCE_LIST ResourceListTranslated;
	UNICODE_STRING InstancePath;
	UNICODE_STRING ServiceName;
	PDEVICE_OBJECT DuplicatePDO;
	PIO_RESOURCE_REQUIREMENTS_LIST ResourceRequirements;
	INTERFACE_TYPE InterfaceType;
	ULONG BusNumber;
	INTERFACE_TYPE ChildInterfaceType;
	ULONG ChildBusNumber;
	USHORT ChildBusTypeIndex;
	UCHAR RemovalPolicy;
	UCHAR HardwareRemovalPolicy;
	LIST_ENTRY TargetDeviceNotify;
	LIST_ENTRY DeviceArbiterList;
	LIST_ENTRY DeviceTranslatorList;
	USHORT NoTranslatorMask;
	USHORT QueryTranslatorMask;
	USHORT NoArbiterMask;
	USHORT QueryArbiterMask;
	union
	{
		struct _DEVICE_NODE* LegacyDeviceNode;
		PDEVICE_RELATIONS PendingDeviceRelations;
	} OverUsed1;
	union
	{
		struct _DEVICE_NODE* NextResourceDeviceNode;
	} OverUsed2;
	PCM_RESOURCE_LIST BootResources;
	ULONG CapabilityFlags;
	struct
	{
		ULONG DockStatus;
		LIST_ENTRY ListEntry;
		WCHAR* SerialNumber;
	} DockInfo;
	ULONG DisableableDepends;
	LIST_ENTRY PendedSetInterfaceState;
	LIST_ENTRY LegacyBusListEntry;
	ULONG DriverUnloadRetryCount;
	struct _DEVICE_NODE* PreviousParent;
	ULONG DeletedChidren;
} DEVICE_NODE, * PDEVICE_NODE;

typedef struct _DEVICE_MEMORY_RANGE {
	DWORD64 low;
	DWORD64 high;

	__forceinline bool operator==(_DEVICE_MEMORY_RANGE& rhs) {
		return memcmp(this, &rhs, sizeof(*this));
	}
	__forceinline bool operator!=(_DEVICE_MEMORY_RANGE& rhs) {
		return !(*this == rhs);
	}
} DEVICE_MEMORY_RANGE, * PDEVICE_MEMORY_RANGE;

typedef struct _DEVICE_MEMORY_RANGES {
	ULONG count;
	DEVICE_MEMORY_RANGE ranges[1];
} DEVICE_MEMORY_RANGES, * PDEVICE_MEMORY_RANGES;

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
	ULONG   Length;
	ULONG   CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;

typedef NTSTATUS(*fnZwQueryInformationProcess) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);

typedef NTSTATUS(*fnZwSetInformationProcess) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength
	);

#define CurrentProcess() PsGetThreadProcess(PsGetCurrentThread())
#define PsProcessDirBase(Process) (*(DWORD64*)((DWORD64)Process + 0x28))
#define PsProcessMitigationFlags1(Process) (*(DWORD32*)((DWORD64)Process + 0x09D0))
#define PsProcessMitigationFlags2(Process) (*(DWORD32*)((DWORD64)Process + 0x09D4))
#define PsProcessMitigationFlagsComplete(Process) (*(DWORD64*)((DWORD64)Process + 0x09D0))
#define LockPage(page) (winternl::LockMemory((PVOID)page, PAGE_SIZE) && MmLockPagableCodeSection((PVOID)page))

namespace winternl {
	extern PVOID pDriverBase;
	extern size_t szDriver;
	extern DWORD64 ntoskrnlSize;
	extern PVOID ntoskrnlBase;
	extern PVOID pExtraBuffer;
	extern fnZwQueryInformationProcess ZwQueryInformationProcess;
	extern fnZwSetInformationProcess ZwSetInformationProcess;

	constexpr auto SystemModuleInformation = 11;
	constexpr auto SystemHandleInformation = 16;
	constexpr auto SystemExtendedHandleInformation = 64;

	NTSTATUS PsLookupProcessByProcessName(CHAR* ProcessName, PEPROCESS* Process);
	NTSTATUS PsLookupProcessByProcessId(HANDLE pid, PEPROCESS* Process);
	string GetImageNameByProcess(PEPROCESS pEprocess);
	string GetImageNameByHandle(HANDLE hProc);
	string GetImageNameByAddress(PVOID pAddress);
	PVOID PsGetThreadStackBase(PETHREAD pEthread);

	void InitImageInfo(PVOID pImageBase);
	void FixSectionPermissions();
	void* GetNtoskrnlBaseAddress();

	bool ClearPIDDBCacheTable(string driverName, DWORD32 timestamp);
	bool ClearKernelHashBucketList(string driverName);
	bool ClearMmUnloadedDrivers(HANDLE hDevice);
	bool LockMemory(PVOID pBase, SIZE_T sz);

	NTSTATUS KeMessageBox(PCWSTR title, PCWSTR text, ULONG_PTR type);

	vector<DEVICE_MEMORY_RANGE> GetDeviceRanges(PDEVICE_OBJECT pDevice);

	__forceinline bool IsNtoskrnlAddress(DWORD64 pAddress) {
		DWORD64 max = (DWORD64)winternl::ntoskrnlBase + winternl::ntoskrnlSize;
		DWORD64 min = (DWORD64)winternl::ntoskrnlBase;
		return (pAddress < max) && (pAddress >= min);
	}
	__forceinline bool IsNtdllAddress(DWORD64 pAddress) {
		return 0;
	}
	__forceinline bool IsSystemAddress(DWORD64 pAddress) {
		return IsNtoskrnlAddress(pAddress);
	}
	__forceinline bool IsDriverAddress(DWORD64 pAddress) {
		return pAddress >= (DWORD64)winternl::pDriverBase
			&& pAddress < ((DWORD64)winternl::pDriverBase + winternl::szDriver);
	}

	__forceinline PKTHREAD KeGetCurrentThread() {
		return (PKTHREAD)__readgsqword(0x188);
	}

	typedef
		NTSTATUS
		(*PROCESS_ENUM_ROUTINE)(
			IN PEPROCESS Process,
			IN PVOID Context
			);

	typedef NTSTATUS
	(*fnPsEnumProcesses)(
		IN PROCESS_ENUM_ROUTINE CallBack,
		IN PVOID Context
		);

	typedef NTSTATUS
	(*fnMmQueryWorkingSetInformation)(
		IN PSIZE_T PeakWorkingSetSize,
		IN PSIZE_T WorkingSetSize,
		IN PSIZE_T MinimumWorkingSetSize,
		IN PSIZE_T MaximumWorkingSetSize,
		IN PULONG HardEnforcementFlags
		);

	typedef NTSTATUS
	(*fnMmAdjustWorkingSetSizeEx)(
		IN SIZE_T WorkingSetMinimumInBytes,
		IN SIZE_T WorkingSetMaximumInBytes,
		IN ULONG SystemCache,
		IN BOOLEAN IncreaseOkay,
		IN ULONG Flags,
		OUT PBOOLEAN IncreaseRequested
		);

	typedef NTSTATUS
	(*fnPspSetQuotaLimits)(
		IN HANDLE ProcessHandle,
		IN PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		IN KPROCESSOR_MODE PreviousMode
		);

	typedef PCHAR(*fnGetProcessImageFileName) (
		PEPROCESS Process
		);

	typedef
		NTSTATUS
		(*THREAD_ENUM_ROUTINE)(
			IN PEPROCESS Process,
			IN PETHREAD Thread,
			IN PVOID Context
			);

	typedef NTSTATUS
	(*fnPsEnumProcessThreads)(
		IN PEPROCESS Process,
		IN THREAD_ENUM_ROUTINE CallBack,
		IN PVOID Context
		);

	typedef NTSTATUS
	(*fnPspTerminateProcess)(
		IN PEPROCESS Process,
		IN PETHREAD CurrentThread,
		IN DWORD ExitCode,
		IN DWORD SomeFlags
		);

	typedef PVOID
	(*fnPsGetProcessSectionBaseAddress)(
		__in PEPROCESS Process
		);

	typedef NTSTATUS
	(*fnPspCreateProcess)(OUT PHANDLE ProcessHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
		IN HANDLE ParentProcess OPTIONAL,
		IN ULONG Flags,
		IN HANDLE SectionHandle OPTIONAL,
		IN HANDLE DebugPort OPTIONAL,
		IN HANDLE ExceptionPort OPTIONAL,
		IN BOOLEAN InJob
		);

	typedef NTSTATUS
	(*fnNtCreateUserProcess)(
		_Out_ PHANDLE ProcessHandle,
		_Out_ PHANDLE ThreadHandle,
		_In_ ACCESS_MASK ProcessDesiredAccess,
		_In_ ACCESS_MASK ThreadDesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
		_In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
		_In_ ULONG ProcessFlags,
		_In_ ULONG ThreadFlags,
		_In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
		_Inout_ PVOID CreateInfo,
		_In_ PVOID AttributeList
		);

	typedef NTSTATUS
	(*fnPspInsertProcess)(
		PEPROCESS pEprocess,
		PEPROCESS pEprocessOwner,
		DWORD64 unknown,
		DWORD64 unknown1,
		DWORD64 exceptionPort,
		DWORD64 someFlags,
		DWORD64 isZero,
		DWORD64 someParamPtr
		);

	typedef NTSTATUS
	(*fnPspInsertThread)(
		PETHREAD pEthread,
		PEPROCESS Process,
		DWORD64 a3,
		DWORD64 a4,
		DWORD32 a5,
		DWORD64 a6,
		DWORD64 a7,
		DWORD64 a8,
		DWORD64 a9,
		DWORD64 a10,
		DWORD64 pStartRoutine
		);

	typedef BOOLEAN
	(*fnMmCreateProcessAddressSpace)(
		DWORD64 a1,
		DWORD64 a2,
		DWORD64 a3,
		DWORD32 a4,
		DWORD32 a5,
		DWORD64 pEprocess
		);

	typedef NTSTATUS(*fnPspCreateProcess)(OUT PHANDLE ProcessHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
		IN HANDLE ParentProcess OPTIONAL,
		IN ULONG Flags,
		IN HANDLE SectionHandle OPTIONAL,
		IN HANDLE DebugPort OPTIONAL,
		IN HANDLE ExceptionPort OPTIONAL,
		IN BOOLEAN InJob);

	typedef NTSTATUS
	(*fnNtResumeThread)(
		HANDLE hThread,
		PDWORD SuspendCount
		);

	typedef LONG
	(*fnKeResumeThread)(
		PKTHREAD pThread,
		DWORD64 win11Param
		);

	typedef NTSTATUS
	(*fnNtLockVirtualMemory)(
		_In_ HANDLE ProcessHandle,
		_Inout_ PVOID* BaseAddress,
		_Inout_ PSIZE_T RegionSize,
		_In_ ULONG MapType
		);

	typedef PVOID
	(*fnPsGetThreadTeb)(
		__in PETHREAD Thread
		);

	typedef NTSTATUS
	(NTAPI* fnNtCreateThreadEx)(
		OUT PHANDLE ThreadHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
		IN HANDLE ProcessHandle,
		IN PVOID StartRoutine,
		IN PVOID Argument OPTIONAL,
		IN ULONG CreateFlags,
		IN SIZE_T ZeroBits OPTIONAL,
		IN SIZE_T StackSize OPTIONAL,
		IN SIZE_T MaximumStackSize OPTIONAL,
		IN PVOID AttributeList OPTIONAL
		);

	typedef NTSTATUS
	(*fnPspCreateThread)(
		PHANDLE pOutThreadHandle,
		ACCESS_MASK a2,
		POBJECT_ATTRIBUTES a3,
		HANDLE a4,
		PEPROCESS a5,
		PCLIENT_ID a6,
		PCONTEXT a7,
		__int64 a8,
		__int64 a9,
		unsigned int a10,
		__int64 a11,
		__int64 a12,
		__int64 a13
		);

	typedef NTSTATUS
	(*fnPspRundownSingleProcess)(
		PEPROCESS pEprocess,
		DWORD64 Flags
		);

	typedef NTSTATUS
	(*fnPspGetContextThreadInternal)(
		PETHREAD pEthread,
		PCONTEXT pOutCtx,
		MODE a3,
		MODE a4,
		MODE a5
		);

	typedef NTSTATUS
	(*fnObpReferenceObjectByHandleWithTag) (
		_In_ HANDLE Handle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_TYPE ObjectType,
		_In_ KPROCESSOR_MODE AccessMode,
		_In_ ULONG Tag,
		_Out_ PVOID* Object,
		_Out_opt_ POBJECT_HANDLE_INFORMATION HandleInformation,
		_In_ ULONG64 a8
		);

	typedef NTSTATUS
	(*fnPsOpenProcess) (
		HANDLE* hProc,
		DWORD32 DesiredAccess,
		DWORD64 ObjectAttributes,
		CLIENT_ID* ClientId,
		KPROCESSOR_MODE prevMode,
		KPROCESSOR_MODE prevMode_1
		);

	typedef NTSTATUS
	(*fnObOpenObjectByPointer)(
		_In_ PVOID Object,
		_In_ ULONG HandleAttributes,
		_In_opt_ PACCESS_STATE PassedAccessState,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_TYPE ObjectType,
		_In_ KPROCESSOR_MODE AccessMode,
		_Out_ PHANDLE Handle
		);

	typedef NTSTATUS
	(*fnPsQueryFullProcessImageName) (
		PEPROCESS pEprocess,
		UNICODE_STRING* pOutUnicodeStr,
		void* pOutStr,
		unsigned int* maxLen
		);

	typedef enum _BOOT_GRAPHICS_INFO : DWORD64 {
		unk0 = 0,
		unk1,
		unk2,
		UserAllocatedBuffer
	} BOOT_GRAPHICS_INFO, * PBOOT_GRAPHICS_INFO;

	typedef enum _MEMORY_INFORMATION_CLASS {
		MemoryBasicInformation,
		MemoryWorkingSetInformation,
		MemoryMappedFilenameInformation,
		MemoryRegionInformation,
		MemoryWorkingSetExInformation,
		MemorySharedCommitInformation
	} MEMORY_INFORMATION_CLASS;

	typedef NTSTATUS
	(*fnBgpFwQueryBootGraphicsInformation) (
		BOOT_GRAPHICS_INFO infoType,
		PVOID pBuffer
		);

	typedef NTSTATUS 
	(*fnMmQueryVirtualMemory) (
			PVOID ProcessHandle,
			PVOID BaseAddress,
			MEMORY_INFORMATION_CLASS MemoryInformationClass,
			PVOID MemoryInformation,
			UINT64 MemoryInformationLength,
			UINT64* ReturnLength,
			UINT64 Flags
		);

	typedef void
	(*fnKiNmiInterruptStart) (
		
		);

	typedef struct _SYSTEM_HANDLE
	{
		PVOID Object;
		HANDLE UniqueProcessId;
		HANDLE HandleValue;
		DWORD32 GrantedAccess;
		USHORT CreatorBackTraceIndex;
		USHORT ObjectTypeIndex;
		DWORD32 HandleAttributes;
		DWORD32 Reserved;
	} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

	typedef struct _SYSTEM_HANDLE_INFORMATION_EX
	{
		DWORD64 HandleCount;
		DWORD64 Reserved;
		SYSTEM_HANDLE Handles[1];
	} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

	typedef struct _QUOTA_LIMITS {
		SIZE_T Reserved0;
		SIZE_T Reserved1;
		SIZE_T MinimumWorkingSetSize;
		SIZE_T MaximumWorkingSetSize;
		SIZE_T Reserved2;
		SIZE_T Reserved3;
		SIZE_T Reserved4;
		SIZE_T Reserved5;
		SIZE_T Reserved6;
		SIZE_T Reserved7;
		DWORD Flags;
		DWORD Reserved8;
	} QUOTA_LIMITS, * PQUOTA_LIMITS;

	typedef struct
	{
		BOOLEAN Used20CallingMethod;
		UCHAR SMBiosMajorVersion;
		UCHAR SMBiosMinorVersion;
		UCHAR DMIBiosRevision;
	} SMBIOSVERSIONINFO, * PSMBIOSVERSIONINFO;

	extern fnPsEnumProcesses PsEnumProcesses;
	extern fnMmQueryWorkingSetInformation MmQueryWorkingSetInformation;
	extern fnMmAdjustWorkingSetSizeEx MmAdjustWorkingSetSizeEx;
	extern fnPspSetQuotaLimits PspSetQuotaLimits;
	extern fnGetProcessImageFileName GetProcessImageFileName;
	extern fnPsGetProcessSectionBaseAddress PsGetProcessSectionBaseAddress;
	extern fnPspInsertProcess PspInsertProcess;
	extern fnPspInsertThread PspInsertThread;
	extern fnNtLockVirtualMemory NtLockVirtualMemory;
	extern fnPsEnumProcessThreads PsEnumProcessThreads;
	extern fnPsGetThreadTeb PsGetThreadTeb;
	extern fnPspCreateThread PspCreateThread;
	extern fnPspTerminateProcess PspTerminateProcess;
	extern fnPspRundownSingleProcess PspRundownSingleProcess;
	extern fnPspGetContextThreadInternal PspGetContextThreadInternal;
	extern fnPsQueryFullProcessImageName PsQueryFullProcessImageName;
	extern fnBgpFwQueryBootGraphicsInformation BgpFwQueryBootGraphicsInformation;
	extern fnMmQueryVirtualMemory MmQueryVirtualMemory;
	extern fnKiNmiInterruptStart KiNmiInterruptStart;
	extern PSMBIOSVERSIONINFO WmipSMBiosVersionInfo;
}

typedef PVOID(*fnRtlPcToFileHeader)(
	PVOID PcValue,
	PVOID* BaseOfImage
	);

extern "C" NTSTATUS NTAPI ZwProtectVirtualMemory(
	__in HANDLE ProcessHandle,
	__inout PVOID * BaseAddress,
	__inout PSIZE_T RegionSize,
	__in ULONG NewProtect,
	__out PULONG OldProtect
);

extern "C" NTSTATUS NTAPI NtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

extern "C" PPEB NTAPI PsGetProcessPeb
(
	IN PEPROCESS Process
);

extern "C" NTSTATUS NTAPI ExRaiseHardError(
	NTSTATUS ErrorStatus, ULONG NumberOfParameters,
	ULONG UnicodeStringParameterMask, PULONG_PTR Parameters,
	ULONG ValidResponseOptions, PNTSTATUS Response);

#else
#include <Windows.h>

namespace winternl {
	constexpr auto STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

	constexpr auto SystemModuleInformation = 11;
	constexpr auto SystemHandleInformation = 16;
	constexpr auto SystemExtendedHandleInformation = 64;

	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		USHORT* Buffer;
	} UNICODE_STRING;

	typedef UNICODE_STRING* PUNICODE_STRING;

	typedef NTSTATUS(*NtLoadDriver)(winternl::UNICODE_STRING* DriverServiceName);
	typedef NTSTATUS(*NtUnloadDriver)(winternl::UNICODE_STRING* DriverServiceName);
	typedef NTSTATUS(*RtlAdjustPrivilege)(_In_ DWORD32 Privilege, _In_ BOOLEAN Enable, _In_ BOOLEAN Client, _Out_ PBOOLEAN WasEnabled);

	typedef struct _SYSTEM_HANDLE
	{
		PVOID Object;
		HANDLE UniqueProcessId;
		HANDLE HandleValue;
		DWORD32 GrantedAccess;
		USHORT CreatorBackTraceIndex;
		USHORT ObjectTypeIndex;
		DWORD32 HandleAttributes;
		DWORD32 Reserved;
	} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

	typedef struct _SYSTEM_HANDLE_INFORMATION_EX
	{
		DWORD64 HandleCount;
		DWORD64 Reserved;
		SYSTEM_HANDLE Handles[1];
	} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

	//Thanks to Pvt Comfy for remember to update this https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_pool_type
	typedef enum class _POOL_TYPE {
		NonPagedPool,
		NonPagedPoolExecute = NonPagedPool,
		PagedPool,
		NonPagedPoolMustSucceed = NonPagedPool + 2,
		DontUseThisType,
		NonPagedPoolCacheAligned = NonPagedPool + 4,
		PagedPoolCacheAligned,
		NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
		MaxPoolType,
		NonPagedPoolBase = 0,
		NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
		NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
		NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
		NonPagedPoolSession = 32,
		PagedPoolSession = NonPagedPoolSession + 1,
		NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
		DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
		NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
		PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
		NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
		NonPagedPoolNx = 512,
		NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
		NonPagedPoolSessionNx = NonPagedPoolNx + 32,
	} POOL_TYPE;

	typedef struct _RTL_PROCESS_MODULE_INFORMATION
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		DWORD32 ImageSize;
		DWORD32 Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES
	{
		DWORD32 NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

	/*added by psec*/
	typedef enum _MEMORY_CACHING_TYPE_ORIG {
		MmFrameBufferCached = 2
	} MEMORY_CACHING_TYPE_ORIG;

	typedef enum _MEMORY_CACHING_TYPE {
		MmNonCached = FALSE,
		MmCached = TRUE,
		MmWriteCombined = MmFrameBufferCached,
		MmHardwareCoherentCached,
		MmNonCachedUnordered,       // IA64
		MmUSWCCached,
		MmMaximumCacheType,
		MmNotMapped = -1
	} MEMORY_CACHING_TYPE;

	typedef CCHAR KPROCESSOR_MODE;

	typedef enum _MODE {
		KernelMode,
		UserMode,
		MaximumMode
	} MODE;

	typedef enum _MM_PAGE_PRIORITY {
		LowPagePriority,
		NormalPagePriority = 16,
		HighPagePriority = 32
	} MM_PAGE_PRIORITY;
}

#endif
