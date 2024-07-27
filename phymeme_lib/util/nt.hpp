#pragma once
#include <Windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")
constexpr auto page_size = 0x1000;

inline const char piddb_lock_sig[] = "\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24";
inline const char piddb_lock_mask[] = "xxxxxx????xxxxx????xxx????xxxxx????x????xx?x";

inline const char piddb_table_sig[] = "\x66\x03\xD2\x48\x8D\x0D";
inline const char piddb_table_mask[] = "xxxxxx";

inline const char piddb_lock_sig2[] = "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8";
inline const char piddb_lock_mask2[] = "xxx????xxxxx????xxx????x????x";

constexpr auto SystemModuleInformation = 11;
constexpr auto SystemHandleInformation = 16;
constexpr auto SystemExtendedHandleInformation = 64;

#define MM_COPY_MEMORY_PHYSICAL             0x1
#define MM_COPY_MEMORY_VIRTUAL              0x2

typedef struct PiDDBCacheEntry
{
	LIST_ENTRY		list;
	UNICODE_STRING	driver_name;
	ULONG			time_stamp;
	NTSTATUS		load_status;
	char			_0x0028[16]; // data from the shim engine, or uninitialized memory for custom drivers
}PIDCacheobj;

typedef struct _SYSTEM_HANDLE
{
	PVOID Object;
	HANDLE UniqueProcessId;
	HANDLE HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR HandleCount;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef enum _POOL_TYPE {
	NonPagedPool,
	NonPagedPoolExecute,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS,
	MaxPoolType,
	NonPagedPoolBase,
	NonPagedPoolBaseMustSucceed,
	NonPagedPoolBaseCacheAligned,
	NonPagedPoolBaseCacheAlignedMustS,
	NonPagedPoolSession,
	PagedPoolSession,
	NonPagedPoolMustSucceedSession,
	DontUseThisTypeSession,
	NonPagedPoolCacheAlignedSession,
	PagedPoolCacheAlignedSession,
	NonPagedPoolCacheAlignedMustSSession,
	NonPagedPoolNx,
	NonPagedPoolNxCacheAligned,
	NonPagedPoolSessionNx
} POOL_TYPE;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef LARGE_INTEGER PHYSICAL_ADDRESS, * PPHYSICAL_ADDRESS;

typedef struct _MM_COPY_ADDRESS {
	union {
		PVOID            VirtualAddress;
		PHYSICAL_ADDRESS PhysicalAddress;
	};
} MM_COPY_ADDRESS, * PMMCOPY_ADDRESS;

using PEPROCESS = PVOID;
using ExAllocatePool = PVOID(__stdcall*) (POOL_TYPE, SIZE_T);
using ExAllocatePoolWithTag = PVOID(__stdcall*)(POOL_TYPE, SIZE_T, ULONG);
using MmCopyMemory = NTSTATUS (__stdcall*)(PVOID, MM_COPY_ADDRESS,SIZE_T,ULONG,PSIZE_T);
using DRIVER_INITIALIZE = NTSTATUS(__stdcall*)(std::uintptr_t, std::size_t);
using ExAcquireResourceExclusiveLite = BOOLEAN(__stdcall*)(void*,bool);
using RtlLookupElementGenericTableAvl = PIDCacheobj* (__stdcall*) (void*, void*);
using RtlDeleteElementGenericTableAvl = bool(__stdcall*)(void*,void*);
using ExReleaseResourceLite = bool(__stdcall*)(void*);
using PsLookupProcessByProcessId = NTSTATUS(__fastcall*)(HANDLE, PEPROCESS*);
using PsGetProcessSectionBaseAddress = void* (__fastcall*)(PEPROCESS);