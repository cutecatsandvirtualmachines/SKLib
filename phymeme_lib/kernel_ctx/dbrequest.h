#pragma once
#include <Windows.h>

typedef enum _DB_CODE : ULONG64 {
	DB_NULL = 0,
	DB_MAP = 0xdeada55,
	DB_ALLOCATE,
	DB_REGISTER_CALLBACK,
	DB_TEST,
	DB_STOP
} DB_CODE, * PDB_CODE;

#pragma pack(push, 1)
typedef union _DB_INFO {
	struct {
		SIZE_T sz;
		DWORD64 pa;
		PVOID* pOut;
		NTSTATUS* pNtStatus;
	} map;
	struct {
		SIZE_T sz;
		PVOID* pOut;
	} allocate;
} DB_INFO, * PDB_INFO;

typedef struct _COMMS_INFO {
	DB_CODE code;
	DWORD64 cr3;
	PDB_INFO pDbInfo;
} COMMS_INFO, * PCOMMS_INFO;
#pragma pack(pop)

namespace db {
	extern "C" DWORD64 DbRequest(DWORD64 code, PDB_INFO pDbInfo);
	PVOID AllocatePool(SIZE_T size);
}