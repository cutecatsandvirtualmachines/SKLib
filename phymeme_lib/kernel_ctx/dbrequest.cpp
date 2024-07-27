#include "dbrequest.h"

PVOID db::AllocatePool(SIZE_T size)
{
	volatile PVOID pOut = 0;
	PDB_INFO pDbInfo = (PDB_INFO)_aligned_malloc(sizeof(*pDbInfo), 0x1000);
	if (!pDbInfo)
		return nullptr;

	pDbInfo->allocate.pOut = (PVOID*)&pOut;
	pDbInfo->allocate.sz = size;

	DbRequest(DB_ALLOCATE, pDbInfo);

	int i = 0;
	while (!pOut) {
		Sleep(1);

		if (i > 1000) {
			return nullptr;
		}
		i++;
	}

	_aligned_free(pDbInfo);
	return pOut;
}
