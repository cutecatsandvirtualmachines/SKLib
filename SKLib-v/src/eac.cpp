#include "eac.h"
#include <VMMDef.h>
#include <identity.h>

vector<eac::CR3_TRACKING>* pCr3s = nullptr;
vector<eac::CR3_TRACKING>* pNmiBlockedCr3s = nullptr;

bool bEacInitialized = false;

void eac::Init()
{
	if (bEacInitialized) {
		DbgMsg("[EAC] Already initialized!");
		return;
	}

	pCr3s = (vector<CR3_TRACKING>*)cpp::kMalloc(sizeof(*pCr3s), PAGE_READWRITE);
	RtlZeroMemory(pCr3s, sizeof(*pCr3s));
	pCr3s->Init();
	pCr3s->DisableLock();
	pCr3s->reserve(64);

	pNmiBlockedCr3s = (vector<CR3_TRACKING>*)cpp::kMalloc(sizeof(*pNmiBlockedCr3s), PAGE_READWRITE);
	RtlZeroMemory(pNmiBlockedCr3s, sizeof(*pNmiBlockedCr3s));
	pNmiBlockedCr3s->Init();
	pNmiBlockedCr3s->DisableLock();
	pNmiBlockedCr3s->reserve(64);

	bEacInitialized = true;
}

void eac::UpdateCr3(CR3 cr3)
{
	if (!bEacInitialized)
		return;

	identity::PhysicalAccess pa(vmm::pIdentityMap, cr3.Flags);
	for (auto& data : *pCr3s) {
		if (data.pCr3
			//&& paging::vmmhost::MapGuestToHost(cr3.Flags, (PVOID)((DWORD64)data.pImageBase + PAGE_SIZE))
			&& pa.getPhysicalAddress((DWORD64)data.pImageBase + PAGE_SIZE)
			) {
			identity::PhysicalAccess paSrc(vmm::pIdentityMap, data.srcCr3);
			paSrc.Write<CR3>(data.pCr3, cr3);
		}
	}
}

void eac::TrackCr3(DWORD64* pCr3, PVOID pAddressToCheck, DWORD64 srcCr3)
{
	if (!bEacInitialized
		|| !pCr3
		|| !srcCr3
		)
		return;

	pCr3s->emplace_back(pAddressToCheck, pCr3, srcCr3);
}

void eac::UntrackCr3(DWORD64* pCr3)
{
	bool bFound = false;
	int i = 0;
	for (auto& cr3 : *pCr3s) {
		if (cr3.pCr3 == pCr3) {
			bFound = true;
			break;
		}
		i++;
	}
	if (bFound)
		pCr3s->RemoveAt(i);
}

void eac::BlockNmi(CR3 cr3)
{
	if (!bEacInitialized
		|| !cr3.Flags
		)
		return;

	CR3_TRACKING tracking;
	tracking.srcCr3 = cr3.Flags;

	bool bFound = false;
	int i = 0;
	for (auto& tracked : *pNmiBlockedCr3s) {
		if (tracked.srcCr3 == cr3.Flags) {
			bFound = true;
			break;
		}
		i++;
	}
	if (bFound)
		return;

	pNmiBlockedCr3s->Append(tracking);
}

void eac::UnblockNmi(CR3 cr3)
{
	bool bFound = false;
	int i = 0;
	for (auto& tracked : *pNmiBlockedCr3s) {
		if (tracked.srcCr3 == cr3.Flags) {
			bFound = true;
			break;
		}
		i++;
	}
	if (bFound)
		pNmiBlockedCr3s->RemoveAt(i);
}

bool eac::IsNmiBlocked(CR3 cr3)
{
	bool bFound = false;
	int i = 0;
	for (auto& tracked : *pNmiBlockedCr3s) {
		if (tracked.srcCr3 == cr3.Flags) {
			bFound = true;
			break;
		}
		i++;
	}
	return bFound;
}

int eac::GetAndDecreaseNmiCount(CR3 cr3)
{
	bool bFound = false;
	int i = 0;
	for (auto& tracked : *pNmiBlockedCr3s) {
		if (tracked.srcCr3 == cr3.Flags) {
			bFound = true;
			break;
		}
		i++;
	}
	if (!bFound)
		return 0;

	auto dwCore = CPU::GetCPUIndex(true);

	auto& count = pNmiBlockedCr3s->at(i).dwNmiQueue[dwCore];

	if (count)
		count -= 1;

	return count;
}

void eac::IncreaseNmiCount(CR3 cr3)
{
	bool bFound = false;
	int i = 0;
	for (auto& tracked : *pNmiBlockedCr3s) {
		if (tracked.srcCr3 == cr3.Flags) {
			bFound = true;
			break;
		}
		i++;
	}
	if (!bFound)
		return;
	auto dwCore = CPU::GetCPUIndex(true);

	auto& count = pNmiBlockedCr3s->at(i).dwNmiQueue[dwCore];

	if(!count)
		count += 1;
}
