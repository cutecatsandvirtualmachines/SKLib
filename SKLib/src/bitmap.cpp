#include "bitmap.h"

DWORD64 Power2(DWORD64 pw) {
	return 1ull << pw;
}

void bitmap::SetBit(PVOID va, DWORD32 bit, BOOLEAN bSet)
{
	DWORD32 byte = bit / 8;
	bit %= 8;

	if (bSet) {
		((PUCHAR)va)[byte] |= Power2(bit);
	}
	else {
		((PUCHAR)va)[byte] &= ~Power2(bit);
	}
}

BOOLEAN bitmap::GetBit(PVOID va, DWORD32 bit)
{
	UCHAR byte = ((PUCHAR)va)[bit / 8];
	bit %= 8;

	return byte & Power2(bit);
}
