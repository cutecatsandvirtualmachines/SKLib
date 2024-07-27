#include "xor.h"

void encryption::xorBytes(PVOID pBase, SIZE_T sz, SIZE_T key)
{
	if (sz % 8) {
		for (SIZE_T i = 0; i < sz; i++) {
			*(char*)pBase ^= key;
		}
	}
	else {
		for (SIZE_T i = 0; i < sz; i += 8) {
			*(DWORD64*)pBase ^= key;
		}
	}
}
