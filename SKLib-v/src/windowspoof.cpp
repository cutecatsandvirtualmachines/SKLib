#include "windowspoof.h"
#include <data.h>

void window::Hide(int hwnd, char* pTeb)
{
	DWORD64* pClientInfo = (DWORD64*)(pTeb + offsets.ClientInfo);
	pClientInfo[offsets.HwndCache] = (DWORD64)hwnd;
	pClientInfo[offsets.HwndCache + 1] = 0; //tagWND cache
}
