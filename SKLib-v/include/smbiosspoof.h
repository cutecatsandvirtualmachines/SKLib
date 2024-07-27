#pragma once

#include "ioctlhook.h"
#include "smbios.h"

namespace smbios {
	bool Spoof(DWORD64 seed = TEST_SEED);
}