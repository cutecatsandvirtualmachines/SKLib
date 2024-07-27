#pragma once

#include "ioctlhook.h"

namespace efi {
	bool Spoof(DWORD64 seed = TEST_SEED);
}

#define VARIABLE_ATTRIBUTE_NON_VOLATILE 1