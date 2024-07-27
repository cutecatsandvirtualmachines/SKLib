#pragma once

#include "cpp.h"
#include "diskspoof.h"
#include "volumespoof.h"
#include "nicspoof.h"
#include "smbiosspoof.h"
#include "gpuspoof.h"
#include "efispoof.h"
#include "wmispoof.h"
#include "usbspoof.h"

namespace spoofer {
	NTSTATUS SpoofAll(DWORD64 seed = TEST_SEED);

	extern DWORD64 seed;
}
