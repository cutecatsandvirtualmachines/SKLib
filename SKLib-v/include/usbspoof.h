#pragma once

#include "ioctlhook.h"
#include <usbioctl.h>

#ifdef _KERNEL_MODE

namespace usb {
	bool Spoof(DWORD64 seed = TEST_SEED);
}

#endif