#pragma once

#include "ioctlhook.h"
#include "disassembler.h"

namespace gpu {
	bool Spoof(DWORD64 seed = TEST_SEED);
}

#define NV_MAX_DEVICES 32
#define IOCTL_NVIDIA_SMIL (0x8DE0008)
#define IOCTL_NVIDIA_SMIL_MAX (512)
#define GPU_SERIAL_OFFSET 0x1AC