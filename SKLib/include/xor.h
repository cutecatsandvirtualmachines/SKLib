#pragma once

#include "cpp.h"

namespace encryption {
	void xorBytes(PVOID pBase, SIZE_T sz, SIZE_T key);
}