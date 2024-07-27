#pragma once

#include "cpp.h"

#define TICKS_TO_S(ns) ((ns) / 10000000)
#define S_TO_TICKS(s) ((s) * 10000000)
#define TICKS_TO_MS(ns) ((ns) / 10000)
#define MS_TO_TICKS(s) ((s) * 10000)

namespace timing {
	LARGE_INTEGER currentTime();

	class StopWatch {
	private:
		LARGE_INTEGER start;
		LARGE_INTEGER stop;

	public:
		StopWatch();

		DWORD64 ms();
		DWORD64 s();
		DWORD64 ticks();

		void reset();
	};
}