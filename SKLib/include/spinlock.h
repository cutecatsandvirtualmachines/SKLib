#pragma once

#include "cpp.h"

#define SPINLOCK_MAX_WAIT ~0ul

#pragma pack(push, 1)
class Spinlock {
public:
	Spinlock() {
		Init();
	}

	void Unlock() {
		InterlockedExchange(&_lock, 0);
	}
	void Disable() {
		_bDisabled = true;
	}
	void Enable() {
		_bDisabled = false;
	}

	void Init() {
		_lock = 0;
		_bDisabled = false;
	}
	void Lock() {
		while (!_bDisabled && (InterlockedCompareExchange(&_lock, 1, 0) == 1))
			;
	}
private:
	long _lock;
	bool _bDisabled;
};
#pragma pack(pop)