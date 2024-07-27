#pragma once

#include "spinlock.h"
#include "RandEx.h"

class SKLibEvent {
private:
	Spinlock _lock;
	bool bPreNotified;

	DWORD64 _id;

public:
	SKLibEvent() : bPreNotified(false), _id(random::NextHardware(0, MAXULONG64)) {};

	bool Triggered();
	void Await();

#ifdef _KERNEL_MODE
	void Trigger();
#endif

	__forceinline bool operator==(SKLibEvent& rhs) {
		return _id == rhs._id;
	}
	__forceinline bool operator!=(SKLibEvent& rhs) {
		return !(*this == rhs);
	}
};