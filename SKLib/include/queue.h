#pragma once
#ifdef _KERNEL_MODE

#include "cpp.h"
#include "VectorEx.h"
#include "RandEx.h"

#define DEFAULT_QUEUE_RESERVE 20

class Queue {
	vector<DWORD32> queue;

	Queue();

	void Lock();
	void Unlock();
};
#endif