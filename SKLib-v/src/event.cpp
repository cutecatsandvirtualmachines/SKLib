#include "event.h"

#include <intrin.h>

bool SKLibEvent::Triggered()
{
	return bPreNotified;
}

void SKLibEvent::Await()
{
	if (bPreNotified)
		return;

	_lock.Lock();
	_lock.Lock();
	_lock.Unlock();
}

void SKLibEvent::Trigger()
{
	bPreNotified = true;
	_lock.Unlock();
}
