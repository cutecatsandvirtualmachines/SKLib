#include "queue.h"

Queue::Queue() {
	queue.reserve(DEFAULT_QUEUE_RESERVE);
}

void Queue::Lock()
{
	unsigned int wait = 1;
	unsigned int maxWait = ~0ul;

	DWORD32 curIndex = (DWORD32)random::Next32(0, MAXUINT32);
	queue.Append(curIndex);

	while (!(queue[0] == curIndex))
	{
		for (unsigned i = 0; i < wait; ++i)
		{
			_mm_pause();
		}

		// Don't call "pause" too many times. If the wait becomes too big,
		// clamp it to the max_wait.

		if (wait * 2 > maxWait)
		{
			wait = maxWait;
		}
		else
		{
			wait = wait * 2;
		}
	}
}

void Queue::Unlock()
{
	queue.RemoveAt(0);
}
