#include "timing.h"

LARGE_INTEGER timing::currentTime()
{
    LARGE_INTEGER currTime = { 0 };
    KeQuerySystemTime(&currTime);
    return currTime;
}

timing::StopWatch::StopWatch()
{
    start = currentTime();
    stop = start;
}

DWORD64 timing::StopWatch::ms()
{
    return TICKS_TO_MS(ticks());
}

DWORD64 timing::StopWatch::s()
{
    return TICKS_TO_S(ticks());
}

DWORD64 timing::StopWatch::ticks()
{
    stop = currentTime();
    return stop.QuadPart - start.QuadPart;
}

void timing::StopWatch::reset()
{
    start = currentTime();
    stop = start;
}
