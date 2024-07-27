#pragma once

#include <collector.h>
#include <data.h>
#include <macros.h>
#include <status.h>

#ifdef _KERNEL_MODE

extern "C" NTSTATUS IoCreateDriver(
	IN  PUNICODE_STRING DriverName    OPTIONAL,
	IN  PDRIVER_INITIALIZE InitializationFunction
);

#endif