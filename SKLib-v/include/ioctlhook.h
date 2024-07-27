#pragma once

#include "cpp.h"
#include "Setup.hpp"

#include <SKLib.h>
#include <registry.h>
#include <VMMDef.h>

#define TEST_SEED 0xb5ff6677
#define SERIAL_MAX_LENGTH 20

#pragma warning (disable:4305)
#pragma warning (disable:4309)

enum HookedDriver : UCHAR {
    DriverUSB,
    DriverDisk,
    DriverNIC,
    DriverTCP,
    DriverNSI,
    DriverWMI,
    DriverPartmgr,
    DriverVolume,
    DriverScsi,
    DriverNvme,
    DriverDump
};

#ifdef _KERNEL_MODE

typedef struct _IOC_REQUEST {
    PVOID Buffer;
    ULONG BufferLength;
    PVOID OldContext;
    PIO_COMPLETION_ROUTINE OldRoutine;
} IOC_REQUEST, * PIOC_REQUEST;

extern random::Random rnd;

VOID ChangeIoc(PIO_STACK_LOCATION ioc, PIRP irp, PIO_COMPLETION_ROUTINE routine);
PWCHAR TrimGUID(PWCHAR guid, DWORD max);

namespace spoofer {
    extern bool bLogHooks;
    extern DWORD64 seed;

    bool LogDetections();
}

__forceinline VOID LogCaller(PIRP pIrp, HookedDriver driverCode)
{
}

extern vector<char*>* vDiskModels;

struct NVME_IDENTIFY_DEVICE
{
    CHAR		Reserved1[4];
    CHAR		SerialNumber[20];
    CHAR		Model[40];
    CHAR		FirmwareRev[8];
    CHAR		Reserved2[9];
    CHAR		MinorVersion;
    SHORT		MajorVersion;
    CHAR		Reserved3[428];
    CHAR		Reserved4[3584];
};

#endif