#pragma once

#include "ioctlhook.h"

#define MOUNTMGRCONTROLTYPE ((ULONG) 'm')
#define MOUNTDEVCONTROLTYPE ((ULONG) 'M')

#define IOCTL_MOUNTDEV_QUERY_UNIQUE_ID            CTL_CODE(MOUNTDEVCONTROLTYPE, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MOUNTMGR_QUERY_POINTS \
  CTL_CODE(MOUNTMGRCONTROLTYPE, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _MOUNTDEV_UNIQUE_ID {
    USHORT UniqueIdLength;
    UCHAR UniqueId[1];
} MOUNTDEV_UNIQUE_ID, * PMOUNTDEV_UNIQUE_ID;

typedef struct _MOUNTMGR_MOUNT_POINT {
    ULONG  SymbolicLinkNameOffset;
    USHORT SymbolicLinkNameLength;
    USHORT Reserved1;
    ULONG  UniqueIdOffset;
    USHORT UniqueIdLength;
    USHORT Reserved2;
    ULONG  DeviceNameOffset;
    USHORT DeviceNameLength;
    USHORT Reserved3;
} MOUNTMGR_MOUNT_POINT, * PMOUNTMGR_MOUNT_POINT;

typedef struct _MOUNTMGR_MOUNT_POINTS {
    ULONG Size;
    ULONG NumberOfMountPoints;
    MOUNTMGR_MOUNT_POINT MountPoints[1];
} MOUNTMGR_MOUNT_POINTS, * PMOUNTMGR_MOUNT_POINTS;

namespace volumes {
    bool Spoof(DWORD64 seed = TEST_SEED);
}