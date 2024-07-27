#pragma once

#pragma warning (disable:4005)
#pragma warning (disable:4267)

#ifdef _KERNEL_MODE
#include <ntddk.h>
#include <ntdef.h>
#endif

#include <intrin.h>

#include "ia32.h"
#include "macros.h"

//
// The result type of Microsoft VMX-intrinsic functions.
//
typedef enum _VMX_RESULT
{
    VmxResultOk = 0,                  //!< Operation succeeded
    VmxResultErrorWithStatus = 1,     //!< Operation failed with extended status available
    VmxResultErrorWithoutStatus = 2,  //!< Operation failed without status available
} VMX_RESULT;

typedef enum _SEGMENT_TYPE
{
    SegmentCs,
    SegmentSs,
    SegmentDs,
    SegmentEs,
    SegmentFs,
    SegmentGs,
} SEGMENT_TYPE;

#define MAX_UINT16 0xffff

#define ASSERT(x) if(!(x)){DbgMsg("[VMCS] ASSERT FAILURE: (%s) at %s:%i\n", #x, __FILE__, __LINE__);}
#define IS_FLAG_SET(F, SF)       ((BOOLEAN)(((F) & (SF)) != 0))

#ifdef _KERNEL_MODE

namespace Checks {
    void CheckGuestVmcsFieldsForVmEntry();
}

#endif