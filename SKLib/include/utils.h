#pragma once
#ifdef _KERNEL_MODE
#ifndef _WDMDDK_
#include <ntifs.h>
#endif
#endif

#include "cpp.h"
#include "StringEx.h"

#ifdef _KERNEL_MODE
//Remember to deallocate string's buffer after you're done using the UNICODE_STRING returned from this function
UNICODE_STRING GetModuleNameFromPath(PUNICODE_STRING path);
#endif