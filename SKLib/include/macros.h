#pragma once

#ifdef _KERNEL_MODE
#define _DEBUG
#endif

/*
* Enables logging, disables DMA protection and guarded regions
*/
#define DEBUG_BUILD

/*
* Log MmCopyMemory and catch serials being copied from memory
*/
//#define LOG_AC

/*
* Log hypervisor operations and hooks
*/
//#define HYPER_LOG

/*
* Defining this macro will disable exception handling, and map
* the driver via kdmapper
*/
#define _KDMAPPED

/*
* Defining this macro will allocate a shared buffer for logging
* that the driver is responsible for passing to the usermode
* module for log retrieval
*/
#define _USERMODE_LOGS

/*
* Defining this macro will link against code virtualizer
* therefore forcing you to go through the protection process
*/
//#define PROTECT_BINARY

/*
* When disabled all pseudorandom generations are treated as hardware generation
* requests
*/
#define ENABLE_PREDICTABLE_RANDOM

/*
* When disabled there will be no bsod customization related setup, and all functions will
* immediately return if invoked
*/
//#define CUSTOMIZE_BSOD

/*
* Necessary to avoid on dump DMA read of hv address space
*/
//#define DISABLE_FULL_DUMPS

/*
* When disabled the function EPT::HideDriver will do nothing, use for debug only
*/
#define ENABLE_EPT_PROTECTION

/*
* When disabled there will be no checks for freeze conditions
*/
//#define ENABLE_CLOCK_TIMEOUT

#pragma warning (disable:4390)
#pragma warning (disable:4189)

#define DbgMsgIfPossible(x, ...) if(KeGetCurrentIrql() <= 2 /*DISPATCH_LEVEL*/) DbgPrintEx(0, 0, x##"\n", __VA_ARGS__)
#define DbgMsgForce(x, ...) DbgPrintEx(0, 0, x##"\n", __VA_ARGS__)

#ifdef DEBUG_BUILD
#ifndef ENABLE_EPT_PROTECTION

#define DbgMsg(x, ...) DbgPrintEx(0, 0, x##"\n", __VA_ARGS__)

#else

#define DbgMsg(x, ...) 

#endif
#else 
#define DbgMsg(x, ...)

/*
* Necessary to protect from DMA dumps
*/
#define ENABLE_DMA_PROTECTION

/*
* Necessary to create guarded regions
*/
//#define ENABLE_IDENTITY_GUARD

#endif

#ifndef _KDMAPPED
#define EntryInit DriverEntryInit
#define EntryPoint DriverEntry
#else
#define EntryInit DriverEntry
#define EntryPoint DriverEntryInit
#endif

#define RND_SECURE 1
#define RND_PSEUDO 0
#define RND_SECURITY_LEVEL RND_PSEUDO

//Functions
#define DebugBreak() 
#define BreakAtIRQL(irql) if(KeGetCurrentIrql() >= irql) DebugBreak();

//Constants
#define DRIVER_TAG NULL

#define INIT_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
        const GUID name \
                = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }

#ifdef BUILD_SPOOFER
#ifdef DEBUG_BUILD
#define BUILD_FLAGS (0x0)
#else
#define BUILD_FLAGS (0x1)
#endif
#else
#ifdef DEBUG_BUILD
#define BUILD_FLAGS (0xff)
#else
#define BUILD_FLAGS (0x2)
#endif
#endif