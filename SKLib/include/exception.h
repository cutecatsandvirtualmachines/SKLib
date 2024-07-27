#pragma once

#include "std.h"

//Standard exception for SKLib
#define STATUS_ACCESS_VIOLATION          ((NTSTATUS)0xC0000005L)
#define STD_EXCEPTION STATUS_ACCESS_VIOLATION

#ifndef _KDMAPPED
#define throw_std() cpp::exception::Throw()
#define STD_TRY_SECTION_START __try {
#define STD_CATCH } __except (cpp::exception::HandleStdEx(GetExceptionInformation())) {
#define STD_FINALLY } __finally {
#define STD_TRY_SECTION_END }
#else
#define throw_std()
#define STD_TRY_SECTION_START {
#define STD_CATCH } if(0) {
#define STD_FINALLY }{
#define STD_TRY_SECTION_END }
#endif

#define throw_std_force() cpp::exception::Throw()

#ifdef _KERNEL_MODE
namespace cpp {
	namespace exception {
		enum EX_CTL : ULONG64 {
			EXECUTE_HANDLER      = 1,
			CONTINUE_SEARCH      = 0,
			CONTINUE_EXECUTION   = -1
		};

		void Throw();
		EX_CTL HandleStdEx(PEXCEPTION_POINTERS pEx);
	}

	__forceinline BOOLEAN IsInRange(PVOID va, PVOID center, size_t radius) {
		size_t upperBound = (size_t)center + radius;
		size_t lowerBound = (size_t)center - radius;

		return ((size_t)va < upperBound) && ((size_t)va > lowerBound);
	}
	__forceinline BOOLEAN IsInRange(PVOID va, DWORD64 start, DWORD64 end) {
		return ((size_t)va >= start) && ((size_t)va <= end);
	}
	__forceinline BOOLEAN IsKernelAddress(PVOID va) {
		return (size_t)va >> (62);
	}
}
#endif