#include "exception.h"

cpp::exception::EX_CTL cpp::exception::HandleStdEx(PEXCEPTION_POINTERS pEx)
{
	if (pEx->ExceptionRecord->ExceptionCode == STD_EXCEPTION
		&& cpp::IsInRange(pEx->ExceptionRecord->ExceptionAddress, Throw, 50)) {
		DbgMsg("[EXCEPTION] Caught standard exception, executing handler!");
		return cpp::exception::EXECUTE_HANDLER;
	}

	DbgMsg("[EXCEPTION] Non standard exception caught, continuing search: 0x%x", pEx->ExceptionRecord->ExceptionCode);
	return cpp::exception::CONTINUE_SEARCH;
}

#pragma warning (disable:6011)
void cpp::exception::Throw()
{
	volatile int* zero = nullptr;
	*zero = 0;
}
#pragma warning (default:6011)