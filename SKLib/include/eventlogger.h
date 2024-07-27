#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>

#include "macros.h"

class EventLogger
{
public:
	PDRIVER_OBJECT pDriverObj;
	
	EventLogger() : pDriverObj(nullptr) {
	};

    void LogEvent(NTSTATUS ntStatus, const WCHAR* pStr, ...)
    {
        if (!pDriverObj) {
            DbgMsg("[EVENTS] Error: Device object is not set, cannot log");
            return;
        }
        size_t entry_size;
        size_t string1_len = 0;
        if (pStr)
            string1_len = (wcslen(pStr) + 1) * sizeof(WCHAR);
        entry_size = sizeof(IO_ERROR_LOG_PACKET) + string1_len;
        if (entry_size <= ERROR_LOG_MAXIMUM_SIZE) {
            IO_ERROR_LOG_PACKET* entry =
                (IO_ERROR_LOG_PACKET*)IoAllocateErrorLogEntry(
                    pDriverObj, (UCHAR)entry_size);
            if (entry) {
                UCHAR* strings;
                entry->RetryCount = 0;
                entry->DumpDataSize = 0;
                entry->NumberOfStrings = 0;
                strings = ((UCHAR*)entry) + sizeof(IO_ERROR_LOG_PACKET);
                if (string1_len > 0) {
                    ++entry->NumberOfStrings;
                    memcpy(strings, pStr, string1_len);
                    strings += string1_len;
                }
                entry->StringOffset = sizeof(IO_ERROR_LOG_PACKET);
                entry->ErrorCode = ntStatus;
                entry->FinalStatus = STATUS_SUCCESS;
                IoWriteErrorLogEntry(entry);
            }
            else {
                DbgMsg("[EVENTS] Error: failed to allocate error log entry");
            }
        }
    }
};
#endif
