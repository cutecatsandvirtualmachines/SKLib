#include "file.h"

file::fstream::fstream(string&& path)
{
    hFile = (HANDLE)~0ull;

    IO_STATUS_BLOCK IoStatusBlock;

    InitializeObjectAttributes(&ObjectAttributes, &path.unicode(), OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS ntStatus = ZwCreateFile(&hFile, GENERIC_ALL, &ObjectAttributes,
        &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(ntStatus))
    {
        DbgMsg("[FSTREAM]: Creating file error: 0x%x", ntStatus);
    }
}

file::fstream::fstream(string& path)
{
    hFile = (HANDLE)~0ull;

    IO_STATUS_BLOCK IoStatusBlock;

    InitializeObjectAttributes(&ObjectAttributes, &path.unicode(), OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS ntStatus = ZwCreateFile(&hFile, GENERIC_ALL, &ObjectAttributes,
        &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(ntStatus))
    {
        DbgMsg("[FSTREAM]: Creating file error: 0x%x", ntStatus);
    }
}

file::fstream::~fstream()
{
    if ((HANDLE)~0ull == hFile)
        return;

    ZwClose(hFile);
}

HANDLE file::fstream::Handle()
{
    return hFile;
}
