#pragma once

#include "VMMDef.h"
#include "MapEx.h"
#include "paging.h"
#include "bugcheck.h"

#ifdef _KERNEL_MODE
typedef NTSTATUS(*fnVmcallCallback)(ULONG64& ulOpt1, ULONG64& ulOpt2, ULONG64& ulOpt3);

namespace vmcall {

    enum VMCALL_TYPE {
        VMCALL_TEST = 0x1,
        VMCALL_VMXOFF,
        VMCALL_INVEPT_CONTEXT,
        VMCALL_HOOK_PAGE,
        VMCALL_UNHOOK_PAGE,
        VMCALL_HOOK_PAGE_RANGE,
        VMCALL_HOOK_PAGE_INDEX,
        VMCALL_SUBSTITUTE_PAGE,
        VMCALL_CRASH,               //Test VMCALL
        VMCALL_PROBE,               //Test VMCALL
        VMCALL_READ_VIRT,
        VMCALL_WRITE_VIRT,
        VMCALL_READ_PHY,
        VMCALL_WRITE_PHY,
        VMCALL_DISABLE_EPT,
        VMCALL_SET_COMM_KEY,
        VMCALL_GET_CR3,
        VMCALL_GET_EPT_BASE,
        VMCALL_VIRT_TO_PHY,
        VMCALL_STORAGE_QUERY
    };

	extern unordered_map<ULONG64, fnVmcallCallback>* vVmcallCallbacks;

	bool Init();
	void Dispose();

	fnVmcallCallback FindHandler(ULONG64 vmcallCode);

	void InsertHandler(fnVmcallCallback pCallback, ULONG64 vmcallCode);
	void RemoveHandler(ULONG64 vmcallCode);

    bool ValidateCommunicationKey(ULONG64 key);
    bool IsVmcall(ULONG64 r9);
    ULONG64 GetCommunicationKey();
    ULONG64 GetLastGuestCr3();
	NTSTATUS HandleVmcall(ULONG64 ulCallNum, ULONG64& ulOpt1, ULONG64& ulOpt2, ULONG64& ulOpt3);

    class RW {
    private:
        DWORD64 _cr3;

    public:
        RW(DWORD64 cr3) : _cr3(cr3) {};

        template<typename T>
        T Read(PVOID pAddress) {
            vmm::PREAD_DATA readData = nullptr;
            char buffer[sizeof(vmm::READ_DATA) * 2] = { 0 };
            if (PAGE_ALIGN(buffer) != PAGE_ALIGN(buffer + sizeof(vmm::READ_DATA))) {
                readData = (vmm::PREAD_DATA)PAGE_ALIGN(buffer + sizeof(vmm::READ_DATA));
            }
            else {
                readData = (vmm::PREAD_DATA)buffer;
            }

            T out;
            readData->length = sizeof(T);
            readData->pOutBuf = &out;
            readData->pTarget = pAddress;

            NTSTATUS ntStatus = CPU::CPUIDVmCall(VMCALL_READ_VIRT, (ULONG64)readData, _cr3, vmcall::GetCommunicationKey());
            if (ntStatus != STATUS_SUCCESS) {
                DbgMsg("[RW] Failed reading %p: 0x%x", pAddress, ntStatus);
                return T();
            }

            return out;
        }

        bool Read(PVOID pAddress, PVOID pOut, SIZE_T sz) {
            vmm::PREAD_DATA readData = nullptr;
            char buffer[sizeof(vmm::READ_DATA) * 2] = { 0 };
            if (PAGE_ALIGN(buffer) != PAGE_ALIGN(buffer + sizeof(vmm::READ_DATA))) {
                readData = (vmm::PREAD_DATA)PAGE_ALIGN(buffer + sizeof(vmm::READ_DATA));
            }
            else {
                readData = (vmm::PREAD_DATA)buffer;
            }

            readData->length = sz;
            readData->pOutBuf = pOut;
            readData->pTarget = pAddress;

            NTSTATUS ntStatus = CPU::CPUIDVmCall(VMCALL_READ_VIRT, (ULONG64)readData, _cr3, vmcall::GetCommunicationKey());
            if (ntStatus != STATUS_SUCCESS) {
                DbgMsg("[RW] Failed reading %p: 0x%x", pAddress, ntStatus);
                return false;
            }

            return true;
        }

        template<typename T>
        bool Write(PVOID pAddress, T obj) {
            vmm::PWRITE_DATA writeData = nullptr;
            char buffer[sizeof(vmm::WRITE_DATA) * 2] = { 0 };
            if (PAGE_ALIGN(buffer) != PAGE_ALIGN(buffer + sizeof(vmm::WRITE_DATA))) {
                writeData = (vmm::PWRITE_DATA)PAGE_ALIGN(buffer + sizeof(vmm::WRITE_DATA));
            }
            else {
                writeData = (vmm::PWRITE_DATA)buffer;
            }
            writeData->length = sizeof(T);
            writeData->pInBuf = &obj;
            writeData->pTarget = pAddress;

            NTSTATUS ntStatus = CPU::CPUIDVmCall(VMCALL_WRITE_VIRT, (ULONG64)writeData, _cr3, vmcall::GetCommunicationKey());
            if (ntStatus != STATUS_SUCCESS) {
                DbgMsg("[RW] Failed writing %p: 0x%x", pAddress, ntStatus);
                return false;
            }
            return true;
        }

        inline bool Write(PVOID pAddress, PVOID pIn, SIZE_T sz) {
            vmm::PWRITE_DATA writeData = nullptr;
            char buffer[sizeof(vmm::WRITE_DATA) * 2] = { 0 };
            if (PAGE_ALIGN(buffer) != PAGE_ALIGN(buffer + sizeof(vmm::WRITE_DATA))) {
                writeData = (vmm::PWRITE_DATA)PAGE_ALIGN(buffer + sizeof(vmm::WRITE_DATA));
            }
            else {
                writeData = (vmm::PWRITE_DATA)buffer;
            }
            writeData->length = sz;
            writeData->pInBuf = pIn;
            writeData->pTarget = pAddress;

            NTSTATUS ntStatus = CPU::CPUIDVmCall(VMCALL_WRITE_VIRT, (ULONG64)writeData, _cr3, vmcall::GetCommunicationKey());
            if (ntStatus != STATUS_SUCCESS) {
                DbgMsg("[RW] Failed writing %p: 0x%x", pAddress, ntStatus);
                return false;
            }
            return true;
        }
    };
}
#endif