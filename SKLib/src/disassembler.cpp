#include "disassembler.h"

size_t disassembler::GetInstrBoundaryLen(PVOID pBase, size_t targetLen)
{
    ZyanUSize instrLen = 0;

    /* Determine the number of instructions necessary to overwrite using Length Disassembler Engine */
    // Initialize decoder context
    ZydisDecoder* pDecoder = (ZydisDecoder*)cpp::kMalloc(sizeof(*pDecoder), PAGE_READWRITE);
    ZyanStatus status = ZydisDecoderInit(pDecoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    if (!ZYAN_SUCCESS(status)) {
        DbgMsg("[ZYDIS] Failed creating decoder: 0x%x", status);
    }
    // Loop over the instructions in our buffer.
    // The runtime-address (instruction pointer) is chosen arbitrary here in order to better
    // visualize relative addressing
    ZyanU8* data = (ZyanU8*)pBase;
    const ZyanUSize length = PAGE_SIZE;
    ZydisDecodedInstruction* instruction = (ZydisDecodedInstruction*)cpp::kMalloc(sizeof(*instruction), PAGE_READWRITE);
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(pDecoder, data + instrLen, length - instrLen,
        instruction)))
    {
        if (instruction->opcode == 0xe8 //Call near
            || instruction->opcode == 0xeb //Jmp near
            )
            break;
        instrLen += instruction->length;
        if (instrLen >= targetLen)
            break;
    }
    cpp::kFree(instruction);
    cpp::kFree(pDecoder);

    return instrLen;
}
