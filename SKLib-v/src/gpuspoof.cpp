#include "gpuspoof.h"

DWORD64 pGpuSystem = 0;
DWORD32 gpuSysOffset = 0;
DWORD32 gpuMgrOffset = 0;
DWORD32 gpuSysOffset2 = 0;
DWORD32 bInitOffset = 0;
DWORD32 uuidOffset = 0;

DWORD64 gpuData(DWORD32 gpuInstance) {
	DWORD64 gpuSys = *(DWORD64*)(pGpuSystem + gpuSysOffset);
	DWORD32 gpuMgr = *(DWORD32*)(gpuSys + gpuMgrOffset);

	if (!gpuMgr) {
		DbgMsg("[GPU] Failed getting gpuMgr");
		return false;
	}

	gpuSys += gpuSysOffset2;
	DWORD64 gpuDevice{};

	while (1) {
		DWORD32 foundInstance = *(DWORD32*)(gpuSys + 0x8);

		if (foundInstance == gpuInstance)
		{
			DWORD64 device = *(DWORD64*)gpuSys;

			if (device != 0)
				gpuDevice = device;

			break;
		}

		gpuSys += 0x10;
	}

	return gpuDevice;
}

DWORD64 nextGpu(DWORD32 deviceMask, DWORD32* startIndex)
{
	if (*startIndex >= NV_MAX_DEVICES)
	{
		DbgMsg("[GPU] Start index too big: %d", *startIndex);
		return 0;

	}

	for (DWORD32 i = *startIndex; i < NV_MAX_DEVICES; ++i)
	{
		if (deviceMask & (1U << i))
		{
			*startIndex = i + 1;
			return gpuData(i);
		}
	}

	*startIndex = NV_MAX_DEVICES;

	DbgMsg("[GPU] All devices have been handled");
	return 0;
}

UINT64 (*GpuMgrGetGpuFromId)(int gpuId);

bool gpu::Spoof(DWORD64 seed)
{
	rnd.setSecLevel(random::SecurityLevel::PREDICTABLE);
	rnd.setSeed(seed);

	PVOID pBase = Memory::GetKernelAddress((PCHAR)"nvlddmkm.sys");
	if (!pBase) {
		//Can happen if the PC does not have a GPU
		DbgMsg("[GPU] Failed getting NVIDIA driver object");
		return true;
	}

	BOOLEAN status = FALSE;

	//DWORD64 gpuSystemOffset =
	//	(DWORD64)Memory::FindPatternImage((PCHAR)pBase, (PCHAR)"\x48\x8b\x05\x00\x00\x00\x00\x33\xd2\x00\x8b\x00\x48", (PCHAR)"xxx????xx?x?x");
	//if (!gpuSystemOffset) {
	//	DbgMsg("[GPU] Failed getting gpuSystem offset");
	//	return false;
	//}
	//DWORD64 gpuMaskOffset1 =
	//	(DWORD64)Memory::FindPatternImage((PCHAR)pBase, (PCHAR)"\x8b\x83\x00\x00\x00\x00\xff\x8b\x00\x00\x00\x00\x0f\xb3\xe8", (PCHAR)"xx????xx????xxx");
	//if (!gpuMaskOffset1) {
	//	DbgMsg("[GPU] Failed getting gpuMask offset");
	//	return false;
	//}
	//DWORD32 gpuMaskOffset = *(PINT)(gpuMaskOffset1 + 2);
	//
	//DWORD64 gpuUUIDOffset =
	//	(DWORD64)Memory::FindPatternImage((PCHAR)pBase, (PCHAR)"\x48\x03\xcd\x4c\x8d\x80\x00\x00\x00\x00\x48\xc1\xe1\x04", (PCHAR)"xxxxxx????xxxx");
	//if (!gpuUUIDOffset) {
	//	DbgMsg("[GPU] Failed getting gpuMask offset");
	//	return false;
	//}
	//gpuUUIDOffset = *(PINT)(gpuUUIDOffset + 6);
	//
	//DWORD64 pInitOffset =
	//	(DWORD64)Memory::FindPatternImage((PCHAR)pBase, (PCHAR)"\x48\x8b\xce\x48\x8b\x87\x00\x00\x00\x00\xff\x15", (PCHAR)"xxxxxx????xx");
	//if (!pInitOffset) {
	//	DbgMsg("[GPU] Failed getting bInit offset");
	//	return false;
	//}
	//
	//pGpuSystem = *(DWORD64*)(gpuSystemOffset + 7 + *(PINT)(gpuSystemOffset + 3));
	//bInitOffset = *(PINT)(pInitOffset + 6);
	//gpuSysOffset = *(PINT)(gpuSystemOffset + 15);
	//gpuMgrOffset = *(PINT)(gpuSystemOffset + 22);
	//gpuSysOffset2 = *(PINT)(gpuSystemOffset + 33);
	//
	//DWORD64 gpuSys = *(DWORD64*)(pGpuSystem + gpuSysOffset);
	//
	//if (!gpuSys) {
	//	DbgMsg("[GPU] Failed getting gpuSys pointer");
	//	return false;
	//}
	//
	//DWORD32 gpuIndex{},
	//	gpuMask = *(DWORD32*)(gpuSys + gpuMaskOffset);
	//
	//// loops through all available GPU's (limited to NV_MAX_DEVICES)
	//while (1)
	//{
	//	DWORD64 gpuObject = nextGpu(gpuMask, &gpuIndex);
	//
	//	if (!gpuObject)
	//	{
	//		break;
	//	}
	//	
	//	UUID* uuid = (UUID*)(gpuObject + gpuUUIDOffset);
	//	_disable();
	//	CPU::DisableWriteProtection();
	//	uuid->Data1 = (DWORD32)rnd.Next(0, MAXULONG);
	//	uuid->Data2 = (UINT16)rnd.Next(0, MAXUSHORT);
	//	uuid->Data3 = (UINT16)rnd.Next(0, MAXUSHORT);
	//	rnd.c_str((char*)uuid->Data4, 8);
	//	CPU::EnableWriteProtection();
	//	_enable();
	//
	//	DbgMsg("[GPU] Spoofed GPU UUID");
	//	status = TRUE;
	//}
	
	UINT64 Addr = (UINT64)Memory::FindPatternImage(pBase,
		(PCHAR)"\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD8\x48\x85\xC0\x0F\x84\xCC\xCC\xCC\xCC\x44\x8B\x80\xCC\xCC\xCC\xCC\x48\x8D\x15",
		(PCHAR)"x????xxxxxxxx????xxx????xxx");

	UINT64 AddrOffset = 0x3B;
	if (!Addr || *(UINT8*)(Addr + AddrOffset) != 0xE8)
	{
		AddrOffset++;
		if (*(UINT8*)(Addr + AddrOffset) != 0xE8) {
			DbgMsg("[GPU] Could not find GpuMgrGetGpuFromId pattern");
			return false;
		}
	}
	
	ZyanUSize instrLen = 0;
	
	/* Determine the number of instructions necessary to overwrite using Length Disassembler Engine */
	// Initialize decoder context
	ZydisDecoder* pDecoder = (ZydisDecoder*)cpp::kMalloc(sizeof(*pDecoder), PAGE_READWRITE);
	ZyanStatus zstatus = ZydisDecoderInit(pDecoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
	if (!ZYAN_SUCCESS(zstatus)) {
		DbgMsg("[ZYDIS] Failed creating decoder: 0x%x", zstatus);
		return false;
	}
	// Loop over the instructions in our buffer.
	// The runtime-address (instruction pointer) is chosen arbitrary here in order to better
	// visualize relative addressing
	const ZyanUSize length = PAGE_SIZE; 
	ZydisDecodedInstruction* instruction = (ZydisDecodedInstruction*)cpp::kMalloc(sizeof(*instruction), PAGE_READWRITE);
	
	// Resolve reference.
	GpuMgrGetGpuFromId = decltype(GpuMgrGetGpuFromId)(*(int*)(Addr + 1) + 5 + Addr);
	
	Addr += AddrOffset;
	
	// gpuGetGidInfo
	Addr += *(int*)(Addr + 1) + 5;
	
	UINT32 UuidValidOffset = 0;
	// Walk instructions to find GPU::gpuUuid.isInitialized offset.
	for (int InstructionCount = 0; ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(pDecoder, (ZyanU8*)Addr + instrLen, length - instrLen, instruction)), InstructionCount < 0x50; InstructionCount++)
	{
		// cmp [rcx + GPU::gpuUuid.isInitialized], dil
		UINT32 Opcode = *(UINT32*)Addr & 0xFFFFFF;
		if (Opcode == 0x818D4C)
		{
			UuidValidOffset = *(UINT32*)(Addr + 3) - 1;
			break;
		}
	
		// Increment instruction pointer.
		Addr += instruction->length;
	}
	
	// Could not find GPU::gpuUuid.isInitialized offset
	if (!UuidValidOffset)
	{
		DbgMsg("[GPU] Failed to find uuid offset");
		return false;
	}
	
	static UUID* origGUIDs[32] = { 0 };

	// Max number of GPUs supported is 32.
	int spoofedGPUs = 0;
	for (int i = 0; i < 32; i++)
	{
		UINT64 ProbedGPU = GpuMgrGetGpuFromId(i);
	
		// Does not exist?
		if (!ProbedGPU) continue;
	
		// Is GPU UUID not initialized?
		if (!*(bool*)(ProbedGPU + UuidValidOffset)) continue;
		
		if (!origGUIDs[i]) {
			origGUIDs[i] = (UUID*)cpp::kMalloc(sizeof(UUID));
			*origGUIDs[i] = *(UUID*)(ProbedGPU + UuidValidOffset + 1);
		}
		else {
			*(UUID*)(ProbedGPU + UuidValidOffset + 1) = *origGUIDs[i];
		}
		rnd.setSeed(seed);
		_disable();
		// UuidValid + 1 = UUID
		rnd.bytes((char*)(ProbedGPU + UuidValidOffset + 1), sizeof(UUID));
		_enable();

		DbgMsg("[GPU] Spoofed GPU %d", i);
		spoofedGPUs++;
	}

	return spoofedGPUs > 0;
}
