#include "VMMDef.h"
#include "Vmcall.h"
#include "Vmexit.h"
#include "Vmoperations.h"
#include "eac.h"
#include <utils.h>
#include <Arch/Msr.h>
#include <Arch/Segmentation.h>
#include <Arch/Intrinsics.h>
#include <Arch/Interrupts.h>
#include <paging.h>
#include <IDT.h>
#include <Arch/Cpuid.h>
#include <identity.h>

#define	CPUIDECX_SSE3	0x00000001	/* streaming SIMD extensions #3 */
#define	CPUIDECX_PCLMUL	0x00000002	/* Carryless Multiplication */
#define	CPUIDECX_DTES64	0x00000004	/* 64bit debug store */
#define	CPUIDECX_MWAIT	0x00000008	/* Monitor/Mwait */
#define	CPUIDECX_DSCPL	0x00000010	/* CPL Qualified Debug Store */
#define	CPUIDECX_VMX	0x00000020	/* Virtual Machine Extensions */
#define	CPUIDECX_SMX	0x00000040	/* Safer Mode Extensions */
#define	CPUIDECX_EST	0x00000080	/* enhanced SpeedStep */
#define	CPUIDECX_TM2	0x00000100	/* thermal monitor 2 */
#define	CPUIDECX_SSSE3	0x00000200	/* Supplemental Streaming SIMD Ext. 3 */
#define	CPUIDECX_CNXTID	0x00000400	/* Context ID */
#define CPUIDECX_SDBG	0x00000800	/* Silicon debug capability */
#define	CPUIDECX_FMA3	0x00001000	/* Fused Multiply Add */
#define	CPUIDECX_CX16	0x00002000	/* has CMPXCHG16B instruction */
#define	CPUIDECX_XTPR	0x00004000	/* xTPR Update Control */
#define	CPUIDECX_PDCM	0x00008000	/* Perfmon and Debug Capability */
#define	CPUIDECX_PCID	0x00020000	/* Process-context ID Capability */
#define	CPUIDECX_DCA	0x00040000	/* Direct Cache Access */
#define	CPUIDECX_SSE41	0x00080000	/* Streaming SIMD Extensions 4.1 */
#define	CPUIDECX_SSE42	0x00100000	/* Streaming SIMD Extensions 4.2 */
#define	CPUIDECX_X2APIC	0x00200000	/* Extended xAPIC Support */
#define	CPUIDECX_MOVBE	0x00400000	/* MOVBE Instruction */
#define	CPUIDECX_POPCNT	0x00800000	/* POPCNT Instruction */
#define	CPUIDECX_DEADLINE	0x01000000	/* APIC one-shot via deadline */
#define	CPUIDECX_AES	0x02000000	/* AES Instruction */
#define	CPUIDECX_XSAVE	0x04000000	/* XSAVE/XSTOR States */
#define	CPUIDECX_OSXSAVE	0x08000000	/* OSXSAVE */
#define	CPUIDECX_AVX	0x10000000	/* Advanced Vector Extensions */
#define	CPUIDECX_F16C	0x20000000	/* 16bit fp conversion  */
#define	CPUIDECX_RDRAND	0x40000000	/* RDRAND instruction  */
#define	CPUIDECX_HV	0x80000000	/* Running on hypervisor */


#define	CPUIDECX_LAHF		0x00000001 /* LAHF and SAHF instructions */
#define	CPUIDECX_CMPLEG		0x00000002 /* Core MP legacy mode */
#define	CPUIDECX_SVM		0x00000004 /* Secure Virtual Machine */
#define	CPUIDECX_EAPICSP	0x00000008 /* Extended APIC space */
#define	CPUIDECX_AMCR8		0x00000010 /* LOCK MOV CR0 means MOV CR8 */
#define	CPUIDECX_ABM		0x00000020 /* LZCNT instruction */
#define	CPUIDECX_SSE4A		0x00000040 /* SSE4-A instruction set */
#define	CPUIDECX_MASSE		0x00000080 /* Misaligned SSE mode */
#define	CPUIDECX_3DNOWP		0x00000100 /* 3DNowPrefetch */
#define	CPUIDECX_OSVW		0x00000200 /* OS visible workaround */
#define	CPUIDECX_IBS		0x00000400 /* Instruction based sampling */
#define	CPUIDECX_XOP		0x00000800 /* Extended operating support */
#define	CPUIDECX_SKINIT		0x00001000 /* SKINIT and STGI are supported */
#define	CPUIDECX_WDT		0x00002000 /* Watchdog timer */
/* Reserved			0x00004000 */
#define	CPUIDECX_LWP		0x00008000 /* Lightweight profiling support */
#define	CPUIDECX_FMA4		0x00010000 /* 4-operand FMA instructions */
#define	CPUIDECX_TCE		0x00020000 /* Translation Cache Extension */
/* Reserved			0x00040000 */
#define	CPUIDECX_NODEID		0x00080000 /* Support for MSRC001C */
/* Reserved			0x00100000 */
#define	CPUIDECX_TBM		0x00200000 /* Trailing bit manipulation instruction */
#define	CPUIDECX_TOPEXT		0x00400000 /* Topology extensions support */
#define	CPUIDECX_CPCTR		0x00800000 /* core performance counter ext */
#define	CPUIDECX_DBKP		0x04000000 /* DataBreakpointExtension */
#define	CPUIDECX_PERFTSC	0x08000000 /* performance time-stamp counter */
#define	CPUIDECX_PCTRL3		0x10000000 /* L3 performance counter ext */
#define	CPUIDECX_MWAITX		0x20000000 /* MWAITX/MONITORX */
#define	CPUID_FPU	0x00000001	/* processor has an FPU? */
#define	CPUID_VME	0x00000002	/* has virtual mode (%cr4's VME/PVI) */
#define	CPUID_DE	0x00000004	/* has debugging extension */
#define	CPUID_PSE	0x00000008	/* has 4MB page size extension */
#define	CPUID_TSC	0x00000010	/* has time stamp counter */
#define	CPUID_MSR	0x00000020	/* has model specific registers */
#define	CPUID_PAE	0x00000040	/* has phys address extension */
#define	CPUID_MCE	0x00000080	/* has machine check exception */
#define	CPUID_CX8	0x00000100	/* has CMPXCHG8B instruction */
#define	CPUID_APIC	0x00000200	/* has enabled APIC */
#define	CPUID_SYS1	0x00000400	/* has SYSCALL/SYSRET inst. (Cyrix) */
#define	CPUID_SEP	0x00000800	/* has SYSCALL/SYSRET inst. (AMD/Intel) */
#define	CPUID_MTRR	0x00001000	/* has memory type range register */
#define	CPUID_PGE	0x00002000	/* has page global extension */
#define	CPUID_MCA	0x00004000	/* has machine check architecture */
#define	CPUID_CMOV	0x00008000	/* has CMOVcc instruction */
#define	CPUID_PAT	0x00010000	/* has page attribute table */
#define	CPUID_PSE36	0x00020000	/* has 36bit page size extension */
#define	CPUID_PSN	0x00040000	/* has processor serial number */
#define	CPUID_CFLUSH	0x00080000	/* CFLUSH insn supported */
#define	CPUID_B20	0x00100000	/* reserved */
#define	CPUID_DS	0x00200000	/* Debug Store */
#define	CPUID_ACPI	0x00400000	/* ACPI performance modulation regs */
#define	CPUID_MMX	0x00800000	/* has MMX instructions */
#define	CPUID_FXSR	0x01000000	/* has FXRSTOR instruction */
#define	CPUID_SSE	0x02000000	/* has streaming SIMD extensions */
#define	CPUID_SSE2	0x04000000	/* has streaming SIMD extensions #2 */
#define	CPUID_SS	0x08000000	/* self-snoop */
#define	CPUID_HTT	0x10000000	/* Hyper-Threading Technology */
#define	CPUID_TM	0x20000000	/* thermal monitor (TCC) */
#define	CPUID_B30	0x40000000	/* reserved */
#define	CPUID_PBE	0x80000000	/* Pending Break Enabled restarts clock */
#define CPUID_RDTSCP	0x08000000	/* RDTSCP / IA32_TSC_AUX available */

#define VMM_ECPUIDECX_MASK ~(CPUIDECX_SVM)
#define SVM_MSRIDX(m)			((m) / 4)
#define SVM_MSRBIT_R(m)			(1 << (((m) % 4) * 2))
#define SVM_MSRBIT_W(m)			(1 << (((m) % 4) * 2 + 1))

namespace SVM {


	bool GetSegmentDescriptor(PSEG_SELECTOR SegmentSelector, USHORT Selector, PUCHAR GdtBase)
	{
		PSEG_DESCRIPTOR SegDesc;

		if (!SegmentSelector)
			return FALSE;

		if (Selector & 0x4) {
			return FALSE;
		}

		SegDesc = (PSEG_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

		SegmentSelector->SEL = Selector;
		SegmentSelector->BASE = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
		SegmentSelector->LIMIT = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
		SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

		if (!(SegDesc->ATTR0 & 0x10)) { // LA_ACCESSED
			ULONG64 tmp;
			// this is a TSS or callgate etc, save the base high part
			tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
			SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (tmp << 32);
		}

		if (SegmentSelector->ATTRIBUTES.Fields.G) {
			// 4096-bit granularity is enabled for this segment, scale the limit
			SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
		}

		return TRUE;
	}

	bool InitialiseCore(SVMState* state) {
		DbgMsg("[SVM] Initialising core");
		int cpuid[4];
		__cpuidex(cpuid, 0, 0);
		state->SVMFlags.CETSupported = (cpuid[2] & (1 << 7)) != 0;
		if(state->SVMFlags.CETSupported)
			DbgMsg("[SVM] CET support detected.");
		state->CPUCore = CPU::GetCPUIndex(false);
		__writemsr((unsigned long)Msr::Amd::AmdMsr::VM_HSAVE_PA, Memory::VirtToPhy(state->HostState));
		state->GuestVmcbPhysicalAddress = Memory::VirtToPhy(state->GuestVmcb);
		state->MsrPermissionsMapPhysicalAddress = Memory::VirtToPhy(state->MsrPermissionsMap);
		return true;
	}

	void ClearEntireTLB(SVMState* state) {
		state->GuestVmcb->ControlArea.TlbControl.layout.TlbControl = 0x1;
	}

	void ClearGuestTLB(SVMState* state) {
		state->GuestVmcb->ControlArea.TlbControl.layout.TlbControl = 0x3;
	}

	void ClearGuestNonGlobalTLB(SVMState* state) {
		state->GuestVmcb->ControlArea.TlbControl.layout.TlbControl = 0x7;
	}

	void CheckInterruptShadow(SVMState* state) {
		if (state->GuestVmcb->ControlArea.InterruptShadow.layout.InterruptShadow == 1) {
			state->EventInjectionShadow = state->GuestVmcb->ControlArea.EventInjection;
			state->GuestVmcb->ControlArea.InterceptVirtualIntr = 1;
			state->GuestVmcb->ControlArea.EventInjection = 0;

			state->GuestVmcb->ControlArea.VirtualIntr.layout.VirtualIrq = 1;
			state->GuestVmcb->ControlArea.VirtualIntr.layout.VirtualIgnoreTpr = 1;
			state->GuestVmcb->ControlArea.VirtualIntr.layout.VirtualIntrPriority = 1;
			state->GuestVmcb->ControlArea.VirtualIntr.layout.VirtualIntrVector = 0;
		}
	}

	void InjectNMI(SVMState* state) {
		Svm::EventInj eventinj = {};
		eventinj.layout.Reserved = 0;
		eventinj.layout.ErrorCodeValid = 0;
		eventinj.layout.Type = EventType::e_NMI;
		eventinj.layout.Valid = 1;
		eventinj.layout.Vector = (unsigned long long)InterruptVector::NmiInterrupt;
		state->GuestVmcb->ControlArea.EventInjection = eventinj.raw;
		CheckInterruptShadow(state);
	}

	void InjectEvent(SVMState* state, EventType type, InterruptVector vector, int errorCode, bool bErrorCodeValid) {
		Svm::EventInj eventinj = {};
		eventinj.layout.Reserved = 0;
		eventinj.layout.ErrorCodeValid = bErrorCodeValid;
		eventinj.layout.Type = type;
		eventinj.layout.ErrorCode = errorCode;
		eventinj.layout.Vector = (int)vector;
		eventinj.layout.Valid = 1;
		state->GuestVmcb->ControlArea.EventInjection = eventinj.raw;
		CheckInterruptShadow(state);
	}

	void SetMsrRead(SVMState* state, unsigned long long msr) {
		unsigned char* msrs;
		unsigned short idx;

		msrs = (unsigned char*)state->MsrPermissionsMap->msrpm;
		if (msr <= 0x1fff)
		{
			idx = SVM_MSRIDX(msr);
			msrs[idx] &= ~(SVM_MSRBIT_R(msr));
		}
		else if (msr >= 0xc0000000 && msr <= 0xc0001fff)
		{
			idx = SVM_MSRIDX(msr - 0xc0000000) + 0x800;
			msrs[idx] &= ~(SVM_MSRBIT_R(msr - 0xc0000000));
		}
		else if (msr >= 0xc0010000 && msr <= 0xc0011fff)
		{
			idx = SVM_MSRIDX(msr - 0xc0010000) + 0x1000;
			msrs[idx] &= ~(SVM_MSRBIT_R(msr - 0xc0010000));
		}
		else
		{
			ASSERT(false);
			return;
		}
	}
	void SetMsrWrite(SVMState* state, unsigned long long msr) {
		unsigned char* msrs;
		unsigned short idx;

		msrs = (unsigned char*)state->MsrPermissionsMap->msrpm;
		if (msr <= 0x1fff)
		{
			idx = SVM_MSRIDX(msr);
			msrs[idx] &= ~(SVM_MSRBIT_W(msr));
		}
		else if (msr >= 0xc0000000 && msr <= 0xc0001fff)
		{
			idx = SVM_MSRIDX(msr - 0xc0000000) + 0x800;
			msrs[idx] &= ~(SVM_MSRBIT_W(msr - 0xc0000000));
		}
		else if (msr >= 0xc0010000 && msr <= 0xc0011fff)
		{
			idx = SVM_MSRIDX(msr - 0xc0010000) + 0x1000;
			msrs[idx] &= ~(SVM_MSRBIT_W(msr - 0xc0010000));
		}
		else
		{
			ASSERT(false);
			return;
		}
	}
	void SetMsrReadWrite(SVMState* state, unsigned long long msr) {
		SetMsrWrite(state, msr);
		SetMsrRead(state, msr);
	}
	__forceinline bool SetupVMCB(SVMState* state, PCONTEXT contextToResume) {
		__svm_vmsave(state->GuestVmcbPhysicalAddress);
		Seg::DescriptorTableRegister<Seg::Mode::longMode> gdt, idt, ldt;
		__sidt(&idt);
		_sgdt(&gdt);


		state->GuestVmcb->ControlArea.NpEnable = 1;
		state->GuestVmcb->ControlArea.NestedPageTableCr3 = vmm::vGuestStates[CPU::GetCPUIndex()].eptState.nCR3.Flags;

		state->GuestVmcb->ControlArea.GuestAsid = (state->CPUCore + 1);
		state->GuestVmcb->ControlArea.TlbControl.layout.TlbControl = 0x1; 
		state->GuestVmcb->ControlArea.InterceptCpuid = 1;
		state->GuestVmcb->ControlArea.InterceptMsr = 1;
		state->GuestVmcb->ControlArea.InterceptVmrun = 1;
		state->GuestVmcb->ControlArea.InterceptVmcall = 1;
		state->GuestVmcb->ControlArea.InterceptVmload = 1;
		state->GuestVmcb->ControlArea.InterceptVmsave = 1;

		//state->GuestVmcb->ControlArea.InterceptCr.rw.write.layout.WriteCr3 = 1;

		state->GuestVmcb->ControlArea.InterceptStgi = 1;
		state->GuestVmcb->ControlArea.InterceptClgi = 1;
		state->GuestVmcb->ControlArea.InterceptSkinit = 1;
		state->GuestVmcb->ControlArea.InterceptInvlpga = 1;

		state->GuestVmcb->ControlArea.MsrpmBasePa = state->MsrPermissionsMapPhysicalAddress;

		SetMsrWrite(state, Msr::Amd::Efer::k_msr);
		SetMsrWrite(state, Msr::Amd::VmCr::k_msr);
		if (CPU::bCETSupported) {
			SetMsrRead(state, Msr::Amd::Efer::k_msr);
			SetMsrRead(state, Msr::Amd::VmCr::k_msr);
		}
		SetMsrReadWrite(state, (unsigned long long)Msr::Amd::AmdMsr::VM_HSAVE_PA);
		SetMsrReadWrite(state, (unsigned long long)Msr::Amd::AmdMsr::PAT);
		state->GuestVmcb->StateSaveArea.Efer = Msr::Msr::read<Msr::Amd::Efer>().raw;
		state->GuestVmcb->StateSaveArea.Cr0 = __readcr0();
		state->GuestVmcb->StateSaveArea.Cr2 = __readcr2();
		state->GuestVmcb->StateSaveArea.Cr3 = __readcr3();
		state->GuestVmcb->StateSaveArea.Cr4 = __readcr4();
		state->GuestShadowRegisters.ShadowCr4 = __readcr4();
		CR4 cr4;
		cr4.Flags = state->GuestShadowRegisters.ShadowCr4;
		//cr4.CETEnabled = 0;

		state->GuestVmcb->StateSaveArea.Cr4 = cr4.Flags;

		state->GuestVmcb->StateSaveArea.GuestPat = __readmsr((unsigned long)Msr::Amd::AmdMsr::PAT);

		state->GuestVmcb->StateSaveArea.Gdtr.Base = gdt.BaseAddress;
		state->GuestVmcb->StateSaveArea.Gdtr.Limit = gdt.Limit;
		state->GuestVmcb->StateSaveArea.Idtr.Base = idt.BaseAddress;
		state->GuestVmcb->StateSaveArea.Idtr.Limit = idt.Limit;
		//state->GuestVmcb->StateSaveArea.Cpl = 0;
		//state->GuestVmcb->StateSaveArea.Cstar = __readmsr((unsigned long)Msr::Amd::AmdMsr::CSTAR);
		//state->GuestVmcb->StateSaveArea.Lstar = __readmsr((unsigned long)Msr::Amd::AmdMsr::LSTAR);
		//state->GuestVmcb->StateSaveArea.Star = __readmsr((unsigned long)Msr::Amd::AmdMsr::STAR);
		//state->GuestVmcb->StateSaveArea.Sfmask = __readmsr((unsigned long)0xC0000084);
		//state->GuestVmcb->StateSaveArea.KernelGsBase = __readmsr((unsigned long)0xC0000102);

		//state->GuestVmcb->StateSaveArea.SysenterCs = __readmsr((unsigned long)0x174);
		//state->GuestVmcb->StateSaveArea.SysenterEsp = __readmsr((unsigned long)0x175);
		//state->GuestVmcb->StateSaveArea.SysenterEip = __readmsr((unsigned long)0x176);


		state->GuestVmcb->StateSaveArea.Cs.Selector.raw = contextToResume->SegCs;
		state->GuestVmcb->StateSaveArea.Ds.Selector.raw = contextToResume->SegDs;
		state->GuestVmcb->StateSaveArea.Es.Selector.raw = contextToResume->SegEs;
		state->GuestVmcb->StateSaveArea.Ss.Selector.raw = contextToResume->SegSs;
		state->GuestVmcb->StateSaveArea.Gs.Selector.raw = contextToResume->SegGs;
		state->GuestVmcb->StateSaveArea.Fs.Selector.raw = contextToResume->SegFs;

		SEG_SELECTOR cs, ds, es, ss, gs, fs;
		GetSegmentDescriptor(&cs, contextToResume->SegCs, (PUCHAR)gdt.BaseAddress);
		GetSegmentDescriptor(&ds, contextToResume->SegDs, (PUCHAR)gdt.BaseAddress);
		GetSegmentDescriptor(&es, contextToResume->SegEs, (PUCHAR)gdt.BaseAddress);
		GetSegmentDescriptor(&ss, contextToResume->SegSs, (PUCHAR)gdt.BaseAddress);
		GetSegmentDescriptor(&gs, contextToResume->SegGs, (PUCHAR)gdt.BaseAddress);
		GetSegmentDescriptor(&fs, contextToResume->SegFs, (PUCHAR)gdt.BaseAddress);

		state->GuestVmcb->StateSaveArea.Cs.Limit = cs.LIMIT;
		state->GuestVmcb->StateSaveArea.Ds.Limit = ds.LIMIT;
		state->GuestVmcb->StateSaveArea.Es.Limit = es.LIMIT;
		state->GuestVmcb->StateSaveArea.Ss.Limit = ss.LIMIT;
		state->GuestVmcb->StateSaveArea.Gs.Limit = gs.LIMIT;
		state->GuestVmcb->StateSaveArea.Fs.Limit = fs.LIMIT;

		state->GuestVmcb->StateSaveArea.Cs.Attrib.raw = cs.ATTRIBUTES.UCHARs;
		state->GuestVmcb->StateSaveArea.Ds.Attrib.raw = ds.ATTRIBUTES.UCHARs;
		state->GuestVmcb->StateSaveArea.Es.Attrib.raw = es.ATTRIBUTES.UCHARs;
		state->GuestVmcb->StateSaveArea.Ss.Attrib.raw = ss.ATTRIBUTES.UCHARs;
		state->GuestVmcb->StateSaveArea.Gs.Attrib.raw = gs.ATTRIBUTES.UCHARs;
		state->GuestVmcb->StateSaveArea.Fs.Attrib.raw = fs.ATTRIBUTES.UCHARs;



		state->GuestVmcb->StateSaveArea.Rflags = contextToResume->EFlags;
		state->GuestVmcb->StateSaveArea.Rsp = contextToResume->Rsp;
		state->GuestVmcb->StateSaveArea.Rip = contextToResume->Rip;
		state->GuestVmcb->StateSaveArea.Rax = contextToResume->Rax;

		state->GuestState.vg_cr2 = __readcr2();
		state->GuestState.vg_dr0 = contextToResume->Dr0;
		state->GuestState.vg_dr1 = contextToResume->Dr1;
		state->GuestState.vg_dr2 = contextToResume->Dr2;
		state->GuestState.vg_dr3 = contextToResume->Dr3;
		state->GuestState.vg_dr6 = contextToResume->Dr6;
		state->GuestState.vg_xcr0 = _xgetbv(0);
		state->GuestState.vg_rflags = contextToResume->EFlags;
		state->GuestState.vg_rsi = contextToResume->Rsi;
		state->GuestState.vg_rax = contextToResume->Rax;
		state->GuestState.vg_rbx = contextToResume->Rbx;
		state->GuestState.vg_rcx = contextToResume->Rcx;
		state->GuestState.vg_rdx = contextToResume->Rdx;
		state->GuestState.vg_rdi = contextToResume->Rdi;
		state->GuestState.vg_rbp = contextToResume->Rbp;
		state->GuestState.vg_r8 = contextToResume->R8;
		state->GuestState.vg_r9 = contextToResume->R9;
		state->GuestState.vg_r10 = contextToResume->R10;
		state->GuestState.vg_r11 = contextToResume->R11;
		state->GuestState.vg_r12 = contextToResume->R12;
		state->GuestState.vg_r13 = contextToResume->R13;
		state->GuestState.vg_r14 = contextToResume->R14;
		state->GuestState.vg_r15 = contextToResume->R15;


		state->GuestState.vg_xmm0 = contextToResume->Xmm0;
		state->GuestState.vg_xmm1 = contextToResume->Xmm1;
		state->GuestState.vg_xmm2 = contextToResume->Xmm2;
		state->GuestState.vg_xmm3 = contextToResume->Xmm3;
		state->GuestState.vg_xmm4 = contextToResume->Xmm4;
		state->GuestState.vg_xmm5 = contextToResume->Xmm5;
		return true;
	}
	bool IsVirtualised(void) {
		return CPU::IsHypervOn();
	}

	ULONG_PTR Virtualise() {
		DbgMsg("[SVM] Virtualising core 0x%x", CPU::GetCPUIndex());
		VirtualiseCore(vmm::vGuestStates[CPU::GetCPUIndex()].SvmState);
		DbgMsg("[SVM] Returning from Virtualise call");
		return STATUS_SUCCESS;
	}
#pragma warning (disable:4065)
	void AdvanceRip(SVMState* state) {
		state->GuestVmcb->StateSaveArea.Rip = state->GuestVmcb->ControlArea.NextRip;
	}

	ULONG_PTR IpiTest(ULONG_PTR useless) {
		DbgMsg("[SVM] IpiTest");
		return useless;
	}

	bool HandleCpuid(SVMState* state) {

		int result[4]{ 0, 0, 0, 0 };
		if (vmcall::ValidateCommunicationKey(0) && //Key not set yet
			state->GuestState.vg_rax == 'Hypr' && state->GuestState.vg_rcx == 'Chck') {
			state->GuestState.vg_rax = 'Yass';
			return true;
		}
		else if (vmcall::ValidateCommunicationKey(state->GuestState.vg_rax)
			&& vmcall::IsVmcall(state->GuestState.vg_r9)) {
			state->GuestState.vg_rax = vmcall::HandleVmcall(state->GuestState.vg_rcx, state->GuestState.vg_rdx, state->GuestState.vg_r8, state->GuestState.vg_r9);
			return true;
		}
		else {
			__cpuidex(result, (INT32)state->GuestState.vg_rax, (INT32)state->GuestState.vg_rcx);
		}
		switch (state->GuestState.vg_rax) {
		case 0x80000001: /* Extended function info */
			result[2] = result[2] & VMM_ECPUIDECX_MASK;
			break;
		case 0x8000000A: /*SVM Features*/

			result[0] = 0;
			result[1] = 0;
			result[2] = 0;
			result[3] = 0;
			break;
		}
		state->GuestState.vg_rax = result[0];
		state->GuestState.vg_rbx = result[1];
		state->GuestState.vg_rcx = result[2];
		state->GuestState.vg_rdx = result[3];
		return true;
	}

	bool HandleMsrRead(SVMState* state) {

		switch (state->GuestState.vg_rcx) {
		case Msr::Amd::Efer::Efer::Efer::Efer::Efer::Efer::k_msr: {
			Msr::MsrLayout<Msr::Amd::Efer> efer;
			efer.raw = state->GuestVmcb->StateSaveArea.Efer;
			efer.layout.SecureVirtualMachineEnable = 0;
			state->GuestState.vg_rax = (efer.raw & 0xFFFFFFFFULL);
			state->GuestState.vg_rdx = (efer.raw >> 32);
			break;
		}
		case Msr::Amd::VmCr::k_msr: {
			Msr::MsrLayout<Msr::Amd::VmCr> efer;
			efer.read();
			efer.layout.LOCK = 1;
			efer.layout.SVMDIS = 1;
			state->GuestState.vg_rax = (efer.raw & 0xFFFFFFFFULL);
			state->GuestState.vg_rdx = (efer.raw >> 32);
			break;
		}
		case (unsigned long long) Msr::Amd::AmdMsr::VM_HSAVE_PA: {
			InjectEvent(state, SVM::e_Exception, InterruptVector::GeneralProtection, 0, true);
			return false;
		}
		default: {
			unsigned long long ret = 0;
			__try {
				ret = __readmsr(state->GuestState.vg_rcx);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				InjectEvent(state, SVM::e_Exception, InterruptVector::GeneralProtection, 0, true);
				return false;
			}
			state->GuestState.vg_rax = (ret & 0xFFFFFFFFULL);
			state->GuestState.vg_rdx = (ret >> 32);
			break;
		}
		}

		return true;
	}
	bool HandleMsrWrite(SVMState* state) {
		unsigned long long val =
			 (state->GuestState.vg_rdx << 32) | (state->GuestState.vg_rax & 0xFFFFFFFFULL);

		switch (state->GuestState.vg_rcx) {
		case Msr::Amd::Efer::k_msr: {
			Msr::MsrLayout<Msr::Amd::Efer> efer;
			efer.raw = val;
			efer.layout.SecureVirtualMachineEnable = 1;
			state->GuestVmcb->StateSaveArea.Efer = efer.raw;
			break;
		}
		case Msr::Amd::VmCr::k_msr:
		case (unsigned long long) Msr::Amd::AmdMsr::VM_HSAVE_PA: {
			InjectEvent(state, SVM::e_Exception, InterruptVector::GeneralProtection, 0, true);
			return false;
		}
		case (unsigned long long) Msr::Amd::AmdMsr::PAT: {
			return true;
		}
		default: {
			__try {
				__writemsr(state->GuestState.vg_rcx, val);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				InjectEvent(state, SVM::e_Exception, InterruptVector::GeneralProtection, vmm::vGuestStates[CPU::GetCPUIndex(true)].lastErrorCode, true);
				return false;
			}
		}
		}

		vmm::UpdateLastValidTsc();
		return true;
	}
	bool HandleVirtualInterrupt(SVMState* state) {
		state->GuestVmcb->ControlArea.EventInjection = state->EventInjectionShadow;
		state->EventInjectionShadow = 0;
		state->GuestVmcb->ControlArea.InterceptVirtualIntr = 0;
		return false;
	}
	UINT64 GetGPRNumberForCrExit(SVMState* state) {
		//DbgMsg("[SVM] ExitInfo1: 0x%x", (state->GuestVmcb->ControlArea.ExitInfo1));
		//DbgMsg("[SVM] GPR number: 0x%x", (state->GuestVmcb->ControlArea.ExitInfo1 & 15));
		return (state->GuestVmcb->ControlArea.ExitInfo1 & 15);
	}

	UINT64* SVM::GetRegisterForCrExit(SVMState* state) {
		switch (GetGPRNumberForCrExit(state)) {
		case 0:
			return &state->GuestState.vg_rax;
		case 1:
			return &state->GuestState.vg_rcx;
		case 2:
			return &state->GuestState.vg_rdx;
		case 3:
			return &state->GuestState.vg_rbx;
		case 4:
			return &state->GuestVmcb->StateSaveArea.Rsp;
		case 5:
			return &state->GuestState.vg_rbp;
		case 6:
			return &state->GuestState.vg_rsi;
		case 7:
			return &state->GuestState.vg_rdi;
		case 8:
			return &state->GuestState.vg_r8;
		case 9:
			return &state->GuestState.vg_r9;
		case 10:
			return &state->GuestState.vg_r10;
		case 11:
			return &state->GuestState.vg_r11;
		case 12:
			return &state->GuestState.vg_r12;
		case 13:
			return &state->GuestState.vg_r13;
		case 14:
			return &state->GuestState.vg_r14;
		case 15:
			return &state->GuestState.vg_r15;
		default:
			return 0;
		}
	}

	bool HandleCr4Write(SVMState* state) {
		CR4 oldCr4;
		oldCr4.Flags = state->GuestVmcb->StateSaveArea.Cr4;
		UINT64* reg = GetRegisterForCrExit(state);
		CR4 cr4;
		cr4.Flags = *reg;

		/*GP: */
		/*If an attempt is made to change CR4.PCIDE from 0 to 1 while CR3[11:0] ≠ 000H.*/
		/*If an attempt is made to write a 1 to any reserved bit in CR4.*/
		/*If an attempt is made to leave IA-32e mode by clearing CR4.PAE[bit 5].*/
		if (cr4.PcidEnable == 1)
		{
			CR3 cr3;
			cr3.Flags = state->GuestVmcb->StateSaveArea.Cr3;
			if (cr3.Flags & 0xFFF) {
				DebugBreak();
				InjectEvent(state, SVM::e_Exception, InterruptVector::GeneralProtection, 0, true);
				return false;
			}
		}


		if (cr4.Reserved1 || cr4.Reserved2 || cr4.Reserved3 || cr4.Reserved4) {
			DebugBreak();
			InjectEvent(state, SVM::e_Exception, InterruptVector::GeneralProtection, 0, true);
			return false;
		}
		if (!state->SVMFlags.CETSupported)
			if (cr4.CETEnabled) {
				InjectEvent(state, SVM::e_Exception, InterruptVector::GeneralProtection, 0, true);
				return false;
			}
		
		state->GuestShadowRegisters.ShadowCr4 = *reg;
		state->GuestVmcb->StateSaveArea.Cr4 = cr4.Flags;
		return true;
	}	
	bool HandleCr4Read(SVMState* state) {
		UINT64* reg = GetRegisterForCrExit(state);
		*reg = state->GuestShadowRegisters.ShadowCr4;
		return true;
	}

	bool HandleCr3Write(SVMState* state) {
		vmm::UpdateLastValidTsc();

		UINT64* reg = GetRegisterForCrExit(state);
		
		//DWORD dwCore = CPU::GetCPUIndex(true);
		//PVM_STATE pState = &vmm::vGuestStates[dwCore];
		//CR3 cr3 = { 0 };
		//cr3.Flags = *reg;
		//
		//CR3 lastBlockedCr3 = { 0 };
		//if (pState->lastExitedCr3)
		//	lastBlockedCr3.Flags = pState->lastExitedCr3;
		//else
		//	lastBlockedCr3 = vmm::GetGuestCR3();
		//
		//if (
		//	!eac::IsNmiBlocked(cr3)
		//	&& eac::IsNmiBlocked(lastBlockedCr3)
		//	) {
		//	if (eac::GetAndDecreaseNmiCount(lastBlockedCr3)) {
		//		InjectNMI(state);
		//		pState->lastExitedCr3 = vmm::GetGuestCR3().Flags;
		//	}
		//	else {
		//		pState->lastExitedCr3 = 0;
		//	}
		//}

		ClearGuestNonGlobalTLB(state);
		state->GuestShadowRegisters.ShadowCr3 = *reg;
		state->GuestVmcb->StateSaveArea.Cr3 = *reg;
		return true;
	}
	bool HandleCr3Read(SVMState* state) {
		UINT64* reg = GetRegisterForCrExit(state);
		*reg = vmm::GetGuestCR3().Flags;
		return true;
	}

	bool HandleNPF(SVMState* state) {
		return EPT::HandlePageHookExit(state->GuestVmcb->ControlArea.ExitInfo2);
	}

	//https://howtohypervise.blogspot.com/2019/01/a-common-missight-in-most-hypervisors.html
	void InjectPendingExceptions(SVMState* state) {
		RFLAGS rFlags = { 0 };
		rFlags.Flags = state->GuestVmcb->StateSaveArea.Rflags;
		//When BTF is active a trap exception is delivered only on branches
		if (rFlags.TrapFlag) {
			DR6 dr6 = { 0 };
			dr6.Flags = state->GuestVmcb->StateSaveArea.Dr6;
			dr6.SingleInstruction = true;
			state->GuestState.vg_dr6 = dr6.Flags;
			InjectEvent(state, SVM::e_Exception, InterruptVector::Debug, 0, false);
		}
	}

	bool HandleVmExit(SVMState* state) {
		vmm::vGuestStates[state->CPUCore].bIncRip = true;

		if (vmm::IsTimeoutExpired()) {
			DWORD dwCore = CPU::GetCPUIndex(true);
			state->GuestState.vg_rcx = vmm::tscDeltaTimeout;
			state->GuestState.vg_rdx = vmm::vGuestStates[dwCore].lastCr3Tsc;
			state->GuestState.vg_r8 = (__rdtsc() - vmm::vGuestStates[dwCore].lastCr3Tsc);
			InjectEvent(state, SVM::e_Exception, InterruptVector::VirtualizationException, 0, false);
		}

		//InjectPendingExceptions(state);
		
		vmoperations::ExecuteOperations(state);
		if (vmexit::OnVmexit(state->GuestState.vg_exit_reason, state))
			return vmm::vGuestStates[state->CPUCore].bIncRip;

		switch ((Svm::SvmExitCode)state->GuestState.vg_exit_reason) {
		case Svm::SvmExitCode::VMEXIT_CPUID:
			if (!HandleCpuid(state))
				return false;
			break;
		case Svm::SvmExitCode::VMEXIT_MSR:

			if (state->GuestVmcb->ControlArea.ExitInfo1 == 1) {
				if (!HandleMsrWrite(state))
					return false;
			}
			else {
				if (!HandleMsrRead(state))
					return false;
			}
			break;
		case Svm::SvmExitCode::VMEXIT_CR4_READ:
			return HandleCr4Read(state);
		case Svm::SvmExitCode::VMEXIT_CR4_WRITE:
			return HandleCr4Write(state);
		case Svm::SvmExitCode::VMEXIT_CR3_READ:
			return HandleCr3Read(state);
		case Svm::SvmExitCode::VMEXIT_CR3_WRITE:
			return HandleCr3Write(state);
		case Svm::SvmExitCode::VMEXIT_INTR:
			return false;
		case Svm::SvmExitCode::VMEXIT_VINTR:
			return HandleVirtualInterrupt(state);
		case Svm::SvmExitCode::VMEXIT_MWAIT:
		case Svm::SvmExitCode::VMEXIT_MWAIT_CONDITIONAL:
		case Svm::SvmExitCode::VMEXIT_MONITOR:
		case Svm::SvmExitCode::VMEXIT_VMRUN:
		case Svm::SvmExitCode::VMEXIT_VMMCALL:
		case Svm::SvmExitCode::VMEXIT_VMLOAD:
		case Svm::SvmExitCode::VMEXIT_VMSAVE:
		case Svm::SvmExitCode::VMEXIT_STGI:
		case Svm::SvmExitCode::VMEXIT_CLGI:
		case Svm::SvmExitCode::VMEXIT_SKINIT:
		case Svm::SvmExitCode::VMEXIT_RDTSCP:
		case Svm::SvmExitCode::VMEXIT_ICEBP:
		case Svm::SvmExitCode::VMEXIT_INVLPGA:
			//Inject UD
			InjectEvent(state, SVM::e_Exception, InterruptVector::InvalidOpcode, 0, false);
			return false;
		case Svm::SvmExitCode::VMEXIT_NPF: {
			if (HandleNPF(state)) {
				InjectEvent(state, SVM::e_Exception, InterruptVector::InvalidOpcode, 0, false);
			}
			return false;
		}
		default:
			DebugBreak();
			InjectEvent(state, SVM::e_Exception, InterruptVector::Overflow, 0, false);
			return false;
		}

		return true;
	}
	bool SVMEnter(SVMState* state) {
		DbgMsg("[SVM] About to turn on SVM");
		//DebugBreak();
		DbgMsg("[SVM] Creating new stack");
		CPU::ChangeRSP((size_t)state->HostStack + 2048);

		while (true) {
			Seg::DescriptorTableRegister<Seg::Mode::longMode> gdt;
			_sgdt(&gdt);

			vmm::vGuestStates[state->CPUCore].bVmxRoot = false;

			int ret = svm_enter_guest(state->GuestVmcbPhysicalAddress, &state->GuestState, &gdt);
			_enable();

			if (!ret /*Success*/) {
				state->GuestVmcb->ControlArea.TlbControl.layout.TlbControl = 0x0;
				state->GuestVmcb->ControlArea.EventInjection = 0;
				state->GuestState.vg_rax = state->GuestVmcb->StateSaveArea.Rax;
				state->GuestState.vg_rflags = state->GuestVmcb->StateSaveArea.Rflags;
				state->GuestState.vg_exit_reason = state->GuestVmcb->ControlArea.ExitCode;

				vmm::vGuestStates[state->CPUCore].bVmxRoot = true;
				if (HandleVmExit(state)) {
					AdvanceRip(state);
				}
			}
			else {
				DbgMsg("[SVM] Failed entering guest: 0x%x", ret);
				KeBugCheck(0xaaaabbbb);
				break;
			}
			state->GuestVmcb->StateSaveArea.Rax = state->GuestState.vg_rax;
			state->GuestVmcb->StateSaveArea.Rflags = state->GuestState.vg_rflags;
		}

		return true;
	}
	bool GoForVirtualisation(CONTEXT* restore, SVMState* state) {
		_disable();
		Seg::DescriptorTableRegister<Seg::Mode::longMode> gdt, idt, ldt;
		__sidt(&idt);
		_sgdt(&gdt);

		DbgMsg("[SVM] Setting up VMCB");
		SetupVMCB(state, restore);

		DbgMsg("[SVM] Setting up page tables");
#ifdef PROPRIETARY_PAGE_TABLES
		__writecr3(vmm::hostCR3.Flags);
#endif
		DbgMsg("[SVM] Setting up GDT");
#ifdef PROPRIETARY_GDT
		SEG_SELECTOR SegmentSelector;
		GetSegmentDescriptor(&SegmentSelector, CPU::GetTr(), (PUCHAR)CPU::GetGdtBase());
		RtlCopyMemory(&state->HostTss, (PVOID)SegmentSelector.BASE, sizeof(state->HostTss));


		RtlCopyMemory(state->HostGdt, (PVOID)CPU::GetGdtBase(), PAGE_SIZE);
		const auto trIndex = SEGMENT_SELECTOR{ CPU::GetTr() }.Index;
		segment_descriptor_addr_t tss{ &state->HostTss };
		state->HostGdt[trIndex].BaseAddressUpper = tss.upper;
		state->HostGdt[trIndex].BaseAddressHigh = tss.high;
		state->HostGdt[trIndex].BaseAddressMiddle = tss.middle;
		state->HostGdt[trIndex].BaseAddressLow = tss.low;
		state->GdtReg.BaseAddress = (uintptr_t)state->HostGdt;
		state->GdtReg.Limit = gdt.Limit;

		_lgdt(&state->GdtReg);
#endif

		DbgMsg("[SVM] Setting up IDT");
#ifdef PROPRIETARY_IDT
		state->HostIdt.setup();
		state->HostIdt.setup_entry(EXCEPTION_VECTOR_NMI, true, __nmi_handler_vm);
		state->HostIdt.setup_entry(EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT, true, __gp_handler_vm);
		state->HostIdt.setup_entry(EXCEPTION_VECTOR_PAGE_FAULT, true, __pf_handler_vm);
		state->HostIdt.setup_entry(EXCEPTION_VECTOR_DIVIDE_ERROR, true, __de_handler_vm);
		state->IdtReg.BaseAddress = (uintptr_t)state->HostIdt.get_address();
		state->IdtReg.Limit = state->HostIdt.get_limit();
		__lidt(&state->IdtReg);
#endif
		return SVMEnter(state);

	} 
	bool VirtualiseCore(SVMState* state) {
		if (!InitialiseCore(state))
			return false;

		Msr::MsrLayout<Msr::Amd::Efer> efer;
		efer.read();
		efer.layout.SecureVirtualMachineEnable = 1;
		efer.write();

		static bool bLoaded[64] = { 0 };

		CONTEXT restore;
		RtlCaptureContext(&restore);

		if (bLoaded[state->CPUCore]) {

			DbgMsg("[SVM] Returning");
			return true;
		}
		bLoaded[state->CPUCore] = true;
		return GoForVirtualisation(&restore, state);
	}
	bool VirtualiseAllCores(void)
	{
		DbgMsg("[SVM] Virtualising all cores");

		for (int i = 0; i < vmm::dwCores; i++) {
			vmm::vGuestStates[i].SvmState = (SVMState*)cpp::kMallocTryAllZero(sizeof(SVMState));
			SVMState* state = vmm::vGuestStates[i].SvmState;
			if (!state)
			{
				DbgMsg("[SVM] Failed to allocate state on core 0x%x, returning", i);
				return false;
			}
			memset(state, 0, sizeof(state));
			state->GuestVmcb = (Svm::Vmcb*)cpp::kMallocTryAllZero(sizeof(Svm::Vmcb));
			ASSERTMSG((PSTR)"No GuestVmcb", state->GuestVmcb);
			if (!state->GuestVmcb)
			{
				DbgMsg("[SVM] Failed to allocate GuestVmcb on core 0x%x, returning", i);
				return false;
			}
			memset(state->GuestVmcb, 0, sizeof(state->GuestVmcb));
			state->HostState = (UINT8*)cpp::kMallocTryAllZero(4096);
			ASSERTMSG((PSTR)"No HostState", state->HostState);
			if (!state->HostState)
			{
				DbgMsg("[SVM] Failed to allocate HostState on core 0x%x, returning", i);
				return false;
			}
			memset(state->HostState, 0, 4096);
			state->MsrPermissionsMap = (Svm::Msrpm*)0;//cpp::kMallocContinuous(sizeof(Svm::Msrpm));
			ASSERTMSG((PSTR)"No MsrPermissionsMap", state->MsrPermissionsMap);

			if (!state->MsrPermissionsMap)
			{
				DbgMsg("[SVM] WARNING: MsrPermissionsMap failed to allocate. Trying to allocate with kMalloc, which may cause issues!");
				state->MsrPermissionsMap = (Svm::Msrpm*)cpp::kMallocTryAllZero(sizeof(Svm::Msrpm));
			}			
			if (!state->MsrPermissionsMap)
			{
				DbgMsg("[SVM] Failed to allocate MsrPermissionsMap on core 0x%x, returning", i);
				return false;
			}
			state->HostStack = cpp::kMallocTryAllZero(4096);

			if (!state->HostStack)
			{
				DbgMsg("[SVM] Failed to allocate HostStack on core 0x%x, returning", i);
				return false;
			}
			ASSERTMSG((PSTR)"No HostStack", state->HostStack);
			memset(state->HostStack, 0, sizeof(4096));
		}
		DbgMsg("[SVM] Copying PML4 mapping");
		PVOID pPML4 = paging::CopyPML4Mapping();
		CR3 newCR3 = { 0 };
		newCR3.Flags = __readcr3();
		newCR3.AddressOfPageDirectory = Memory::VirtToPhy(pPML4) >> 12;

		vmm::hostCR3 = newCR3;

		vmm::pIdentityMap = identity::MapIdentityUntracked(vmm::hostCR3);
		DbgMsg("[VMM] Mapped vmx host identity mapping");

		PROCESSOR_RUN_INFO procInfo;
		procInfo.Flags = ~0ull;
		procInfo.bHighIrql = FALSE;

		//CPU::RunOnAllCPUs(SVM::Virtualise, procInfo);
		KeIpiGenericCall((PKIPI_BROADCAST_WORKER)&SVM::Virtualise, 0);
		DbgMsg("[SVM] KeIpiGenericCall done");
		return true;
	}

	bool IsAmdCpu(void) {
		bool isAMD = Cpuid::Cpuid::query<Cpuid::Generic::MaximumFunctionNumberAndVendorId>()->isAmd();
		if (isAMD)
			DbgMsg("[SVM] Is AMD");
		else
			DbgMsg("[SVM] Is not AMD");
		return isAMD;
	}

	bool CanEnterSvm(void) {
		DbgMsg("[SVM] CanEnterSVM");
		return IsAmdCpu() && CPU::CheckForSvmFeatures();
	}

}