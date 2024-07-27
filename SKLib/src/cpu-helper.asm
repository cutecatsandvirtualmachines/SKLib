.code _text

; void SaveContext(REGS& context);
SaveContext PROC
	mov [rcx], rax
	mov [rcx+8h], rcx
	mov [rcx+10h], rdx
	mov [rcx+18h], rbx
	mov [rcx+20h], rsp
	mov [rcx+28h], rbp
	mov [rcx+30h], rsi
	mov [rcx+38h], rdi
	mov [rcx+40h], r8
	mov [rcx+48h], r9
	mov [rcx+50h], r10
	mov [rcx+58h], r11
	mov [rcx+60h], r12
	mov [rcx+68h], r13
	mov [rcx+70h], r14
	mov [rcx+78h], r15

	; Adjust rsp to point to the caller's one
	mov rdx, [rcx+20h]
	add rdx, 8h
	mov [rcx+20h], rdx

	pushfq	
	pop rax
	mov [rcx+88h], rax

	movaps xmmword ptr [rcx + 90h + 0h] , xmm0
    movaps xmmword ptr [rcx + 90h + 10h], xmm1
    movaps xmmword ptr [rcx + 90h + 20h], xmm2
    movaps xmmword ptr [rcx + 90h + 30h], xmm3
    movaps xmmword ptr [rcx + 90h + 40h], xmm4
    movaps xmmword ptr [rcx + 90h + 50h], xmm5

	ret
SaveContext ENDP	

; void RestoreContext(REGS& context);
RestoreContext PROC
	mov rax, [rcx]
	mov rdx, [rcx+10h]
	mov rbx, [rcx+18h]
	mov rsp, [rcx+20h]
	mov rbp, [rcx+28h]
	mov rsi, [rcx+30h]
	mov rdi, [rcx+38h]
	mov r8,  [rcx+40h]
	mov r9,  [rcx+48h]
	mov r10, [rcx+50h]
	mov r11, [rcx+58h]
	mov r12, [rcx+60h]
	mov r13, [rcx+68h]
	mov r14, [rcx+70h]
	mov r15, [rcx+78h]
	
	push [rcx+88h] 
	popfq	
	push [rcx+80h]

	movaps xmm0, xmmword ptr [rcx + 90h + 0h]
    movaps xmm1, xmmword ptr [rcx + 90h + 10h]
    movaps xmm2, xmmword ptr [rcx + 90h + 20h]
    movaps xmm3, xmmword ptr [rcx + 90h + 30h]
    movaps xmm4, xmmword ptr [rcx + 90h + 40h]
    movaps xmm5, xmmword ptr [rcx + 90h + 50h]

	mov rcx, [rcx+8h]

	ret
RestoreContext ENDP	

; DWORD64 GetGdtBase();
GetGdtBase PROC
	LOCAL GDTR[10]:BYTE
	sgdt GDTR					; save global descriptor table register in local GDTR
	mov rax, qword ptr GDTR[2]	; the first 2 bytes indicate the GDT size
	ret
GetGdtBase ENDP

; DWORD32 GetGdtLimit();
GetGdtLimit PROC
	LOCAL GDTR[10]:BYTE
	sgdt GDTR					; save global descriptor table register in local GDTR
	mov ax, word ptr GDTR[0]	; the first 2 bytes indicate the GDT size
	ret
GetGdtLimit ENDP

; DWORD64 GetIdtBase();
GetIdtBase PROC
	LOCAL IDTR[10]:BYTE
	sidt IDTR					; save interrupt descriptor table in local IDTR
	mov rax, qword ptr IDTR[2]	; the first 2 bytes indicate the IDT size
	ret
GetIdtBase ENDP

; DWORD32 GetIdtLimit();
GetIdtLimit PROC
	LOCAL IDTR[10]:BYTE
	sidt IDTR					; save interrupt descriptor table in local IDTR
	mov ax, word ptr IDTR[0]	; the first 2 bytes indicate the IDT size
	ret
GetIdtLimit ENDP

; USHORT GetCs();
GetCs PROC
	mov rax, cs
	ret
GetCs ENDP

; USHORT GetDs();
GetDs PROC
	mov rax, ds
	ret
GetDs ENDP

; USHORT GetEs();
GetEs PROC
	mov rax, es
	ret
GetEs ENDP

; USHORT GetSs();
GetSs PROC
	mov rax, ss
	ret
GetSs ENDP

; USHORT GetFs();
GetFs PROC
	mov rax, fs
	ret
GetFs ENDP

; USHORT GetGs();
GetGs PROC
	mov rax, gs
	ret
GetGs ENDP

; USHORT GetTr();
GetTr PROC
	str rax
	ret
GetTr ENDP

; USHORT SetCs();
SetCs PROC
	mov cs, rcx
	ret
SetCs ENDP

; USHORT SetDs();
SetDs PROC
	mov ds, rcx
	ret
SetDs ENDP

; USHORT SetEs();
SetEs PROC
	mov es, rcx
	ret
SetEs ENDP

; USHORT SetSs();
SetSs PROC
	mov ss, rcx
	ret
SetSs ENDP

; USHORT SetFs();
SetFs PROC
	mov fs, rcx
	ret
SetFs ENDP

; USHORT SetGs();
SetGs PROC
	mov gs, rcx
	ret
SetGs ENDP

; USHORT SetTr();
SetTr PROC
	ltr cx
	ret
SetTr ENDP

; DWORD64 GetRflags();
GetRflags PROC
	PUSHFQ
	pop rax
	ret
GetRflags ENDP

; void SetRflags(DWORD64);
SetRflags PROC
	push rcx
	POPFQ
	ret
SetRflags ENDP

; USHORT GetLdtr();
GetLdtr PROC
	sldt rax
	ret
GetLdtr ENDP

; USHORT SetLdtr();
SetLdtr PROC
	lldt cx
	ret
SetLdtr ENDP

;void GetGdt(PVOID pGdt);
GetGdt PROC
	sgdt fword ptr [rcx]
	ret
GetGdt ENDP

;void SetGdt(PVOID pGdt);
SetGdt PROC
	lgdt fword ptr [rcx]
	ret
SetGdt ENDP	

;void GetIdt(PVOID pIdt);
GetIdt PROC
	sidt fword ptr [rcx]
	ret
GetIdt ENDP

;void SetIdt(PVOID pIdt);
SetIdt PROC
	lidt fword ptr [rcx]
	ret
SetIdt ENDP	

;void SetIF(bool bSet);
SetIF PROC
	PUSHFQ	
	pop rdx
	cmp rcx, 0
	je _unset
	or rdx, 200h
	jmp _end
_unset:
	mov r8, 200h
	not	r8
	and rdx, r8
_end:
	push rdx
	POPFQ
SetIF ENDP

; DWORD64 MSRRead(ULONG rcx);
MSRRead PROC
	rdmsr			; MSR[ecx] => edx:eax
	shl rdx, 32
	or rax, rdx
	ret
MSRRead ENDP

; void MSRWrite(ULONG32 rcx, ULONG64 ulVal);
MSRWrite PROC
	mov rax, rdx
	shr rdx, 32
	wrmsr			; edx:eax => MSR
	ret
MSRWrite ENDP

; NTSTATUS VMCALL(ULONG64 ulCallNum, ULONG64 ulOpt1, ULONG64 ulOpt2, ULONG64 ulOpt3);
VmxVMCALL PROC
	mov rax, r9
	xor r9, 0deada55h
	vmcall	
	ret
VmxVMCALL ENDP

; NTSTATUS CPUIDVmCall(ULONG64 ulCallNum, ULONG64 ulOpt1, ULONG64 ulOpt2, ULONG64 ulOpt3);
CPUIDVmCall PROC
	mov rax, r9
	xor r9, 0deada55h
	push rbx
	cpuid
	pop rbx
	ret
CPUIDVmCall ENDP

VMX_ERROR_CODE_SUCCESS              = 0
VMX_ERROR_CODE_FAILED_WITH_STATUS   = 1
VMX_ERROR_CODE_FAILED               = 2

; VMX_ERROR InveptContext(ULONG Type, PVOID Descriptors);
InveptContext PROC PUBLIC
	mov rax, 1397443682 ;'SKLb'
    invept  rcx, oword ptr [rdx]
    jz @jz
    jc @jc
    xor     rax, rax
    ret

    @jz: 
    mov     rax, VMX_ERROR_CODE_FAILED_WITH_STATUS
    ret

    @jc:
    mov     rax, VMX_ERROR_CODE_FAILED
    ret

InveptContext ENDP

; VMX_ERROR Invvpid(ULONG Type, PVOID Descriptors);
InvalidateVPID PROC
    invvpid  rcx, oword ptr [rdx]
    jz @jz
    jc @jc
    xor     rax, rax
    ret

    @jz: 
    mov     rax, VMX_ERROR_CODE_FAILED_WITH_STATUS
    ret

    @jc:
    mov     rax, VMX_ERROR_CODE_FAILED
    ret

InvalidateVPID ENDP

; void Jump(PVOID rip);
Jump PROC PUBLIC
	jmp rcx
Jump ENDP

; void ChangeRSP(size_t rsp);
ChangeRSP PROC
	mov rdx, qword ptr [rsp] ; return address of this function
	mov rsp, rcx
	push rdx
	ret
ChangeRSP ENDP

; void ClearTLB();
ClearTLB PROC
	mov rax, cr3
	mov cr3, rax
	ret
ClearTLB ENDP

; char IsVmxSupported();
IsVmxSupported PROC
	mov rax, 1
	cpuid
	mov rax, 1
	bt ecx, 5 ; test bit 5 for VMX support https://www.felixcloutier.com/x86/cpuid#fig-3-7
	jc done
	dec rax
done:
	ret
IsVmxSupported ENDP

; char EnableVmx();
EnableVmx PROC
	xor rax, rax
	mov rax, cr4

	or rax, 2000h ; bit 13
	mov cr4, rax

	mov rax, 1
	ret
EnableVmx ENDP

; char DisableVmx();
DisableVmx PROC
	xor rax, rax
	mov rax, cr4

	xor rax, 2000h ; bit 13
	mov cr4, rax

	mov rax, 1
	ret
DisableVmx ENDP

; char IsVmxEnabled();
IsVmxEnabled PROC
	mov eax, 1
	mov rcx, cr4
	bt rcx, 13
	jc done
	dec eax
done:
	ret
IsVmxEnabled ENDP

END