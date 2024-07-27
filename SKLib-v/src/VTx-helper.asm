;x64 ABI is described here https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention

EXTERN VmExitHandler:PROC
EXTERN VmResumeExec:PROC
EXTERN SaveContext:PROC	
EXTERN RestoreContext:PROC
EXTERN VmxLaunch:PROC

.CONST

KTRAP_FRAME_SIZE            EQU     190h
MACHINE_FRAME_SIZE          EQU     28h

.code _text

; void VmxSaveAndLaunch(REGS& context);
VmxSaveAndLaunch PROC
	mov rax, _end
	push rax
	call SaveContext

	vmlaunch

	pop rax ; in case vmlaunch fails we restore the right return address
_end:
	ret
VmxSaveAndLaunch ENDP

; void VmxRestore(REGS& context);
VmxRestore PROC
	xor eax, eax
	mov al, byte ptr [rdx]
	cmp eax, 1
	je _skip_vmxoff
	vmxoff 
	mov qword ptr [rdx], 0

_skip_vmxoff:
	call RestoreContext ;This is a non returning call

	int 3
VmxRestore ENDP

; void VmExitWrapper();
VmExitWrapper PROC FRAME
    ; In oder for Windbg to display the stack trace of the guest while the
    ; VM-exit handlers are being executed, we use several tricks:
    ;   - The use of the FRAME (above) attribute. This emits a function table
    ;     entry for this function in the .pdata section. See also:
    ;     https://docs.microsoft.com/en-us/cpp/assembler/masm/proc?view=vs-2017
    ;
    ;   - The use of the .PUSHFRAME pseudo operation: This emits unwind data
    ;     indicating that a machine frame has been pushed on the stack. A machine
    ;     frame is usually pushed by the CPU in response to a trap or fault (
    ;     see: Exception- or Interrupt-Handler Procedures), hence this pseudo
    ;     operation is often used for their handler code. (In Windows kernel, the
    ;     use of this pseudo operation is often wrapped in the GENERATE_TRAP_FRAME
    ;     macro.) In our case, since VM-exit does not push the machine frame, we
    ;     manually allocate it in right above the VMM stack pointer. Nothing has
    ;     to be done in this function with regard to pushing the machine frame
    ;     since that and the VMM stack pointer are both already set up in
    ;     VmpInitializeVm. See the diagram in VmpInitializeVm for more details.
    ;     See also:
    ;     https://docs.microsoft.com/en-us/cpp/assembler/masm/dot-pushframe?view=vs-2017
    ;
    ;   - The use of the .ALLOCSTACK pseudo operation: This also emits another
    ;     unwind data indicating how much the function uses stack. (This pseudo
    ;     code is often wrapped by the alloc_stack macro and used within the
    ;     GENERATE_TRAP_FRAME macro). This function consumes 108h of stack on
    ;     the top of the KTRAP_FRAME size (minus the machine frame size which is
    ;     already allocated outside this function). See also:
    ;     https://docs.microsoft.com/en-us/cpp/assembler/masm/dot-allocstack?view=vs-2017
    .PUSHFRAME
    sub rsp, KTRAP_FRAME_SIZE - MACHINE_FRAME_SIZE
    .ALLOCSTACK KTRAP_FRAME_SIZE - MACHINE_FRAME_SIZE + 108h

	push 0		; align stack
	push 0
	and rsp, -16

	push 0 
	push 0 ;for extended control register

	sub rsp, 160h
    movaps xmmword ptr [rsp +  0h], xmm0
    movaps xmmword ptr [rsp + 10h], xmm1
    movaps xmmword ptr [rsp + 20h], xmm2
    movaps xmmword ptr [rsp + 30h], xmm3
    movaps xmmword ptr [rsp + 40h], xmm4
    movaps xmmword ptr [rsp + 50h], xmm5
	movaps xmmword ptr [rsp + 60h], xmm6
    movaps xmmword ptr [rsp + 70h], xmm7
    movaps xmmword ptr [rsp + 80h], xmm8
    movaps xmmword ptr [rsp + 90h], xmm9
    movaps xmmword ptr [rsp + 0a0h], xmm10
    movaps xmmword ptr [rsp + 0b0h], xmm11
	movaps xmmword ptr [rsp + 0c0h], xmm12
    movaps xmmword ptr [rsp + 0d0h], xmm13
	movaps xmmword ptr [rsp + 0e0h], xmm14
    movaps xmmword ptr [rsp + 0f0h], xmm15

	pushfq	
	push 0		; we do not need RIP here
	push r15
	push r14
	push r13
	push r12
	push r11
	push r10
	push r9
	push r8
	push rdi
	push rsi
	push rbp
	push rbp
	push rbx
	push rdx
	push rcx
	push rax

	mov rcx, rsp

	sub rsp, 20h		; make space on the stack
	.ENDPROLOG

	call VmExitHandler

	add rsp, 20h		; restore rsp

	pop rax
	pop rcx
	pop rdx
	pop rbx
	pop rbp
	pop rbp
	pop rsi
	pop rdi
	pop r8
	pop r9
	pop r10
	pop r11
	pop r12
	pop r13
	pop r14
	pop r15
	popfq				; just to move rsp
	popfq
	
	movaps xmm0,  xmmword ptr [rsp +  0h]
    movaps xmm1,  xmmword ptr [rsp + 10h]
    movaps xmm2,  xmmword ptr [rsp + 20h]
    movaps xmm3,  xmmword ptr [rsp + 30h]
    movaps xmm4,  xmmword ptr [rsp + 40h]
    movaps xmm5,  xmmword ptr [rsp + 50h]
	movaps xmm6, xmmword ptr [rsp + 60h]
    movaps xmm7, xmmword ptr [rsp + 70h]
    movaps xmm8, xmmword ptr [rsp + 80h]
    movaps xmm9, xmmword ptr [rsp + 90h]
    movaps xmm10, xmmword ptr [rsp + 0a0h]
    movaps xmm11, xmmword ptr [rsp + 0b0h]
	movaps xmm12, xmmword ptr [rsp + 0c0h]
    movaps xmm13, xmmword ptr [rsp + 0d0h]
	movaps xmm14, xmmword ptr [rsp + 0e0h]
    movaps xmm15, xmmword ptr [rsp + 0f0h]
	add rsp, 60h

	jmp VmResumeExec
VmExitWrapper ENDP

; void VmRestore(PREGS pContext);
VmRestore PROC
	mov rax, [rcx]
	mov rcx, [rcx+8h]
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

	movaps xmm0,  xmmword ptr [rcx + 80h +  0h]
    movaps xmm1,  xmmword ptr [rcx + 80h + 10h]
    movaps xmm2,  xmmword ptr [rcx + 80h + 20h]
    movaps xmm3,  xmmword ptr [rcx + 80h + 30h]
    movaps xmm4,  xmmword ptr [rcx + 80h + 40h]
    movaps xmm5,  xmmword ptr [rcx + 80h + 50h]

	push rax
	push rdx
	push rbp

	mov rax, qword ptr [rcx + 80h + 50h + 18h]
	cmp rax, 0
	je _skipxsetbv

	mov rdx, rax
	xsetbv	

_skipxsetbv:
	lea rbp, [rsp + 38h]

	; push SS
	mov rdx, 0804h; VMCS_GUEST_SS_SELECTOR
	vmread rax, rdx
	mov [rbp - 00h], rax

	; push RSP
	mov rdx, 681Ch; VMCS_GUEST_RSP
	vmread rax, rdx
	mov [rbp - 08h], rax

	; push RFLAGS
	mov rdx, 6820h; VMCS_GUEST_RFLAGS
	vmread rax, rdx
	mov [rbp - 10h], rax

	; push CS
	mov rdx, 0802h; VMCS_GUEST_CS_SELECTOR
	vmread rax, rdx
	mov [rbp - 18h], rax

	; push RIP
	mov rdx, 681Eh; VMCS_GUEST_RIP
	vmread rax, rdx
	mov [rbp - 20h], rax

	; the C++ exit-handler needs to ensure that the control register shadows
	; contain the current guest control register values (even the guest-owned
	; bits!) before returning.

	; store cr0 in rax
	mov rax, 6004h ; VMCS_CTRL_CR0_READ_SHADOW
	vmread rax, rax

	; store cr4 in rdx
	mov rdx, 6006h ; VMCS_CTRL_CR4_READ_SHADOW
	vmread rdx, rdx

	; execute vmxoff before we restore cr0 and cr4
	vmxoff

	; restore cr0 and cr4
	mov cr0, rax
	mov cr4, rdx
	vmxoff	

	pop rbp
	pop rdx
	pop rax

	iretq
VmRestore ENDP

AsmVmxSaveState PROC
	pushfq	; save r/eflag

	push rax
	push rcx
	push rdx
	push rbx
	push rbp
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	sub rsp, 0100h
	; It a x64 FastCall function so the first parameter should go to rcx

	mov rcx, rsp

	call VmxLaunch

	jmp AsmVmxRestoreState
		
AsmVmxSaveState ENDP

AsmVmxRestoreState PROC
	add rsp, 0100h

	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbp
	pop rbx
	pop rdx
	pop rcx
	pop rax
	
	popfq	; restore r/eflags

	xor eax, eax ; return STATUS_SUCCESS
	ret
	
AsmVmxRestoreState ENDP

END