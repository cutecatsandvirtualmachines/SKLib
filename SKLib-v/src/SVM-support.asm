.code _text

EXTERN memcpy :PROC 
public new_stack
new_stack PROC
	sub rcx, 1024
	mov rdx, rsp
	sub rdx, 1024
	mov r8, 2048
	call memcpy
	add rax, 1024
	mov rsp, rax
	ret
new_stack ENDP


public _sldt
_sldt PROC
	sldt rcx
	ret
_sldt ENDP

public cr4test
cr4test PROC
	push rax ;0
	mov rax, cr4
	pop rax
	push rbx ;3 
	mov rbx, cr4
	pop rbx
	push rcx ;1
	mov rcx, cr4
	pop rcx
	push rdx ;2
	mov rdx, cr4
	pop rdx
	push rdi ;7
	mov rdi, cr4
	pop rdi
	push rsi ;6
	mov rsi, cr4
	pop rsi
	push rbp ;5
	mov rbp, cr4
	pop rbp
	ret
cr4test ENDP

;System V AMD64 argument order:

;RDI, RSI, RDX

;If the callee wishes to use registers RBX, RSP, RBP, and R12-R15, it must restore their original values before returning control to the caller. All other registers must be saved by the caller if it wishes to preserve their values.

;MSVC64 argument order:

;RCX, RDX, R8
;The registers RAX, RCX, RDX, R8, R9, R10, R11 are considered volatile (caller-saved).[25] 
;The registers RBX, RBP, RDI, RSI, RSP, R12, R13, R14, and R15 are considered nonvolatile (callee-saved).[25] 

;extern "C" int svm_enter_guest(ULONG64 vmcb, struct vcpu_gueststate* state, Seg::DescriptorTableRegister<Seg::Mode::longMode>* gdt);
public svm_enter_guest
svm_enter_guest PROC
	;clgi
	mov		r9, rcx ; Needs to be the FIRST ARGUMENT
	pushfq

	push	r8	; gdt pointer */ ;MUST BE THE THIRD ARGUMENT
	mov		r10, rdx
	;
	; Save (possibly) lazy-switched selectors
	;
	str		ax
	push	ax
	mov		ax, es
	push	ax
	mov		ax, ds
	push	ax
	mov		ax, ss
	push	ax

	mov		rcx, 0c0000100h ;MSR_FSBASE*/ 
	rdmsr
	push	rax
	push	rdx
	push	fs
	mov		rcx, 0c0000101h ;MSR_GSBASE*/ 
	rdmsr
	push	rax
	push	rdx
	push	gs
	mov		rcx, 0c0000102h ;MSR_KERNELGSBASE*/
	rdmsr
	push	rax
	push	rdx

	;/*
	; * Save various MSRs
	; */
	mov		rcx, 0c0000081h ;MSR_STAR*/
	rdmsr
	push	rax
	push	rdx

	mov		rcx, 0c0000082h ;MSR_LSTAR*/
	rdmsr
	push	rax
	push	rdx

	; XXX - unused? */
	mov		rcx, 0c0000083h ;MSR_CSTAR*/
	rdmsr
	push	rax
	push	rdx

	mov		rcx, 0c0000084h ;MSR_SFMASK*/
	rdmsr
	push	rax
	push	rdx

	; Preserve callee-preserved registers as per AMD64 ABI */
	;The registers RBX, RBP, RDI, RSI, RSP, R12, R13, R14, and R15 are considered nonvolatile (callee-saved).[25] 

	push	r15
	push	r14
	push	r13
	push	r12
	push	rbp
	push	rbx
	push	rdi
	push	rsi
	
	push	r10		; Guest Regs Pointer */ ; MUST BE SECOND ARGUMENT

	; Restore guest registers */
	mov		rax, r9; ; rax = vmcb pa */
	mov		r8,  [r10 + 0A0h]
	mov		dr0, r8
	mov		r8,  [r10 + 0A8h]
	mov		dr1, r8
	mov		r8,  [r10 + 0B0h]
	mov		dr2, r8
	mov		r8,  [r10 + 0B8h]
	mov		dr3, r8
	; %dr6 is saved in the VMCB */
	mov		r8,  [r10 + 078h]
	mov		cr2, r8
	mov		r15, [r10 + 070h]
	mov		r14, [r10 + 068h]
	mov		r13, [r10 + 060h]
	mov		r12, [r10 + 058h]
	mov		r11, [r10 + 050h]
	mov		rsi, [r10]
	mov		r9,  [r10 + 040h] ;marge
	mov		r8,  [r10 + 038h]
	mov		rbp, [r10 + 030h]
	mov		rdi, [r10 + 028h]
	mov		rdx, [r10 + 020h]
	mov		rcx, [r10 + 018h]
	mov		rbx, [r10 + 010h]
	; %rax at 0x08(%rsi) is not needed in SVM */
	movups xmm0,  xmmword ptr [r10 + 0d0h +  0h]
    movups xmm1,  xmmword ptr [r10 + 0d0h + 10h]
    movups xmm2,  xmmword ptr [r10 + 0d0h + 20h]
    movups xmm3,  xmmword ptr [r10 + 0d0h + 30h]
    movups xmm4,  xmmword ptr [r10 + 0d0h + 40h]
    movups xmm5,  xmmword ptr [r10 + 0d0h + 50h]

	mov		r10, [r10 + 048h]

	vmload	rax
	vmrun	rax
	vmsave	rax

	; Preserve guest registers not saved in VMCB */
	push	r10
	push	rdi
	mov		rdi, [rsp+010h] ;Gets the R10 we pushed earlier while saving callee-preserved regs
	mov		r10, [rsp+08h] ; Gets the guest R10
	mov		[rdi + 048h], r10
	pop		rdi
	pop		r10 ;discard

	pop		r10
	; %rax at 0x08(%rsi) is not needed in SVM */
	mov		[r10], rsi
	mov		[r10 + 010h], rbx
	mov		[r10 + 018h], rcx
	mov		[r10 + 020h], rdx
	mov		[r10 + 028h], rdi
	mov		[r10 + 030h], rbp
	mov		[r10 + 038h], r8
	mov		[r10 + 040h], r9
	mov		[r10 + 050h], r11
	mov		[r10 + 058h], r12
	mov		[r10 + 060h], r13
	mov		[r10 + 068h], r14
	mov		[r10 + 070h], r15

    movups xmmword ptr [r10 + 0d0h +  0h], xmm0
    movups xmmword ptr [r10 + 0d0h + 10h], xmm1
    movups xmmword ptr [r10 + 0d0h + 20h], xmm2
    movups xmmword ptr [r10 + 0d0h + 30h], xmm3
    movups xmmword ptr [r10 + 0d0h + 40h], xmm4
    movups xmmword ptr [r10 + 0d0h + 50h], xmm5
	mov		rax, cr2
	mov		[r10 + 078h], rax
	mov		rax, dr0
	mov		[r10 + 0a0h], rax
	mov		rax, dr1
	mov		[r10 + 0a8h], rax
	mov		rax, dr2
	mov		[r10 + 0b0h], rax
	mov		rax, dr3
	mov		[r10 + 0b8h], rax


	; %dr6 is saved in the VMCB */

	; %rdi = 0 means we took an exit */
	xor		r11, r11
restore_host_svm:
	pop		rsi
	pop		rdi
	pop		rbx
	pop		rbp
	pop		r12
	pop		r13
	pop		r14
	pop		r15

;	/*
;	 * Restore saved MSRs
;	 */
	pop		rdx
	pop		rax
	mov		rcx, 0c0000084h ;MSR_SFMASK*/
	wrmsr

	; XXX - unused? */
	pop		rdx
	pop		rax
	mov		rcx, 0c0000083h ;MSR_CSTAR*/
	wrmsr

	pop		rdx
	pop		rax
	mov		rcx, 0c0000082h ;MSR_LSTAR*/
	wrmsr

	pop		rdx
	pop		rax
	mov		rcx, 0c0000081h ;MSR_STAR*/
	wrmsr

;	/*
;	 * popw %gs will reset gsbase to 0, so preserve it
;	 * first. This is to accommodate possibly lazy-switched
;	 * selectors from above
;	 */
	cli
	pop		rdx
	pop		rax
	mov		rcx, 0c0000102h ;MSR_KERNELGSBASE*/
	wrmsr

	pop		gs
	pop		rdx
	pop		rax
	mov		rcx, 0c0000101h ;MSR_GSBASE*/ 
	wrmsr

	pop		fs
	pop		rdx
	pop		rax
	mov		rcx, 0c0000100h ;MSR_FSBASE*/ 
	wrmsr

	pop		ax
	mov		ss, ax
	pop		ax
	mov		ds, ax
	pop		ax
	mov		es, ax

	xor		rax, rax
	lldt	ax		; Host LDT is always 0 */

	pop		ax		; ax = saved TR */

	pop		rdx
	add		rdx, 2
	mov		rdx, [rdx]

	; rdx = GDTR base addr */
	and byte ptr[rdx + rax + 5], 0F9h	
	;andb	$0xF9, 5(%rdx, %rax)

	ltr		ax

	popfq

	mov		rax, r11
	ret
	lfence

svm_enter_guest ENDP

END