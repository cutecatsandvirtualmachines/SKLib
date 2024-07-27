
.code _text

;void nmiHandler();
EXTERN NmiHandler:PROC

EXTERN seh_handler_vm : proc
EXTERN seh_handler_ecode_vm : proc

; Macro for NMI-blocking iret.
nmiret macro

	; Emulate the iret instruction in order not to unblock NMIs.
	push rax					; Save the rax
	; Now the stack layout would be like:
	; qword ptr [rsp+8*0]	rax
	; qword ptr [rsp+8*1]	rip
	; word ptr [rsp+8*2]	cs
	; qword ptr [rsp+8*3]	rflags
	; qword ptr [rsp+8*4]	rsp
	; qword ptr [rsp+8*5]	ss
	mov rax,rsp					; Save the NMI stack pointer.
	lss rsp,[rax+8*4]			; Restore ss and rsp
	; Note that rsp is switched to pre-NMI stack, so use rax for memory addressing.
	push qword ptr [rax+18h]	; Store rflags to pre-NMI stack.
	popfq						; Restore rflags
	push qword ptr [rax+10h]	; Store cs to pre-NMI stack.
	push qword ptr [rax+8h]		; Store rip to pre-NMI stack.
	mov rax,qword ptr [rax]		; Restore rax
	retfq						; Restore cs and rip

endm

__nmi_handler_vm PROC
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	sub rsp, 20h
	call NmiHandler
	add rsp, 20h

	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp 
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax

	nmiret
__nmi_handler_vm ENDP

; #DE has no error code...
generic_interrupt_handler_vm PROC
__de_handler_vm proc
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	mov rcx, rsp
	sub rsp, 20h
	call seh_handler_vm
	add rsp, 20h

	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp 
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax

	iretq
__de_handler_vm endp
generic_interrupt_handler_vm ENDP

; PF and GP have error code...
generic_interrupt_handler_ecode_vm PROC
__pf_handler_vm proc
__gp_handler_vm proc
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	mov rcx, rsp
	sub rsp, 20h
	call seh_handler_ecode_vm
	add rsp, 20h

	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp 
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	add rsp, 8	; remove error code on the stack...

	iretq
__gp_handler_vm endp
__pf_handler_vm endp
generic_interrupt_handler_ecode_vm ENDP

END